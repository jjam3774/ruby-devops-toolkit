#!/usr/bin/env ruby
# frozen_string_literal: true
#
# win_print_spooler_audit.rb -- Audit the Windows Print Spooler attack surface.
#
# THE PROBLEM
# -----------
# The Print Spooler runs as SYSTEM, is enabled by default on every Windows
# install including domain controllers, and exposes an RPC interface that lets
# clients install printer drivers. "Install a driver" means "load a DLL into a
# SYSTEM process". That combination is why PrintNightmare (CVE-2021-1675 /
# CVE-2021-34527) turned into a two-year patch treadmill, and why the mitigation
# is not a single hotfix but a set of registry policies that are easy to set
# once and then silently regress the next time somebody edits a GPO.
#
# The dangerous state is not obvious from the Services console. A box can be
# fully patched and still be exploitable because a GPO sets
# NoWarningNoElevationOnInstall=1 -- a value Microsoft's own advisory calls out
# as making the system "vulnerable by design". Conversely, a box can look
# alarming (spooler running) and be perfectly fine, because it genuinely is a
# print server with restricted driver installation.
#
# WHAT THIS SCRIPT DOES
# ---------------------
# It reads the spooler's real configuration -- the service state via WMI, the
# printers and drivers via WMI, and the seven registry values that actually
# decide whether driver installation is privileged -- and grades each one
# PASS / WARN / FAIL with the exact remediation.
#
#   * Spooler service state and start mode, judged against the host's role
#   * RestrictDriverInstallationToAdministrators  (the primary mitigation)
#   * Point and Print: NoWarningNoElevationOnInstall, UpdatePromptSettings
#   * Point and Print: Restricted / TrustedServers / ServerList
#   * Package Point and Print only, and its server allow-list
#   * RpcAuthnLevelPrivacyEnabled (CVE-2021-1678 relay hardening)
#   * RegisterSpoolerRemoteRpcEndPoint (inbound remote print RPC)
#   * Inventory of installed drivers and shared printers, with FILE: ports flagged
#
# Read-only. It never stops the spooler, never writes a registry value, and
# never removes a driver. Every finding prints the command you would run.
#
# Usage:
#   ruby win_print_spooler_audit.rb                       # audit this host
#   ruby win_print_spooler_audit.rb --role print-server   # relax spooler checks
#   ruby win_print_spooler_audit.rb --json
#   ruby win_print_spooler_audit.rb --fixture sample.json # replay captured data
#   ruby win_print_spooler_audit.rb --capture out.json    # save this host's data
#
# Exit codes:  0 = clean   1 = warnings   2 = failures   3 = usage error

require 'json'
require 'optparse'
require 'time'

WINDOWS = RUBY_PLATFORM =~ /mswin|mingw|cygwin/ ? true : false

if WINDOWS
  require 'win32ole'
  require 'win32/registry'
end

# ===========================================================================
# Collectors
#
# Everything that touches the OS lives behind this interface. That is what
# makes the audit logic testable on a machine that has no spooler at all: the
# FixtureCollector replays a captured (or hand-written) JSON snapshot through
# exactly the same code path the live audit uses.
# ===========================================================================

# Reads live state from WMI and the registry.
class WindowsCollector
  HKLM = 0x80000002

  def initialize
    @wmi = WIN32OLE.connect('winmgmts://./root/cimv2')
  end

  def service(name)
    q = "SELECT Name, State, StartMode, StartName FROM Win32_Service WHERE Name='#{name}'"
    row = @wmi.ExecQuery(q).each.first
    return nil unless row

    { 'name' => row.Name, 'state' => row.State,
      'start_mode' => row.StartMode, 'start_name' => row.StartName }
  end

  def printers
    @wmi.ExecQuery('SELECT Name, Shared, ShareName, PortName, DriverName, Published, Local ' \
                   'FROM Win32_Printer').map do |p|
      { 'name' => p.Name, 'shared' => p.Shared, 'share_name' => p.ShareName,
        'port' => p.PortName, 'driver' => p.DriverName,
        'published' => p.Published, 'local' => p.Local }
    end
  rescue WIN32OLERuntimeError
    []
  end

  def drivers
    @wmi.ExecQuery('SELECT Name, DriverPath, Version, SupportedPlatform FROM Win32_PrinterDriver')
        .map do |d|
      { 'name' => d.Name, 'path' => d.DriverPath,
        'version' => d.Version, 'platform' => d.SupportedPlatform }
    end
  rescue WIN32OLERuntimeError
    []
  end

  def os_role
    row = @wmi.ExecQuery('SELECT ProductType, Caption FROM Win32_OperatingSystem').each.first
    return {} unless row

    # ProductType: 1 = workstation, 2 = domain controller, 3 = member server
    { 'product_type' => row.ProductType.to_i, 'caption' => row.Caption }
  rescue WIN32OLERuntimeError
    {}
  end

  # Returns nil when the value (or the whole key) is absent, which is a
  # meaningful state in its own right: "policy not configured".
  def reg_value(subkey, name)
    Win32::Registry::HKEY_LOCAL_MACHINE.open(subkey) do |k|
      begin
        k[name]
      rescue Win32::Registry::Error
        nil
      end
    end
  rescue Win32::Registry::Error
    nil
  end
end

# Replays a JSON snapshot. Same interface, no OS dependency.
class FixtureCollector
  def initialize(path)
    @data = JSON.parse(File.read(path))
  end

  def service(name) = (@data['services'] || {})[name]
  def printers     = @data['printers'] || []
  def drivers      = @data['drivers']  || []
  def os_role      = @data['os'] || {}

  def reg_value(subkey, name)
    (@data.dig('registry', subkey) || {})[name]
  end

  def to_h = @data
end

# ===========================================================================
# The registry values that matter
# ===========================================================================

PRINTERS_POLICY = 'SOFTWARE\Policies\Microsoft\Windows NT\Printers'
POINT_AND_PRINT = 'SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
PRINT_CONTROL   = 'System\CurrentControlSet\Control\Print'

# ===========================================================================
# Audit
# ===========================================================================

SEVERITY_ORDER = { 'FAIL' => 0, 'WARN' => 1, 'INFO' => 2, 'PASS' => 3 }.freeze

# File.dirname is platform-aware, which is exactly wrong here: we may be parsing
# a Windows path on a Linux box (fixture replay), where File.dirname('C:\a\b.dll')
# returns '.'. Split on both separators explicitly so the remediation command is
# correct no matter where the audit runs.
def win_dirname(path)
  parts = path.to_s.split(%r{[\\/]})
  return path.to_s if parts.size < 2

  parts[0..-2].join('\\')
end

def finding(sev, id, message, remediation = nil, **extra)
  { 'severity' => sev, 'id' => id, 'message' => message,
    'remediation' => remediation }.merge(extra.transform_keys(&:to_s)).compact
end

class SpoolerAudit
  def initialize(collector, role: nil)
    @c = collector
    @role = role
    @findings = []
    @facts = {}
  end

  attr_reader :findings, :facts

  def run
    check_service_state
    check_restrict_driver_install
    check_point_and_print
    check_package_point_and_print
    check_rpc_hardening
    inventory_printers
    inventory_drivers
    [@findings, @facts]
  end

  private

  def add(*args, **kw) = @findings << finding(*args, **kw)

  # --- 1. Is the spooler even running, and should it be? -------------------
  def check_service_state
    svc = @c.service('Spooler')
    os = @c.os_role
    @facts['os'] = os
    @facts['spooler'] = svc

    if svc.nil?
      add('INFO', 'spooler.absent', 'Print Spooler service not found on this host')
      return
    end

    running = svc['state'].to_s.casecmp('running').zero?
    product_type = os['product_type'].to_i
    role = @role || case product_type
                    when 2 then 'domain-controller'
                    when 3 then 'member-server'
                    else 'workstation'
                    end
    @facts['role'] = role

    if !running
      add('PASS', 'spooler.state',
          "Print Spooler is #{svc['state']} (start mode #{svc['start_mode']}) -- " \
          'the RPC attack surface is closed')
      return
    end

    case role
    when 'domain-controller'
      add('FAIL', 'spooler.on_dc',
          'Print Spooler is RUNNING on a domain controller',
          'A DC has no business printing. This is the single highest-value spooler ' \
          'target on the network (it enables the printer-bug coercion used in ' \
          'NTLM relay to AD CS). Disable it: ' \
          'Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled')
    when 'print-server'
      add('INFO', 'spooler.on_print_server',
          'Print Spooler is running on a declared print server (expected)',
          'Role declared via --role print-server; the driver-install policies below ' \
          'carry the whole weight of the mitigation here.')
    when 'member-server'
      add('WARN', 'spooler.on_member_server',
          'Print Spooler is running on a member server that is not a declared print server',
          'If this box does not serve printers, disable the spooler: ' \
          'Set-Service Spooler -StartupType Disabled. If it does, re-run with ' \
          '--role print-server.')
    else
      add('INFO', 'spooler.on_workstation',
          'Print Spooler is running on a workstation (normal, but keep the policies below correct)')
    end

    if svc['start_name'] && !svc['start_name'].to_s.match?(/LocalSystem/i)
      add('INFO', 'spooler.account',
          "Spooler runs as #{svc['start_name']} rather than LocalSystem")
    end
  end

  # --- 2. The primary PrintNightmare mitigation ---------------------------
  def check_restrict_driver_install
    v = @c.reg_value(PRINTERS_POLICY, 'RestrictDriverInstallationToAdministrators')
    @facts['RestrictDriverInstallationToAdministrators'] = v

    # Microsoft changed the DEFAULT to "restricted" in the August 2021 updates,
    # so an absent value is safe on a patched host -- but only implicitly, and a
    # single GPO can flip it. Absent is a WARN, not a PASS.
    if v.nil?
      add('WARN', 'pnp.restrict_driver_install.unset',
          'RestrictDriverInstallationToAdministrators is not configured',
          'Patched hosts default to restricted, but the value is unset so nothing ' \
          'pins it. Set it explicitly: reg add "HKLM\\' + PRINTERS_POLICY +
          '" /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f')
    elsif v.to_i == 1
      add('PASS', 'pnp.restrict_driver_install',
          'RestrictDriverInstallationToAdministrators = 1 (only admins may install drivers)')
    else
      add('FAIL', 'pnp.restrict_driver_install',
          "RestrictDriverInstallationToAdministrators = #{v} -- non-admins may install printer drivers",
          'This is the PrintNightmare mitigation and it is explicitly disabled. ' \
          'Set it to 1: reg add "HKLM\\' + PRINTERS_POLICY +
          '" /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f')
    end
  end

  # --- 3. Point and Print warning suppression -----------------------------
  def check_point_and_print
    no_warn = @c.reg_value(POINT_AND_PRINT, 'NoWarningNoElevationOnInstall')
    update  = @c.reg_value(POINT_AND_PRINT, 'UpdatePromptSettings')
    @facts['NoWarningNoElevationOnInstall'] = no_warn
    @facts['UpdatePromptSettings'] = update

    if no_warn.to_i == 1
      add('FAIL', 'pnp.no_warning',
          'NoWarningNoElevationOnInstall = 1 -- driver install prompts are suppressed entirely',
          'Microsoft states a system with this value set is vulnerable by design. ' \
          'Delete it or set 0: reg add "HKLM\\' + POINT_AND_PRINT +
          '" /v NoWarningNoElevationOnInstall /t REG_DWORD /d 0 /f')
    else
      add('PASS', 'pnp.no_warning',
          "NoWarningNoElevationOnInstall = #{no_warn.nil? ? 'not set' : no_warn} (prompts intact)")
    end

    if update.to_i == 1
      add('FAIL', 'pnp.update_prompt',
          'UpdatePromptSettings = 1 -- driver UPDATE prompts are suppressed',
          'Same class of bypass as NoWarningNoElevationOnInstall, on the update path. ' \
          'Set to 0: reg add "HKLM\\' + POINT_AND_PRINT +
          '" /v UpdatePromptSettings /t REG_DWORD /d 0 /f')
    else
      add('PASS', 'pnp.update_prompt',
          "UpdatePromptSettings = #{update.nil? ? 'not set' : update} (prompts intact)")
    end

    restricted = @c.reg_value(POINT_AND_PRINT, 'Restricted')
    trusted    = @c.reg_value(POINT_AND_PRINT, 'TrustedServers')
    list       = @c.reg_value(POINT_AND_PRINT, 'ServerList')
    @facts['PointAndPrint.Restricted'] = restricted
    @facts['PointAndPrint.TrustedServers'] = trusted
    @facts['PointAndPrint.ServerList'] = list

    if restricted.to_i == 1 && trusted.to_i == 1 && !list.to_s.strip.empty?
      add('PASS', 'pnp.trusted_servers',
          "Point and Print restricted to an explicit server list (#{list})")
    elsif restricted.to_i == 1 && trusted.to_i != 1
      add('WARN', 'pnp.trusted_servers',
          'Point and Print is Restricted but TrustedServers is not enforced -- ' \
          'clients may pull drivers from any server',
          'Set TrustedServers=1 and populate ServerList with your print servers only.')
    else
      add('WARN', 'pnp.trusted_servers',
          'Point and Print server allow-listing is not configured',
          'Restrict driver sources: set Restricted=1, TrustedServers=1 and ' \
          'ServerList="printsrv01.corp.example;printsrv02.corp.example" under HKLM\\' +
          POINT_AND_PRINT)
    end
  end

  # --- 4. Package Point and Print -----------------------------------------
  def check_package_point_and_print
    only = @c.reg_value(PRINTERS_POLICY + '\PackagePointAndPrintOnly', 'PackagePointAndPrintOnly')
    only = @c.reg_value(POINT_AND_PRINT, 'PackagePointAndPrintOnly') if only.nil?
    srv  = @c.reg_value(PRINTERS_POLICY + '\PackagePointAndPrintServerList',
                        'PackagePointAndPrintServerList')
    @facts['PackagePointAndPrintOnly'] = only
    @facts['PackagePointAndPrintServerList'] = srv

    if only.to_i == 1
      add('PASS', 'pnp.package_only',
          'PackagePointAndPrintOnly = 1 -- only signed, packaged drivers may be installed')
    else
      add('WARN', 'pnp.package_only',
          "PackagePointAndPrintOnly = #{only.nil? ? 'not set' : only} -- unpackaged (v3) drivers are allowed",
          'Packaged drivers must be digitally signed as a unit, which closes the ' \
          'unsigned-DLL path. Enable via GPO: Computer Configuration > Policies > ' \
          'Administrative Templates > Printers > "Only use Package Point and Print".')
    end

    if only.to_i == 1 && srv.to_s.strip.empty?
      add('WARN', 'pnp.package_serverlist',
          'Package Point and Print is on but no approved server list is set',
          'Populate PackagePointAndPrintServerList so clients only accept packages ' \
          'from your print servers.')
    end
  end

  # --- 5. RPC hardening ----------------------------------------------------
  def check_rpc_hardening
    privacy = @c.reg_value(PRINT_CONTROL, 'RpcAuthnLevelPrivacyEnabled')
    @facts['RpcAuthnLevelPrivacyEnabled'] = privacy

    # 1 (or absent on a patched host) = packet privacy enforced. 0 = explicitly
    # weakened, which re-opens the CVE-2021-1678 relay path.
    if privacy.nil?
      add('PASS', 'rpc.authn_privacy',
          'RpcAuthnLevelPrivacyEnabled not set (patched hosts default to enforced)')
    elsif privacy.to_i == 1
      add('PASS', 'rpc.authn_privacy', 'RpcAuthnLevelPrivacyEnabled = 1 (packet privacy enforced)')
    else
      add('FAIL', 'rpc.authn_privacy',
          'RpcAuthnLevelPrivacyEnabled = 0 -- spooler RPC authentication has been downgraded',
          'This was explicitly set to a weakened value and re-enables the ' \
          'CVE-2021-1678 NTLM relay path. Remove the value or set it to 1 under HKLM\\' +
          PRINT_CONTROL)
    end

    endpoint = @c.reg_value(PRINTERS_POLICY, 'RegisterSpoolerRemoteRpcEndPoint')
    @facts['RegisterSpoolerRemoteRpcEndPoint'] = endpoint

    if endpoint.to_i == 2
      add('PASS', 'rpc.remote_endpoint',
          'RegisterSpoolerRemoteRpcEndPoint = 2 (inbound remote print RPC disabled)')
    elsif @facts.dig('spooler', 'state').to_s.casecmp('running').zero? && @facts['role'] != 'print-server'
      add('WARN', 'rpc.remote_endpoint',
          "RegisterSpoolerRemoteRpcEndPoint = #{endpoint.nil? ? 'not set' : endpoint} -- " \
          'this host accepts inbound remote print RPC',
          'On anything that is not a print server, disable inbound remote printing ' \
          'while keeping local printing working: reg add "HKLM\\' + PRINTERS_POLICY +
          '" /v RegisterSpoolerRemoteRpcEndPoint /t REG_DWORD /d 2 /f')
    end
  end

  # --- 6. Inventory --------------------------------------------------------
  def inventory_printers
    printers = @c.printers
    @facts['printer_count'] = printers.size
    shared = printers.select { |p| p['shared'] }
    @facts['shared_printer_count'] = shared.size

    shared.each do |p|
      add('INFO', "printer.shared:#{p['name']}",
          "shared printer '#{p['name']}' (share #{p['share_name']}, driver #{p['driver']})",
          nil, port: p['port'], published: p['published'])
    end

    # A FILE: port writes the spooled job to a path chosen at print time. On a
    # shared printer that is a remote arbitrary-file-write primitive.
    printers.select { |p| p['port'].to_s.upcase.start_with?('FILE:') }.each do |p|
      sev = p['shared'] ? 'FAIL' : 'WARN'
      add(sev, "printer.file_port:#{p['name']}",
          "printer '#{p['name']}' uses a FILE: port#{p['shared'] ? ' AND IS SHARED' : ''}",
          'A FILE: port turns a print job into a file write performed by the spooler ' \
          '(SYSTEM). Remove the port or unshare the printer.')
    end
  end

  def inventory_drivers
    drivers = @c.drivers
    @facts['driver_count'] = drivers.size

    # Drivers whose payload lives outside the protected driver store are the
    # ones worth a human look -- that is where sideloaded v3 drivers land.
    outside = drivers.reject do |d|
      d['path'].to_s.downcase.include?('\\system32\\spool\\drivers') ||
        d['path'].to_s.downcase.include?('\\windows\\system32\\driverstore')
    end

    outside.each do |d|
      add('WARN', "driver.outside_store:#{d['name']}",
          "driver '#{d['name']}' loads from #{d['path']} (outside the protected driver store)",
          'Verify the publisher and that the path is not writable by non-admins ' \
          "(icacls \"#{win_dirname(d['path'])}\").")
    end

    add('INFO', 'driver.count', "#{drivers.size} printer driver(s) installed") if drivers.any?
  end
end

# ===========================================================================
# Reporting
# ===========================================================================

COLOR = { 'FAIL' => "\e[31m", 'WARN' => "\e[33m", 'PASS' => "\e[32m", 'INFO' => "\e[36m" }.freeze
RESET = "\e[0m"

def print_report(findings, facts, color:, source:)
  puts '=' * 78
  puts "  WINDOWS PRINT SPOOLER AUDIT -- #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}"
  puts '=' * 78
  puts
  puts "  Data source       : #{source}"
  puts "  Host role         : #{facts['role'] || 'unknown'}"
  puts "  OS                : #{facts.dig('os', 'caption') || 'unknown'}"
  puts "  Spooler           : #{facts.dig('spooler', 'state') || 'n/a'} " \
       "(start #{facts.dig('spooler', 'start_mode') || 'n/a'})"
  puts "  Printers          : #{facts['printer_count'] || 0} " \
       "(#{facts['shared_printer_count'] || 0} shared)"
  puts "  Drivers installed : #{facts['driver_count'] || 0}"
  puts
  puts '-' * 78
  puts

  findings.sort_by { |f| [SEVERITY_ORDER[f['severity']] || 9, f['id']] }.each do |f|
    tag = format('[%-4s]', f['severity'])
    tag = "#{COLOR[f['severity']]}#{tag}#{RESET}" if color
    puts "#{tag} #{f['message']}"
    if f['remediation']
      f['remediation'].scan(/.{1,86}(?:\s|\z)/).map(&:strip).reject(&:empty?).each_with_index do |ln, i|
        puts(i.zero? ? "       -> #{ln}" : "          #{ln}")
      end
    end
    puts
  end

  counts = findings.map { |f| f['severity'] }.tally
  puts '-' * 78
  puts "  #{counts.fetch('FAIL', 0)} fail   #{counts.fetch('WARN', 0)} warn   " \
       "#{counts.fetch('INFO', 0)} info   #{counts.fetch('PASS', 0)} pass"
  puts '=' * 78
end

# Dump everything the audit reads, so a Windows host can be captured once and
# replayed (or regression-tested) anywhere.
def capture(collector, path)
  reg_keys = {
    PRINTERS_POLICY => %w[RestrictDriverInstallationToAdministrators
                          RegisterSpoolerRemoteRpcEndPoint],
    POINT_AND_PRINT => %w[NoWarningNoElevationOnInstall UpdatePromptSettings
                          Restricted TrustedServers ServerList PackagePointAndPrintOnly],
    PRINT_CONTROL => %w[RpcAuthnLevelPrivacyEnabled],
    PRINTERS_POLICY + '\PackagePointAndPrintOnly' => %w[PackagePointAndPrintOnly],
    PRINTERS_POLICY + '\PackagePointAndPrintServerList' => %w[PackagePointAndPrintServerList]
  }
  registry = {}
  reg_keys.each do |key, names|
    registry[key] = names.to_h { |n| [n, collector.reg_value(key, n)] }.compact
  end

  data = { 'captured_at' => Time.now.utc.iso8601,
           'os' => collector.os_role,
           'services' => { 'Spooler' => collector.service('Spooler') },
           'printers' => collector.printers,
           'drivers' => collector.drivers,
           'registry' => registry }
  File.write(path, JSON.pretty_generate(data))
  path
end

# ===========================================================================
# Entry point
# ===========================================================================

def main(argv)
  opts = { json: false, color: $stdout.tty?, role: nil, fixture: nil, capture: nil }

  parser = OptionParser.new do |o|
    o.banner = 'Usage: ruby win_print_spooler_audit.rb [options]'
    o.on('--role ROLE', %w[workstation member-server print-server domain-controller],
         'Declare the host role (default: inferred from WMI)') { |v| opts[:role] = v }
    o.on('--fixture PATH', 'Audit a captured JSON snapshot instead of this host') { |v| opts[:fixture] = v }
    o.on('--capture PATH', 'Write this host\'s spooler state to PATH and exit') { |v| opts[:capture] = v }
    o.on('--json', 'Emit JSON instead of a text report') { opts[:json] = true }
    o.on('--[no-]color', 'Force ANSI colour on/off') { |v| opts[:color] = v }
    o.on('-h', '--help', 'Show this help') { puts o; exit 0 }
  end

  begin
    parser.parse!(argv)
  rescue OptionParser::ParseError => e
    warn "error: #{e.message}"
    warn parser.to_s
    return 3
  end

  if opts[:fixture]
    unless File.file?(opts[:fixture])
      warn "error: fixture not found: #{opts[:fixture]}"
      return 3
    end
    collector = FixtureCollector.new(opts[:fixture])
    source = "fixture #{opts[:fixture]}"
  else
    unless WINDOWS
      warn 'error: live audit requires Windows (win32ole + win32/registry).'
      warn '       On Linux/macOS, replay a captured snapshot: --fixture sample.json'
      return 3
    end
    collector = WindowsCollector.new
    source = 'live host (WMI + registry)'
  end

  if opts[:capture]
    path = capture(collector, opts[:capture])
    puts "captured spooler state to #{path}"
    return 0
  end

  findings, facts = SpoolerAudit.new(collector, role: opts[:role]).run

  if opts[:json]
    puts JSON.pretty_generate('generated_at' => Time.now.utc.iso8601,
                              'source' => source,
                              'facts' => facts,
                              'findings' => findings)
  else
    print_report(findings, facts, color: opts[:color], source: source)
  end

  return 2 if findings.any? { |f| f['severity'] == 'FAIL' }
  return 1 if findings.any? { |f| f['severity'] == 'WARN' }

  0
end

exit(main(ARGV)) if __FILE__ == $PROGRAM_NAME
