#!/usr/bin/env ruby
# frozen_string_literal: true
#
# win_rdp_hardening_audit.rb -- audit Remote Desktop (RDP) hardening on a
# Windows host using only Ruby's bundled win32/registry library.
#
# Exposed RDP is the #1 initial-access vector for ransomware crews, and the
# settings that matter are scattered across three registry hives. This script
# reads each one, scores it against a baseline (CIS / Microsoft security
# baseline defaults), and prints a pass/fail table plus a JSON blob you can
# ship to your SIEM.
#
# Checks:
#   * RDP enabled at all?                  (fDenyTSConnections)
#   * Network Level Authentication on?     (UserAuthentication)
#   * TLS required for the RDP transport?  (SecurityLayer)
#   * Encryption level High/FIPS?          (MinEncryptionLevel)
#   * Listening port changed from 3389?    (PortNumber -- informational)
#   * Idle/disconnect session timeouts?    (MaxIdleTime / MaxDisconnectionTime)
#   * Clipboard / drive redirection off?   (fDisableClip / fDisableCdm)
#   * Windows Firewall RDP rule scope      (via Windows Firewall registry)
#   * Restrict local admin RDP via policy? (fPromptForPassword)
#
# Usage (on Windows, elevated prompt recommended):
#   ruby win_rdp_hardening_audit.rb            # table
#   ruby win_rdp_hardening_audit.rb --json     # JSON
#   ruby win_rdp_hardening_audit.rb --fixture rdp_fixture.json   # test anywhere
#
# Exit codes: 0 = all pass, 1 = warnings only, 2 = at least one FAIL.

require 'json'
require 'optparse'

# ----------------------------------------------------------------------------
# Registry access layer.
#
# RegistryReader talks to the real registry through win32/registry (bundled
# with the RubyInstaller builds). FixtureReader loads a JSON file of the same
# shape so the audit logic can be tested on Linux/macOS or in CI. The audit
# only ever calls #read(hive, key, value) so the two are interchangeable.
# ----------------------------------------------------------------------------
class RegistryReader
  def initialize
    require 'win32/registry'
    @hives = {
      'HKLM' => Win32::Registry::HKEY_LOCAL_MACHINE,
      'HKCU' => Win32::Registry::HKEY_CURRENT_USER
    }
  end

  # Returns the value, or nil if the key/value does not exist.
  def read(hive, key, value)
    # KEY_READ | KEY_WOW64_64KEY so a 32-bit Ruby still sees the 64-bit view.
    access = Win32::Registry::KEY_READ | 0x0100
    @hives.fetch(hive).open(key, access) { |reg| reg[value] }
  rescue Win32::Registry::Error
    nil
  end
end

class FixtureReader
  def initialize(path)
    @data = JSON.parse(File.read(path))
  end

  def read(hive, key, value)
    @data.dig(hive, key, value)
  end
end

# ----------------------------------------------------------------------------
# The checks. Each is a hash describing where the value lives, what "good"
# looks like, and how to explain a failure to a human.
# ----------------------------------------------------------------------------
TS = 'SYSTEM\CurrentControlSet\Control\Terminal Server'
RDP_TCP = "#{TS}\\WinStations\\RDP-Tcp"
POLICY = 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
FW_RULES = 'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'

# A value can be set by Group Policy (POLICY hive) which overrides the local
# WinStations setting. We check policy first, then fall back to the local key.
def policy_or_local(reg, value)
  v = reg.read('HKLM', POLICY, value)
  v.nil? ? reg.read('HKLM', RDP_TCP, value) : v
end

CHECKS = [
  {
    id: 'rdp_enabled',
    title: 'Remote Desktop enabled',
    severity: :info,
    fetch: ->(r) { r.read('HKLM', TS, 'fDenyTSConnections') },
    pass: ->(v) { v == 1 },
    explain: ->(v) { v == 1 ? 'RDP disabled (fDenyTSConnections=1)' : 'RDP is ENABLED; remaining checks matter' }
  },
  {
    id: 'nla_required',
    title: 'Network Level Authentication required',
    severity: :fail,
    fetch: ->(r) { policy_or_local(r, 'UserAuthentication') },
    pass: ->(v) { v == 1 },
    explain: ->(v) { "UserAuthentication=#{v.inspect}; without NLA attackers reach the login screen pre-auth (BlueKeep class bugs)" }
  },
  {
    id: 'security_layer_tls',
    title: 'Security layer set to TLS',
    severity: :fail,
    fetch: ->(r) { policy_or_local(r, 'SecurityLayer') },
    pass: ->(v) { v == 2 },
    explain: ->(v) { "SecurityLayer=#{v.inspect}; 0=RDP-native, 1=negotiate, 2=TLS/SSL. Require TLS" }
  },
  {
    id: 'encryption_high',
    title: 'Encryption level High or FIPS',
    severity: :fail,
    fetch: ->(r) { policy_or_local(r, 'MinEncryptionLevel') },
    pass: ->(v) { [3, 4].include?(v) },
    explain: ->(v) { "MinEncryptionLevel=#{v.inspect}; 1=Low 2=Client-compatible 3=High 4=FIPS" }
  },
  {
    id: 'idle_timeout',
    title: 'Idle session timeout configured',
    severity: :warn,
    fetch: ->(r) { policy_or_local(r, 'MaxIdleTime') },
    pass: ->(v) { v.is_a?(Integer) && v.positive? && v <= 15 * 60 * 1000 },
    explain: ->(v) { "MaxIdleTime=#{v.inspect} ms; set <= 900000 (15 min) so abandoned sessions cannot be hijacked" }
  },
  {
    id: 'disconnect_timeout',
    title: 'Disconnected session timeout configured',
    severity: :warn,
    fetch: ->(r) { policy_or_local(r, 'MaxDisconnectionTime') },
    pass: ->(v) { v.is_a?(Integer) && v.positive? },
    explain: ->(v) { "MaxDisconnectionTime=#{v.inspect}; disconnected sessions linger forever and hold licences/memory" }
  },
  {
    id: 'clipboard_redirect',
    title: 'Clipboard redirection disabled',
    severity: :warn,
    fetch: ->(r) { policy_or_local(r, 'fDisableClip') },
    pass: ->(v) { v == 1 },
    explain: ->(v) { "fDisableClip=#{v.inspect}; clipboard is a common exfil path for jump hosts" }
  },
  {
    id: 'drive_redirect',
    title: 'Drive redirection disabled',
    severity: :warn,
    fetch: ->(r) { policy_or_local(r, 'fDisableCdm') },
    pass: ->(v) { v == 1 },
    explain: ->(v) { "fDisableCdm=#{v.inspect}; mapped client drives let malware hop across the session" }
  },
  {
    id: 'prompt_for_password',
    title: 'Always prompt for password on connect',
    severity: :warn,
    fetch: ->(r) { policy_or_local(r, 'fPromptForPassword') },
    pass: ->(v) { v == 1 },
    explain: ->(v) { "fPromptForPassword=#{v.inspect}; prevents saved-credential auto-logon from stolen .rdp files" }
  },
  {
    id: 'port_nonstandard',
    title: 'Listening port (informational)',
    severity: :info,
    fetch: ->(r) { r.read('HKLM', RDP_TCP, 'PortNumber') },
    pass: ->(v) { v != 3389 },
    explain: ->(v) { "PortNumber=#{v.inspect}; 3389 is scanned constantly. Changing it is obscurity, not security, but cuts log noise" }
  }
].freeze

# Firewall rule check is different in shape: we scan every rule string under
# FirewallRules for the built-in RDP rules and look at its RA4= (remote
# address) scope. "RA4=*"/absent means the whole internet may connect.
def firewall_scope(reg)
  rules = reg.read('HKLM', FW_RULES, '__ALL__') # FixtureReader convenience
  if rules.nil? && defined?(Win32::Registry)
    rules = {}
    Win32::Registry::HKEY_LOCAL_MACHINE.open(FW_RULES, Win32::Registry::KEY_READ | 0x0100) do |k|
      k.each_value { |name, _type, data| rules[name] = data }
    end
  end
  return nil if rules.nil?

  rdp = rules.select { |name, data| name =~ /RemoteDesktop/i && data.include?('Active=TRUE') && data.include?('Dir=In') }
  rdp.map do |name, data|
    scope = data[/RA4=([^|]+)/, 1] || '*'
    # A rule can list Profile= several times (Domain|Private|Public); no
    # Profile= token at all means it applies to every profile.
    profiles = data.scan(/Profile=([^|]+)/).flatten
    profiles = ['Any'] if profiles.empty?
    { rule: name, profiles: profiles, remote_scope: scope }
  end
end

# ----------------------------------------------------------------------------
# Runner
# ----------------------------------------------------------------------------
class RdpAudit
  def initialize(reader)
    @reader = reader
  end

  def run
    results = CHECKS.map do |c|
      value = c[:fetch].call(@reader)
      ok = c[:pass].call(value)
      status = ok ? 'PASS' : (c[:severity] == :info ? 'INFO' : c[:severity].to_s.upcase)
      { id: c[:id], title: c[:title], value: value, status: status, detail: ok ? nil : c[:explain].call(value) }
    end

    fw = firewall_scope(@reader)
    unless fw.nil?
      open_rules = fw.select { |r| r[:remote_scope] == '*' && r[:profiles].any? { |p| p =~ /Public|Any/i } }
      results << {
        id: 'firewall_scope', title: 'Firewall RDP rule limited to trusted subnets',
        value: fw, status: open_rules.empty? ? 'PASS' : 'FAIL',
        detail: open_rules.empty? ? nil : "#{open_rules.size} inbound RDP rule(s) allow any remote address on Public/Any profile"
      }
    end

    # If RDP is off entirely, everything else is moot: downgrade to INFO.
    if results.first[:value] == 1
      results.each { |r| r[:status] = 'INFO' if r[:status] != 'PASS' }
    end
    results
  end
end

def overall(results)
  return 2 if results.any? { |r| r[:status] == 'FAIL' }
  return 1 if results.any? { |r| r[:status] == 'WARN' }

  0
end

def print_table(results, host)
  puts "RDP hardening audit  host=#{host}"
  puts '=' * 78
  results.each do |r|
    mark = { 'PASS' => '[ OK ]', 'WARN' => '[WARN]', 'FAIL' => '[FAIL]', 'INFO' => '[INFO]' }[r[:status]]
    puts format('%s %-46s %s', mark, r[:title], r[:value].is_a?(Array) ? "#{r[:value].size} rule(s)" : r[:value].inspect)
    puts "       -> #{r[:detail]}" if r[:detail]
  end
  puts '=' * 78
  counts = results.group_by { |r| r[:status] }.transform_values(&:size)
  puts "summary: #{counts.map { |k, v| "#{k}=#{v}" }.join('  ')}"
end

if __FILE__ == $PROGRAM_NAME
  opts = { json: false, fixture: nil }
  OptionParser.new do |o|
    o.banner = 'Usage: win_rdp_hardening_audit.rb [--json] [--fixture FILE.json]'
    o.on('--json', 'JSON output') { opts[:json] = true }
    o.on('--fixture FILE', 'Read registry values from a JSON fixture (testing)') { |f| opts[:fixture] = f }
  end.parse!

  reader = opts[:fixture] ? FixtureReader.new(opts[:fixture]) : RegistryReader.new
  host = ENV['COMPUTERNAME'] || (`hostname`.strip rescue 'unknown')
  results = RdpAudit.new(reader).run

  if opts[:json]
    puts JSON.pretty_generate(host: host, generated: Time.now.utc, exit_code: overall(results), checks: results)
  else
    print_table(results, host)
  end
  exit overall(results)
end
