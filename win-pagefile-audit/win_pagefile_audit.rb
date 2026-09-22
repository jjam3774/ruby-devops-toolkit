#!/usr/bin/env ruby
# frozen_string_literal: true
#
# win_pagefile_audit.rb -- Audit Windows pagefile and crash-dump configuration
# across a fleet, using WMI through win32ole.
#
# Why this matters:
#
# The pagefile is the setting nobody owns. It defaults to "System managed",
# which is fine on a laptop and quietly wrong on a 256 GB database server. Two
# failures follow from it, and both show up at the worst possible moment:
#
#   1. Capacity. A system-managed pagefile grows into whatever free space the
#      system volume has. On a C: drive sized for the OS, a memory spike fills
#      the disk, and a full system volume takes down everything on the box --
#      not just the process that spiked.
#
#   2. Crash dumps. Windows writes a kernel memory dump THROUGH the pagefile on
#      the boot volume. If the pagefile is too small, or was moved off C:, or
#      the dump type is set to "None", then when the server bugchecks you get a
#      reboot and no dump file. The one artifact that would have told you why
#      the machine died does not exist. You find this out after the outage.
#
# Neither is visible in a typical monitoring dashboard: disk usage looks fine
# until it isn't, and dump configuration has no metric at all. This script
# inspects it directly.
#
# It reads four WMI classes:
#   Win32_ComputerSystem      -- installed RAM, and whether the pagefile is automatic
#   Win32_PageFileSetting     -- the CONFIGURED initial/maximum size (persisted)
#   Win32_PageFileUsage       -- the CURRENT allocated size and peak usage
#   Win32_OSRecoveryConfiguration -- crash dump type, dump file path, overwrite
#
# It is read-only. Changing pagefile settings requires a reboot and is not
# something a fleet audit should do behind your back.
#
# Usage (on Windows, elevated PowerShell or cmd):
#   ruby win_pagefile_audit.rb
#   ruby win_pagefile_audit.rb --host SERVER01 --host SERVER02
#   ruby win_pagefile_audit.rb --format json
#   ruby win_pagefile_audit.rb --fail-on high
#   ruby win_pagefile_audit.rb --mock fixtures/sample_hosts.json   # offline test
#
# Exit codes: 0 = clean, 1 = findings at/above --fail-on, 2 = collection failed.

require 'optparse'
require 'json'
require 'time'

Finding = Struct.new(:severity, :host, :check, :message, :evidence, keyword_init: true)
SEVERITY_ORDER = { 'high' => 3, 'medium' => 2, 'low' => 1 }.freeze

MB = 1024.0 * 1024.0

# ---------------------------------------------------------------------------
# Collector: pulls the raw facts from WMI.
#
# win32ole ships with Ruby on Windows -- no gem required. The connection is made
# with GetObject("winmgmts:{impersonationLevel=impersonate}!\\\\HOST\\root\\cimv2"),
# which works against the local box and, with the right rights and DCOM/firewall
# rules, against a remote one.
#
# Everything is funnelled through #collect so the mock collector below can be a
# drop-in replacement. That separation is what makes this script testable off
# Windows -- see the Troubleshooting notes.
# ---------------------------------------------------------------------------
class WmiCollector
  def initialize(host = '.')
    @host = host
  end

  def collect
    require 'win32ole'

    wmi = WIN32OLE.connect(
      "winmgmts:{impersonationLevel=impersonate}!\\\\#{@host}\\root\\cimv2"
    )

    {
      'host' => @host == '.' ? local_name : @host,
      'computer_system' => first(wmi, 'SELECT Name, TotalPhysicalMemory, AutomaticManagedPagefile, ' \
                                      'DomainRole FROM Win32_ComputerSystem') do |o|
        {
          'name' => o.Name,
          'total_physical_memory' => o.TotalPhysicalMemory.to_i,
          'automatic_managed_pagefile' => to_bool(o.AutomaticManagedPagefile),
          'domain_role' => o.DomainRole.to_i
        }
      end,
      'pagefile_settings' => all(wmi, 'SELECT Name, InitialSize, MaximumSize FROM Win32_PageFileSetting') do |o|
        { 'name' => o.Name, 'initial_size_mb' => o.InitialSize.to_i, 'maximum_size_mb' => o.MaximumSize.to_i }
      end,
      'pagefile_usage' => all(wmi, 'SELECT Name, AllocatedBaseSize, CurrentUsage, PeakUsage FROM Win32_PageFileUsage') do |o|
        {
          'name' => o.Name,
          'allocated_base_size_mb' => o.AllocatedBaseSize.to_i,
          'current_usage_mb' => o.CurrentUsage.to_i,
          'peak_usage_mb' => o.PeakUsage.to_i
        }
      end,
      'recovery' => first(wmi, 'SELECT DebugInfoType, DebugFilePath, OverwriteExistingDebugFile, ' \
                               'AutoReboot FROM Win32_OSRecoveryConfiguration') do |o|
        {
          'debug_info_type' => o.DebugInfoType.to_i,
          'debug_file_path' => o.DebugFilePath.to_s,
          'overwrite_existing' => to_bool(o.OverwriteExistingDebugFile),
          'auto_reboot' => to_bool(o.AutoReboot)
        }
      end,
      'free_space' => all(wmi, "SELECT DeviceID, FreeSpace, Size FROM Win32_LogicalDisk WHERE DriveType=3") do |o|
        { 'device_id' => o.DeviceID, 'free_bytes' => o.FreeSpace.to_i, 'size_bytes' => o.Size.to_i }
      end
    }
  rescue LoadError
    raise "win32ole is not available -- this script must run on Windows (use --mock for offline testing)"
  rescue WIN32OLERuntimeError => e
    raise "WMI query against '#{@host}' failed: #{e.message.lines.first.to_s.strip}"
  end

  private

  def local_name
    ENV['COMPUTERNAME'] || (require('socket') && Socket.gethostname)
  end

  # WMI booleans come back as true/false already, but a remote provider can hand
  # back the string "True". Normalise both.
  def to_bool(val)
    return val if [true, false].include?(val)

    val.to_s.strip.downcase == 'true'
  end

  def all(wmi, query)
    wmi.ExecQuery(query).each.map { |o| yield(o) }
  end

  def first(wmi, query)
    all(wmi, query) { |o| yield(o) }.first || {}
  end
end

# A collector that reads a JSON file instead of WMI, so the analysis logic can
# be exercised on any OS. The JSON shape is exactly what WmiCollector#collect
# returns -- dump a real host with --format json to produce new fixtures.
class MockCollector
  def initialize(path, host)
    @path = path
    @host = host
  end

  def collect
    data = JSON.parse(File.read(@path))
    hosts = data.is_a?(Array) ? data : [data]
    found = hosts.find { |h| h['host'] == @host } || hosts.first
    raise "no host data in #{@path}" unless found

    found
  end
end

# ---------------------------------------------------------------------------
# Analysis. Pure functions over the collected hash -- no WMI, no I/O.
# ---------------------------------------------------------------------------
class PagefileAuditor
  # DebugInfoType values from Win32_OSRecoveryConfiguration.
  DUMP_TYPES = {
    0 => 'None',
    1 => 'Complete memory dump',
    2 => 'Kernel memory dump',
    3 => 'Small memory dump (256 KB)',
    4 => 'Automatic memory dump',
    7 => 'Active memory dump'
  }.freeze

  # Rough floor for a kernel dump to be writable. Microsoft's guidance scales
  # with RAM; this is the conservative simplification most baselines use.
  def kernel_dump_floor_mb(ram_mb)
    ram_mb <= 4096 ? ram_mb : [ram_mb / 8, 32 * 1024].min + 512
  end

  def audit(data)
    host = data['host'].to_s
    cs = data['computer_system'] || {}
    settings = data['pagefile_settings'] || []
    usage = data['pagefile_usage'] || []
    rec = data['recovery'] || {}
    disks = data['free_space'] || []

    ram_mb = (cs['total_physical_memory'].to_i / MB).round
    findings = []

    findings.concat(check_no_pagefile(host, settings, usage, ram_mb))
    findings.concat(check_automatic(host, cs, ram_mb))
    findings.concat(check_sizing(host, settings, ram_mb))
    findings.concat(check_growth_window(host, settings))
    findings.concat(check_peak_pressure(host, usage))
    findings.concat(check_dump_config(host, rec, settings, usage, ram_mb))
    findings.concat(check_volume_headroom(host, settings, disks))

    [findings, summary(host, cs, ram_mb, settings, usage, rec)]
  end

  private

  def boot_volume_pagefile?(entry)
    entry['name'].to_s.upcase.start_with?('C:')
  end

  # ---- No pagefile at all --------------------------------------------------
  def check_no_pagefile(host, settings, usage, ram_mb)
    return [] unless settings.empty? && usage.empty?

    [Finding.new(
      severity: 'high', host: host, check: 'pagefile.absent',
      message: 'No pagefile is configured on this host. Windows cannot write a kernel ' \
               'crash dump without one, and commit-limit exhaustion will kill processes ' \
               'that a pagefile would have absorbed.',
      evidence: "RAM=#{ram_mb} MB, Win32_PageFileSetting and Win32_PageFileUsage both empty"
    )]
  end

  # ---- System-managed on a large-memory host -------------------------------
  def check_automatic(host, cs, ram_mb)
    return [] unless cs['automatic_managed_pagefile']

    sev = ram_mb >= 32 * 1024 ? 'high' : 'medium'
    [Finding.new(
      severity: sev, host: host, check: 'pagefile.automatic_managed',
      message: 'AutomaticManagedPagefile is enabled. The pagefile is free to grow into ' \
               'whatever space the system volume has, so a memory spike can fill C: and ' \
               'take the whole host down rather than just the offending process.',
      evidence: "AutomaticManagedPagefile=true, RAM=#{ram_mb} MB"
    )]
  end

  # ---- Absolute sizing -----------------------------------------------------
  def check_sizing(host, settings, ram_mb)
    settings.filter_map do |s|
      init = s['initial_size_mb'].to_i
      next if init.zero?

      # A pagefile smaller than an eighth of RAM will thrash under commit pressure.
      floor = [ram_mb / 8, 2048].max
      next if init >= floor

      Finding.new(
        severity: 'medium', host: host, check: 'pagefile.undersized',
        message: "#{s['name']} has an initial size of #{init} MB against #{ram_mb} MB of RAM. " \
                 "Under commit pressure the system will expand it mid-incident, which is when " \
                 "you least want the disk I/O.",
        evidence: "#{s['name']} initial=#{init} MB, recommended floor=#{floor} MB"
      )
    end
  end

  # ---- Initial != Maximum --------------------------------------------------
  # A pagefile whose maximum exceeds its initial size will be grown on demand.
  # Growth is slow, fragmenting, and happens exactly when the box is already
  # under pressure. Production baselines pin initial == maximum.
  def check_growth_window(host, settings)
    settings.filter_map do |s|
      init = s['initial_size_mb'].to_i
      max = s['maximum_size_mb'].to_i
      next if init.zero? || max.zero? || max <= init

      Finding.new(
        severity: 'low', host: host, check: 'pagefile.growth_window',
        message: "#{s['name']} can grow from #{init} MB to #{max} MB. On-demand growth is " \
                 'slow and fragments the file; pin initial == maximum so the allocation is ' \
                 'made once, at a quiet moment.',
        evidence: "#{s['name']} initial=#{init} MB, maximum=#{max} MB"
      )
    end
  end

  # ---- Peak usage close to the allocation ----------------------------------
  def check_peak_pressure(host, usage)
    usage.filter_map do |u|
      allocated = u['allocated_base_size_mb'].to_i
      peak = u['peak_usage_mb'].to_i
      next if allocated.zero?

      ratio = peak.to_f / allocated
      next if ratio < 0.7

      sev = ratio >= 0.9 ? 'high' : 'medium'
      Finding.new(
        severity: sev, host: host, check: 'pagefile.peak_pressure',
        message: "#{u['name']} peaked at #{peak} MB of #{allocated} MB " \
                 "(#{(ratio * 100).round}%). This host has genuinely needed the pagefile; " \
                 'treat the sizing numbers here as a real capacity signal, not a formality.',
        evidence: "#{u['name']} peak=#{peak} MB, allocated=#{allocated} MB, current=#{u['current_usage_mb']} MB"
      )
    end
  end

  # ---- Crash dump viability -------------------------------------------------
  # This is the check that earns the script its keep.
  def check_dump_config(host, rec, settings, usage, ram_mb)
    out = []
    type = rec['debug_info_type']
    return out if type.nil?

    type = type.to_i

    if type.zero?
      out << Finding.new(
        severity: 'high', host: host, check: 'dump.disabled',
        message: 'Crash dump collection is set to "None". When this host bugchecks it will ' \
                 'reboot with no dump file, and the cause will be unrecoverable after the fact.',
        evidence: "DebugInfoType=0 (#{DUMP_TYPES[0]})"
      )
      return out
    end

    if type == 3
      out << Finding.new(
        severity: 'medium', host: host, check: 'dump.minidump_only',
        message: 'Only a small (256 KB) minidump is collected. That is enough to identify a ' \
                 'faulting driver in simple cases and not enough for anything involving ' \
                 'kernel pool, memory pressure, or a hung I/O path.',
        evidence: "DebugInfoType=3 (#{DUMP_TYPES[3]})"
      )
    end

    # Kernel/complete/automatic dumps are staged through the BOOT volume pagefile.
    if [1, 2, 4, 7].include?(type)
      boot_pf = settings.find { |s| boot_volume_pagefile?(s) } ||
                usage.find { |u| boot_volume_pagefile?(u) }

      if boot_pf.nil?
        out << Finding.new(
          severity: 'high', host: host, check: 'dump.no_boot_volume_pagefile',
          message: "Dump type is '#{DUMP_TYPES[type]}' but there is no pagefile on the boot " \
                   'volume (C:). Windows stages the dump through the boot-volume pagefile, so ' \
                   'no pagefile there means no dump will ever be written.',
          evidence: "DebugInfoType=#{type}, pagefiles: #{(settings + usage).map { |e| e['name'] }.uniq.join(', ')}"
        )
      else
        size = boot_pf['initial_size_mb'].to_i
        size = boot_pf['allocated_base_size_mb'].to_i if size.zero?
        needed = type == 1 ? ram_mb + 512 : kernel_dump_floor_mb(ram_mb)

        if size.positive? && size < needed
          out << Finding.new(
            severity: 'high', host: host, check: 'dump.pagefile_too_small',
            message: "The boot-volume pagefile is #{size} MB but a '#{DUMP_TYPES[type]}' on a " \
                     "#{ram_mb} MB host needs roughly #{needed} MB to stage. The dump will be " \
                     'truncated or skipped entirely.',
            evidence: "#{boot_pf['name']} size=#{size} MB, required>=#{needed} MB, RAM=#{ram_mb} MB"
          )
        end
      end
    end

    if rec['overwrite_existing'] == false
      out << Finding.new(
        severity: 'low', host: host, check: 'dump.no_overwrite',
        message: 'OverwriteExistingDebugFile is false. After the first crash, later dumps are ' \
                 'discarded rather than written -- so a repeat failure produces nothing new.',
        evidence: 'OverwriteExistingDebugFile=false'
      )
    end

    out
  end

  # ---- Room on the volume to actually write the thing ----------------------
  def check_volume_headroom(host, settings, disks)
    return [] if disks.empty?

    settings.filter_map do |s|
      drive = s['name'].to_s[0, 2].upcase
      disk = disks.find { |d| d['device_id'].to_s.upcase == drive }
      next unless disk

      free_mb = (disk['free_bytes'].to_i / MB).round
      max = s['maximum_size_mb'].to_i
      next if max.zero?

      # Headroom that the pagefile hasn't claimed yet.
      current = s['initial_size_mb'].to_i
      growth_room = max - current
      next if growth_room <= 0 || free_mb >= growth_room + 5120

      Finding.new(
        severity: 'medium', host: host, check: 'pagefile.volume_headroom',
        message: "#{drive} has #{free_mb} MB free but #{s['name']} is allowed to grow by " \
                 "another #{growth_room} MB. If it does, the volume runs out of space and " \
                 'every service writing to that drive fails at once.',
        evidence: "#{drive} free=#{free_mb} MB, pagefile growth room=#{growth_room} MB"
      )
    end
  end

  def summary(host, cs, ram_mb, settings, usage, rec)
    {
      'host' => host,
      'name' => cs['name'],
      'ram_mb' => ram_mb,
      'automatic_managed' => cs['automatic_managed_pagefile'],
      'pagefiles' => settings.map { |s| "#{s['name']} #{s['initial_size_mb']}-#{s['maximum_size_mb']} MB" },
      'allocated_mb' => usage.sum { |u| u['allocated_base_size_mb'].to_i },
      'peak_mb' => usage.sum { |u| u['peak_usage_mb'].to_i },
      'dump_type' => DUMP_TYPES[rec['debug_info_type'].to_i] || "unknown(#{rec['debug_info_type']})",
      'dump_path' => rec['debug_file_path']
    }
  end
end

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
class Reporter
  COLORS = { 'high' => "\e[31m", 'medium' => "\e[33m", 'low' => "\e[36m" }.freeze
  RESET = "\e[0m"

  def initialize(color: $stdout.tty?)
    @color = color
  end

  def text(results)
    lines = ['Windows pagefile + crash dump audit', '=' * 78]

    results.each do |host, payload|
      s = payload[:summary]
      f = payload[:findings]

      lines << ''
      lines << "#{host}  (#{s['name'] || host})"
      lines << "  RAM              : #{s['ram_mb']} MB"
      lines << "  system managed   : #{s['automatic_managed'] ? 'YES' : 'no'}"
      lines << "  pagefiles        : #{s['pagefiles'].empty? ? '(none)' : s['pagefiles'].join(', ')}"
      lines << "  allocated / peak : #{s['allocated_mb']} MB / #{s['peak_mb']} MB"
      lines << "  crash dump       : #{s['dump_type']} -> #{s['dump_path']}"

      if f.empty?
        lines << "  #{paint('OK', 'low')}    no findings"
        next
      end

      f.sort_by { |x| -SEVERITY_ORDER.fetch(x.severity, 0) }.each do |x|
        lines << "  #{paint(x.severity.upcase.ljust(6), x.severity)} #{x.check}"
        lines << "         #{x.message}"
        lines << "         -> #{x.evidence}"
      end
    end

    all = results.values.flat_map { |p| p[:findings] }
    lines << ''
    lines << '=' * 78
    counts = all.group_by(&:severity).transform_values(&:size)
                .sort_by { |s, _| -SEVERITY_ORDER.fetch(s, 0) }
                .map { |s, n| "#{s}=#{n}" }.join('  ')
    lines << "summary: #{results.size} host(s), #{all.size} finding(s)  #{counts}"
    lines.join("\n")
  end

  def json(results)
    JSON.pretty_generate(
      generated_at: Time.now.utc.iso8601,
      hosts: results.map do |host, payload|
        { host: host, summary: payload[:summary], findings: payload[:findings].map(&:to_h) }
      end
    )
  end

  private

  def paint(text, severity)
    return text unless @color

    "#{COLORS.fetch(severity, '')}#{text}#{RESET}"
  end
end

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv)
  opts = { hosts: [], format: 'text', fail_on: nil, mock: nil, dump_raw: false }

  OptionParser.new do |o|
    o.banner = 'Usage: ruby win_pagefile_audit.rb [options]'
    o.on('--host NAME', 'Remote host to audit (repeatable; default local)') { |v| opts[:hosts] << v }
    o.on('--mock PATH', 'Read collected facts from JSON instead of WMI') { |v| opts[:mock] = v }
    o.on('--dump-raw', 'Print the raw collected facts as JSON and exit') { opts[:dump_raw] = true }
    o.on('--format FMT', %w[text json], 'text (default) or json') { |v| opts[:format] = v }
    o.on('--fail-on LEVEL', %w[high medium low], 'Exit 1 at/above this severity') { |v| opts[:fail_on] = v }
    o.on('-h', '--help') { puts o; exit 0 }
  end.parse!(argv)

  hosts = opts[:hosts].empty? ? ['.'] : opts[:hosts]
  auditor = PagefileAuditor.new
  results = {}
  errors = []

  hosts.each do |host|
    collector = opts[:mock] ? MockCollector.new(opts[:mock], host) : WmiCollector.new(host)
    begin
      data = collector.collect
    rescue StandardError => e
      errors << "#{host}: #{e.message}"
      next
    end

    if opts[:dump_raw]
      puts JSON.pretty_generate(data)
      next
    end

    findings, summary = auditor.audit(data)
    results[data['host'] || host] = { findings: findings, summary: summary }
  end

  errors.each { |e| warn "error: #{e}" }
  return 2 if results.empty? && !opts[:dump_raw]
  return 0 if opts[:dump_raw]

  reporter = Reporter.new
  puts(opts[:format] == 'json' ? reporter.json(results) : reporter.text(results))

  if opts[:fail_on]
    threshold = SEVERITY_ORDER.fetch(opts[:fail_on])
    all = results.values.flat_map { |p| p[:findings] }
    return 1 if all.any? { |f| SEVERITY_ORDER.fetch(f.severity, 0) >= threshold }
  end
  0
end

exit(main(ARGV)) if __FILE__ == $PROGRAM_NAME
