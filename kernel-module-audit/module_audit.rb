#!/usr/bin/env ruby
# frozen_string_literal: true
#
# module_audit.rb -- audit the Linux kernel modules loaded on a host.
#
# Answers three questions a sysadmin actually has to answer during an incident
# or an audit:
#
#   1. What is loaded right now, and what is holding it in memory?
#   2. Did anything appear that was not on this host's approved baseline?
#   3. Is the kernel tainted -- and if so, which module did it?
#
# Reads /proc/modules, /proc/sys/kernel/tainted and /sys/module/<name>/*.
# Pure Ruby stdlib. No gems, no modinfo shell-outs, no root required for the
# read-only audit.
#
# Usage:
#   ruby module_audit.rb                          # audit this host
#   ruby module_audit.rb --write-baseline base.txt
#   ruby module_audit.rb --baseline base.txt      # drift check, exit 1 on drift
#   ruby module_audit.rb --format json
#   ruby module_audit.rb --root ./fixtures/host-a # audit a captured snapshot
#
# Exit codes: 0 = clean  1 = drift or risky module found  2 = usage/IO error
#
# Tested on Ruby 3.0+ / kernel 6.8.

require 'optparse'
require 'json'
require 'time'
require 'set'

module ModuleAudit
  VERSION = '1.0.0'

  # --------------------------------------------------------------------------
  # Per-module taint letters, from Documentation/admin-guide/tainted-kernels.rst.
  # /sys/module/<name>/taint holds only the letters that apply to that module,
  # which is how you attribute a tainted kernel to a specific driver.
  # --------------------------------------------------------------------------
  MODULE_TAINT = {
    'P' => ['proprietary', 'high',     'Proprietary (non-GPL) module'],
    'O' => ['out-of-tree', 'medium',   'Built outside the mainline kernel tree'],
    'F' => ['forced-load', 'high',     'Force-loaded with insmod -f'],
    'C' => ['staging',     'low',      'From the staging tree (unstable)'],
    'E' => ['unsigned',    'high',     'Loaded unsigned on a signature-enforcing kernel'],
    'X' => ['vendor',      'low',      'Vendor-supplied, supported by the distro']
  }.freeze

  # /proc/sys/kernel/tainted is a bitmask. Only the bits an auditor cares about
  # are decoded here; the rest are reported as "bit N".
  KERNEL_TAINT_BITS = {
    0  => 'G/P  proprietary module loaded',
    1  => 'F    module force-loaded',
    2  => 'S    SMP kernel on an unsupported CPU',
    3  => 'R    module force-unloaded',
    4  => 'M    machine check exception',
    5  => 'B    bad page reference',
    6  => 'U    userspace-requested taint',
    7  => 'D    kernel has died (oops/BUG)',
    8  => 'A    ACPI table overridden',
    9  => 'W    kernel issued a warning',
    10 => 'C    staging driver loaded',
    11 => 'I    workaround for firmware bug applied',
    12 => 'O    out-of-tree module loaded',
    13 => 'E    unsigned module loaded',
    14 => 'L    soft lockup occurred',
    15 => 'K    kernel live-patched',
    16 => 'X    auxiliary (vendor) taint',
    17 => 'T    built with struct randomisation'
  }.freeze

  # Modules that CIS/STIG hardening guides tell you to blacklist on a server.
  # Presence is not automatically a finding -- a laptop legitimately needs
  # bluetooth -- but on a fleet of headless app servers it is worth a look.
  RISKY_MODULES = {
    'usb-storage'  => 'USB mass storage -- data exfiltration path',
    'firewire-core'=> 'FireWire DMA -- historic memory-read attack surface',
    'bluetooth'    => 'Bluetooth stack -- unnecessary on a server',
    'dccp'         => 'DCCP -- rarely used, repeated CVE history',
    'sctp'         => 'SCTP -- rarely used, repeated CVE history',
    'rds'          => 'RDS -- rarely used, repeated CVE history',
    'tipc'         => 'TIPC -- rarely used, repeated CVE history',
    'cramfs'       => 'cramfs -- obsolete filesystem driver',
    'freevxfs'     => 'freevxfs -- obsolete filesystem driver',
    'jffs2'        => 'jffs2 -- obsolete filesystem driver',
    'hfsplus'      => 'hfsplus -- obsolete filesystem driver',
    'squashfs'     => 'squashfs -- unnecessary unless using snaps/containers',
    'udf'          => 'udf -- optical media filesystem'
  }.freeze

  Mod = Struct.new(:name, :size, :refcount, :used_by, :state, :address,
                   :taint, :srcversion, :holders, :params, :risky_reason,
                   keyword_init: true) do
    def out_of_tree? = taint.include?('O')
    def unsigned?    = taint.include?('E')
    def proprietary? = taint.include?('P')
    def forced?      = taint.include?('F')
    def removable?   = refcount.zero? && used_by.empty?

    # Highest severity implied by this module's taint letters.
    def taint_severity
      sevs = taint.chars.map { |c| MODULE_TAINT.dig(c, 1) }.compact
      return nil if sevs.empty?

      %w[high medium low].find { |s| sevs.include?(s) }
    end
  end

  # --------------------------------------------------------------------------
  # Collector -- everything that touches the filesystem lives here, and every
  # path is built from @root. Point --root at a captured tree and the exact
  # same code audits a snapshot from another machine (or a test fixture).
  # --------------------------------------------------------------------------
  class Collector
    def initialize(root: '/')
      @root = root
    end

    def path(*parts) = File.join(@root, *parts)

    def modules
      raw = read(path('proc', 'modules'))
      raise IOError, "cannot read #{path('proc', 'modules')}" if raw.nil?

      raw.each_line.filter_map { |line| parse_proc_modules_line(line) }
    end

    # /proc/sys/kernel/tainted -> [bitmask, ["G/P proprietary...", ...]]
    def kernel_taint
      raw = read(path('proc', 'sys', 'kernel', 'tainted'))
      return [0, []] if raw.nil?

      mask = raw.strip.to_i
      flags = (0..31).select { |b| mask.anybits?(1 << b) }
                     .map { |b| KERNEL_TAINT_BITS.fetch(b, "bit #{b}") }
      [mask, flags]
    end

    private

    # /proc/modules columns:
    #   name  size  refcount  used_by  state  address  [taint]
    # `used_by` is "-" when empty and otherwise a comma-terminated list.
    def parse_proc_modules_line(line)
      f = line.split
      return nil if f.size < 5

      name = f[0]
      used_by = f[3] == '-' ? [] : f[3].split(',').reject(&:empty?)

      Mod.new(
        name: name,
        size: f[1].to_i,
        refcount: f[2].to_i,
        used_by: used_by,
        state: f[4],
        address: f[5],
        taint: sysfs(name, 'taint').to_s.strip,
        srcversion: sysfs(name, 'srcversion').to_s.strip,
        holders: holders(name),
        params: params(name),
        risky_reason: RISKY_MODULES[name.tr('_', '-')] || RISKY_MODULES[name]
      )
    end

    # /sys/module/<name>/holders/ lists the modules depending on this one.
    # It is authoritative where /proc/modules' used_by column can be stale.
    def holders(name)
      dir = path('sys', 'module', name, 'holders')
      return [] unless File.directory?(dir)

      Dir.children(dir).sort
    rescue SystemCallError
      []
    end

    # Non-default module parameters are a common source of "why is this box
    # behaving differently" -- worth capturing in the report.
    def params(name)
      dir = path('sys', 'module', name, 'parameters')
      return {} unless File.directory?(dir)

      Dir.children(dir).sort.each_with_object({}) do |p, h|
        v = read(File.join(dir, p))
        h[p] = v.strip unless v.nil? || v.strip.empty?
      end
    rescue SystemCallError
      {}
    end

    def sysfs(name, leaf) = read(path('sys', 'module', name, leaf))

    # Sysfs reads fail in interesting ways (EACCES, EINVAL, ENODEV on a module
    # unloading mid-scan). None of them should abort the audit.
    def read(file)
      File.read(file)
    rescue SystemCallError, IOError
      nil
    end
  end

  # --------------------------------------------------------------------------
  # Baseline: one module name per line, '#' comments allowed.
  # --------------------------------------------------------------------------
  module Baseline
    def self.load(file)
      Set.new(
        File.readlines(file, chomp: true)
            .map { |l| l.sub(/#.*/, '').strip }
            .reject(&:empty?)
      )
    end

    def self.write(file, mods)
      File.write(file, <<~HEAD + mods.map(&:name).sort.join("\n") + "\n")
        # kernel module baseline
        # host: #{`hostname`.strip rescue 'unknown'}
        # generated: #{Time.now.utc.iso8601}
        # one module name per line; '#' starts a comment
      HEAD
    end
  end

  # --------------------------------------------------------------------------
  # Audit -- pure logic over collected data, so it is trivially testable.
  # --------------------------------------------------------------------------
  class Audit
    attr_reader :mods, :taint_mask, :taint_flags, :added, :missing

    def initialize(mods, taint_mask, taint_flags, baseline: nil)
      @mods = mods.sort_by(&:name)
      @taint_mask = taint_mask
      @taint_flags = taint_flags
      names = Set.new(@mods.map(&:name))
      @added   = baseline ? (names - baseline).to_a.sort : []
      @missing = baseline ? (baseline - names).to_a.sort : []
    end

    def tainted_mods = @mods.select { |m| !m.taint.empty? }
    def risky        = @mods.select(&:risky_reason)
    def removable    = @mods.select(&:removable?)
    def total_bytes  = @mods.sum(&:size)

    def problems? = !(@added.empty? && risky.empty? && tainted_mods.empty?)

    def to_h
      {
        audited_at: Time.now.utc.iso8601,
        module_count: @mods.size,
        total_bytes: total_bytes,
        kernel_taint_mask: @taint_mask,
        kernel_taint_flags: @taint_flags,
        baseline_added: @added,
        baseline_missing: @missing,
        risky: risky.map { |m| { name: m.name, reason: m.risky_reason } },
        tainted: tainted_mods.map do |m|
          { name: m.name, taint: m.taint, severity: m.taint_severity }
        end,
        modules: @mods.map do |m|
          { name: m.name, size: m.size, refcount: m.refcount,
            used_by: m.used_by, holders: m.holders, state: m.state,
            taint: m.taint, srcversion: m.srcversion,
            removable: m.removable?, params: m.params }
        end
      }
    end
  end

  # --------------------------------------------------------------------------
  # Reporting
  # --------------------------------------------------------------------------
  module Report
    def self.text(a, root)
      o = []
      o << '=' * 78
      o << "  KERNEL MODULE AUDIT   #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}"
      o << "  root: #{root}   kernel: #{kernel_release(root)}"
      o << '=' * 78
      o << format('  modules loaded: %-6d  resident: %-10s  removable: %d',
                  a.mods.size, human(a.total_bytes), a.removable.size)

      o << ''
      o << '  KERNEL TAINT'
      o << '  ' + '-' * 74
      if a.taint_mask.zero?
        o << '    clean (0)'
      else
        o << "    mask #{a.taint_mask}"
        a.taint_flags.each { |f| o << "      #{f}" }
      end

      unless a.tainted_mods.empty?
        o << ''
        o << '  TAINTING MODULES'
        o << '  ' + '-' * 74
        a.tainted_mods.each do |m|
          letters = m.taint.chars.map do |c|
            n, _s, d = MODULE_TAINT[c]
            n ? "#{c}=#{n} (#{d})" : "#{c}=unknown"
          end
          o << format('    %-24s [%s]', m.name, m.taint)
          letters.each { |l| o << "        #{l}" }
        end
      end

      unless a.risky.empty?
        o << ''
        o << '  MODULES FLAGGED BY HARDENING GUIDES'
        o << '  ' + '-' * 74
        a.risky.each { |m| o << format('    %-16s %s', m.name, m.risky_reason) }
      end

      unless a.added.empty?
        o << ''
        o << "  BASELINE DRIFT -- #{a.added.size} module(s) not in baseline"
        o << '  ' + '-' * 74
        a.added.each { |n| o << "    + #{n}" }
      end

      unless a.missing.empty?
        o << ''
        o << "  BASELINE DRIFT -- #{a.missing.size} baseline module(s) absent"
        o << '  ' + '-' * 74
        a.missing.each { |n| o << "    - #{n}" }
      end

      o << ''
      o << '  TOP 10 BY RESIDENT SIZE'
      o << '  ' + '-' * 74
      o << format('    %-26s %10s %5s  %s', 'MODULE', 'SIZE', 'REFS', 'USED BY')
      a.mods.sort_by { |m| -m.size }.first(10).each do |m|
        used = m.holders.empty? ? (m.used_by.empty? ? '-' : m.used_by.join(',')) \
                                : m.holders.join(',')
        used = used[0, 30]
        o << format('    %-26s %10s %5d  %s', m.name, human(m.size), m.refcount, used)
      end

      o << ''
      o << '=' * 78
      o.join("\n")
    end

    def self.kernel_release(root = '/')
      File.read(File.join(root, 'proc', 'sys', 'kernel', 'osrelease')).strip
    rescue StandardError
      'unknown'
    end

    def self.human(b)
      units = %w[B KiB MiB]
      i = 0
      v = b.to_f
      while v >= 1024 && i < units.size - 1
        v /= 1024
        i += 1
      end
      format('%.1f %s', v, units[i])
    end
  end
end

# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  opts = { root: '/', format: 'text', baseline: nil, write_baseline: nil }

  parser = OptionParser.new do |o|
    o.banner = 'Usage: ruby module_audit.rb [options]'
    o.on('-r', '--root DIR', 'audit a captured tree instead of / ') { |v| opts[:root] = v }
    o.on('-f', '--format F', %w[text json], 'text (default) or json') { |v| opts[:format] = v }
    o.on('-b', '--baseline FILE', 'compare against baseline file') { |v| opts[:baseline] = v }
    o.on('-w', '--write-baseline FILE', 'write current modules as baseline') do |v|
      opts[:write_baseline] = v
    end
    o.on('--version', 'print version') { puts ModuleAudit::VERSION; exit 0 }
    o.on('-h', '--help', 'show this help') { puts o; exit 0 }
  end

  begin
    parser.parse!
  rescue OptionParser::ParseError => e
    warn "module_audit: #{e.message}"
    exit 2
  end

  begin
    collector = ModuleAudit::Collector.new(root: opts[:root])
    mods = collector.modules
    mask, flags = collector.kernel_taint
  rescue IOError, SystemCallError => e
    warn "module_audit: #{e.message}"
    warn 'module_audit: is this a Linux host? /proc/modules is required.'
    exit 2
  end

  if opts[:write_baseline]
    ModuleAudit::Baseline.write(opts[:write_baseline], mods)
    warn "module_audit: wrote #{mods.size} modules to #{opts[:write_baseline]}"
    exit 0
  end

  baseline = opts[:baseline] ? ModuleAudit::Baseline.load(opts[:baseline]) : nil
  audit = ModuleAudit::Audit.new(mods, mask, flags, baseline: baseline)

  if opts[:format] == 'json'
    puts JSON.pretty_generate(audit.to_h)
  else
    puts ModuleAudit::Report.text(audit, opts[:root])
  end

  exit(audit.problems? ? 1 : 0)
end
