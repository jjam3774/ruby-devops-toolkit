#!/usr/bin/env ruby
# frozen_string_literal: true
#
# cgroup_resource_audit.rb -- audit systemd unit resource limits and headroom
#                             straight from the cgroup v2 filesystem.
#
# WHY THIS EXISTS
# ---------------
# On a modern Linux box every systemd service lives in its own cgroup v2
# directory under /sys/fs/cgroup. That directory is the *authoritative* record
# of what the kernel will actually let the service do: how much memory before
# it gets OOM-killed, how much CPU before it gets throttled, how many tasks
# before fork() starts failing -- and, just as usefully, how close the service
# is to each of those walls right now.
#
# "systemctl show" will tell you what the unit file *asked* for. The cgroup
# filesystem tells you what the kernel is *enforcing*, plus live counters for
# how often it has already had to enforce it. That second set of numbers is
# where the interesting findings are: a service that has been silently
# OOM-killed eleven times this week, a service pinned at 97% of its memory
# cap, a service being CPU-throttled 40% of the time because someone set
# CPUQuota=5% two years ago and forgot.
#
# This script reads that filesystem directly -- no gems, no shelling out to
# systemctl for the numbers -- and reports every unit that is in trouble or
# about to be.
#
# Ruby >= 2.7, standard library only. Linux with cgroup v2 (unified hierarchy).
#
# Usage:
#   ruby cgroup_resource_audit.rb
#   ruby cgroup_resource_audit.rb --slice system.slice --slice user.slice
#   ruby cgroup_resource_audit.rb --json
#   ruby cgroup_resource_audit.rb --min-severity high --quiet
#
# Exit codes (designed for Nagios/Icinga-style checks and CI gates):
#   0 = no findings at or above the reporting threshold
#   1 = warnings only (medium/low)
#   2 = at least one high or critical finding
#   3 = could not audit (no cgroup v2, bad arguments)

require 'optparse'
require 'json'

# --------------------------------------------------------------------------
# Tunables. Every threshold is a policy decision, so they all live in one
# place where you can argue about them without touching the logic.
# --------------------------------------------------------------------------
module Thresholds
  MEM_CRITICAL_PCT   = 90.0  # memory.current as % of memory.max -> critical
  MEM_WARN_PCT       = 75.0  # ... -> medium
  PIDS_CRITICAL_PCT  = 85.0  # pids.current as % of pids.max
  PIDS_WARN_PCT      = 70.0
  THROTTLE_HIGH_PCT  = 10.0  # cpu throttled_usec as % of usage -> high
  THROTTLE_WARN_PCT  = 2.0
  PRESSURE_HIGH      = 10.0  # memory.pressure "full avg60" percent -> high
  PRESSURE_WARN      = 2.0
  # A service with no memory cap is only interesting once it is actually
  # big. An unbounded 4 MB helper cannot take the host down; an unbounded
  # process already holding 20% of RAM absolutely can.
  UNBOUNDED_RSS_PCT  = 15.0
end

SEVERITIES = %w[critical high medium low].freeze
SEV_RANK   = SEVERITIES.each_with_index.to_h.freeze

# ==========================================================================
# CgroupReader -- the only part of the script that touches the filesystem.
#
# Keeping all I/O behind this tiny class is what makes the auditor testable:
# point it at a fixture tree instead of /sys/fs/cgroup and everything else
# behaves identically.
# ==========================================================================
class CgroupReader
  attr_reader :root

  def initialize(root = '/sys/fs/cgroup')
    @root = root
  end

  # cgroup v2 mounts a single unified hierarchy; v1 mounts one directory per
  # controller. The presence of cgroup.controllers at the root is the standard
  # way to tell them apart without parsing /proc/mounts.
  def unified?
    File.readable?(File.join(@root, 'cgroup.controllers'))
  end

  # Enabled controllers at the root. If "memory" is missing here, nothing
  # below has memory accounting and most of this audit is meaningless.
  def root_controllers
    read('cgroup.controllers').to_s.split
  end

  # Every leaf cgroup that represents a unit: *.service, *.scope, *.mount,
  # *.socket. Nested slices (system-getty.slice) are walked into but are not
  # themselves reported -- they are containers, not workloads.
  def unit_dirs(slice)
    base = File.join(@root, slice)
    return [] unless File.directory?(base)

    out = []
    stack = [base]
    while (dir = stack.pop)
      Dir.children(dir).sort.each do |name|
        path = File.join(dir, name)
        next unless File.directory?(path)

        if name.end_with?('.slice')
          stack << path            # recurse into sub-slices
        elsif name =~ /\.(service|scope|socket|mount)\z/
          out << path
        end
      end
    end
    out
  rescue Errno::EACCES, Errno::ENOENT
    out || []
  end

  # Read a cgroup control file. Anything unreadable comes back as nil rather
  # than raising: on a real box files vanish mid-scan (the unit stopped) and
  # controllers you do not have delegated are simply absent. Treating both as
  # "no data" is the only sane behaviour for an auditor.
  def read(rel, dir = @root)
    File.read(File.join(dir, rel)).strip
  rescue Errno::ENOENT, Errno::EACCES, Errno::ENODEV, Errno::EINVAL, Errno::EIO
    nil
  end

  # Flat key/value control files: "usage_usec 5999046\nuser_usec 1692474".
  def read_kv(rel, dir)
    body = read(rel, dir)
    return {} if body.nil?

    body.each_line.with_object({}) do |line, h|
      key, value = line.split(' ', 2)
      next if key.nil? || value.nil?

      h[key] = value.strip.to_i
    end
  end

  # PSI files: "some avg10=0.00 avg60=0.00 avg300=0.00 total=0".
  # Returns { "some" => {"avg10"=>0.0, ...}, "full" => {...} }.
  def read_pressure(rel, dir)
    body = read(rel, dir)
    return {} if body.nil?

    body.each_line.with_object({}) do |line, h|
      parts = line.split
      scope = parts.shift
      next if scope.nil?

      h[scope] = parts.each_with_object({}) do |pair, m|
        k, v = pair.split('=', 2)
        m[k] = v.to_f if v
      end
    end
  end
end

# ==========================================================================
# Unit -- one service's worth of numbers, parsed into plain Ruby values.
#
# cgroup v2 uses the literal string "max" for "no limit". Converting that to
# nil at the edge means the rest of the code can just ask "is the limit nil?"
# instead of string-comparing "max" in six different places.
# ==========================================================================
class Unit
  attr_reader :name, :slice, :path,
              :mem_current, :mem_max, :mem_high, :mem_peak,
              :oom_kills, :max_events, :high_events,
              :pids_current, :pids_max,
              :cpu_quota_pct, :cpu_usage_usec, :cpu_throttled_usec, :nr_throttled,
              :mem_pressure_full60, :cpu_pressure_some60,
              :controllers, :proc_count

  LIMIT_NONE = 'max'

  def initialize(reader, path, slice)
    @path  = path
    @slice = slice
    @name  = File.basename(path)

    @controllers = reader.read('cgroup.controllers', path).to_s.split

    # ---- memory ----------------------------------------------------------
    @mem_current = to_i_or_nil(reader.read('memory.current', path))
    @mem_max     = to_limit(reader.read('memory.max', path))
    @mem_high    = to_limit(reader.read('memory.high', path))
    @mem_peak    = to_i_or_nil(reader.read('memory.peak', path)) # kernel >= 5.19

    # memory.events is the money file. Each counter is cumulative since the
    # cgroup was created, so a non-zero "oom_kill" means the kernel has
    # already killed something in this unit -- an event that leaves no trace
    # in the service's own logs, because the process never got to log it.
    events       = reader.read_kv('memory.events', path)
    @oom_kills   = events['oom_kill'] || events['oom'] || 0
    @max_events  = events['max'] || 0
    @high_events = events['high'] || 0

    # ---- pids ------------------------------------------------------------
    @pids_current = to_i_or_nil(reader.read('pids.current', path))
    @pids_max     = to_limit(reader.read('pids.max', path))

    # ---- cpu -------------------------------------------------------------
    # cpu.max is "QUOTA PERIOD" in microseconds, or "max PERIOD" for no cap.
    quota, period = reader.read('cpu.max', path).to_s.split
    @cpu_quota_pct = if quota.nil? || quota == LIMIT_NONE || period.to_i.zero?
                       nil
                     else
                       (quota.to_f / period.to_f) * 100.0
                     end

    cpu = reader.read_kv('cpu.stat', path)
    @cpu_usage_usec     = cpu['usage_usec']
    @cpu_throttled_usec = cpu['throttled_usec']
    @nr_throttled       = cpu['nr_throttled']

    # ---- pressure (PSI) --------------------------------------------------
    # "full" memory pressure means *every* task in the cgroup was stalled on
    # memory. Non-zero full pressure is the clearest single signal that a
    # memory limit is hurting rather than protecting.
    @mem_pressure_full60 = reader.read_pressure('memory.pressure', path).dig('full', 'avg60')
    @cpu_pressure_some60 = reader.read_pressure('cpu.pressure', path).dig('some', 'avg60')

    @proc_count = reader.read('cgroup.procs', path).to_s.split("\n").count { |l| !l.empty? }
  end

  # Live? An empty cgroup.procs with no memory charged is a leftover
  # directory for a stopped unit -- reporting on it is pure noise.
  def active?
    @proc_count.positive? || (@mem_current || 0) > 0
  end

  def mem_pct
    return nil if @mem_max.nil? || @mem_max.zero? || @mem_current.nil?

    (@mem_current.to_f / @mem_max) * 100.0
  end

  def pids_pct
    return nil if @pids_max.nil? || @pids_max.zero? || @pids_current.nil?

    (@pids_current.to_f / @pids_max) * 100.0
  end

  # Share of wall-clock CPU time the kernel spent refusing to schedule this
  # unit. Only meaningful when a quota exists.
  def throttle_pct
    return nil if @cpu_throttled_usec.nil? || @cpu_usage_usec.nil?

    total = @cpu_usage_usec + @cpu_throttled_usec
    return nil if total.zero?

    (@cpu_throttled_usec.to_f / total) * 100.0
  end

  def to_h
    {
      unit: @name, slice: @slice,
      memory_current: @mem_current, memory_max: @mem_max, memory_high: @mem_high,
      memory_peak: @mem_peak, memory_pct: round1(mem_pct),
      oom_kills: @oom_kills, memory_max_events: @max_events,
      pids_current: @pids_current, pids_max: @pids_max, pids_pct: round1(pids_pct),
      cpu_quota_pct: round1(@cpu_quota_pct), cpu_throttle_pct: round1(throttle_pct),
      nr_throttled: @nr_throttled,
      memory_pressure_full_avg60: @mem_pressure_full60,
      cpu_pressure_some_avg60: @cpu_pressure_some60,
      controllers: @controllers, processes: @proc_count
    }
  end

  private

  def to_i_or_nil(str)
    str.nil? ? nil : str.to_i
  end

  # "max" -> nil (unlimited); "2147483648" -> 2147483648
  def to_limit(str)
    return nil if str.nil? || str == LIMIT_NONE

    str.to_i
  end

  def round1(val)
    val.nil? ? nil : val.round(1)
  end
end

# ==========================================================================
# Auditor -- turns Units into findings. No I/O, no printing: just rules.
# ==========================================================================
class Auditor
  Finding = Struct.new(:unit, :severity, :code, :detail, :evidence, keyword_init: true)

  def initialize(host_ram_bytes:)
    @host_ram = host_ram_bytes
  end

  def audit(unit)
    findings = []
    findings.concat(memory_findings(unit))
    findings.concat(pids_findings(unit))
    findings.concat(cpu_findings(unit))
    findings.concat(pressure_findings(unit))
    findings.concat(delegation_findings(unit))
    findings
  end

  private

  def memory_findings(u)
    out = []

    # An OOM kill inside a cgroup is invisible from the service's point of
    # view: SIGKILL cannot be caught, so nothing gets logged by the app. This
    # counter is often the only evidence that it happened at all.
    if u.oom_kills.positive?
      out << Finding.new(
        unit: u.name, severity: 'critical', code: 'OOM_KILLED',
        detail: "kernel has OOM-killed #{u.oom_kills} process(es) in this unit " \
                "since boot -- the memory limit is too low or the service leaks",
        evidence: "memory.events oom_kill=#{u.oom_kills}"
      )
    end

    pct = u.mem_pct
    if pct
      if pct >= Thresholds::MEM_CRITICAL_PCT
        out << Finding.new(
          unit: u.name, severity: 'critical', code: 'MEM_AT_LIMIT',
          detail: "using #{pct.round(1)}% of its memory limit -- the next " \
                  'allocation spike ends in an OOM kill',
          evidence: "memory.current=#{human(u.mem_current)} / memory.max=#{human(u.mem_max)}"
        )
      elsif pct >= Thresholds::MEM_WARN_PCT
        out << Finding.new(
          unit: u.name, severity: 'medium', code: 'MEM_HEADROOM_LOW',
          detail: "using #{pct.round(1)}% of its memory limit -- little headroom left",
          evidence: "memory.current=#{human(u.mem_current)} / memory.max=#{human(u.mem_max)}"
        )
      end
    elsif u.mem_current && @host_ram.positive?
      # No cap at all. Only worth flagging once the unit is genuinely large.
      share = (u.mem_current.to_f / @host_ram) * 100.0
      if share >= Thresholds::UNBOUNDED_RSS_PCT
        out << Finding.new(
          unit: u.name, severity: 'medium', code: 'MEM_UNBOUNDED',
          detail: "no MemoryMax set and already holding #{share.round(1)}% of host RAM -- " \
                  'a leak here takes the whole box down, not just this service',
          evidence: "memory.max=max, memory.current=#{human(u.mem_current)}"
        )
      end
    end

    # memory.high throttles reclaim instead of killing. Repeated "high"
    # events mean the service is being deliberately slowed down, which looks
    # like mysterious latency rather than an error.
    if u.high_events > 0 && u.mem_high
      out << Finding.new(
        unit: u.name, severity: 'medium', code: 'MEM_HIGH_THROTTLED',
        detail: "breached MemoryHigh #{u.high_events} time(s) -- reclaim pressure " \
                'is being applied, which shows up as latency, not errors',
        evidence: "memory.events high=#{u.high_events}, memory.high=#{human(u.mem_high)}"
      )
    end

    out
  end

  def pids_findings(u)
    pct = u.pids_pct
    return [] if pct.nil?

    if pct >= Thresholds::PIDS_CRITICAL_PCT
      [Finding.new(
        unit: u.name, severity: 'high', code: 'PIDS_AT_LIMIT',
        detail: "at #{pct.round(1)}% of its task limit -- fork()/pthread_create() " \
                'will start failing, usually as an unhelpful generic error',
        evidence: "pids.current=#{u.pids_current} / pids.max=#{u.pids_max}"
      )]
    elsif pct >= Thresholds::PIDS_WARN_PCT
      [Finding.new(
        unit: u.name, severity: 'medium', code: 'PIDS_HEADROOM_LOW',
        detail: "at #{pct.round(1)}% of its task limit",
        evidence: "pids.current=#{u.pids_current} / pids.max=#{u.pids_max}"
      )]
    else
      []
    end
  end

  def cpu_findings(u)
    pct = u.throttle_pct
    return [] if pct.nil? || pct <= 0

    if pct >= Thresholds::THROTTLE_HIGH_PCT
      [Finding.new(
        unit: u.name, severity: 'high', code: 'CPU_THROTTLED',
        detail: "throttled #{pct.round(1)}% of its CPU time by a " \
                "#{u.cpu_quota_pct ? "#{u.cpu_quota_pct.round(0)}%" : 'configured'} quota -- " \
                'this is latency you cannot profile away in application code',
        evidence: "cpu.stat throttled_usec=#{u.cpu_throttled_usec}, nr_throttled=#{u.nr_throttled}"
      )]
    elsif pct >= Thresholds::THROTTLE_WARN_PCT
      [Finding.new(
        unit: u.name, severity: 'low', code: 'CPU_THROTTLED_MILD',
        detail: "throttled #{pct.round(1)}% of its CPU time",
        evidence: "cpu.stat throttled_usec=#{u.cpu_throttled_usec}"
      )]
    else
      []
    end
  end

  def pressure_findings(u)
    val = u.mem_pressure_full60
    return [] if val.nil? || val <= 0

    if val >= Thresholds::PRESSURE_HIGH
      [Finding.new(
        unit: u.name, severity: 'high', code: 'MEM_PRESSURE',
        detail: "every task in this unit was stalled on memory #{val.round(1)}% " \
                'of the last minute -- it is thrashing, not working',
        evidence: "memory.pressure full avg60=#{val}"
      )]
    elsif val >= Thresholds::PRESSURE_WARN
      [Finding.new(
        unit: u.name, severity: 'low', code: 'MEM_PRESSURE_MILD',
        detail: "sustained memory stall of #{val.round(1)}% over the last minute",
        evidence: "memory.pressure full avg60=#{val}"
      )]
    else
      []
    end
  end

  # A limit you cannot set is a limit you do not have. If the cpu controller
  # is not delegated into this cgroup, CPUQuota= in the unit file is silently
  # inert -- which is exactly the kind of thing that only surfaces during an
  # incident.
  def delegation_findings(u)
    out = []
    unless u.controllers.include?('cpu')
      out << Finding.new(
        unit: u.name, severity: 'low', code: 'CPU_CTRL_MISSING',
        detail: 'cpu controller is not delegated to this cgroup, so CPUQuota=/' \
                'CPUWeight= cannot be enforced here at all',
        evidence: "cgroup.controllers=#{u.controllers.join(',')}"
      )
    end
    out
  end

  def human(bytes)
    return 'max' if bytes.nil?

    units = %w[B K M G T]
    idx = 0
    val = bytes.to_f
    while val >= 1024 && idx < units.length - 1
      val /= 1024
      idx += 1
    end
    format('%.1f%s', val, units[idx])
  end
end

# ==========================================================================
# Reporting
# ==========================================================================
module Report
  COLORS = { 'critical' => "\e[1;31m", 'high' => "\e[31m",
             'medium' => "\e[33m", 'low' => "\e[36m" }.freeze
  RESET = "\e[0m"

  def self.color?
    $stdout.tty? && ENV['NO_COLOR'].nil?
  end

  def self.tint(text, severity)
    color? ? "#{COLORS.fetch(severity, '')}#{text}#{RESET}" : text
  end

  def self.human(bytes)
    return '-' if bytes.nil?

    units = %w[B K M G T]
    idx = 0
    val = bytes.to_f
    while val >= 1024 && idx < units.length - 1
      val /= 1024
      idx += 1
    end
    format('%.1f%s', val, units[idx])
  end

  def self.text(units, findings, opts)
    lines = []
    lines << "cgroup v2 resource audit -- #{Time.now.strftime('%Y-%m-%d %H:%M:%S %Z')}"
    lines << "root=#{opts[:root]}  slices=#{opts[:slices].join(',')}"
    lines << '=' * 78
    lines << ''

    unless opts[:quiet]
      lines << format('%-30s %9s %9s %7s %7s %6s', 'UNIT', 'MEM', 'LIMIT', 'MEM%', 'TASKS', 'OOM')
      lines << '-' * 78
      units.sort_by { |u| -(u.mem_current || 0) }.each do |u|
        lines << format(
          '%-30s %9s %9s %7s %7s %6s',
          u.name[0, 30],
          human(u.mem_current),
          u.mem_max ? human(u.mem_max) : 'unset',
          u.mem_pct ? "#{u.mem_pct.round(1)}%" : '-',
          u.pids_max ? "#{u.pids_current}/#{u.pids_max}" : (u.pids_current || '-').to_s,
          u.oom_kills.to_s
        )
      end
      lines << ''
    end

    if findings.empty?
      lines << 'No findings at or above the configured severity threshold.'
    else
      lines << "FINDINGS (#{findings.length})"
      lines << '-' * 78
      findings.each do |f|
        lines << tint("[#{f.severity.upcase}] #{f.unit} -- #{f.code}", f.severity)
        lines << "    #{f.detail}"
        lines << "    evidence: #{f.evidence}"
        lines << ''
      end
    end

    counts = findings.group_by(&:severity).transform_values(&:length)
    lines << '=' * 78
    lines << "#{units.length} active unit(s) audited; " +
             (SEVERITIES.map { |s| "#{counts.fetch(s, 0)} #{s}" }.join(', '))
    lines.join("\n")
  end

  def self.json(units, findings, opts)
    JSON.pretty_generate(
      generated_at: Time.now.utc.iso8601,
      cgroup_root: opts[:root],
      slices: opts[:slices],
      units: units.map(&:to_h),
      findings: findings.map(&:to_h),
      summary: {
        units_audited: units.length,
        findings: findings.group_by(&:severity).transform_values(&:length)
      }
    )
  end
end

# ==========================================================================
# CLI
# ==========================================================================
def parse_options(argv)
  opts = {
    root: '/sys/fs/cgroup',
    slices: [],
    json: false,
    quiet: false,
    min_severity: 'low'
  }

  parser = OptionParser.new do |o|
    o.banner = 'Usage: cgroup_resource_audit.rb [options]'
    o.on('--root PATH', 'cgroup v2 mount point (default /sys/fs/cgroup)') { |v| opts[:root] = v }
    o.on('--slice NAME', 'slice to audit; repeatable (default system.slice)') { |v| opts[:slices] << v }
    o.on('--json', 'emit JSON instead of a text table') { opts[:json] = true }
    o.on('--quiet', 'suppress the per-unit table, print findings only') { opts[:quiet] = true }
    o.on('--min-severity SEV', SEVERITIES, "report only SEV and above (#{SEVERITIES.join('|')})") do |v|
      opts[:min_severity] = v
    end
    o.on('-h', '--help') { puts o; exit 0 }
  end
  parser.parse!(argv)
  opts[:slices] = ['system.slice'] if opts[:slices].empty?
  opts
rescue OptionParser::ParseError => e
  warn "argument error: #{e.message}"
  exit 3
end

def host_ram_bytes
  line = File.read('/proc/meminfo')[/MemTotal:\s+(\d+) kB/, 1]
  line ? line.to_i * 1024 : 0
rescue StandardError
  0
end

def main(argv)
  require 'time'
  opts = parse_options(argv)
  reader = CgroupReader.new(opts[:root])

  unless reader.unified?
    warn "error: #{opts[:root]} is not a cgroup v2 (unified) hierarchy."
    warn '       This host is probably on cgroup v1. Boot with'
    warn '       systemd.unified_cgroup_hierarchy=1 or use a newer distro.'
    exit 3
  end

  unless reader.root_controllers.include?('memory')
    warn 'warning: the memory controller is not enabled at the cgroup root;'
    warn '         memory findings will be empty.'
  end

  units = opts[:slices].flat_map do |slice|
    reader.unit_dirs(slice).map { |dir| Unit.new(reader, dir, slice) }
  end.select(&:active?)

  auditor  = Auditor.new(host_ram_bytes: host_ram_bytes)
  findings = units.flat_map { |u| auditor.audit(u) }

  cutoff   = SEV_RANK.fetch(opts[:min_severity])
  findings = findings.select { |f| SEV_RANK.fetch(f.severity) <= cutoff }
  findings.sort_by! { |f| [SEV_RANK.fetch(f.severity), f.unit] }

  puts(opts[:json] ? Report.json(units, findings, opts) : Report.text(units, findings, opts))

  worst = findings.map { |f| SEV_RANK.fetch(f.severity) }.min
  return 0 if worst.nil?
  return 2 if worst <= SEV_RANK.fetch('high')

  1
end

exit main(ARGV) if __FILE__ == $PROGRAM_NAME
