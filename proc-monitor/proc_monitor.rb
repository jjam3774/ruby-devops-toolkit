#!/usr/bin/env ruby
# frozen_string_literal: true
#
# proc_monitor.rb - A lightweight process & resource monitor built on Linux's
# /proc filesystem. No gems, no agents, no daemons to install - just Ruby
# stdlib reading the same kernel-exposed files that `ps`/`top` read.
#
# Watches one or more processes (by name or PID), reports RSS memory, CPU%,
# process state and command line, flags WARN/CRIT threshold breaches, and
# exits non-zero when something needs attention - so it drops straight into
# cron or a CI health-check step.
#
# Author: tha-shed.com / ruby-devops-toolkit
# Ruby:   3.0+
# OS:     Linux (relies on /proc; will not work on macOS/BSD/Windows)
#
# Usage:
#   ./proc_monitor.rb -p sshd -p 1 --mem-mb 200 --cpu-pct 50
#   ./proc_monitor.rb -p nginx --json
#   ./proc_monitor.rb -p myapp --watch --interval 5 --mem-mb 512 --cpu-pct 80
#
# Exit codes (cron-friendly):
#   0 = OK, everything under thresholds and every watched target found
#   1 = WARN, something is within 80% of a threshold
#   2 = CRIT, a threshold was breached
#   3 = a watched target could not be found (process missing/dead)
#
# When multiple targets are watched, the exit code reflects the WORST status
# across all of them (missing > crit > warn > ok).

require 'optparse'
require 'etc'
require 'json'
require 'time'

module ProcMonitor
  # --------------------------------------------------------------------
  # Constants
  # --------------------------------------------------------------------

  # Clock ticks per second - needed to convert utime/stime (field 14/15 of
  # /proc/[pid]/stat) from "jiffies" into seconds. This is almost always
  # 100 on Linux, but we ask the kernel via Etc.sysconf rather than
  # hardcoding it, since it *can* differ on some architectures/kernels.
  CLK_TCK = begin
    Etc.sysconf(Etc::SC_CLK_TCK).to_f
  rescue StandardError
    100.0 # sane fallback if sysconf lookup ever fails
  end

  EXIT_OK      = 0
  EXIT_WARN    = 1
  EXIT_CRIT    = 2
  EXIT_MISSING = 3

  # Map of Linux process-state letters (from /proc/[pid]/stat field 3 or
  # /proc/[pid]/status "State:") to human-readable labels.
  STATE_LABELS = {
    'R' => 'running',
    'S' => 'sleeping',
    'D' => 'disk-sleep (uninterruptible)',
    'Z' => 'zombie',
    'T' => 'stopped',
    't' => 'tracing-stop',
    'X' => 'dead',
    'I' => 'idle'
  }.freeze

  # --------------------------------------------------------------------
  # Low-level /proc readers
  #
  # Every one of these can race against a process exiting mid-read, so we
  # treat Errno::ENOENT / Errno::ESRCH as "the process is gone" rather than
  # letting the script crash. That race is inherent to /proc: there is no
  # atomic "read all of a process's stats" syscall.
  # --------------------------------------------------------------------

  ProcNotFound = Class.new(StandardError)

  module_function

  # Returns true if /proc/[pid] exists (cheapest possible liveness check).
  def pid_alive?(pid)
    Dir.exist?("/proc/#{pid}")
  end

  # Walks the PPid chain from the current process up to PID 1 and returns
  # the set of ancestor PIDs (shell, supervisor, container init, etc).
  #
  # We exclude these from name/cmdline matching in resolve_pids. Without
  # this, a wrapper/supervisor process whose argv happens to echo back the
  # command that launched proc_monitor.rb (common in shells, CI runners,
  # and sandboxed containers) can "match" itself on a cmdline substring
  # search - you almost never want to monitor your own ancestor chain as
  # if it were the target process.
  def ancestor_pids(start_pid = Process.pid)
    ancestors = []
    pid = start_pid
    10.times do # hard cap: never walk more than 10 levels
      ppid = begin
        File.foreach("/proc/#{pid}/status") do |line|
          break Regexp.last_match(1).to_i if line =~ /^PPid:\s*(\d+)/
        end
      rescue Errno::ENOENT, Errno::ESRCH
        nil
      end
      break unless ppid && ppid.positive?

      ancestors << ppid
      pid = ppid
    end
    ancestors
  end

  # Reads /proc/[pid]/stat and pulls out state, utime, and stime.
  #
  # The tricky part: field 2 (comm, the executable name) is wrapped in
  # parentheses and may itself contain spaces or parentheses (e.g. a
  # process renamed to "my (odd) name"). The kernel guarantees the *last*
  # ')' in the line closes the comm field, so we split on that instead of
  # naively splitting the whole line on whitespace.
  def read_stat(pid)
    raw = File.read("/proc/#{pid}/stat")
    close_paren = raw.rindex(')')
    raise ProcNotFound, "malformed /proc/#{pid}/stat" unless close_paren

    remainder = raw[(close_paren + 2)..].split(' ')
    # remainder[0] is field 3 (state); fields are 1-indexed in `man proc`,
    # so remainder[i] == field (3 + i).
    {
      state: remainder[0],
      utime: remainder[11].to_i, # field 14: user-mode CPU ticks
      stime: remainder[12].to_i  # field 15: kernel-mode CPU ticks
    }
  rescue Errno::ENOENT, Errno::ESRCH
    raise ProcNotFound, "pid #{pid} vanished while reading stat"
  end

  # Reads VmRSS (resident set size, i.e. actual RAM used, in KB) out of
  # /proc/[pid]/status. status is a simple "Key:\tvalue" file, easier to
  # parse reliably than the packed stat line.
  def read_rss_kb(pid)
    File.foreach("/proc/#{pid}/status") do |line|
      next unless line.start_with?('VmRSS:')

      # e.g. "VmRSS:\t    1234 kB\n"
      return line.split(':', 2).last.strip.split(' ').first.to_i
    end
    0 # some kernel threads report no VmRSS line at all
  rescue Errno::ENOENT, Errno::ESRCH
    raise ProcNotFound, "pid #{pid} vanished while reading status"
  end

  # Reads the full command line, joining the NUL-separated argv entries
  # with spaces. Falls back to "[comm]" (kernel threads / zombies have an
  # empty cmdline).
  def read_cmdline(pid)
    raw = File.read("/proc/#{pid}/cmdline")
    parts = raw.split("\0")
    return parts.join(' ') unless parts.empty?

    "[#{read_comm(pid)}]"
  rescue Errno::ENOENT, Errno::ESRCH
    raise ProcNotFound, "pid #{pid} vanished while reading cmdline"
  end

  # Short process name straight from /proc/[pid]/comm (kernel truncates
  # this to 15 chars - fine for matching, not always fine for display).
  def read_comm(pid)
    File.read("/proc/#{pid}/comm").strip
  rescue Errno::ENOENT, Errno::ESRCH
    raise ProcNotFound, "pid #{pid} vanished while reading comm"
  end

  # System uptime in seconds (float), first field of /proc/uptime. We use
  # this as a monotonic-ish wall clock for CPU% math instead of Time.now
  # so everything derives from the same /proc snapshot source.
  def system_uptime
    File.read('/proc/uptime').split(' ').first.to_f
  end

  # Resolves a user-supplied target string to a list of live PIDs.
  #   - Pure digits  -> treated as a literal PID.
  #   - Anything else -> scanned against every /proc/[pid]/comm (exact or
  #     substring match) first. Only if NOTHING matches on comm do we fall
  #     back to scanning the full cmdline (so "watch a ruby script by its
  #     filename" works even though comm only shows "ruby").
  #
  # Why comm gets priority: cmdline is free-form argv text, so a naive
  # substring search against it can produce surprising false positives -
  # e.g. a supervisor/wrapper process whose argv happens to quote a
  # command line that mentions your query string (this bit us for real
  # while testing this script under a sandboxed shell wrapper, where PID 1's
  # argv embedded the very shell command that launched proc_monitor.rb,
  # causing it to "match" itself). Preferring the short, kernel-assigned
  # comm name avoids that whole class of false positive whenever possible.
  def resolve_pids(query)
    return [query.to_i] if query.match?(/\A\d+\z/) && pid_alive?(query.to_i)
    return [] if query.match?(/\A\d+\z/) # numeric but not alive -> no match

    comm_matches = []
    cmdline_matches = []
    excluded = [Process.pid] + ancestor_pids

    Dir.glob('/proc/[0-9]*').each do |dir|
      pid = File.basename(dir).to_i
      next if excluded.include?(pid) # never match ourselves or our own ancestor chain

      comm = begin
        File.read("#{dir}/comm").strip
      rescue Errno::ENOENT, Errno::ESRCH, Errno::EACCES
        nil
      end

      if comm && (comm == query || comm.include?(query))
        comm_matches << pid
        next
      end

      cmdline = begin
        File.read("#{dir}/cmdline").tr("\0", ' ')
      rescue Errno::ENOENT, Errno::ESRCH, Errno::EACCES
        nil
      end

      cmdline_matches << pid if cmdline && cmdline.include?(query)
    end

    (comm_matches.empty? ? cmdline_matches : comm_matches).uniq.sort
  end

  # --------------------------------------------------------------------
  # Sampling
  # --------------------------------------------------------------------

  # A single point-in-time snapshot of a watched process.
  Sample = Struct.new(:pid, :query, :state, :utime, :stime, :rss_kb, :cmdline, :uptime, keyword_init: true)

  # Takes one full snapshot for a pid. Raises ProcNotFound if the process
  # disappears between calls (handled by the caller).
  def sample(pid, query)
    stat = read_stat(pid)
    Sample.new(
      pid: pid,
      query: query,
      state: stat[:state],
      utime: stat[:utime],
      stime: stat[:stime],
      rss_kb: read_rss_kb(pid),
      cmdline: read_cmdline(pid),
      uptime: system_uptime
    )
  end

  # Computes CPU% between two samples of the SAME pid using the standard
  # /proc CPU% formula:
  #
  #   cpu% = 100 * ((utime2 + stime2) - (utime1 + stime1)) / CLK_TCK
  #              / (wall_clock_seconds_elapsed)
  #
  # utime/stime are cumulative CPU-tick counters since the process
  # started, so we need two samples spaced `interval` seconds apart to
  # derive a rate. This mirrors what `top`/`ps` do internally.
  def cpu_percent(prev, cur)
    tick_delta = (cur.utime + cur.stime) - (prev.utime + prev.stime)
    wall_delta = cur.uptime - prev.uptime
    return 0.0 if wall_delta <= 0

    cpu_seconds = tick_delta / CLK_TCK
    ((cpu_seconds / wall_delta) * 100).round(2)
  end
end

# --------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------

class ProcMonitorCLI
  Options = Struct.new(
    :targets, :interval, :watch, :iterations, :mem_mb, :cpu_pct, :json,
    keyword_init: true
  )

  def self.parse(argv)
    opts = Options.new(
      targets: [],
      interval: 1.0,
      watch: false,
      iterations: nil, # nil == run forever in watch mode
      mem_mb: nil,
      cpu_pct: nil,
      json: false
    )

    parser = OptionParser.new do |o|
      o.banner = "Usage: proc_monitor.rb -p NAME_OR_PID [-p ...] [options]"

      o.on('-p', '--process NAME_OR_PID',
           'Process name or PID to watch (repeatable)') do |v|
        opts.targets << v
      end

      o.on('-i', '--interval SECONDS', Float,
           'Sampling interval for CPU delta / watch loop (default: 1.0)') do |v|
        opts.interval = v
      end

      o.on('-w', '--watch', 'Continuous mode: sample repeatedly until Ctrl-C') do
        opts.watch = true
      end

      o.on('-n', '--iterations N', Integer,
           'Stop watch mode after N reports (default: run forever)') do |v|
        opts.iterations = v
      end

      o.on('--mem-mb MB', Float, 'RSS memory threshold in MB for WARN/CRIT') do |v|
        opts.mem_mb = v
      end

      o.on('--cpu-pct PCT', Float, 'CPU percent threshold for WARN/CRIT') do |v|
        opts.cpu_pct = v
      end

      o.on('--json', 'Emit machine-readable JSON instead of text') do
        opts.json = true
      end

      o.on('-h', '--help', 'Show this help') do
        puts o
        exit ProcMonitor::EXIT_OK
      end
    end

    parser.parse!(argv)

    if opts.targets.empty?
      warn parser.banner
      warn "\nError: at least one -p/--process NAME_OR_PID is required."
      exit ProcMonitor::EXIT_MISSING
    end

    opts
  end
end

# --------------------------------------------------------------------
# Threshold evaluation & reporting
# --------------------------------------------------------------------

class Report
  attr_reader :query, :status, :sample, :cpu_pct, :reasons

  # status is one of :ok, :warn, :crit, :missing
  def initialize(query:, status:, sample: nil, cpu_pct: nil, reasons: [])
    @query = query
    @status = status
    @sample = sample
    @cpu_pct = cpu_pct
    @reasons = reasons
  end

  def missing?
    status == :missing
  end

  def to_h
    if missing?
      { query: query, status: 'missing', reasons: reasons }
    else
      {
        query: query,
        status: status.to_s,
        pid: sample.pid,
        state: sample.state,
        state_label: ProcMonitor::STATE_LABELS.fetch(sample.state, 'unknown'),
        rss_mb: (sample.rss_kb / 1024.0).round(2),
        cpu_pct: cpu_pct,
        cmdline: sample.cmdline,
        reasons: reasons
      }
    end
  end
end

# Given a prior + current sample and configured thresholds, builds a
# Report with WARN/CRIT classification. WARN triggers at 80% of a CRIT
# threshold; CRIT triggers at/above the threshold itself. Either
# threshold can independently push the status to a worse level - the
# overall status is the worse of the memory verdict and the CPU verdict.
def evaluate(query, prev, cur, mem_mb_limit, cpu_pct_limit)
  cpu_pct = ProcMonitor.cpu_percent(prev, cur)
  rss_mb = cur.rss_kb / 1024.0
  reasons = []
  worst = :ok

  bump = lambda do |level|
    order = { ok: 0, warn: 1, crit: 2 }
    worst = level if order[level] > order[worst]
  end

  if mem_mb_limit
    if rss_mb >= mem_mb_limit
      bump.call(:crit)
      reasons << format('RSS %.1fMB >= CRIT threshold %.1fMB', rss_mb, mem_mb_limit)
    elsif rss_mb >= mem_mb_limit * 0.8
      bump.call(:warn)
      reasons << format('RSS %.1fMB >= WARN threshold %.1fMB (80%% of CRIT)', rss_mb, mem_mb_limit * 0.8)
    end
  end

  if cpu_pct_limit
    if cpu_pct >= cpu_pct_limit
      bump.call(:crit)
      reasons << format('CPU %.1f%% >= CRIT threshold %.1f%%', cpu_pct, cpu_pct_limit)
    elsif cpu_pct >= cpu_pct_limit * 0.8
      bump.call(:warn)
      reasons << format('CPU %.1f%% >= WARN threshold %.1f%% (80%% of CRIT)', cpu_pct, cpu_pct_limit * 0.8)
    end
  end

  Report.new(query: query, status: worst, sample: cur, cpu_pct: cpu_pct, reasons: reasons)
end

# --------------------------------------------------------------------
# Text output
# --------------------------------------------------------------------

def status_tag(status)
  { ok: 'OK', warn: 'WARN', crit: 'CRIT', missing: 'MISSING' }.fetch(status)
end

def print_text_report(reports, at)
  puts "=== proc_monitor @ #{at} ==="
  reports.each do |r|
    if r.missing?
      puts format('[%-7s] %-20s pid=--    NOT FOUND (%s)', status_tag(r.status), r.query, r.reasons.join('; '))
      next
    end

    s = r.sample
    line = format(
      '[%-7s] %-20s pid=%-7d state=%-1s (%s) rss=%.1fMB cpu=%.1f%%',
      status_tag(r.status), r.query, s.pid, s.state,
      ProcMonitor::STATE_LABELS.fetch(s.state, 'unknown'), s.rss_kb / 1024.0, r.cpu_pct
    )
    puts line
    puts "           cmd: #{s.cmdline}"
    r.reasons.each { |reason| puts "           -> #{reason}" }
  end
end

def print_json_report(reports, at)
  puts JSON.generate(timestamp: at, results: reports.map(&:to_h))
end

# --------------------------------------------------------------------
# Main run loop
# --------------------------------------------------------------------

def worst_exit_code(reports)
  return ProcMonitor::EXIT_MISSING if reports.any?(&:missing?)
  return ProcMonitor::EXIT_CRIT if reports.any? { |r| r.status == :crit }
  return ProcMonitor::EXIT_WARN if reports.any? { |r| r.status == :warn }

  ProcMonitor::EXIT_OK
end

# Takes one sampling pass: for every target query, resolve to a pid (if
# not already known), sample it twice `interval` seconds apart to get a
# CPU delta, and build a Report. `known_pids` lets watch mode "stick" to
# the PID it already found for a name, so it can detect a PID CHANGE
# (i.e. the process died and something else restarted under the same
# name) instead of silently re-resolving every loop.
def run_pass(targets, interval, mem_mb, cpu_pct, known_pids)
  reports = []
  new_known = {}

  targets.each do |query|
    pid = known_pids[query]
    pid = nil if pid && !ProcMonitor.pid_alive?(pid)
    pid ||= ProcMonitor.resolve_pids(query).first

    if pid.nil?
      reports << Report.new(query: query, status: :missing, reasons: ['no matching process found'])
      next
    end

    begin
      prev = ProcMonitor.sample(pid, query)
      sleep interval
      cur = ProcMonitor.sample(pid, query)
      reports << evaluate(query, prev, cur, mem_mb, cpu_pct)
      new_known[query] = pid
    rescue ProcMonitor::ProcNotFound
      reports << Report.new(query: query, status: :missing, reasons: ['process exited during sampling'])
    end
  end

  [reports, new_known]
end

def main
  opts = ProcMonitorCLI.parse(ARGV)
  known_pids = {}
  last_pids = {}
  exit_code = ProcMonitor::EXIT_OK
  iteration = 0

  loop do
    reports, known_pids = run_pass(opts.targets, opts.interval, opts.mem_mb, opts.cpu_pct, known_pids)
    at = Time.now.utc.iso8601

    # Detect PID changes (process died and restarted under a new PID)
    # since the previous watch iteration and surface it as an extra note.
    reports.each do |r|
      next if r.missing?

      prior = last_pids[r.query]
      if prior && prior != r.sample.pid
        r.reasons << "pid changed #{prior} -> #{r.sample.pid} (process restarted)"
      end
      last_pids[r.query] = r.sample.pid
    end

    if opts.json
      print_json_report(reports, at)
    else
      print_text_report(reports, at)
    end

    exit_code = worst_exit_code(reports)
    iteration += 1

    break unless opts.watch
    break if opts.iterations && iteration >= opts.iterations

    sleep [opts.interval, 1.0].max
  end

  exit_code
end

exit main if __FILE__ == $PROGRAM_NAME
