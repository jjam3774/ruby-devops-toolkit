#!/usr/bin/env ruby
# frozen_string_literal: true
#
# proc_watchdog.rb -- a /proc-based process watchdog for Linux.
#
# Watches one or more process patterns, reports PID / CPU% / RSS / uptime for
# every match, flags processes that exceed a memory ceiling, and (optionally)
# runs a restart command when a watched pattern has no live process at all.
#
# Uses ONLY the Ruby standard library. No gems, no agents, no daemons --
# designed to run from cron or a systemd timer and exit with a meaningful code:
#
#   0  every watched pattern healthy
#   1  at least one WARN  (memory over soft ceiling)
#   2  at least one CRIT  (pattern missing entirely, or restart attempted)
#
# Usage:
#   ruby proc_watchdog.rb sshd cron
#   ruby proc_watchdog.rb --max-rss-mb 512 --json nginx postgres
#   ruby proc_watchdog.rb --restart 'systemctl restart myapp' myapp
#
require 'optparse'
require 'json'
require 'etc'
require 'time'

options = {
  max_rss_mb: nil,     # soft memory ceiling per process (WARN when exceeded)
  restart: nil,        # command to run when a pattern has zero live matches
  interval: 1.0,       # CPU sampling window in seconds
  json: false
}

parser = OptionParser.new do |o|
  o.banner = 'Usage: proc_watchdog.rb [options] PATTERN [PATTERN...]'
  o.on('--max-rss-mb MB', Integer, 'WARN when a matched process RSS exceeds MB') { |v| options[:max_rss_mb] = v }
  o.on('--restart CMD', 'Run CMD when a pattern has no live process (CRIT)')    { |v| options[:restart] = v }
  o.on('--interval SECS', Float, 'CPU sampling window (default 1.0)')           { |v| options[:interval] = v }
  o.on('--json', 'Emit JSON instead of text')                                   { options[:json] = true }
end
parser.parse!(ARGV)
patterns = ARGV
abort(parser.to_s) if patterns.empty?

# ---------------------------------------------------------------------------
# /proc plumbing
# ---------------------------------------------------------------------------

CLK_TCK   = Etc.sysconf(Etc::SC_CLK_TCK)        # jiffies per second (usually 100)
PAGE_SIZE = Etc.sysconf(Etc::SC_PAGESIZE)       # bytes per memory page

# Seconds the kernel has been up -- needed to turn a process start time
# (measured in jiffies since boot) into a wall-clock age.
def uptime_seconds
  File.read('/proc/uptime').split.first.to_f
end

# Parse /proc/<pid>/stat. Field 2 (comm) can contain spaces and parentheses --
# "(tmux: server)" is a classic -- so split on the LAST ')' rather than
# splitting the whole line on whitespace.
def read_stat(pid)
  raw   = File.read("/proc/#{pid}/stat")
  lparen = raw.index('(')
  rparen = raw.rindex(')')
  comm   = raw[(lparen + 1)...rparen]
  rest   = raw[(rparen + 2)..].split
  {
    comm: comm,
    utime: rest[11].to_i,        # user-mode jiffies
    stime: rest[12].to_i,        # kernel-mode jiffies
    starttime: rest[19].to_i,    # jiffies after boot when process started
    rss_pages: rest[21].to_i     # resident set size in pages
  }
rescue Errno::ENOENT, Errno::ESRCH
  nil # process exited between listing and reading -- normal, skip it
end

# Full command line, NUL-separated in /proc; empty for kernel threads.
def read_cmdline(pid)
  File.read("/proc/#{pid}/cmdline").tr("\0", ' ').strip
rescue Errno::ENOENT, Errno::EACCES
  ''
end

def list_pids
  Dir.children('/proc').select { |e| e.match?(/\A\d+\z/) }.map(&:to_i)
end

# A pattern matches on comm (the 15-char kernel name) or anywhere in cmdline.
def matches?(pattern, stat, cmdline)
  stat[:comm].include?(pattern) || cmdline.include?(pattern)
end

# ---------------------------------------------------------------------------
# Sample twice to compute CPU%: delta jiffies / delta wall time.
# ---------------------------------------------------------------------------

def snapshot(patterns)
  found = {}
  me = Process.pid
  list_pids.each do |pid|
    next if pid == me # never match ourselves (our argv contains the patterns)
    stat = read_stat(pid)
    next unless stat
    cmdline = read_cmdline(pid)
    next if cmdline.empty? && stat[:comm].empty?
    patterns.each do |pat|
      next unless matches?(pat, stat, cmdline)
      (found[pat] ||= {})[pid] = { stat: stat, cmdline: cmdline }
    end
  end
  found
end

first  = snapshot(patterns)
sleep options[:interval]
second = snapshot(patterns)
up     = uptime_seconds

results  = []
exit_code = 0

patterns.each do |pat|
  procs = second[pat] || {}
  if procs.empty?
    entry = { pattern: pat, status: 'CRIT', reason: 'no live process matches pattern', processes: [] }
    if options[:restart]
      ok = system(options[:restart])
      entry[:restart] = { command: options[:restart], success: !!ok }
      entry[:reason] += ok ? ' -- restart command succeeded' : ' -- restart command FAILED'
    end
    results << entry
    exit_code = 2
    next
  end

  plist = procs.map do |pid, info|
    stat = info[:stat]
    prev = first.dig(pat, pid, :stat)
    cpu_pct =
      if prev
        delta_jiffies = (stat[:utime] + stat[:stime]) - (prev[:utime] + prev[:stime])
        (delta_jiffies.to_f / CLK_TCK / options[:interval] * 100).round(1)
      else
        0.0 # brand-new process; no baseline sample
      end
    rss_mb = (stat[:rss_pages] * PAGE_SIZE / 1024.0 / 1024.0).round(1)
    age_s  = (up - stat[:starttime].to_f / CLK_TCK).round
    { pid: pid, comm: stat[:comm], cpu_pct: cpu_pct, rss_mb: rss_mb,
      uptime_s: age_s, cmdline: info[:cmdline][0, 120] }
  end

  over = options[:max_rss_mb] ? plist.select { |p| p[:rss_mb] > options[:max_rss_mb] } : []
  status = over.empty? ? 'OK' : 'WARN'
  reason = over.empty? ? "#{plist.size} live" :
           "#{over.size} process(es) over #{options[:max_rss_mb]} MB RSS ceiling"
  results << { pattern: pat, status: status, reason: reason, processes: plist }
  exit_code = [exit_code, 1].max if status == 'WARN'
end

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

if options[:json]
  puts JSON.pretty_generate(generated_at: Time.now.utc.iso8601, results: results)
else
  results.each do |r|
    badge = { 'OK' => '[ OK ]', 'WARN' => '[WARN]', 'CRIT' => '[CRIT]' }[r[:status]]
    puts "#{badge} #{r[:pattern]} -- #{r[:reason]}"
    r[:processes].each do |p|
      puts format('        pid %-7d %-15s cpu %5.1f%%  rss %8.1f MB  up %6ds  %s',
                  p[:pid], p[:comm], p[:cpu_pct], p[:rss_mb], p[:uptime_s], p[:cmdline])
    end
  end
end

exit exit_code
