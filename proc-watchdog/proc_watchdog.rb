#!/usr/bin/env ruby
# frozen_string_literal: true
#
# proc_watchdog.rb -- Linux process watchdog built directly on /proc.
#
# Give it a list of process name patterns you expect to be running (sshd,
# cron, nginx, your app worker...). It walks /proc, finds matching processes,
# samples CPU over a short interval, reads RSS, and reports:
#
#   RUNNING   -> at least one match, same PID as last run
#   RESTARTED -> running now, but the PID changed since the last run (WARN)
#   MISSING   -> no matching process found (CRIT)
#
# Restart detection works via a small JSON state file that remembers the PIDs
# seen on the previous run -- so a crash-loop that is "up" every time you look
# still gets caught, because the PID keeps changing.
#
# Usage:
#   ruby proc_watchdog.rb sshd cron
#   ruby proc_watchdog.rb --state /var/tmp/watchdog.json --interval 1 --json nginx puma
#
# Exit codes: 0 = all RUNNING, 1 = something RESTARTED, 2 = something MISSING.
# Only the Ruby standard library is used: json, optparse. No gems.

require "json"
require "optparse"
require "time"

options = {
  state:    "/tmp/proc_watchdog_state.json",
  interval: 1.0,   # seconds between the two CPU samples
  json:     false
}

OptionParser.new do |o|
  o.banner = "Usage: ruby proc_watchdog.rb [options] pattern ..."
  o.on("--state PATH", "State file for restart detection (default /tmp/proc_watchdog_state.json)") { |v| options[:state] = v }
  o.on("--interval SEC", Float, "CPU sampling interval in seconds (default 1.0)") { |v| options[:interval] = v }
  o.on("--json", "Emit JSON instead of the text table") { options[:json] = true }
end.parse!

patterns = ARGV
abort("No patterns given. Try: ruby proc_watchdog.rb sshd cron") if patterns.empty?

CLK_TCK   = 100                     # USER_HZ; getconf CLK_TCK on virtually every Linux
PAGE_SIZE = 4096                    # bytes; getconf PAGESIZE if you need to be exact

# ---------------------------------------------------------------------------
# /proc plumbing
# ---------------------------------------------------------------------------

# Every numeric directory under /proc is one process.
def pids
  Dir.children("/proc").select { |d| d.match?(/\A\d+\z/) }.map(&:to_i)
end

# comm  = the short executable name (what `pgrep` matches by default).
# cmdline = full argv, NUL-separated -- useful for matching "puma: worker 2".
def read_proc(pid)
  comm    = File.read("/proc/#{pid}/comm").strip
  cmdline = File.read("/proc/#{pid}/cmdline").split("\0").join(" ")
  # /proc/<pid>/stat field 14 utime + 15 stime (1-indexed), 22 starttime,
  # 24 rss (in pages). comm can contain spaces/parens, so split AFTER the
  # closing paren rather than naively on whitespace.
  stat  = File.read("/proc/#{pid}/stat")
  after = stat[(stat.rindex(")") + 2)..].split
  {
    pid:        pid,
    comm:       comm,
    cmdline:    cmdline.empty? ? "[#{comm}]" : cmdline,
    cpu_ticks:  after[11].to_i + after[12].to_i,   # utime + stime
    start_ticks: after[19].to_i,                   # starttime, ticks since boot
    rss_bytes:  after[21].to_i * PAGE_SIZE
  }
rescue Errno::ENOENT, Errno::ESRCH, Errno::EACCES
  nil   # the process exited (or is inaccessible) mid-scan; skip it
end

def uptime_seconds
  File.read("/proc/uptime").split[0].to_f
end

# A pattern matches on the process NAME, not the full command line: either
# the kernel's comm field or the basename of argv[0]. Matching the raw
# cmdline sounds convenient but is a classic false-positive trap -- e.g.
# `bash -c "sleep 300"` would match a "sleep" watch via its argv even though
# bash is not sleep. (The first version of this script did exactly that.)
def match?(info, pat)
  argv0 = File.basename(info[:cmdline].split(" ").first.to_s)
  info[:comm].include?(pat) || argv0.include?(pat)
end

def snapshot(patterns)
  found = Hash.new { |h, k| h[k] = [] }
  pids.each do |pid|
    info = read_proc(pid)
    next unless info
    next if pid == Process.pid                 # never report the watchdog itself
    patterns.each do |pat|
      found[pat] << info if match?(info, pat)  # a proc may match several patterns
    end
  end
  found
end

# ---------------------------------------------------------------------------
# Two samples, options[:interval] apart -> CPU% per process.
# ---------------------------------------------------------------------------
first  = snapshot(patterns)
sleep options[:interval]
second = snapshot(patterns)

# Previous run's PIDs, for restart detection.
prev_state = File.exist?(options[:state]) ? JSON.parse(File.read(options[:state])) : {}

now_uptime = uptime_seconds
rows = []
new_state = {}

patterns.each do |pat|
  procs = second[pat]
  if procs.empty?
    rows << { pattern: pat, status: "MISSING", detail: "no matching process in /proc" }
    new_state[pat] = []
    next
  end

  pids_now  = procs.map { |p| p[:pid] }.sort
  pids_prev = (prev_state[pat] || []).sort
  restarted = !pids_prev.empty? && pids_prev != pids_now
  new_state[pat] = pids_now

  procs.each do |p|
    prev = first[pat].find { |q| q[:pid] == p[:pid] }
    cpu_pct = if prev
                dt = options[:interval]
                100.0 * (p[:cpu_ticks] - prev[:cpu_ticks]) / CLK_TCK / dt
              else
                0.0
              end
    age = now_uptime - (p[:start_ticks].to_f / CLK_TCK)
    rows << {
      pattern:  pat,
      status:   restarted ? "RESTARTED" : "RUNNING",
      pid:      p[:pid],
      comm:     p[:comm],
      cpu_pct:  cpu_pct.round(1),
      rss_mb:   (p[:rss_bytes] / 1024.0 / 1024.0).round(1),
      uptime_s: age.round,
      detail:   restarted ? "pids changed #{pids_prev.inspect} -> #{pids_now.inspect}" : nil
    }.compact
  end
end

File.write(options[:state], JSON.pretty_generate(new_state))

# ---------------------------------------------------------------------------
# Output + exit code
# ---------------------------------------------------------------------------
statuses  = rows.map { |r| r[:status] }
exit_code = statuses.include?("MISSING") ? 2 : (statuses.include?("RESTARTED") ? 1 : 0)

if options[:json]
  puts JSON.pretty_generate(
    generated_at: Time.now.utc.iso8601,
    summary: { running:   statuses.count("RUNNING"),
               restarted: statuses.count("RESTARTED"),
               missing:   statuses.count("MISSING") },
    processes: rows
  )
else
  puts format("%-12s %-10s %7s %-16s %6s %8s %9s  %s",
              "PATTERN", "STATUS", "PID", "COMM", "CPU%", "RSS(MB)", "UPTIME(S)", "DETAIL")
  puts "-" * 92
  rows.each do |r|
    puts format("%-12s %-10s %7s %-16s %6s %8s %9s  %s",
                r[:pattern], r[:status], r[:pid] || "-", r[:comm] || "-",
                r[:cpu_pct] || "-", r[:rss_mb] || "-", r[:uptime_s] || "-", r[:detail])
  end
  puts "-" * 92
  puts "running=#{statuses.count('RUNNING')} restarted=#{statuses.count('RESTARTED')} missing=#{statuses.count('MISSING')}"
end

exit exit_code
