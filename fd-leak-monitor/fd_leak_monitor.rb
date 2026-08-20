#!/usr/bin/env ruby
# frozen_string_literal: true
#
# fd_leak_monitor.rb — find processes leaking file descriptors on Linux, in
# pure Ruby stdlib by reading /proc directly. No gems, no lsof required.
#
# A slow file-descriptor leak is one of the nastiest production failures: a
# long-running daemon opens sockets or files and never closes them, its FD
# count creeps up for days, and then it hits the per-process limit and starts
# throwing "Too many open files" — usually at peak traffic. This script walks
# /proc, counts each process's open descriptors, compares them to that
# process's own RLIMIT_NOFILE soft limit, and flags the ones getting close:
#
#   CRIT  — using >= --crit-pct of its FD limit (default 90%)
#   WARN  — using >= --warn-pct of its FD limit (default 75%)
#   OK    — comfortable
#
# It also breaks each process's descriptors down by kind (sockets, regular
# files, pipes, anon inodes) so you can see *what* is leaking, and can watch a
# single PID over time with --watch to see the count actually climbing.
#
# Exit codes (cron/monitoring friendly):
#   0 = all OK, 1 = at least one WARN, 2 = at least one CRIT
#
# Usage:
#   ruby fd_leak_monitor.rb                      # audit every visible process
#   ruby fd_leak_monitor.rb --top 15 --json
#   ruby fd_leak_monitor.rb --warn-pct 60 --crit-pct 85
#   ruby fd_leak_monitor.rb --watch 1234 --interval 5   # trend one PID
#
# Linux only (needs /proc). Run as root to see every process; without it you
# only see your own, which the summary makes explicit.
#
# Pure stdlib: optparse, json. The /proc reader is injectable for testing.

require 'optparse'
require 'json'

module FdLeakMonitor
  module_function

  PROC = '/proc'

  # Enumerate PIDs from /proc (numeric directory names).
  def pids(proc_root = PROC)
    Dir.children(proc_root).select { |e| e.match?(/\A\d+\z/) }.map(&:to_i).sort
  rescue SystemCallError
    []
  end

  # Inspect one process. Returns a hash or nil if it vanished / is unreadable
  # (processes come and go while you scan — that's normal, not an error).
  def inspect_pid(pid, proc_root = PROC)
    base = File.join(proc_root, pid.to_s)
    fd_dir = File.join(base, 'fd')
    entries = Dir.children(fd_dir)
    kinds = Hash.new(0)
    entries.each do |fd|
      target = begin
        File.readlink(File.join(fd_dir, fd))
      rescue SystemCallError
        next
      end
      kinds[classify(target)] += 1
    end
    { pid: pid, comm: comm(base), count: entries.size,
      limit: nofile_limit(base), kinds: kinds }
  rescue Errno::ENOENT, Errno::ESRCH
    nil                # process exited mid-scan
  rescue Errno::EACCES
    { pid: pid, comm: comm(base), count: nil, limit: nil, kinds: {}, denied: true }
  end

  def classify(link_target)
    case link_target
    when /\Asocket:/       then 'socket'
    when /\Apipe:/         then 'pipe'
    when /\Aanon_inode:/   then 'anon'
    when %r{\A/}           then 'file'
    else 'other'
    end
  end

  def comm(base)
    File.read(File.join(base, 'comm')).strip
  rescue SystemCallError
    '?'
  end

  # Soft RLIMIT_NOFILE from /proc/<pid>/limits ("Max open files").
  def nofile_limit(base)
    line = File.read(File.join(base, 'limits')).lines.find { |l| l.start_with?('Max open files') }
    return nil unless line
    soft = line.split(/\s{2,}/)[1]
    soft == 'unlimited' ? nil : soft.to_i
  rescue SystemCallError
    nil
  end

  def classify_severity(count, limit, warn_pct, crit_pct)
    return 'OK' unless limit && count
    pct = count.to_f / limit * 100
    if    pct >= crit_pct then 'CRIT'
    elsif pct >= warn_pct then 'WARN'
    else 'OK'
    end
  end

  def audit(procs:, warn_pct:, crit_pct:)
    procs.compact.each do |p|
      next if p[:denied]
      p[:pct] = p[:limit] ? (p[:count].to_f / p[:limit] * 100).round(1) : nil
      p[:status] = classify_severity(p[:count], p[:limit], warn_pct, crit_pct)
    end
    procs.compact
  end

  def worst_exit(rows)
    return 2 if rows.any? { |r| r[:status] == 'CRIT' }
    return 1 if rows.any? { |r| r[:status] == 'WARN' }
    0
  end
end

if __FILE__ == $PROGRAM_NAME
  options = { top: 20, warn_pct: 75.0, crit_pct: 90.0, json: false, watch: nil, interval: 5 }
  OptionParser.new do |o|
    o.banner = 'Usage: ruby fd_leak_monitor.rb [options]'
    o.on('--top N', Integer, 'Show top N processes by FD usage (default 20)') { |v| options[:top] = v }
    o.on('--warn-pct N', Float, 'WARN at >= N% of FD limit (default 75)') { |v| options[:warn_pct] = v }
    o.on('--crit-pct N', Float, 'CRIT at >= N% of FD limit (default 90)') { |v| options[:crit_pct] = v }
    o.on('--watch PID', Integer, 'Watch one PID over time instead of a full scan') { |v| options[:watch] = v }
    o.on('--interval SECS', Integer, 'Watch interval (default 5)') { |v| options[:interval] = v }
    o.on('--json', 'Emit JSON') { options[:json] = true }
  end.parse!

  abort 'error: this tool needs /proc (Linux only)' unless File.directory?(FdLeakMonitor::PROC)

  if options[:watch]
    pid = options[:watch]
    puts "watching pid #{pid} every #{options[:interval]}s (Ctrl-C to stop)"
    prev = nil
    loop do
      info = FdLeakMonitor.inspect_pid(pid)
      break puts "pid #{pid} is gone" unless info
      delta = prev ? format('%+d', info[:count] - prev) : '  —'
      puts format('%s  pid %d (%s)  fds=%-6d limit=%-6s  Δ%s',
                  Time.now.strftime('%H:%M:%S'), pid, info[:comm],
                  info[:count], info[:limit] || 'inf', delta)
      prev = info[:count]
      sleep options[:interval]
    end
    exit 0
  end

  rows = FdLeakMonitor.audit(
    procs: FdLeakMonitor.pids.map { |pid| FdLeakMonitor.inspect_pid(pid) },
    warn_pct: options[:warn_pct], crit_pct: options[:crit_pct]
  )
  denied = FdLeakMonitor.pids.size - rows.size
  ranked = rows.select { |r| r[:count] }
               .sort_by { |r| [-(r[:pct] || 0), -r[:count]] }
               .first(options[:top])
  code = FdLeakMonitor.worst_exit(rows)

  if options[:json]
    puts JSON.pretty_generate(scanned: rows.size, exit_code: code, top: ranked)
  else
    puts "fd_leak_monitor — #{rows.size} processes scanned" \
         "#{denied.positive? ? " (#{denied} not readable — run as root for full coverage)" : ''}"
    puts
    puts format('  %-5s %-18s %6s %8s %6s  %s', 'STAT', 'COMMAND', 'PID', 'FDs', 'USE%', 'breakdown')
    ranked.each do |r|
      kinds = r[:kinds].sort_by { |_, n| -n }.map { |k, n| "#{k}:#{n}" }.join(' ')
      puts format('  %-5s %-18s %6d %8d %5s%%  %s',
                  r[:status], r[:comm][0, 18], r[:pid], r[:count],
                  r[:pct] ? r[:pct].to_s : '  ?', kinds)
    end
    puts
    puts "worst status: #{%w[OK WARN CRIT][code]}"
  end
  exit code
end
