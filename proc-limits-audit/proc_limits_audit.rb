#!/usr/bin/env ruby
# frozen_string_literal: true
# proc_limits_audit.rb - find processes close to their "Max open files" soft limit.
# Usage: ruby proc_limits_audit.rb [--threshold 80] [--proc /proc] [--json]
require 'optparse'
require 'json'

opts = { threshold: 80.0, proc: '/proc', json: false }
OptionParser.new do |o|
  o.banner = 'Usage: proc_limits_audit.rb [options]'
  o.on('--threshold PCT', Float, 'flag at or above this % of soft limit (default 80)') { |v| opts[:threshold] = v }
  o.on('--proc DIR', 'procfs root (default /proc; useful for tests)') { |v| opts[:proc] = v }
  o.on('--json', 'emit JSON instead of a table') { opts[:json] = true }
end.parse!

# Parse the "Max open files" line of /proc/PID/limits -> [soft, hard] (nil = unlimited)
def open_files_limit(path)
  File.foreach(path) do |line|
    next unless line.start_with?('Max open files')
    soft, hard = line.split[3, 2].map { |v| v == 'unlimited' ? nil : v.to_i }
    return [soft, hard]
  end
  nil
end

rows = []
Dir.children(opts[:proc]).grep(/\A\d+\z/).each do |pid|
  dir = File.join(opts[:proc], pid)
  begin
    soft, hard = open_files_limit(File.join(dir, 'limits'))
    next if soft.nil? # unlimited or missing: nothing to compare against
    used = Dir.children(File.join(dir, 'fd')).size
    name = File.read(File.join(dir, 'comm')).strip
    rows << { pid: pid.to_i, name: name, used: used, soft: soft, hard: hard,
              pct: (used * 100.0 / soft).round(1) }
  rescue Errno::ENOENT, Errno::ESRCH, Errno::EACCES
    next # process exited mid-scan, or not ours to read (run as root for full view)
  end
end

rows.sort_by! { |r| -r[:pct] }
flagged = rows.select { |r| r[:pct] >= opts[:threshold] }

if opts[:json]
  puts JSON.pretty_generate(scanned: rows.size, flagged: flagged)
else
  puts format('Scanned %d processes, %d at or above %.0f%% of soft NOFILE limit', rows.size, flagged.size, opts[:threshold])
  puts format('%-7s %-18s %7s %7s %6s', 'PID', 'NAME', 'USED', 'SOFT', 'PCT')
  (flagged.empty? ? rows.first(5) : flagged).each do |r|
    puts format('%-7d %-18s %7d %7d %5.1f%%', r[:pid], r[:name][0, 18], r[:used], r[:soft], r[:pct])
  end
end
exit(flagged.empty? ? 0 : 1) # non-zero exit lets cron/CI alert
