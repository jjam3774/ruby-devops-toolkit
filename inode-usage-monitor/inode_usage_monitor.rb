#!/usr/bin/env ruby
# frozen_string_literal: true
#
# inode_usage_monitor.rb -- inode-exhaustion monitor for Linux.
#
# A filesystem can hit "No space left on device" while df -h shows plenty of
# free bytes -- because it has run out of *inodes*, not space. That happens on
# boxes that create millions of tiny files (mail queues, session dirs, cache
# fan-out). This script reports inode usage per filesystem, alerts on any that
# cross a threshold, and can hunt the directories holding the most files.
#
#   ruby inode_usage_monitor.rb                     # per-filesystem inode table
#   ruby inode_usage_monitor.rb --warn 80 --crit 95 # custom thresholds (percent)
#   ruby inode_usage_monitor.rb --hunt /var         # find inode-hog dirs under /var
#   ruby inode_usage_monitor.rb --json              # machine-readable
#
# Stdlib only: open3, find, json, optparse. No gems. Exit codes: 0 ok,
# 1 warning, 2 critical -- drops straight into cron / Nagios.

require 'open3'
require 'find'
require 'json'
require 'optparse'

options = { warn: 80, crit: 90, hunt: nil, top: 12, json: false }
OptionParser.new do |o|
  o.banner = 'Usage: ruby inode_usage_monitor.rb [options]'
  o.on('--warn PCT', Integer, 'warn threshold %% inodes used (default 80)') { |v| options[:warn] = v }
  o.on('--crit PCT', Integer, 'crit threshold %% inodes used (default 90)') { |v| options[:crit] = v }
  o.on('--hunt DIR', 'find the directories with the most files under DIR') { |v| options[:hunt] = v }
  o.on('--top N', Integer, 'rows for --hunt (default 12)') { |v| options[:top] = v }
  o.on('--json', 'JSON output') { options[:json] = true }
end.parse!

# --- read per-filesystem inode stats from `df -iP` -------------------------
# -P = POSIX output (one line per fs, stable columns); -i = inodes not blocks.
# Columns: Filesystem Inodes IUsed IFree IUse% Mounted-on

def read_inode_table
  out, err, st = Open3.capture3('df', '-iP')
  raise "df failed: #{err}" unless st.success?
  rows = []
  out.each_line.drop(1).each do |line|
    f = line.split
    next if f.size < 6
    inodes, iused, ifree = f[1].to_i, f[2].to_i, f[3].to_i
    next if inodes.zero?                     # pseudo-fs (tmpfs, proc) report 0
    pct = (iused * 100.0 / inodes).round(1)
    rows << { 'filesystem' => f[0], 'inodes' => inodes, 'iused' => iused,
              'ifree' => ifree, 'pct' => pct, 'mount' => f[5] }
  end
  rows.sort_by { |r| -r['pct'] }
end

# --- optional: hunt the directories that hold the most files ---------------
# One Find pass; every file/dir bumps the counter of its PARENT directory.

def hunt_dirs(root, top)
  counts = Hash.new(0)
  Find.find(root) do |path|
    counts[File.dirname(path)] += 1
  rescue Errno::EACCES, Errno::ENOENT
    next
  end
  counts.sort_by { |_, c| -c }.first(top)
end

rows = read_inode_table
crit = rows.select { |r| r['pct'] >= options[:crit] }
warn = rows.select { |r| r['pct'] >= options[:warn] && r['pct'] < options[:crit] }
hunt = options[:hunt] ? hunt_dirs(File.expand_path(options[:hunt]), options[:top]) : nil

if options[:json]
  puts JSON.pretty_generate('filesystems' => rows,
                            'warn_threshold' => options[:warn],
                            'crit_threshold' => options[:crit],
                            'alerts' => (crit + warn).map { |r| r['mount'] },
                            'hunt' => hunt&.map { |d, c| { 'dir' => d, 'files' => c } })
else
  puts format('%-6s %-22s %12s %12s %7s  %s', 'STATE', 'FILESYSTEM', 'IUSED', 'IFREE', 'IUSE%', 'MOUNT')
  rows.each do |r|
    state = r['pct'] >= options[:crit] ? 'CRIT' : r['pct'] >= options[:warn] ? 'WARN' : 'ok'
    puts format('%-6s %-22s %12d %12d %6.1f%%  %s', state, r['filesystem'], r['iused'], r['ifree'], r['pct'], r['mount'])
  end
  if hunt
    puts
    puts format('%12s  %s', 'FILES', "INODE-HOG DIRECTORIES under #{options[:hunt]}")
    hunt.each { |d, c| puts format('%12d  %s', c, d) }
  end
  puts
  puts "#{crit.size} critical, #{warn.size} warning"
end

exit(crit.any? ? 2 : warn.any? ? 1 : 0)
