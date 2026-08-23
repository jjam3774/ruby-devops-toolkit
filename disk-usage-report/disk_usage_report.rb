#!/usr/bin/env ruby
# frozen_string_literal: true
#
# disk_usage_report.rb -- disk usage reporting and growth tracking for Linux.
#
# Walks one or more directory trees, reports the largest directories and
# files, and (optionally) compares against a saved snapshot so you can see
# WHICH paths grew since the last run -- the question `df` never answers.
#
#   ruby disk_usage_report.rb /var /home                # one-off report
#   ruby disk_usage_report.rb /var --top 15             # more rows
#   ruby disk_usage_report.rb /var --snapshot /tmp/var.json   # save baseline
#   ruby disk_usage_report.rb /var --snapshot /tmp/var.json   # next run: growth report
#   ruby disk_usage_report.rb /var --json               # machine-readable
#   ruby disk_usage_report.rb /var --alert-gb 5         # exit 2 if any dir > 5 GiB
#
# Stdlib only: find, json, optparse. No gems.

require 'find'
require 'json'
require 'optparse'

options = {
  top: 10,          # how many rows to show per table
  json: false,      # emit JSON instead of text
  snapshot: nil,    # path to snapshot file (read old + write new)
  alert_gb: nil,    # threshold: exit 2 if any first-level dir exceeds this
  min_mb: 1         # ignore files smaller than this in the big-files table
}

OptionParser.new do |o|
  o.banner = 'Usage: ruby disk_usage_report.rb DIR [DIR...] [options]'
  o.on('--top N', Integer, 'Rows per table (default 10)') { |v| options[:top] = v }
  o.on('--json', 'JSON output') { options[:json] = true }
  o.on('--snapshot FILE', 'Save/compare a usage snapshot for growth tracking') { |v| options[:snapshot] = v }
  o.on('--alert-gb N', Float, 'Exit 2 if any first-level directory exceeds N GiB') { |v| options[:alert_gb] = v }
  o.on('--min-mb N', Float, 'Minimum file size for the big-files table (default 1)') { |v| options[:min_mb] = v }
end.parse!

roots = ARGV
abort('error: give me at least one directory to scan') if roots.empty?
roots.each { |r| abort("error: #{r} is not a directory") unless File.directory?(r) }

# --- helpers ---------------------------------------------------------------

def human(bytes)
  units = %w[B KiB MiB GiB TiB]
  size = bytes.to_f
  i = 0
  while size >= 1024 && i < units.size - 1
    size /= 1024
    i += 1
  end
  format(i.zero? ? '%d %s' : '%.1f %s', size, units[i])
end

# --- scan ------------------------------------------------------------------
# One pass per root: accumulate per-directory totals (each file's size is
# charged to every ancestor directory up to the root, giving `du`-style
# cumulative totals) and remember the biggest individual files.

dir_totals = Hash.new(0)      # "/var/log" => bytes (cumulative)
big_files  = []               # [ [bytes, path], ... ]
file_count = 0
errors     = 0
min_bytes  = (options[:min_mb] * 1024 * 1024).to_i

roots.each do |root|
  root = File.expand_path(root)
  Find.find(root) do |path|
    stat = File.lstat(path)          # lstat: don't follow symlinks (no loops)
    next unless stat.file?
    file_count += 1
    size = stat.size
    big_files << [size, path] if size >= min_bytes
    # charge this file's size to every ancestor dir up to (and incl.) root
    dir = File.dirname(path)
    while dir.start_with?(root)
      dir_totals[dir] += size
      break if dir == root
      dir = File.dirname(dir)
    end
  rescue Errno::EACCES, Errno::ENOENT, Errno::ELOOP
    errors += 1                      # unreadable/vanished paths: count, move on
  end
end

big_files.sort_by! { |s, _| -s }
big_files = big_files.first(options[:top])
top_dirs = dir_totals.sort_by { |_, s| -s }.first(options[:top])

# --- growth tracking -------------------------------------------------------
# The snapshot is just the dir_totals hash dumped to JSON. On the next run we
# diff current totals against it and report the biggest movers.

growth = nil
if options[:snapshot]
  if File.exist?(options[:snapshot])
    old = JSON.parse(File.read(options[:snapshot]))
    growth = dir_totals.map { |dir, size| [dir, size - old.fetch(dir, 0)] }
                       .reject { |_, delta| delta.zero? }
                       .sort_by { |_, delta| -delta }
                       .first(options[:top])
  end
  File.write(options[:snapshot], JSON.generate(dir_totals))
end

# --- alerts ----------------------------------------------------------------
# Check the first-level children of each root against --alert-gb.

alerts = []
if options[:alert_gb]
  limit = (options[:alert_gb] * 1024**3).to_i
  roots.each do |root|
    root = File.expand_path(root)
    dir_totals.each do |dir, size|
      next unless File.dirname(dir) == root && size > limit
      alerts << { 'dir' => dir, 'bytes' => size }
    end
  end
end

# --- output ----------------------------------------------------------------

if options[:json]
  puts JSON.pretty_generate(
    'scanned_roots' => roots,
    'files_seen'    => file_count,
    'skipped_paths' => errors,
    'top_dirs'      => top_dirs.map  { |d, s| { 'dir' => d, 'bytes' => s } },
    'top_files'     => big_files.map { |s, f| { 'file' => f, 'bytes' => s } },
    'growth'        => growth&.map   { |d, delta| { 'dir' => d, 'delta_bytes' => delta } },
    'alerts'        => alerts
  )
else
  puts "disk usage report -- #{roots.join(', ')}"
  puts "files scanned: #{file_count}  (#{errors} unreadable paths skipped)"
  puts
  puts format('%-12s %s', 'SIZE', 'LARGEST DIRECTORIES (cumulative)')
  top_dirs.each { |d, s| puts format('%-12s %s', human(s), d) }
  puts
  puts format('%-12s %s', 'SIZE', "LARGEST FILES (>= #{options[:min_mb]} MB)")
  big_files.each { |s, f| puts format('%-12s %s', human(s), f) }
  if growth
    puts
    puts format('%-12s %s', 'GROWTH', 'BIGGEST MOVERS SINCE LAST SNAPSHOT')
    growth.each { |d, delta| puts format('%-12s %s', (delta.positive? ? '+' : '') + human(delta.abs), d) }
  elsif options[:snapshot]
    puts
    puts "snapshot saved to #{options[:snapshot]} -- run again to see growth"
  end
  alerts.each { |a| puts "\nALERT: #{a['dir']} is #{human(a['bytes'])} (over #{options[:alert_gb]} GiB limit)" }
end

exit(alerts.empty? ? 0 : 2)   # non-zero on alert => drops into cron/Nagios cleanly
