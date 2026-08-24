#!/usr/bin/env ruby
# frozen_string_literal: true
#
# disk_usage_report.rb — disk usage reporting with growth tracking.
#
# Answers the three questions every on-call engineer asks when a
# "filesystem almost full" alert fires at 3am:
#   1. Which filesystems are actually in trouble?  (df-level view)
#   2. What inside them is eating the space?       (top-N dirs/files)
#   3. What GREW since the last time we looked?    (snapshot deltas)
#
# Stdlib only — no gems. Text and --json output, cron-friendly exit codes:
#   0 = everything under thresholds, 1 = WARN crossed, 2 = CRIT crossed.
#
# Usage:
#   ruby disk_usage_report.rb /var /home --top 10 --state /var/tmp/du_state.json
#   ruby disk_usage_report.rb /var --warn-pct 80 --crit-pct 92 --json

require 'find'
require 'json'
require 'optparse'
require 'time'

options = {
  top: 10,            # how many largest dirs/files to report
  warn_pct: 80,       # filesystem %use that triggers WARN
  crit_pct: 90,       # filesystem %use that triggers CRIT
  min_mb: 1,          # ignore files smaller than this in the top-N file list
  state: nil,         # JSON snapshot path for growth tracking
  json: false
}

OptionParser.new do |o|
  o.banner = 'Usage: disk_usage_report.rb PATH [PATH...] [options]'
  o.on('--top N', Integer, 'Top N dirs and files to show (default 10)') { |v| options[:top] = v }
  o.on('--warn-pct N', Integer, 'WARN when filesystem use%% >= N (default 80)') { |v| options[:warn_pct] = v }
  o.on('--crit-pct N', Integer, 'CRIT when filesystem use%% >= N (default 90)') { |v| options[:crit_pct] = v }
  o.on('--min-mb N', Integer, 'Ignore files under N MB in file list (default 1)') { |v| options[:min_mb] = v }
  o.on('--state FILE', 'Snapshot file for growth deltas between runs') { |v| options[:state] = v }
  o.on('--json', 'Emit JSON instead of text') { options[:json] = true }
end.parse!

paths = ARGV.empty? ? ['.'] : ARGV
paths.each do |p|
  abort "disk_usage_report: no such directory: #{p}" unless File.directory?(p)
end

# ---------------------------------------------------------------------------
# 1. Filesystem-level view. `df -Pk` is POSIX and stable enough to parse:
#    Filesystem 1024-blocks Used Available Capacity Mounted-on
# ---------------------------------------------------------------------------
def filesystems(paths)
  out = `df -Pk #{paths.map { |p| "'#{p}'" }.join(' ')} 2>/dev/null`
  return [] unless $?.success?

  out.lines.drop(1).map do |line|
    cols = line.split
    next if cols.size < 6
    {
      'filesystem' => cols[0],
      'size_kb'    => cols[1].to_i,
      'used_kb'    => cols[2].to_i,
      'avail_kb'   => cols[3].to_i,
      'use_pct'    => cols[4].delete('%').to_i,
      'mount'      => cols[5..].join(' ')
    }
  end.compact.uniq { |fs| fs['mount'] }
end

# ---------------------------------------------------------------------------
# 2. Walk each path once. We accumulate:
#    - total bytes per immediate child directory (the "who is eating it" view)
#    - the largest individual files
#    Find.prune keeps us out of other mounted filesystems' /proc-style traps.
# ---------------------------------------------------------------------------
def scan(root, min_bytes)
  dir_bytes  = Hash.new(0)
  big_files  = []           # [[bytes, path], ...] kept small via periodic trim
  root_dev   = File.stat(root).dev
  errors     = 0

  Find.find(root) do |path|
    begin
      st = File.lstat(path)
      # Do not cross filesystem boundaries — a bind-mounted /var/lib/docker
      # would otherwise get double-counted against the wrong mount.
      if st.directory? && st.dev != root_dev
        Find.prune
        next
      end
      next unless st.file?

      # Attribute the file to the top-level child of root it lives under,
      # e.g. /var/log/syslog counts toward "/var/log".
      rel = path.sub(%r{\A#{Regexp.escape(root)}/?}, '')
      child = rel.include?('/') ? File.join(root, rel.split('/').first) : root
      dir_bytes[child] += st.size

      if st.size >= min_bytes
        big_files << [st.size, path]
        # trim occasionally so memory stays flat on huge trees
        big_files = big_files.max_by(200) { |b, _| b } if big_files.size > 4000
      end
    rescue Errno::EACCES, Errno::ENOENT, Errno::ELOOP
      errors += 1 # unreadable/racing files are counted, not fatal
    end
  end

  { dirs: dir_bytes, files: big_files, errors: errors }
end

# ---------------------------------------------------------------------------
# 3. Growth tracking. The state file is just {"dir" => bytes} from last run;
#    the delta between runs is usually more interesting than the absolute
#    number — a 2 GB log dir is fine, a log dir that grew 2 GB overnight isn't.
# ---------------------------------------------------------------------------
def load_state(path)
  return {} unless path && File.exist?(path)
  JSON.parse(File.read(path))
rescue JSON::ParserError
  {}
end

def human(bytes)
  units = %w[B KB MB GB TB]
  u = 0
  b = bytes.to_f
  while b >= 1024 && u < units.size - 1
    b /= 1024
    u += 1
  end
  format(b >= 10 || u.zero? ? '%.0f %s' : '%.1f %s', b, units[u])
end

min_bytes = options[:min_mb] * 1024 * 1024
fs_view   = filesystems(paths)
prev      = load_state(options[:state])

all_dirs  = {}
all_files = []
errors    = 0
paths.each do |root|
  r = scan(root, min_bytes)
  all_dirs.merge!(r[:dirs]) { |_k, a, b| a + b }
  all_files.concat(r[:files])
  errors += r[:errors]
end

top_dirs  = all_dirs.sort_by { |_d, b| -b }.first(options[:top])
top_files = all_files.max_by(options[:top]) { |b, _| b }

growth = top_dirs.map do |dir, bytes|
  delta = prev.key?(dir) ? bytes - prev[dir] : nil
  [dir, bytes, delta]
end

# Persist the new snapshot for next run (whole dir map, not just top-N,
# so a directory that newly enters the top-N still has a real delta).
if options[:state]
  File.write(options[:state], JSON.pretty_generate(all_dirs))
end

# ---------------------------------------------------------------------------
# 4. Verdict + output
# ---------------------------------------------------------------------------
worst = fs_view.map { |f| f['use_pct'] }.max || 0
status = if worst >= options[:crit_pct] then 'CRIT'
         elsif worst >= options[:warn_pct] then 'WARN'
         else 'OK'
         end

if options[:json]
  puts JSON.pretty_generate(
    'generated_at' => Time.now.iso8601,
    'status'       => status,
    'filesystems'  => fs_view,
    'top_dirs'     => growth.map { |d, b, delta| { 'dir' => d, 'bytes' => b, 'delta_bytes' => delta } },
    'top_files'    => top_files.map { |b, p| { 'file' => p, 'bytes' => b } },
    'scan_errors'  => errors
  )
else
  puts "disk usage report — #{Time.now.strftime('%Y-%m-%d %H:%M')}  [#{status}]"
  puts
  puts 'FILESYSTEMS'
  fs_view.each do |f|
    flag = f['use_pct'] >= options[:crit_pct] ? ' <-- CRIT' : (f['use_pct'] >= options[:warn_pct] ? ' <-- WARN' : '')
    puts format('  %-24s %8s used / %8s  (%3d%%)  %s%s',
                f['mount'], human(f['used_kb'] * 1024), human(f['size_kb'] * 1024), f['use_pct'], f['filesystem'], flag)
  end
  puts
  puts "TOP #{options[:top]} DIRECTORIES"
  growth.each do |dir, bytes, delta|
    d = delta.nil? ? '   (new)' : format('%+9s', human(delta.abs) .prepend(delta.negative? ? '-' : '+'))
    puts format('  %10s  %s  %s', human(bytes), d, dir)
  end
  puts
  puts "TOP #{options[:top]} FILES (>= #{options[:min_mb]} MB)"
  top_files.each { |b, p| puts format('  %10s  %s', human(b), p) }
  puts
  puts "unreadable entries skipped: #{errors}" if errors.positive?
end

exit(status == 'CRIT' ? 2 : status == 'WARN' ? 1 : 0)
