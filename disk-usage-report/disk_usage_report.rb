#!/usr/bin/env ruby
# frozen_string_literal: true
#
# disk_usage_report.rb — disk usage reporting with snapshot diffing.
#
# Walks one or more directory trees, reports the largest subdirectories and
# files, checks filesystem fullness against warn/crit thresholds, and —
# the part `du` won't do for you — persists a JSON snapshot each run so the
# NEXT run can tell you what actually GREW since last time. Finding out that
# /var/log is 40 GB is useful once; finding out it grew 6 GB overnight is
# useful every day.
#
# Usage:
#   ruby disk_usage_report.rb [options] DIR [DIR ...]
#
#   -n, --top N            show top N entries per section (default 10)
#   -d, --depth N          aggregate directory sizes at depth N below each
#                          root (default 1: immediate children)
#   -s, --snapshot FILE    read previous snapshot from FILE (if it exists),
#                          diff against it, then overwrite it with this run
#   -w, --warn PCT         WARN when a filesystem is >= PCT% full (default 80)
#   -c, --crit PCT         CRIT when a filesystem is >= PCT% full (default 90)
#   -g, --growth-warn MB   WARN when a directory grew >= MB since snapshot
#                          (default 512)
#   -j, --json             emit JSON instead of text
#   -x, --one-file-system  don't cross filesystem boundaries while walking
#
# Exit codes: 0 = OK, 1 = WARN, 2 = CRIT. Cron/Nagios friendly.
#
# Stdlib only — no gems. Tested on Ruby 3.0+.

require 'optparse'
require 'json'
require 'find'

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
options = {
  top: 10, depth: 1, snapshot: nil,
  warn_pct: 80, crit_pct: 90, growth_warn_mb: 512,
  json: false, one_fs: false
}

OptionParser.new do |o|
  o.banner = 'Usage: ruby disk_usage_report.rb [options] DIR [DIR ...]'
  o.on('-n', '--top N', Integer)            { |v| options[:top] = v }
  o.on('-d', '--depth N', Integer)          { |v| options[:depth] = v }
  o.on('-s', '--snapshot FILE', String)     { |v| options[:snapshot] = v }
  o.on('-w', '--warn PCT', Integer)         { |v| options[:warn_pct] = v }
  o.on('-c', '--crit PCT', Integer)         { |v| options[:crit_pct] = v }
  o.on('-g', '--growth-warn MB', Integer)   { |v| options[:growth_warn_mb] = v }
  o.on('-j', '--json')                      { options[:json] = true }
  o.on('-x', '--one-file-system')           { options[:one_fs] = true }
end.parse!

roots = ARGV.map { |a| File.expand_path(a) }
abort 'error: give me at least one directory to scan' if roots.empty?
roots.each { |r| abort "error: not a directory: #{r}" unless File.directory?(r) }

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def human(bytes)
  units = %w[B KiB MiB GiB TiB]
  size  = bytes.to_f
  unit  = 0
  while size >= 1024 && unit < units.size - 1
    size /= 1024
    unit += 1
  end
  format(unit.zero? ? '%d %s' : '%.1f %s', size, units[unit])
end

# Aggregation bucket for a path: which depth-N ancestor a file belongs to.
def bucket_for(path, root, depth)
  rel = path[(root.length + 1)..]
  return root if rel.nil? || rel.empty?

  parts = rel.split(File::SEPARATOR)
  return root if parts.length <= depth && !File.directory?(path)

  File.join(root, parts.first(depth))
end

# ---------------------------------------------------------------------------
# Walk the trees
# ---------------------------------------------------------------------------
dir_sizes   = Hash.new(0)          # bucket path  -> bytes
big_files   = []                   # [bytes, path] min-heap-ish (we sort later)
errors      = 0
file_count  = 0

roots.each do |root|
  root_dev = File.lstat(root).dev
  Find.find(root) do |path|
    begin
      st = File.lstat(path)
    rescue SystemCallError
      errors += 1
      next
    end

    # Optionally refuse to wander onto other mounts (/proc, NFS, ...).
    if st.directory? && options[:one_fs] && st.dev != root_dev
      Find.prune
      next
    end

    next unless st.file?

    file_count += 1
    dir_sizes[bucket_for(path, root, options[:depth])] += st.size
    big_files << [st.size, path]
    # Keep the candidate list small; no need to hold every file in RAM.
    big_files = big_files.max_by(options[:top] * 4) { |s, _| s } if big_files.size > options[:top] * 8
  end
end

top_dirs  = dir_sizes.sort_by { |_, v| -v }.first(options[:top])
top_files = big_files.max_by(options[:top]) { |s, _| s }
              .sort_by { |s, _| -s }

# ---------------------------------------------------------------------------
# Filesystem fullness via `df` (POSIX -P output is stable and parseable)
# ---------------------------------------------------------------------------
fs_alerts = []
filesystems = []
roots.uniq.each do |root|
  out = `df -kP #{root} 2>/dev/null`.lines
  next if out.length < 2

  cols = out[1].split
  next if cols.length < 6

  pct = cols[4].delete('%').to_i
  fs  = { mount: cols[5], size_kb: cols[1].to_i, used_kb: cols[2].to_i, used_pct: pct }
  next if filesystems.any? { |f| f[:mount] == fs[:mount] }

  filesystems << fs
  level = pct >= options[:crit_pct] ? 'CRIT' : (pct >= options[:warn_pct] ? 'WARN' : nil)
  fs_alerts << { level: level, mount: fs[:mount], used_pct: pct } if level
end

# ---------------------------------------------------------------------------
# Snapshot diffing: what grew since last run?
# ---------------------------------------------------------------------------
growth = []
if options[:snapshot]
  previous = {}
  if File.exist?(options[:snapshot])
    begin
      previous = JSON.parse(File.read(options[:snapshot]))['dirs'] || {}
    rescue JSON::ParserError
      warn "warning: snapshot #{options[:snapshot]} is corrupt, ignoring"
    end
  end

  dir_sizes.each do |path, bytes|
    delta = bytes - (previous[path] || 0)
    growth << { path: path, bytes: bytes, delta: delta } if delta.abs > 0 && previous.key?(path)
  end
  growth.sort_by! { |g| -g[:delta] }

  # Persist this run for next time (write-then-rename would be even safer).
  File.write(options[:snapshot],
             JSON.pretty_generate(scanned_at: Time.now.to_s, dirs: dir_sizes))
end

growth_alerts = growth.select { |g| g[:delta] >= options[:growth_warn_mb] * 1024 * 1024 }

# ---------------------------------------------------------------------------
# Verdict + output
# ---------------------------------------------------------------------------
exit_code = 0
exit_code = 1 if fs_alerts.any? { |a| a[:level] == 'WARN' } || growth_alerts.any?
exit_code = 2 if fs_alerts.any? { |a| a[:level] == 'CRIT' }

if options[:json]
  puts JSON.pretty_generate(
    scanned_roots: roots, files_seen: file_count, walk_errors: errors,
    filesystems: filesystems,
    top_dirs: top_dirs.map  { |p, b| { path: p, bytes: b } },
    top_files: top_files.map { |b, p| { path: p, bytes: b } },
    growth: growth.first(options[:top]),
    alerts: fs_alerts + growth_alerts.map { |g| { level: 'WARN', path: g[:path], grew: g[:delta] } },
    exit_code: exit_code
  )
else
  puts "disk_usage_report — #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}"
  puts "scanned #{roots.join(', ')} (#{file_count} files, #{errors} unreadable)"
  puts

  filesystems.each do |fs|
    flag = fs[:used_pct] >= options[:crit_pct] ? ' [CRIT]' :
           fs[:used_pct] >= options[:warn_pct] ? ' [WARN]' : ''
    puts format('filesystem %-20s %3d%% full%s', fs[:mount], fs[:used_pct], flag)
  end

  puts "\ntop #{options[:top]} directories (depth #{options[:depth]}):"
  top_dirs.each { |p, b| puts format('  %10s  %s', human(b), p) }

  puts "\ntop #{options[:top]} files:"
  top_files.each { |b, p| puts format('  %10s  %s', human(b), p) }

  unless growth.empty?
    puts "\ngrowth since last snapshot:"
    growth.first(options[:top]).each do |g|
      sign = g[:delta].positive? ? '+' : '-'
      flag = g[:delta] >= options[:growth_warn_mb] * 1024 * 1024 ? ' [WARN]' : ''
      puts format('  %s%9s  %s%s', sign, human(g[:delta].abs), g[:path], flag)
    end
  end

  puts "\nverdict: #{%w[OK WARN CRIT][exit_code]}"
end

exit exit_code
