#!/usr/bin/env ruby
# frozen_string_literal: true
#
# disk_usage_report.rb -- answer "what is eating this disk?" in one pass.
#
# Combines three views a sysadmin usually assembles by hand from df, du and
# find:
#
#   1. Filesystem fill levels (parsed from `df -P`, the POSIX-stable format),
#      flagged against warn/crit thresholds.
#   2. The heaviest directories under a scan root -- computed from ONE
#      recursive walk, sizes aggregated bottom-up, no shelling out to du.
#   3. The largest and stalest files (old + big = archive candidates).
#
# Standard library only. Text or --json output, cron-friendly exit codes:
#   0 = all filesystems under warn threshold
#   1 = at least one filesystem over --warn %
#   2 = at least one filesystem over --crit %
#
# Usage:
#   ruby disk_usage_report.rb /var/log
#   ruby disk_usage_report.rb --top 10 --stale-days 90 --warn 80 --crit 90 /srv
#   ruby disk_usage_report.rb --json /var/log | jq .
#
require 'optparse'
require 'json'
require 'find'
require 'time'

opts = { top: 8, stale_days: 30, warn: 80, crit: 90, json: false }
parser = OptionParser.new do |o|
  o.banner = 'Usage: disk_usage_report.rb [options] SCAN_ROOT [SCAN_ROOT...]'
  o.on('--top N', Integer, 'How many heaviest dirs/files to show (default 8)') { |v| opts[:top] = v }
  o.on('--stale-days N', Integer, 'Files not modified in N days are stale (default 30)') { |v| opts[:stale_days] = v }
  o.on('--warn PCT', Integer, 'Filesystem WARN threshold %% (default 80)') { |v| opts[:warn] = v }
  o.on('--crit PCT', Integer, 'Filesystem CRIT threshold %% (default 90)') { |v| opts[:crit] = v }
  o.on('--json', 'Emit JSON instead of text') { opts[:json] = true }
end
parser.parse!(ARGV)
roots = ARGV
abort(parser.to_s) if roots.empty?

def human(bytes)
  units = %w[B KB MB GB TB]
  size = bytes.to_f
  unit = 0
  while size >= 1024 && unit < units.size - 1
    size /= 1024
    unit += 1
  end
  format(unit.zero? ? '%d %s' : '%.1f %s', size, units[unit])
end

# ---------------------------------------------------------------------------
# 1. Filesystem fill levels via `df -P` (POSIX output: stable columns, one
#    line per filesystem -- safe to parse, unlike the default GNU format).
# ---------------------------------------------------------------------------
def filesystems
  out = `df -P -k 2>/dev/null`
  seen = {} # dedupe bind mounts: same device listed once, first mount wins
  out.lines.drop(1).filter_map do |line|
    cols = line.split
    next if cols.size < 6
    dev, blocks, used, avail, pct, mount = cols[0], cols[1].to_i, cols[2].to_i, cols[3].to_i, cols[4].delete('%').to_i, cols[5..].join(' ')
    next if dev == 'tmpfs' || dev == 'none' || blocks.zero?
    next if seen[dev]
    seen[dev] = true
    { device: dev, mount: mount, size_kb: blocks, used_kb: used, avail_kb: avail, used_pct: pct }
  end
end

# ---------------------------------------------------------------------------
# 2 + 3. One recursive walk per root. For every file we bill its size to every
# ancestor directory up to the root, so directory totals are cumulative --
# what `du -s` would report -- but from a single pass that also collects the
# largest/stalest file lists at the same time.
# ---------------------------------------------------------------------------
def scan(root, stale_before)
  dir_sizes = Hash.new(0)
  files = []
  errors = 0
  root = File.expand_path(root)

  Find.find(root) do |path|
    begin
      stat = File.lstat(path)
    rescue Errno::ENOENT, Errno::EACCES
      errors += 1
      next
    end
    if stat.directory?
      dir_sizes[path] += 0 # make empty dirs visible
    elsif stat.file?
      files << { path: path, bytes: stat.size, mtime: stat.mtime }
      # bill the file to every ancestor up to (and including) the root
      dir = File.dirname(path)
      while dir.start_with?(root)
        dir_sizes[dir] += stat.size
        break if dir == root
        dir = File.dirname(dir)
      end
    end
  end

  stale = files.select { |f| f[:mtime] < stale_before }
  { root: root, dir_sizes: dir_sizes, files: files, stale: stale, errors: errors }
end

stale_before = Time.now - opts[:stale_days] * 86_400
fs = filesystems
worst = fs.map { |f| f[:used_pct] }.max || 0
exit_code = worst >= opts[:crit] ? 2 : (worst >= opts[:warn] ? 1 : 0)

reports = roots.map { |r| scan(r, stale_before) }

if opts[:json]
  payload = {
    generated_at: Time.now.utc.iso8601,
    thresholds: { warn_pct: opts[:warn], crit_pct: opts[:crit] },
    filesystems: fs,
    scans: reports.map do |rep|
      {
        root: rep[:root],
        total_bytes: rep[:dir_sizes][rep[:root]] || 0,
        file_count: rep[:files].size,
        unreadable: rep[:errors],
        heaviest_dirs: rep[:dir_sizes].sort_by { |_, v| -v }.first(opts[:top])
                          .map { |d, b| { dir: d, bytes: b } },
        largest_files: rep[:files].max_by(opts[:top]) { |f| f[:bytes] }
                          .map { |f| { path: f[:path], bytes: f[:bytes], mtime: f[:mtime].utc.iso8601 } },
        stale_files: rep[:stale].sort_by { |f| -f[:bytes] }.first(opts[:top])
                          .map { |f| { path: f[:path], bytes: f[:bytes], mtime: f[:mtime].utc.iso8601 } },
        stale_total_bytes: rep[:stale].sum { |f| f[:bytes] }
      }
    end
  }
  puts JSON.pretty_generate(payload)
else
  puts '== Filesystems =='
  fs.each do |f|
    badge = f[:used_pct] >= opts[:crit] ? '[CRIT]' : (f[:used_pct] >= opts[:warn] ? '[WARN]' : '[ OK ]')
    puts format('%s %-28s %-16s %9s used of %-9s (%d%%)',
                badge, f[:device], f[:mount], human(f[:used_kb] * 1024), human(f[:size_kb] * 1024), f[:used_pct])
  end
  reports.each do |rep|
    total = rep[:dir_sizes][rep[:root]] || 0
    puts
    puts "== #{rep[:root]} -- #{human(total)} in #{rep[:files].size} files" \
         "#{rep[:errors] > 0 ? " (#{rep[:errors]} unreadable, skipped)" : ''} =="
    puts "-- heaviest directories (cumulative) --"
    rep[:dir_sizes].sort_by { |_, v| -v }.first(opts[:top]).each do |dir, bytes|
      puts format('  %10s  %s', human(bytes), dir)
    end
    puts "-- largest files --"
    rep[:files].max_by(opts[:top]) { |f| f[:bytes] }.each do |f|
      puts format('  %10s  %s  (modified %s)', human(f[:bytes]), f[:path], f[:mtime].strftime('%Y-%m-%d'))
    end
    unless rep[:stale].empty?
      puts "-- stale files (untouched > #{opts[:stale_days]} days, top #{opts[:top]} by size) --"
      rep[:stale].sort_by { |f| -f[:bytes] }.first(opts[:top]).each do |f|
        puts format('  %10s  %s  (modified %s)', human(f[:bytes]), f[:path], f[:mtime].strftime('%Y-%m-%d'))
      end
      puts format('  reclaimable if archived: %s across %d stale files',
                  human(rep[:stale].sum { |f| f[:bytes] }), rep[:stale].size)
    end
  end
end

exit exit_code
