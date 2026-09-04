#!/usr/bin/env ruby
# frozen_string_literal: true
#
# disk_usage_report.rb — answer "where did the disk go?" without leaving Ruby.
#
# Walks one or more directory trees and reports:
#   * total usage per top-level subdirectory (a du-style rollup)
#   * the N largest individual files
#   * "stale heavyweights": big files nobody has touched in a long time
#   * filesystem capacity via `df -kP`, with warn/crit thresholds for cron
#   * optional JSON snapshots, so a later run can show you exactly which
#     directories grew between two points in time
#
# Standard library only — no gems. Ruby >= 2.7. Linux/macOS (anything with
# a POSIX `df`). The tree walker itself is pure Ruby and runs anywhere.
#
# Usage:
#   ruby disk_usage_report.rb /var /home --top 10 --stale-days 180
#   ruby disk_usage_report.rb /data --snapshot /var/tmp/du_snap.json
#   ruby disk_usage_report.rb /data --compare /var/tmp/du_snap.json
#   ruby disk_usage_report.rb /var --warn-pct 80 --crit-pct 90 --json
#
# Exit codes: 0 = ok, 1 = WARN threshold breached, 2 = CRIT threshold breached.
# That makes it drop straight into cron/Nagios-style checks without wrapping.

require "find"
require "json"
require "optparse"
require "shellwords"
require "time"

options = {
  top: 15,
  dirs: 12,
  stale_days: 90,
  stale_min_bytes: 50 * 1024 * 1024, # only nag about stale files >= 50 MB
  warn_pct: nil,
  crit_pct: nil,
  snapshot: nil,
  compare: nil,
  json: false
}

parser = OptionParser.new do |o|
  o.banner = "Usage: ruby disk_usage_report.rb PATH [PATH...] [options]"
  o.on("--top N", Integer, "Largest files to list (default 15)") { |v| options[:top] = v }
  o.on("--dirs N", Integer, "Top-level subdirectories to list (default 12)") { |v| options[:dirs] = v }
  o.on("--stale-days N", Integer, "Age in days before a file counts as stale (default 90)") { |v| options[:stale_days] = v }
  o.on("--stale-min-size BYTES", Integer, "Minimum size for stale reporting (default 50 MiB)") { |v| options[:stale_min_bytes] = v }
  o.on("--warn-pct N", Integer, "WARN when filesystem use%% >= N") { |v| options[:warn_pct] = v }
  o.on("--crit-pct N", Integer, "CRIT when filesystem use%% >= N") { |v| options[:crit_pct] = v }
  o.on("--snapshot FILE", "Write per-directory totals to FILE as JSON") { |v| options[:snapshot] = v }
  o.on("--compare FILE", "Diff this run against a previous snapshot") { |v| options[:compare] = v }
  o.on("--json", "Emit the whole report as JSON") { options[:json] = true }
  o.on("-h", "--help") { puts o; exit 0 }
end
parser.parse!

roots = ARGV.empty? ? ["."] : ARGV
roots.map! { |r| File.expand_path(r) }
missing = roots.reject { |r| File.directory?(r) }
abort "error: not a directory: #{missing.join(', ')}" unless missing.empty?

# ---------------------------------------------------------------------------
# Human-friendly byte formatting. IEC units, one decimal where it matters.
# ---------------------------------------------------------------------------
def human(bytes)
  units = %w[B KiB MiB GiB TiB]
  size = bytes.to_f
  unit = 0
  while size >= 1024 && unit < units.size - 1
    size /= 1024
    unit += 1
  end
  unit.zero? ? "#{bytes} B" : format("%.1f %s", size, units[unit])
end

# ---------------------------------------------------------------------------
# The scanner. One pass with Find, three data structures filled as we go:
#   dir_totals : { "top-level subdir" => bytes }  (du-style rollup)
#   top_files  : running list of the largest files seen
#   stale      : big files whose mtime is older than the cutoff
#
# We use lstat, not stat, so symlinks are counted as themselves (a link to
# a 40 GB image is a few bytes of pointer, not 40 GB) and symlink loops
# can't trap the walker. Unreadable entries are counted and skipped —
# a disk report that dies on the first EACCES is useless on a real box.
# ---------------------------------------------------------------------------
def scan(root, stale_cutoff, stale_min_bytes)
  dir_totals = Hash.new(0)
  top_files = []
  stale = []
  file_count = 0
  errors = 0
  total = 0

  Find.find(root) do |path|
    begin
      st = File.lstat(path)
    rescue SystemCallError
      errors += 1
      next
    end

    if st.directory?
      # Never descend into a different filesystem's mountpoint? We keep it
      # simple and descend everywhere; use separate invocations per mount
      # if you need isolation.
      next
    end

    next unless st.file?

    file_count += 1
    total += st.size

    # Attribute the file to the top-level directory directly under root,
    # or to "." for files sitting in root itself. delete_prefix handles
    # root == "/" correctly, where naive length math would eat a character.
    rel = path.delete_prefix(root).delete_prefix(File::SEPARATOR)
    bucket = rel.include?(File::SEPARATOR) ? rel.split(File::SEPARATOR).first : "."
    dir_totals[bucket] += st.size

    top_files << [st.size, path]
    # Keep the candidate list small; sorting 30 elements every few
    # thousand files is far cheaper than sorting millions at the end.
    if top_files.size > 512
      top_files.sort_by! { |s, _| -s }
      top_files.slice!(64..)
    end

    stale << [st.size, path, st.mtime] if st.size >= stale_min_bytes && st.mtime < stale_cutoff
  end

  top_files.sort_by! { |s, _| -s }
  stale.sort_by! { |s, _, _| -s }
  { total: total, files: file_count, errors: errors,
    dir_totals: dir_totals, top_files: top_files, stale: stale }
end

# ---------------------------------------------------------------------------
# Filesystem capacity via `df -kP`. POSIX output is stable and parseable:
# last line, columns: device, 1k-blocks, used, available, use%, mountpoint.
# ---------------------------------------------------------------------------
def df_for(path)
  out = `df -kP #{path.shellescape} 2>/dev/null` rescue ""
  line = out.lines.last
  return nil unless line
  cols = line.split
  return nil if cols.size < 6
  { device: cols[0], size_kb: cols[1].to_i, used_kb: cols[2].to_i,
    avail_kb: cols[3].to_i, use_pct: cols[4].delete("%").to_i, mount: cols[5] }
end

stale_cutoff = Time.now - options[:stale_days] * 86_400
report = { generated: Time.now.iso8601, roots: {} }
worst = 0 # exit-code accumulator

roots.each do |root|
  data = scan(root, stale_cutoff, options[:stale_min_bytes])
  fs = df_for(root)

  status = "OK"
  if fs && options[:crit_pct] && fs[:use_pct] >= options[:crit_pct]
    status = "CRIT"
    worst = [worst, 2].max
  elsif fs && options[:warn_pct] && fs[:use_pct] >= options[:warn_pct]
    status = "WARN"
    worst = [worst, 1].max
  end

  report[:roots][root] = {
    status: status,
    total_bytes: data[:total],
    file_count: data[:files],
    unreadable: data[:errors],
    filesystem: fs,
    dirs: data[:dir_totals].sort_by { |_, v| -v }.first(options[:dirs])
                           .map { |d, b| { dir: d, bytes: b } },
    top_files: data[:top_files].first(options[:top])
                               .map { |b, p| { bytes: b, path: p } },
    stale: data[:stale].first(options[:top])
                       .map { |b, p, m| { bytes: b, path: p, mtime: m.iso8601 } }
  }
end

# ---------------------------------------------------------------------------
# Snapshot / compare. A snapshot is just {root => {dir => bytes}}. On
# --compare we align the two maps and print the delta per directory —
# which is usually the fastest possible answer to "what grew overnight?".
# ---------------------------------------------------------------------------
if options[:snapshot]
  snap = report[:roots].transform_values { |r| r[:dirs].to_h { |d| [d[:dir], d[:bytes]] } }
  File.write(options[:snapshot], JSON.pretty_generate({ taken: Time.now.iso8601, dirs: snap }))
end

growth = nil
if options[:compare]
  old = JSON.parse(File.read(options[:compare]))
  growth = {}
  report[:roots].each do |root, r|
    prev = (old.dig("dirs", root) || {})
    now = r[:dirs].to_h { |d| [d[:dir], d[:bytes]] }
    deltas = (prev.keys | now.keys).map do |dir|
      { dir: dir, before: prev[dir] || 0, after: now[dir] || 0,
        delta: (now[dir] || 0) - (prev[dir] || 0) }
    end
    growth[root] = deltas.reject { |d| d[:delta].zero? }.sort_by { |d| -d[:delta] }
  end
  report[:compared_against] = old["taken"]
  report[:growth] = growth
end

# ---------------------------------------------------------------------------
# Output. --json emits the machine version; otherwise a terminal report.
# ---------------------------------------------------------------------------
if options[:json]
  puts JSON.pretty_generate(report)
else
  report[:roots].each do |root, r|
    fs = r[:filesystem]
    puts "== #{root}  [#{r[:status]}]"
    puts "   total #{human(r[:total_bytes])} in #{r[:file_count]} files" \
         "#{r[:unreadable].positive? ? " (#{r[:unreadable]} unreadable, skipped)" : ''}"
    if fs
      puts format("   filesystem %s on %s: %s used of %s (%d%%), %s free",
                  fs[:device], fs[:mount], human(fs[:used_kb] * 1024),
                  human(fs[:size_kb] * 1024), fs[:use_pct], human(fs[:avail_kb] * 1024))
    end
    puts "   -- largest subdirectories --"
    r[:dirs].each { |d| puts format("   %10s  %s/", human(d[:bytes]), d[:dir]) }
    puts "   -- largest files --"
    r[:top_files].each { |f| puts format("   %10s  %s", human(f[:bytes]), f[:path]) }
    unless r[:stale].empty?
      puts "   -- stale (>= #{human(options[:stale_min_bytes])}, untouched #{options[:stale_days]}+ days) --"
      r[:stale].each { |f| puts format("   %10s  %s  (mtime %s)", human(f[:bytes]), f[:path], f[:mtime][0, 10]) }
    end
    puts
  end

  if growth
    puts "== growth since #{report[:compared_against]}"
    growth.each do |root, deltas|
      puts "   #{root}:"
      if deltas.empty?
        puts "   (no change)"
      else
        deltas.first(12).each do |d|
          sign = d[:delta].positive? ? "+" : "-"
          puts format("   %s%9s  %s/  (%s -> %s)", sign, human(d[:delta].abs),
                      d[:dir], human(d[:before]), human(d[:after]))
        end
      end
    end
  end
end

exit worst
