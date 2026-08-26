#!/usr/bin/env ruby
# frozen_string_literal: true
#
# disk_usage_report.rb — disk usage reporting and growth tracking for Linux/macOS.
#
# Walks one or more directory trees, reports the biggest immediate
# subdirectories and the biggest individual files, and (optionally) compares
# the current scan against a saved JSON snapshot so you can see exactly WHERE
# a filesystem grew since the last run — the question `df` can never answer.
#
# Stdlib only: find, json, optparse, etc. No gems.
#
# Usage:
#   ruby disk_usage_report.rb /var /home                 # human-readable report
#   ruby disk_usage_report.rb --top 15 /var              # more rows
#   ruby disk_usage_report.rb --json /var                # machine-readable
#   ruby disk_usage_report.rb --save-snapshot /var/tmp/du.json /var
#   ruby disk_usage_report.rb --compare /var/tmp/du.json /var
#   ruby disk_usage_report.rb --warn-gb 50 /var          # exit 1 if a root exceeds 50 GiB
#
# Exit codes: 0 = ok, 1 = a --warn-gb threshold was exceeded, 2 = usage error.

require "find"
require "json"
require "optparse"
require "time"

options = {
  top: 10,
  json: false,
  save_snapshot: nil,
  compare: nil,
  warn_gb: nil,
  min_file_mb: 100 # only individual files at least this big make the "big files" table
}

parser = OptionParser.new do |o|
  o.banner = "Usage: ruby disk_usage_report.rb [options] DIR [DIR...]"
  o.on("--top N", Integer, "Rows per table (default 10)") { |v| options[:top] = v }
  o.on("--json", "Emit JSON instead of text") { options[:json] = true }
  o.on("--save-snapshot FILE", "Write scan results to FILE for later --compare") { |v| options[:save_snapshot] = v }
  o.on("--compare FILE", "Diff this scan against a snapshot produced by --save-snapshot") { |v| options[:compare] = v }
  o.on("--warn-gb N", Float, "Exit 1 if any scanned root exceeds N GiB") { |v| options[:warn_gb] = v }
  o.on("--min-file-mb N", Integer, "Big-file table cutoff in MiB (default 100)") { |v| options[:min_file_mb] = v }
end
parser.parse!

roots = ARGV
if roots.empty?
  warn parser.banner
  exit 2
end

# ---------------------------------------------------------------------------
# Scanning.
#
# For each root we account every regular file's size (lstat — we never follow
# symlinks, so a link farm can't double-count or loop us) into:
#   * the root's total
#   * the root's immediate child directory that contains it
# and we keep a global top-N list of the largest individual files.
# ---------------------------------------------------------------------------

def human(bytes)
  units = %w[B KiB MiB GiB TiB]
  return "0 B" if bytes.zero?
  exp = [(Math.log(bytes) / Math.log(1024)).floor, units.size - 1].min
  format("%.1f %s", bytes.to_f / (1024**exp), units[exp])
end

def scan_root(root, min_file_bytes)
  totals   = Hash.new(0)  # immediate-child dir (or "<root files>") => bytes
  big      = []           # [path, bytes, mtime]
  errors   = 0
  total    = 0
  root     = File.expand_path(root)
  prefix   = root.end_with?("/") ? root : "#{root}/"

  Find.find(root) do |path|
    begin
      st = File.lstat(path)
    rescue SystemCallError
      errors += 1
      next
    end
    # Don't descend into other mounted filesystems' mountpoints? Keeping it
    # simple: we do descend, but we skip symlinks entirely.
    if st.symlink?
      Find.prune if st.ftype == "directory" rescue nil
      next
    end
    next unless st.file?

    total += st.size
    rel = path.delete_prefix(prefix)
    child = rel.include?("/") ? rel.split("/", 2).first : "<root files>"
    totals[child] += st.size
    big << [path, st.size, st.mtime] if st.size >= min_file_bytes
  rescue SystemCallError
    errors += 1
  end

  big.sort_by! { |(_, sz, _)| -sz }
  { root: root, total_bytes: total, children: totals, big_files: big, stat_errors: errors }
end

min_file_bytes = options[:min_file_mb] * 1024 * 1024
scans = roots.map { |r| scan_root(r, min_file_bytes) }

# ---------------------------------------------------------------------------
# Snapshot save / compare.
#
# A snapshot is just the per-child byte totals keyed by root. Comparing two
# snapshots turns "the disk filled up" into "var/log grew 9.2 GiB since
# Tuesday", which is the actual question during an incident.
# ---------------------------------------------------------------------------

if options[:save_snapshot]
  snap = {
    "taken_at" => Time.now.utc.iso8601,
    "roots" => scans.to_h { |s| [s[:root], { "total_bytes" => s[:total_bytes], "children" => s[:children] }] }
  }
  File.write(options[:save_snapshot], JSON.pretty_generate(snap))
end

growth = nil
if options[:compare]
  old = JSON.parse(File.read(options[:compare]))
  growth = {}
  scans.each do |s|
    prev = old.dig("roots", s[:root]) or next
    deltas = {}
    keys = (s[:children].keys | prev["children"].keys)
    keys.each do |k|
      d = s[:children][k].to_i - prev["children"][k].to_i
      deltas[k] = d unless d.zero?
    end
    growth[s[:root]] = {
      since: old["taken_at"],
      total_delta: s[:total_bytes] - prev["total_bytes"].to_i,
      children: deltas.sort_by { |_, d| -d }
    }
  end
end

# ---------------------------------------------------------------------------
# Threshold + output.
# ---------------------------------------------------------------------------

breaches = []
if options[:warn_gb]
  limit = (options[:warn_gb] * 1024**3).to_i
  scans.each { |s| breaches << s[:root] if s[:total_bytes] > limit }
end

if options[:json]
  out = {
    "generated_at" => Time.now.utc.iso8601,
    "roots" => scans.map do |s|
      {
        "root" => s[:root],
        "total_bytes" => s[:total_bytes],
        "stat_errors" => s[:stat_errors],
        "top_children" => s[:children].sort_by { |_, b| -b }.first(options[:top]).map { |n, b| { "name" => n, "bytes" => b } },
        "big_files" => s[:big_files].first(options[:top]).map { |p, b, m| { "path" => p, "bytes" => b, "mtime" => m.utc.iso8601 } }
      }
    end,
    "growth" => growth&.transform_values { |g| { "since" => g[:since], "total_delta" => g[:total_delta], "children" => g[:children].to_h } },
    "warn_breaches" => breaches
  }
  puts JSON.pretty_generate(out)
else
  scans.each do |s|
    puts "== #{s[:root]}  (total #{human(s[:total_bytes])}, #{s[:stat_errors]} unreadable)"
    puts "-- largest immediate subdirectories:"
    s[:children].sort_by { |_, b| -b }.first(options[:top]).each do |name, bytes|
      pct = s[:total_bytes].zero? ? 0 : bytes * 100.0 / s[:total_bytes]
      puts format("   %9s  %5.1f%%  %s", human(bytes), pct, name)
    end
    top_files = s[:big_files].first(options[:top])
    unless top_files.empty?
      puts "-- largest files (>= #{options[:min_file_mb]} MiB):"
      top_files.each { |p, b, m| puts format("   %9s  %s  %s", human(b), m.strftime("%Y-%m-%d"), p) }
    end
    puts
  end

  growth&.each do |root, g|
    puts "== growth for #{root} since #{g[:since]}: #{g[:total_delta] >= 0 ? '+' : ''}#{human(g[:total_delta].abs)}#{g[:total_delta].negative? ? ' freed' : ''}"
    g[:children].first(options[:top]).each do |name, d|
      puts format("   %+11s  %s", (d >= 0 ? "+" : "-") + human(d.abs), name)
    end
    puts
  end

  breaches.each { |r| puts "WARN: #{r} exceeds --warn-gb #{options[:warn_gb]} threshold" }
end

exit(breaches.empty? ? 0 : 1)
