#!/usr/bin/env ruby
# frozen_string_literal: true
#
# disk_usage_report.rb
#
# A pure stdlib (Ruby 3.0+) disk-usage reporting and cleanup-candidate tool.
#
# WHAT IT DOES
#   1. Walks one or more directory trees and aggregates disk usage per
#      top-level subdirectory, plus finds the N largest individual files.
#   2. Flags files older than a configurable age that match "cleanup"
#      glob patterns (logs, tmp files, core dumps, etc.) and reports how
#      much space could be reclaimed.
#   3. Optionally deletes those flagged files -- but ONLY when you pass
#      --delete explicitly. The default is always a safe, read-only
#      --dry-run.
#   4. Runs a filesystem-level threshold check (like a Nagios/monitoring
#      plugin) by shelling out to `df` and parsing its output, returning
#      cron/monitoring-friendly exit codes: 0=OK, 1=WARN, 2=CRIT, 3=UNKNOWN.
#   5. Emits either human-readable text or --json, matching the rest of
#      this toolkit's convention of "text/JSON on every script, cron-
#      friendly exit codes."
#
# WHY `df` VIA Open3 INSTEAD OF A GEM
#   There is no filesystem-statistics call in Ruby's stdlib (no `statvfs`
#   wrapper, no `Sys::Filesystem`). The two realistic options are:
#     a) add the `sys-filesystem` gem, or
#     b) shell out to the `df` utility, which exists on every Linux/macOS
#        box by definition and prints exactly the numbers we need.
#   Since this toolkit is pure-stdlib-only, we shell out to `df -Pk` via
#   Open3.capture3 (POSIX output format -- stable column layout across
#   Linux and macOS/BSD) and parse the result. Open3 is used (rather than
#   backticks or `system`) so we get separate stdout/stderr streams and a
#   real Process::Status we can check, without invoking a shell.
#
# SAFETY MODEL
#   - Default mode is --dry-run: the script only ever *reports* what it
#     would delete and how much space would be reclaimed.
#   - --delete is required to actually remove anything, and even then:
#       * only files that are BOTH older than --older-than-days AND match
#         one of --pattern's globs are eligible ("belt and suspenders" --
#         age alone or pattern alone is not enough).
#       * symlinks are never followed or deleted (File.symlink? check).
#       * a bare `--pattern '*'` (matches everything) is rejected unless
#         --force-wildcard is also given, to stop a fat-fingered "delete
#         everything old" run.
#       * every deletion (and every deletion failure) is logged.
#   - Permission errors on individual files/dirs are caught and reported
#     as skipped entries; the script never aborts the whole run because
#     of one unreadable file.

require 'find'
require 'optparse'
require 'json'
require 'open3'
require 'time'

# ---------------------------------------------------------------------------
# Option parsing
# ---------------------------------------------------------------------------

Options = Struct.new(
  :paths, :top_n, :older_than_days, :patterns, :dry_run, :force_wildcard,
  :json, :warn_pct, :crit_pct, :df_paths, :skip_threshold, :quiet_skips,
  keyword_init: true
)

def parse_options(argv)
  opts = Options.new(
    paths: [],
    top_n: 15,
    older_than_days: 30,
    patterns: ['*.log', '*.tmp', 'core.*', '*.core', '*~'],
    dry_run: true,
    force_wildcard: false,
    json: false,
    warn_pct: 80,
    crit_pct: 90,
    df_paths: [],
    skip_threshold: false,
    quiet_skips: false
  )

  parser = OptionParser.new do |o|
    o.banner = "Usage: disk_usage_report.rb [options] PATH [PATH ...]"

    o.on('-nN', '--top-n=N', Integer, 'Number of largest files to report (default 15)') do |v|
      opts.top_n = v
    end

    o.on('--older-than-days=N', Integer,
         'Age threshold in days for cleanup candidates (default 30)') do |v|
      opts.older_than_days = v
    end

    o.on('--pattern=LIST', Array,
         "Comma-separated glob patterns for cleanup candidates\n" \
         "                                     (default: *.log,*.tmp,core.*,*.core,*~)") do |v|
      opts.patterns = v
    end

    o.on('--dry-run', 'Report only, delete nothing (default)') do
      opts.dry_run = true
    end

    o.on('--delete', 'Actually delete flagged cleanup candidates (explicit opt-in)') do
      opts.dry_run = false
    end

    o.on('--force-wildcard', 'Allow a bare "*" cleanup pattern with --delete') do
      opts.force_wildcard = true
    end

    o.on('--json', 'Emit machine-readable JSON instead of text') do
      opts.json = true
    end

    o.on('--warn-pct=N', Integer, 'Filesystem use% that triggers WARN (default 80)') do |v|
      opts.warn_pct = v
    end

    o.on('--crit-pct=N', Integer, 'Filesystem use% that triggers CRIT (default 90)') do |v|
      opts.crit_pct = v
    end

    o.on('--df-path=PATH', 'Filesystem (mount point or any path on it) to threshold-check.',
         'Repeatable. Defaults to the scanned PATH(s) if omitted.') do |v|
      opts.df_paths << v
    end

    o.on('--skip-threshold', 'Skip the df threshold check entirely') do
      opts.skip_threshold = true
    end

    o.on('-q', '--quiet-skips', 'Do not list individual permission-denied skips') do
      opts.quiet_skips = true
    end

    o.on('-h', '--help', 'Show this help') do
      puts o
      exit 0
    end
  end

  opts.paths = parser.parse(argv)
  opts.paths = ['.'] if opts.paths.empty?
  opts.df_paths = opts.paths.dup if opts.df_paths.empty?

  if !opts.dry_run && opts.patterns.include?('*') && !opts.force_wildcard
    warn "refusing to --delete with a bare '*' pattern (would match everything)."
    warn "pass --force-wildcard if you really mean it."
    exit 3
  end

  opts
end

# ---------------------------------------------------------------------------
# Tree walk + aggregation
# ---------------------------------------------------------------------------

# One record per file we successfully stat'd.
FileRecord = Struct.new(:path, :size, :mtime, :top_dir)

# Walks `root` with Find, yielding a FileRecord for every regular file and
# accumulating permission/stat errors into `skipped` instead of raising.
def walk(root, skipped)
  records = []
  root = File.expand_path(root)

  unless File.exist?(root)
    skipped << { path: root, error: 'no such file or directory' }
    return records
  end

  Find.find(root) do |path|
    begin
      stat = File.lstat(path) # lstat: never follow symlinks into the void
      if stat.symlink?
        Find.prune if stat.directory? # don't descend into symlinked dirs
        next
      end

      if stat.directory?
        # Find.find already recurses; nothing to record for the dir itself,
        # but we do want to skip directories we can't read at all.
        begin
          Dir.entries(path)
        rescue Errno::EACCES, Errno::EPERM => e
          skipped << { path: path, error: e.message }
          Find.prune
        end
        next
      end

      next unless stat.file?

      top_dir = top_level_subdir(root, path)
      records << FileRecord.new(path, stat.size, stat.mtime, top_dir)
    rescue Errno::ENOENT
      # File vanished between Find yielding it and us stat'ing it -- ignore.
      next
    rescue Errno::EACCES, Errno::EPERM => e
      skipped << { path: path, error: e.message }
      next
    end
  end

  records
end

# Maps an absolute file path back to the first path segment under `root`,
# e.g. root=/var/log, path=/var/log/nginx/access.log -> "nginx"
# Files directly inside root are bucketed under "." (root itself).
def top_level_subdir(root, path)
  rel = path.delete_prefix(root).delete_prefix(File::SEPARATOR)
  first = rel.split(File::SEPARATOR).first
  first.nil? || first == File.basename(path) ? '.' : first
end

def human_bytes(n)
  units = %w[B KB MB GB TB PB]
  size = n.to_f
  idx = 0
  while size >= 1024 && idx < units.length - 1
    size /= 1024
    idx += 1
  end
  idx.zero? ? "#{n} #{units[idx]}" : format('%.2f %s', size, units[idx])
end

# ---------------------------------------------------------------------------
# Cleanup candidate detection
# ---------------------------------------------------------------------------

def cleanup_candidate?(record, cutoff_time, patterns)
  return false unless record.mtime < cutoff_time

  base = File.basename(record.path)
  patterns.any? { |glob| File.fnmatch(glob, base, File::FNM_EXTGLOB) }
end

# Deletes flagged records for real. Returns [deleted, failed] arrays.
def delete_candidates(candidates)
  deleted = []
  failed = []
  candidates.each do |rec|
    begin
      # Re-check symlink-ness right before unlinking (TOCTOU hardening).
      if File.symlink?(rec.path)
        failed << { path: rec.path, error: 'refusing to delete a symlink' }
        next
      end
      File.delete(rec.path)
      deleted << rec
    rescue Errno::ENOENT
      # Already gone -- treat as success, nothing left to reclaim.
      deleted << rec
    rescue Errno::EACCES, Errno::EPERM => e
      failed << { path: rec.path, error: e.message }
    end
  end
  [deleted, failed]
end

# ---------------------------------------------------------------------------
# `df`-based filesystem threshold check
# ---------------------------------------------------------------------------

DfResult = Struct.new(:target, :filesystem, :mount, :use_pct, :status, :error, keyword_init: true)

STATUS_OK   = 'OK'
STATUS_WARN = 'WARN'
STATUS_CRIT = 'CRIT'
STATUS_UNKNOWN = 'UNKNOWN'

EXIT_CODES = { STATUS_OK => 0, STATUS_WARN => 1, STATUS_CRIT => 2, STATUS_UNKNOWN => 3 }.freeze

# Shells out to `df -Pk <path>` (POSIX output, 1024-byte blocks -- a stable
# format on both GNU/Linux and macOS/BSD) and parses the single data line.
# Using Open3.capture3 avoids a shell entirely (no injection risk from a
# user-supplied path) and gives us stdout, stderr and exit status separately.
def df_check(path, warn_pct, crit_pct)
  stdout, stderr, status = Open3.capture3('df', '-Pk', path)

  unless status.success?
    return DfResult.new(target: path, status: STATUS_UNKNOWN,
                         error: stderr.strip.empty? ? "df exited #{status.exitstatus}" : stderr.strip)
  end

  lines = stdout.lines.map(&:strip).reject(&:empty?)
  # lines[0] is the header; the data line may wrap onto a second line if the
  # filesystem name is long (common on Linux with long device paths), in
  # which case df puts the remaining columns on the next line. Handle both.
  data_lines = lines[1..] || []
  fields = data_lines.join(' ').split(/\s+/)

  if fields.size < 6
    return DfResult.new(target: path, status: STATUS_UNKNOWN, error: "unparseable df output: #{stdout.inspect}")
  end

  filesystem = fields[0]
  use_pct_str = fields[4] # e.g. "83%"
  mount = fields[5]
  use_pct = use_pct_str.delete('%').to_i

  status_label =
    if use_pct >= crit_pct then STATUS_CRIT
    elsif use_pct >= warn_pct then STATUS_WARN
    else STATUS_OK
    end

  DfResult.new(target: path, filesystem: filesystem, mount: mount,
               use_pct: use_pct, status: status_label)
rescue Errno::ENOENT
  DfResult.new(target: path, status: STATUS_UNKNOWN, error: 'df: command not found')
end

def worst_status(results)
  order = [STATUS_UNKNOWN, STATUS_CRIT, STATUS_WARN, STATUS_OK]
  results.map(&:status).min_by { |s| order.index(s) } || STATUS_OK
end

# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------

def build_report(opts)
  skipped = []
  all_records = opts.paths.flat_map { |p| walk(p, skipped) }

  per_root = opts.paths.each_with_object({}) do |root, h|
    root_exp = File.expand_path(root)
    recs = all_records.select { |r| r.path.start_with?(root_exp) }
    totals = Hash.new(0)
    counts = Hash.new(0)
    recs.each do |r|
      totals[r.top_dir] += r.size
      counts[r.top_dir] += 1
    end
    h[root] = {
      total_bytes: recs.sum(&:size),
      file_count: recs.size,
      subdirs: totals.map { |name, bytes| { name: name, bytes: bytes, files: counts[name] } }
                      .sort_by { |h2| -h2[:bytes] }
    }
  end

  largest_files = all_records.sort_by { |r| -r.size }.first(opts.top_n).map do |r|
    { path: r.path, bytes: r.size, mtime: r.mtime.iso8601 }
  end

  cutoff = Time.now - (opts.older_than_days * 86_400)
  candidates = all_records.select { |r| cleanup_candidate?(r, cutoff, opts.patterns) }
  reclaimable_bytes = candidates.sum(&:size)

  deleted, delete_failed = if !opts.dry_run && !candidates.empty?
                             delete_candidates(candidates)
                           else
                             [[], []]
                           end

  threshold_results = opts.skip_threshold ? [] : opts.df_paths.map { |p| df_check(p, opts.warn_pct, opts.crit_pct) }

  {
    scanned_paths: opts.paths.map { |p| File.expand_path(p) },
    generated_at: Time.now.iso8601,
    dry_run: opts.dry_run,
    per_root: per_root,
    largest_files: largest_files,
    cleanup: {
      older_than_days: opts.older_than_days,
      patterns: opts.patterns,
      candidate_count: candidates.size,
      reclaimable_bytes: reclaimable_bytes,
      deleted_count: deleted.size,
      deleted_bytes: deleted.sum(&:size),
      delete_failed: delete_failed,
      candidates: candidates.first(200).map { |r| { path: r.path, bytes: r.size, mtime: r.mtime.iso8601 } }
    },
    skipped: skipped,
    threshold: threshold_results.map do |r|
      { target: r.target, filesystem: r.filesystem, mount: r.mount,
        use_pct: r.use_pct, status: r.status, error: r.error }
    end
  }
end

# ---------------------------------------------------------------------------
# Output rendering
# ---------------------------------------------------------------------------

def render_text(report, opts)
  out = +''
  out << "disk_usage_report -- #{report[:generated_at]}\n"
  out << "mode: #{opts.dry_run ? 'DRY-RUN (no files deleted)' : 'DELETE (files removed below)'}\n"
  out << ("=" * 70) << "\n"

  report[:per_root].each do |root, data|
    out << "\nPATH: #{File.expand_path(root)}\n"
    out << "  total: #{human_bytes(data[:total_bytes])} across #{data[:file_count]} files\n"
    out << "  by subdirectory (top-level):\n"
    data[:subdirs].first(10).each do |sd|
      out << format("    %-30s %10s  (%d files)\n", sd[:name], human_bytes(sd[:bytes]), sd[:files])
    end
  end

  out << "\nTOP #{opts.top_n} LARGEST FILES\n"
  report[:largest_files].each_with_index do |f, i|
    out << format("  %2d. %10s  %s  (mtime %s)\n", i + 1, human_bytes(f[:bytes]), f[:path], f[:mtime])
  end

  cu = report[:cleanup]
  out << "\nCLEANUP CANDIDATES (older than #{cu[:older_than_days]}d, matching #{cu[:patterns].join(', ')})\n"
  out << "  candidates: #{cu[:candidate_count]}\n"
  out << "  reclaimable: #{human_bytes(cu[:reclaimable_bytes])}\n"
  cu[:candidates].first(20).each do |c|
    out << format("    %10s  %s  (mtime %s)\n", human_bytes(c[:bytes]), c[:path], c[:mtime])
  end
  if cu[:candidates].size < cu[:candidate_count]
    out << "    ... and #{cu[:candidate_count] - cu[:candidates].size} more\n"
  end

  if !opts.dry_run
    out << "\nDELETED: #{cu[:deleted_count]} files, #{human_bytes(cu[:deleted_bytes])} reclaimed\n"
    unless cu[:delete_failed].empty?
      out << "DELETE FAILURES:\n"
      cu[:delete_failed].each { |f| out << "    #{f[:path]}: #{f[:error]}\n" }
    end
  else
    out << "\n(dry-run: nothing deleted -- rerun with --delete to actually remove these files)\n"
  end

  unless report[:skipped].empty?
    out << "\nSKIPPED (permission errors, #{report[:skipped].size} total)#{opts.quiet_skips ? '' : ':'}\n"
    unless opts.quiet_skips
      report[:skipped].first(15).each { |s| out << "    #{s[:path]}: #{s[:error]}\n" }
      out << "    ... and #{report[:skipped].size - 15} more\n" if report[:skipped].size > 15
    end
  end

  unless report[:threshold].empty?
    out << "\nFILESYSTEM THRESHOLD CHECK (warn>=#{opts.warn_pct}% crit>=#{opts.crit_pct}%)\n"
    report[:threshold].each do |t|
      if t[:error]
        out << format("  %-30s UNKNOWN  (%s)\n", t[:target], t[:error])
      else
        out << format("  %-30s %3d%%  [%s]  fs=%s mount=%s\n",
                       t[:target], t[:use_pct], t[:status], t[:filesystem], t[:mount])
      end
    end
  end

  out
end

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv)
  opts = parse_options(argv)
  report = build_report(opts)

  if opts.json
    puts JSON.pretty_generate(report)
  else
    puts render_text(report, opts)
  end

  exit_status =
    if report[:threshold].empty?
      0
    else
      worst = worst_status(report[:threshold].map { |t| Struct.new(:status).new(t[:status]) })
      EXIT_CODES[worst]
    end

  exit exit_status
end

main(ARGV) if $PROGRAM_NAME == __FILE__
