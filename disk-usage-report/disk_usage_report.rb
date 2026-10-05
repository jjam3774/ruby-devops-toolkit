#!/usr/bin/env ruby
# frozen_string_literal: true
#
# disk_usage_report.rb — Disk usage reporting and safe cleanup for Linux/macOS.
#
# Walks a directory tree, reports the biggest top-level subdirectories, flags
# individual files above a size threshold, and finds "stale junk" (old logs,
# core dumps, tmp files) that's safe to reclaim — with a dry-run by default
# and an explicit --clean flag required to actually delete anything.
#
# Usage:
#   ruby disk_usage_report.rb [path] [options]
#
# Examples:
#   ruby disk_usage_report.rb /var                     # report only (dry run)
#   ruby disk_usage_report.rb /var --top 15 --json
#   ruby disk_usage_report.rb /var/log --stale-days 30 --clean   # actually delete
#
# Author: tha-shed.com Ruby-for-DevOps series
# Ruby: 3.0+ (stdlib only — no gems required)

require 'find'
require 'optparse'
require 'json'
require 'fileutils'
require 'time' # needed for Time#iso8601 used in the JSON report

# Human-readable byte formatting, e.g. 1_536 -> "1.5K"
def human_size(bytes)
  units = %w[B K M G T P]
  size = bytes.to_f
  idx = 0
  while size >= 1024.0 && idx < units.length - 1
    size /= 1024.0
    idx += 1
  end
  idx.zero? ? "#{bytes}#{units[idx]}" : format('%.1f%s', size, units[idx])
end

# Patterns that are conventionally safe "junk" on a Linux/macOS box.
# Deliberately conservative: only well-known throwaway artifacts.
STALE_PATTERNS = [
  /\.log(\.\d+)?(\.gz)?\z/i,
  /\.tmp\z/i,
  /\A#.*#\z/,        # emacs autosave
  /\.swp\z/,         # vim swap
  /\Acore(\.\d+)?\z/,
  /\.old\z/i
].freeze

# Walks +root+ once, collecting:
#   - size per immediate child directory of root (for the "top consumers" table)
#   - individual files >= large_file_bytes
#   - "stale" files matching STALE_PATTERNS whose mtime is older than stale_days
# Symlinks are not followed (Find#prune-free traversal skips them), and any
# directory we can't stat/read (permission denied) is counted, not fatal.
class DiskWalker
  Result = Struct.new(:by_child, :large_files, :stale_files, :total_bytes,
                       :files_scanned, :dirs_skipped, keyword_init: true)

  def initialize(root, large_file_bytes:, stale_days:, excludes:)
    @root = File.expand_path(root)
    @large_file_bytes = large_file_bytes
    @stale_cutoff = Time.now - (stale_days * 86_400)
    @excludes = excludes.map { |e| File.expand_path(e) }
  end

  def walk
    by_child = Hash.new(0)
    large_files = []
    stale_files = []
    total_bytes = 0
    files_scanned = 0
    dirs_skipped = 0

    Find.find(@root) do |path|
      if excluded?(path)
        Find.prune if File.directory?(path)
        next
      end

      begin
        stat = File.lstat(path)
      rescue Errno::ENOENT, Errno::EACCES
        dirs_skipped += 1 if File.directory?(path) rescue nil
        next
      end

      next if stat.symlink? # never follow or count symlink targets twice
      next if stat.directory?

      size = stat.size
      total_bytes += size
      files_scanned += 1

      child = top_level_child(path)
      by_child[child] += size if child

      large_files << [path, size] if size >= @large_file_bytes

      if stale?(path) && stat.mtime < @stale_cutoff
        stale_files << [path, size, stat.mtime]
      end
    rescue Errno::EACCES, Errno::ENOENT
      dirs_skipped += 1
      next
    end

    Result.new(
      by_child: by_child.sort_by { |_, v| -v }.to_h,
      large_files: large_files.sort_by { |_, s| -s },
      stale_files: stale_files.sort_by { |_, s, _| -s },
      total_bytes: total_bytes,
      files_scanned: files_scanned,
      dirs_skipped: dirs_skipped
    )
  end

  private

  def excluded?(path)
    @excludes.any? { |e| path == e || path.start_with?("#{e}/") }
  end

  def stale?(path)
    STALE_PATTERNS.any? { |re| re.match?(File.basename(path)) }
  end

  # Bucket a file under the first path segment below @root, so /var/log/foo.log
  # and /var/log/bar.log both roll up under "log" when root is /var.
  def top_level_child(path)
    rel = path.delete_prefix("#{@root}/")
    return nil if rel == path # path wasn't under root (shouldn't happen)

    rel.split('/').first
  end
end

def parse_options(argv)
  opts = {
    top: 10,
    large_file_bytes: 100 * 1024 * 1024, # 100MB
    stale_days: 60,
    json: false,
    clean: false,
    excludes: []
  }

  parser = OptionParser.new do |o|
    o.banner = 'Usage: disk_usage_report.rb [path] [options]'
    o.on('--top N', Integer, 'How many top directories/files to show (default 10)') { |v| opts[:top] = v }
    o.on('--large-mb N', Integer, 'Flag individual files >= N MB (default 100)') { |v| opts[:large_file_bytes] = v * 1024 * 1024 }
    o.on('--stale-days N', Integer, 'Consider junk files older than N days stale (default 60)') { |v| opts[:stale_days] = v }
    o.on('--exclude PATH', 'Exclude a path from the scan (repeatable)') { |v| opts[:excludes] << v }
    o.on('--json', 'Emit JSON instead of a text report') { opts[:json] = true }
    o.on('--clean', 'Actually delete stale junk files found (default is dry-run report only)') { opts[:clean] = true }
    o.on('-h', '--help', 'Show this help') { puts o; exit 0 }
  end
  parser.parse!(argv)

  opts[:root] = argv.first || '.'
  opts
end

def print_text_report(result, opts)
  puts "Disk usage report for #{File.expand_path(opts[:root])}"
  puts "Files scanned: #{result.files_scanned}  |  Unreadable dirs skipped: #{result.dirs_skipped}"
  puts "Total size: #{human_size(result.total_bytes)}"
  puts

  puts "== Top #{opts[:top]} subdirectories by size =="
  result.by_child.first(opts[:top]).each do |name, size|
    pct = result.total_bytes.zero? ? 0 : (size.to_f / result.total_bytes * 100)
    printf("  %-30s %10s  (%.1f%%)\n", name, human_size(size), pct)
  end
  puts

  puts "== Files >= #{human_size(opts[:large_file_bytes])} (top #{opts[:top]}) =="
  if result.large_files.empty?
    puts '  none found'
  else
    result.large_files.first(opts[:top]).each do |path, size|
      printf("  %10s  %s\n", human_size(size), path)
    end
  end
  puts

  reclaimable = result.stale_files.sum { |_, s, _| s }
  puts "== Stale junk older than #{opts[:stale_days]}d (logs/tmp/core/swap) =="
  puts "  #{result.stale_files.size} files, #{human_size(reclaimable)} reclaimable"
  result.stale_files.first(opts[:top]).each do |path, size, mtime|
    printf("  %10s  %s  (mtime %s)\n", human_size(size), path, mtime.strftime('%Y-%m-%d'))
  end
end

def print_json_report(result, opts)
  puts JSON.pretty_generate(
    root: File.expand_path(opts[:root]),
    total_bytes: result.total_bytes,
    files_scanned: result.files_scanned,
    dirs_skipped: result.dirs_skipped,
    top_subdirectories: result.by_child.first(opts[:top]).map { |n, s| { name: n, bytes: s } },
    large_files: result.large_files.first(opts[:top]).map { |p, s| { path: p, bytes: s } },
    stale_files: result.stale_files.map { |p, s, m| { path: p, bytes: s, mtime: m.iso8601 } },
    stale_reclaimable_bytes: result.stale_files.sum { |_, s, _| s }
  )
end

def clean_stale_files!(result)
  freed = 0
  result.stale_files.each do |path, size, _|
    File.delete(path)
    freed += size
    puts "deleted: #{path} (#{human_size(size)})"
  rescue Errno::ENOENT, Errno::EACCES => e
    warn "skip #{path}: #{e.message}"
  end
  puts "\nFreed #{human_size(freed)} across #{result.stale_files.size} files."
end

if __FILE__ == $PROGRAM_NAME
  opts = parse_options(ARGV)
  walker = DiskWalker.new(
    opts[:root],
    large_file_bytes: opts[:large_file_bytes],
    stale_days: opts[:stale_days],
    excludes: opts[:excludes]
  )
  result = walker.walk

  if opts[:json]
    print_json_report(result, opts)
  else
    print_text_report(result, opts)
  end

  if opts[:clean]
    if result.stale_files.empty?
      puts "\nNothing to clean."
    else
      print "\nAbout to permanently delete #{result.stale_files.size} files. Type 'yes' to confirm: "
      confirm = $stdin.gets&.strip
      if confirm == 'yes'
        clean_stale_files!(result)
      else
        puts 'Aborted — no files deleted.'
      end
    end
  end
end
