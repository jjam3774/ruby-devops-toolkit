#!/usr/bin/env ruby
# frozen_string_literal: true
#
# disk_usage_report.rb - Find out where the disk space went.
# Walks a directory tree once (no shelling out to du) and reports:
#   * the biggest directories (cumulative size, rolled up from children)
#   * the biggest individual files
#   * usage grouped by file extension
#   * "stale giants": big files nobody has touched in N days
# Pure Ruby stdlib. Linux/macOS (works on Windows too, but ignores inodes).

require 'find'
require 'optparse'
require 'json'
require 'time'

Options = Struct.new(:path, :top, :stale_days, :min_stale_mb, :json, :one_fs)

def parse_options(argv)
  o = Options.new('.', 10, 180, 50, false, true)
  OptionParser.new do |op|
    op.banner = 'Usage: disk_usage_report.rb [options] [PATH]'
    op.on('-n', '--top N', Integer, 'rows per section (default 10)') { |v| o.top = v }
    op.on('--stale-days N', Integer, 'age threshold for stale giants (default 180)') { |v| o.stale_days = v }
    op.on('--min-stale-mb N', Integer, 'minimum size for a stale giant (default 50)') { |v| o.min_stale_mb = v }
    op.on('--json', 'emit JSON instead of text') { o.json = true }
    op.on('--cross-fs', 'descend into other filesystems') { o.one_fs = false }
  end.parse!(argv)
  o.path = argv.first || '.'
  o
end

# 1_536 -> "1.5 KiB"
def human(bytes)
  units = %w[B KiB MiB GiB TiB]
  size = bytes.to_f
  i = 0
  while size >= 1024 && i < units.size - 1
    size /= 1024
    i += 1
  end
  i.zero? ? "#{bytes} B" : format('%.1f %s', size, units[i])
end

def scan(opts)
  root = File.expand_path(opts.path)
  root_dev = File.stat(root).dev
  dir_sizes = Hash.new(0) # directory => cumulative bytes
  files = []              # [size, path, mtime]
  by_ext = Hash.new { |h, k| h[k] = [0, 0] } # ext => [count, bytes]
  errors = 0

  Find.find(root) do |path|
    begin
      st = File.lstat(path)
      if st.directory?
        # Don't cross mount points (e.g. /proc, NFS) unless asked to.
        Find.prune if opts.one_fs && st.dev != root_dev
        next
      end
      next unless st.file? # skip symlinks, sockets, devices

      # st.blocks * 512 is *allocated* space (matches du); falls back to size.
      size = st.blocks ? st.blocks * 512 : st.size
      files << [size, path, st.mtime]
      ext = File.extname(path).downcase
      ext = '(none)' if ext.empty?
      by_ext[ext][0] += 1
      by_ext[ext][1] += size

      # Roll the size up into every ancestor directory.
      dir = File.dirname(path)
      loop do
        dir_sizes[dir] += size
        break if dir == root || dir == File.dirname(dir)
        dir = File.dirname(dir)
      end
    rescue Errno::EACCES, Errno::ENOENT, Errno::EPERM
      errors += 1 # unreadable or vanished mid-scan; keep going
    end
  end

  cutoff = Time.now - opts.stale_days * 86_400
  min_bytes = opts.min_stale_mb * 1024 * 1024
  {
    root: root,
    total: dir_sizes[root],
    file_count: files.size,
    errors: errors,
    top_dirs: dir_sizes.reject { |d, _| d == root }.sort_by { |_, s| -s }.first(opts.top),
    top_files: files.sort_by { |s, _, _| -s }.first(opts.top),
    by_ext: by_ext.sort_by { |_, (_, b)| -b }.first(opts.top),
    stale: files.select { |s, _, m| s >= min_bytes && m < cutoff }.sort_by { |s, _, _| -s }.first(opts.top)
  }
end

def print_text(r, opts)
  puts "Disk usage report for #{r[:root]}"
  puts "Total: #{human(r[:total])} in #{r[:file_count]} files (#{r[:errors]} unreadable)"
  puts "\n== Biggest directories =="
  r[:top_dirs].each { |d, s| puts format('%10s  %5.1f%%  %s', human(s), r[:total].zero? ? 0 : s * 100.0 / r[:total], d) }
  puts "\n== Biggest files =="
  r[:top_files].each { |s, p, _| puts format('%10s  %s', human(s), p) }
  puts "\n== By extension =="
  r[:by_ext].each { |e, (c, b)| puts format('%10s  %6d files  %s', human(b), c, e) }
  puts "\n== Stale giants (>= #{opts.min_stale_mb} MiB, untouched #{opts.stale_days}+ days) =="
  if r[:stale].empty?
    puts '(none)'
  else
    r[:stale].each { |s, p, m| puts format('%10s  %s  %s', human(s), m.strftime('%Y-%m-%d'), p) }
  end
end

def print_json(r)
  puts JSON.pretty_generate(
    root: r[:root], total_bytes: r[:total], files: r[:file_count], errors: r[:errors],
    top_dirs: r[:top_dirs].map { |d, s| { path: d, bytes: s } },
    top_files: r[:top_files].map { |s, p, m| { path: p, bytes: s, mtime: m.iso8601 } },
    by_extension: r[:by_ext].map { |e, (c, b)| { ext: e, files: c, bytes: b } },
    stale_giants: r[:stale].map { |s, p, m| { path: p, bytes: s, mtime: m.iso8601 } }
  )
end

if $PROGRAM_NAME == __FILE__
  opts = parse_options(ARGV)
  abort "No such directory: #{opts.path}" unless File.directory?(opts.path)
  res = scan(opts)
  opts.json ? print_json(res) : print_text(res, opts)
end
