#!/usr/bin/env ruby
# frozen_string_literal: true
# disk_usage_report.rb - Report filesystem usage and the biggest directories.
# Usage: ruby disk_usage_report.rb [--path DIR] [--top N] [--warn PCT] [--crit PCT] [--json]
# Exit codes: 0 ok, 1 warning, 2 critical (handy for cron / monitoring).
require 'optparse'
require 'json'
require 'open3'

Filesystem = Struct.new(:device, :size_kb, :used_kb, :avail_kb, :pct, :mount)

# Convert kilobytes to a human readable string.
def human(kb)
  units = %w[KB MB GB TB]
  v = kb.to_f
  i = 0
  while v >= 1024 && i < units.size - 1
    v /= 1024
    i += 1
  end
  format('%.1f %s', v, units[i])
end

# Parse the output of `df -P -k` (POSIX format: one line per filesystem).
def parse_df(text)
  text.lines.drop(1).filter_map do |line|
    f = line.split
    next if f.size < 6
    Filesystem.new(f[0], f[1].to_i, f[2].to_i, f[3].to_i, f[4].to_i, f[5..].join(' '))
  end
end

def read_df
  out, status = Open3.capture2('df', '-P', '-k')
  raise 'df failed' unless status.success?
  # Skip pseudo filesystems that are never interesting for capacity planning.
  parse_df(out).reject { |fs| fs.device =~ /\A(tmpfs|devtmpfs|overlay|udev|none)\z/ || fs.size_kb.zero? }
end

# Sum file sizes under each immediate child of root. Does not follow symlinks.
def dir_sizes(root)
  sizes = Hash.new(0)
  Dir.children(root).each do |child|
    path = File.join(root, child)
    next if File.symlink?(path)
    if File.directory?(path)
      Dir.glob(File.join(path, '**', '*'), File::FNM_DOTMATCH).each do |f|
        sizes[path] += File.size(f) / 1024 if File.file?(f) && !File.symlink?(f)
      rescue SystemCallError
        next # unreadable file: skip rather than abort the whole report
      end
    elsif File.file?(path)
      sizes[path] += File.size(path) / 1024
    end
  rescue SystemCallError
    next
  end
  sizes
end

def level(pct, warn, crit)
  return :critical if pct >= crit
  return :warning if pct >= warn
  :ok
end

opts = { path: '.', top: 5, warn: 80, crit: 90, json: false }
OptionParser.new do |o|
  o.on('--path DIR') { |v| opts[:path] = v }
  o.on('--top N', Integer) { |v| opts[:top] = v }
  o.on('--warn PCT', Integer) { |v| opts[:warn] = v }
  o.on('--crit PCT', Integer) { |v| opts[:crit] = v }
  o.on('--json') { opts[:json] = true }
end.parse!

filesystems = read_df
top = dir_sizes(opts[:path]).sort_by { |_, s| -s }.first(opts[:top])
worst = filesystems.map { |fs| level(fs.pct, opts[:warn], opts[:crit]) }.max_by { |l| %i[ok warning critical].index(l) } || :ok

if opts[:json]
  puts JSON.pretty_generate(
    filesystems: filesystems.map { |fs| fs.to_h.merge(level: level(fs.pct, opts[:warn], opts[:crit])) },
    top_dirs: top.map { |p, s| { path: p, kb: s } }, status: worst
  )
else
  puts format('%-22s %9s %9s %5s  %s', 'MOUNT', 'SIZE', 'USED', 'USE%', 'STATUS')
  filesystems.each do |fs|
    puts format('%-22s %9s %9s %4d%%  %s', fs.mount, human(fs.size_kb), human(fs.used_kb), fs.pct,
                level(fs.pct, opts[:warn], opts[:crit]).to_s.upcase)
  end
  puts "\nTop #{opts[:top]} entries under #{opts[:path]}:"
  top.each { |p, s| puts format('  %10s  %s', human(s), p) }
end
exit({ ok: 0, warning: 1, critical: 2 }[worst])
