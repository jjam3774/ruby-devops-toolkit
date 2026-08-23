#!/usr/bin/env ruby
# frozen_string_literal: true
#
# duplicate_file_finder.rb -- find duplicate files and reclaimable space.
#
# Duplicate files quietly eat disk: the same ISO in three download folders,
# a photo library copied "just in case", build artifacts checked in twice.
# This finds byte-for-byte duplicates efficiently and reports how much space
# you'd get back by keeping one copy of each.
#
#   ruby duplicate_file_finder.rb ~/Downloads ~/Documents
#   ruby duplicate_file_finder.rb /data --min-size 1048576   # ignore < 1 MiB
#   ruby duplicate_file_finder.rb /data --json
#   ruby duplicate_file_finder.rb /data --script > dedup.sh  # emit rm commands
#
# Efficiency: files are first grouped by SIZE (a cheap stat). Only groups with
# 2+ same-size files are hashed, and hashing is done in two stages -- a fast
# partial hash of the first 64 KiB, then a full SHA-256 only for partial-hash
# collisions -- so huge unique files are never fully read.
#
# Stdlib only: find, digest, json, optparse. No gems. Cross-platform.

require 'find'
require 'digest'
require 'json'
require 'optparse'

options = { min_size: 1, json: false, script: false }
OptionParser.new do |o|
  o.banner = 'Usage: ruby duplicate_file_finder.rb DIR [DIR...] [options]'
  o.on('--min-size BYTES', Integer, 'ignore files smaller than BYTES (default 1)') { |v| options[:min_size] = v }
  o.on('--json', 'JSON output') { options[:json] = true }
  o.on('--script', 'emit shell rm commands (keeps the first of each group)') { options[:script] = true }
end.parse!

roots = ARGV
abort('error: give me at least one directory to scan') if roots.empty?

def human(bytes)
  units = %w[B KiB MiB GiB TiB]
  size = bytes.to_f; i = 0
  while size >= 1024 && i < units.size - 1
    size /= 1024; i += 1
  end
  format(i.zero? ? '%d %s' : '%.1f %s', size, units[i])
end

PARTIAL = 64 * 1024   # bytes read for the fast pre-hash

def partial_hash(path)
  File.open(path, 'rb') { |f| Digest::SHA256.hexdigest(f.read(PARTIAL) || '') }
end

def full_hash(path)
  d = Digest::SHA256.new
  File.open(path, 'rb') { |f| d.update(f.read(1 << 20)) until f.eof? }
  d.hexdigest
end

# --- stage 1: group candidate files by size --------------------------------
by_size = Hash.new { |h, k| h[k] = [] }
scanned = 0
roots.each do |root|
  Find.find(File.expand_path(root)) do |path|
    stat = File.lstat(path)
    next unless stat.file? && stat.size >= options[:min_size]
    scanned += 1
    by_size[stat.size] << path
  rescue Errno::EACCES, Errno::ENOENT, Errno::ELOOP
    next
  end
end

# --- stage 2 + 3: partial hash, then full hash only for collisions ---------
dupes = []   # [ [path, path, ...], size ]
by_size.each do |size, paths|
  next if paths.size < 2
  paths.group_by { |p| partial_hash(p) rescue nil }.each_value do |same_partial|
    next if same_partial.size < 2
    same_partial.group_by { |p| full_hash(p) rescue nil }.each_value do |same_full|
      dupes << [same_full, size] if same_full.compact.size > 1
    end
  end
end

dupes.sort_by! { |group, size| -(size * (group.size - 1)) }   # biggest wins first
reclaimable = dupes.sum { |group, size| size * (group.size - 1) }

if options[:script]
  puts '#!/bin/sh'
  puts "# review before running -- keeps the FIRST file of each duplicate group"
  dupes.each do |group, _|
    group.drop(1).each { |p| puts "rm -- #{p.inspect}" }
  end
elsif options[:json]
  puts JSON.pretty_generate('scanned' => scanned,
                            'duplicate_groups' => dupes.size,
                            'reclaimable_bytes' => reclaimable,
                            'groups' => dupes.map { |g, s| { 'size' => s, 'copies' => g.size, 'files' => g } })
else
  puts "duplicate file finder -- scanned #{scanned} files in #{roots.join(', ')}"
  puts
  dupes.each do |group, size|
    puts "#{group.size} copies x #{human(size)}  (reclaim #{human(size * (group.size - 1))})"
    group.each { |p| puts "    #{p}" }
  end
  puts
  puts "#{dupes.size} duplicate groups, #{human(reclaimable)} reclaimable"
end

exit(dupes.empty? ? 0 : 1)   # exit 1 when duplicates exist -> easy cron gating
