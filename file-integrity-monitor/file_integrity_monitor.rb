#!/usr/bin/env ruby
# frozen_string_literal: true
#
# file_integrity_monitor.rb — A lightweight, dependency-free file integrity
# monitor (FIM). Snapshots SHA-256 hashes, mtimes, sizes, and permission bits
# for every file under one or more watched paths, then on later runs diffs
# the current state against the saved baseline and reports what changed.
#
# Problem this solves:
#   You want to know when something under /etc, a webroot, or a deploy
#   directory changes *outside* of your normal deploy/config-management
#   process — a sign of tampering, a misconfigured process writing where it
#   shouldn't, or just "who touched this file and when." Commercial/AIDE-
#   style tools solve this, but a lot of shops just need something small,
#   auditable, and cron-friendly. This script is that: two subcommands,
#   one JSON baseline file, no daemon, no external services.
#
# Usage:
#   ruby file_integrity_monitor.rb baseline PATH [PATH ...] [--db FILE]
#   ruby file_integrity_monitor.rb check    [--db FILE] [--exit-code]
#
# Examples:
#   ruby file_integrity_monitor.rb baseline /etc/nginx /etc/ssh --db fim.json
#   ruby file_integrity_monitor.rb check --db fim.json --exit-code
#
# Exit codes (check subcommand with --exit-code):
#   0  no changes detected
#   1  changes detected (added/removed/modified files)
#   2  usage / IO error

require 'digest'
require 'find'
require 'json'
require 'time'
require 'optparse'

BANNER = <<~USAGE
  Usage:
    file_integrity_monitor.rb baseline PATH [PATH ...] [--db FILE]
    file_integrity_monitor.rb check    [--db FILE] [--exit-code]
USAGE

def sha256_of(path)
  digest = Digest::SHA256.new
  File.open(path, 'rb') { |f| digest.update(f.read(65_536)) while !f.eof? }
  digest.hexdigest
rescue Errno::EACCES, Errno::ENOENT
  nil # unreadable file — recorded as a hash of nil so it still shows up as "changed" if it later becomes readable
end

# Build a fingerprint record for a single file: hash + the metadata that
# commonly matters for security review (mtime, size, POSIX mode bits).
def record_for(path)
  stat = File.stat(path)
  {
    'sha256' => sha256_of(path),
    'size' => stat.size,
    'mtime' => stat.mtime.utc.iso8601,
    'mode' => stat.mode.to_s(8)[-4..] # last 4 octal digits, e.g. "0644"
  }
rescue Errno::EACCES, Errno::ENOENT
  nil
end

# Walk every watched root and build { absolute_path => record }.
# Symlinks are skipped (not followed) to avoid escaping the watched tree
# and to avoid false positives from targets that move around.
def snapshot(paths)
  state = {}
  paths.each do |root|
    unless File.exist?(root)
      warn "WARNING: watched path does not exist, skipping: #{root}"
      next
    end
    Find.find(root) do |path|
      next if File.symlink?(path)
      next unless File.file?(path)
      rec = record_for(path)
      state[path] = rec if rec
    end
  end
  state
end

def load_db(path)
  raise "baseline file not found: #{path}\n(run the 'baseline' subcommand first)" unless File.exist?(path)
  JSON.parse(File.read(path))
end

def save_db(path, watched_paths, state)
  payload = {
    'generated_at' => Time.now.utc.iso8601,
    'watched_paths' => watched_paths,
    'files' => state
  }
  File.write(path, JSON.pretty_generate(payload))
end

# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_baseline(args, db_path)
  if args.empty?
    warn BANNER
    exit 2
  end
  puts "Building baseline over: #{args.join(', ')}"
  state = snapshot(args)
  save_db(db_path, args, state)
  puts "Baseline saved: #{db_path} (#{state.size} file(s))"
end

def cmd_check(db_path, want_exit_code)
  db = load_db(db_path)
  watched_paths = db['watched_paths']
  baseline = db['files']

  puts "Checking #{watched_paths.join(', ')} against baseline from #{db['generated_at']}"
  current = snapshot(watched_paths)

  added = current.keys - baseline.keys
  removed = baseline.keys - current.keys
  common = current.keys & baseline.keys

  modified = common.select do |path|
    old = baseline[path]
    new = current[path]
    old['sha256'] != new['sha256'] || old['mode'] != new['mode']
  end

  permission_only = modified.select do |path|
    baseline[path]['sha256'] == current[path]['sha256'] && baseline[path]['mode'] != current[path]['mode']
  end
  content_changed = modified - permission_only

  if added.empty? && removed.empty? && modified.empty?
    puts 'RESULT: no changes detected (%d files checked)' % current.size
    exit 0 if want_exit_code
    return
  end

  puts "RESULT: CHANGES DETECTED"
  unless added.empty?
    puts "\n+ ADDED (#{added.size}):"
    added.sort.each { |p| puts "    #{p}" }
  end
  unless removed.empty?
    puts "\n- REMOVED (#{removed.size}):"
    removed.sort.each { |p| puts "    #{p}" }
  end
  unless content_changed.empty?
    puts "\n~ CONTENT CHANGED (#{content_changed.size}):"
    content_changed.sort.each do |p|
      old_sha = baseline[p]['sha256']
      new_sha = current[p]['sha256']
      old_short = old_sha ? old_sha[0, 10] : 'unreadable'
      new_short = new_sha ? new_sha[0, 10] : 'unreadable'
      puts "    #{p}"
      puts "        sha256: #{old_short}... -> #{new_short}..."
      puts "        mtime:  #{baseline[p]['mtime']} -> #{current[p]['mtime']}"
    end
  end
  unless permission_only.empty?
    puts "\n! PERMISSIONS CHANGED (#{permission_only.size}):"
    permission_only.each do |p|
      puts "    #{p}: #{baseline[p]['mode']} -> #{current[p]['mode']}"
    end
  end

  exit 1 if want_exit_code
end

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

subcommand = ARGV.shift
db_path = 'fim.json'
want_exit_code = false

remaining = []
i = 0
while i < ARGV.length
  case ARGV[i]
  when '--db'
    db_path = ARGV[i + 1]
    i += 2
  when '--exit-code'
    want_exit_code = true
    i += 1
  when '-h', '--help'
    puts BANNER
    exit 0
  else
    remaining << ARGV[i]
    i += 1
  end
end

case subcommand
when 'baseline'
  cmd_baseline(remaining, db_path)
when 'check'
  cmd_check(db_path, want_exit_code)
else
  warn BANNER
  exit 2
end
