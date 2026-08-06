#!/usr/bin/env ruby
# frozen_string_literal: true
#
# backup_verify.rb — Create tar.gz backups of a directory, checksum them,
# and *prove* they restore correctly by extracting to a scratch directory
# and diffing file-by-file against the source.
#
# Problem this solves:
#   Most "backup" scripts stop at "the tarball exists." Nobody finds out a
#   backup is corrupt / incomplete until the day they actually need it —
#   which is the worst possible day to learn that. This script closes that
#   gap: every backup run also runs a restore-test in the same pass, so a
#   failed backup fails LOUDLY at 2am via a non-zero exit code and a log
#   line, not three months later during a disaster recovery.
#
# Usage:
#   ruby backup_verify.rb SOURCE_DIR BACKUP_DIR [--keep N] [--manifest FILE]
#
# Example:
#   ruby backup_verify.rb /etc/myapp /var/backups/myapp --keep 7
#
# Exit codes:
#   0  backup created and verified successfully
#   1  backup verification failed (checksum mismatch or restore diff)
#   2  usage / IO error (bad args, source missing, etc.)

require 'digest'
require 'fileutils'
require 'find'
require 'time'
require 'optparse'
require 'json'
require 'tmpdir'
require 'open3'

# ---------------------------------------------------------------------------
# CLI options
# ---------------------------------------------------------------------------
options = { keep: 7, manifest: nil }
parser = OptionParser.new do |o|
  o.banner = 'Usage: backup_verify.rb SOURCE_DIR BACKUP_DIR [options]'
  o.on('--keep N', Integer, 'How many backups to retain (default 7)') { |n| options[:keep] = n }
  o.on('--manifest FILE', 'Where to write the JSON run manifest (default BACKUP_DIR/manifest.json)') { |f| options[:manifest] = f }
  o.on('-h', '--help', 'Show this help') { puts o; exit 0 }
end
parser.parse!(ARGV)

source_dir = ARGV[0]
backup_dir = ARGV[1]

if source_dir.nil? || backup_dir.nil?
  warn parser.banner
  exit 2
end

unless Dir.exist?(source_dir)
  warn "ERROR: source directory does not exist: #{source_dir}"
  exit 2
end

FileUtils.mkdir_p(backup_dir)
options[:manifest] ||= File.join(backup_dir, 'manifest.json')

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Compute a SHA-256 for a single file, streaming in 64KB chunks so large
# files don't get slurped fully into memory.
def sha256_of(path)
  digest = Digest::SHA256.new
  File.open(path, 'rb') do |f|
    while (chunk = f.read(65_536))
      digest.update(chunk)
    end
  end
  digest.hexdigest
end

# Cheap relative-path helper (avoids pulling in the 'pathname' stdlib just
# for one call — plain String#sub does the job here).
def relative_to(path, root)
  root_with_slash = root.end_with?('/') ? root : "#{root}/"
  path.sub(root_with_slash, '')
end

# Build a { relative_path => sha256 } map for every regular file under root.
# Used both to fingerprint the source tree and to fingerprint the restored
# tree, so the two maps can be diffed directly.
def fingerprint_tree(root)
  map = {}
  Find.find(root) do |path|
    next unless File.file?(path)
    rel = relative_to(path, root)
    map[rel] = sha256_of(path)
  end
  map
end

def run!(cmd)
  stdout, stderr, status = Open3.capture3(*cmd)
  [status.success?, stdout, stderr]
end

log = ->(msg) { puts "[#{Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ')}] #{msg}" }

# ---------------------------------------------------------------------------
# 1. Fingerprint the source tree BEFORE archiving
# ---------------------------------------------------------------------------
log.call("Fingerprinting source: #{source_dir}")
source_fingerprint = fingerprint_tree(source_dir)
log.call("  #{source_fingerprint.size} file(s) hashed")

# ---------------------------------------------------------------------------
# 2. Create the tar.gz archive
# ---------------------------------------------------------------------------
timestamp = Time.now.utc.strftime('%Y%m%d-%H%M%S')
base_name = File.basename(File.expand_path(source_dir))
archive_name = "#{base_name}-#{timestamp}.tar.gz"
archive_path = File.join(backup_dir, archive_name)

log.call("Creating archive: #{archive_path}")
parent = File.dirname(File.expand_path(source_dir))
entry = base_name
ok, _out, err = run!(['tar', '-C', parent, '-czf', archive_path, entry])
unless ok
  warn "ERROR: tar failed: #{err}"
  exit 1
end

archive_sha256 = sha256_of(archive_path)
archive_size = File.size(archive_path)
log.call("  archive size: #{archive_size} bytes, sha256: #{archive_sha256[0, 16]}...")

# ---------------------------------------------------------------------------
# 3. Restore-test: extract into a throwaway temp dir and diff
# ---------------------------------------------------------------------------
log.call('Running restore-test into scratch directory...')
restore_ok = true
diff_report = { missing: [], extra: [], mismatched: [] }

Dir.mktmpdir('backup-verify-restore-') do |scratch|
  ok, _out, err = run!(['tar', '-xzf', archive_path, '-C', scratch])
  unless ok
    warn "ERROR: restore extraction failed: #{err}"
    exit 1
  end

  restored_root = File.join(scratch, base_name)
  restored_fingerprint = fingerprint_tree(restored_root)

  # Files present in source but missing after restore
  diff_report[:missing] = source_fingerprint.keys - restored_fingerprint.keys
  # Files present after restore but not in source (shouldn't happen, but check)
  diff_report[:extra] = restored_fingerprint.keys - source_fingerprint.keys
  # Files present in both but with a different hash — silent corruption
  common = source_fingerprint.keys & restored_fingerprint.keys
  diff_report[:mismatched] = common.select { |k| source_fingerprint[k] != restored_fingerprint[k] }

  restore_ok = diff_report.values.all?(&:empty?)
end

if restore_ok
  log.call("Restore-test PASSED: all #{source_fingerprint.size} file(s) verified byte-for-byte")
else
  warn 'Restore-test FAILED:'
  warn "  missing:    #{diff_report[:missing].inspect}" unless diff_report[:missing].empty?
  warn "  extra:      #{diff_report[:extra].inspect}" unless diff_report[:extra].empty?
  warn "  mismatched: #{diff_report[:mismatched].inspect}" unless diff_report[:mismatched].empty?
end

# ---------------------------------------------------------------------------
# 4. Retention: keep only the newest N verified backups
# ---------------------------------------------------------------------------
existing = Dir.glob(File.join(backup_dir, "#{base_name}-*.tar.gz")).sort
excess = existing.length - options[:keep]
removed = []
if excess > 0
  existing.first(excess).each do |old|
    removed << File.basename(old)
    File.delete(old)
  end
  log.call("Retention: removed #{removed.size} old backup(s), keeping newest #{options[:keep]}")
end

# ---------------------------------------------------------------------------
# 5. Write a JSON manifest for this run (handy for monitoring/alerting hooks)
# ---------------------------------------------------------------------------
manifest_entry = {
  timestamp: Time.now.utc.iso8601,
  source_dir: File.expand_path(source_dir),
  archive: archive_name,
  archive_sha256: archive_sha256,
  archive_size_bytes: archive_size,
  files_verified: source_fingerprint.size,
  restore_verified: restore_ok,
  diff: diff_report,
  removed_old_backups: removed
}

history = File.exist?(options[:manifest]) ? JSON.parse(File.read(options[:manifest])) : []
history << JSON.parse(manifest_entry.to_json) # round-trip to plain hash w/ string keys
File.write(options[:manifest], JSON.pretty_generate(history))
log.call("Manifest updated: #{options[:manifest]}")

if restore_ok
  log.call('RESULT: OK')
  exit 0
else
  log.call('RESULT: FAILED')
  exit 1
end
