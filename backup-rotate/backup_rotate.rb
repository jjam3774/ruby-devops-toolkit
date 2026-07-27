#!/usr/bin/env ruby
# frozen_string_literal: true
#
# backup_rotate.rb - Back up a directory to a timestamped, gzip-compressed
# tarball, verify it with a SHA-256 checksum, and enforce a retention policy
# so old backups don't quietly fill the disk. Meant to be dropped into cron
# for config directories, small databases dumps, or app data folders that
# don't already have a dedicated backup tool.
#
# Usage:
#   ruby backup_rotate.rb /etc/myapp /var/backups/myapp
#   ruby backup_rotate.rb /etc/myapp /var/backups/myapp --keep 14
#   ruby backup_rotate.rb /etc/myapp /var/backups/myapp --keep 14 --json
#   ruby backup_rotate.rb --verify-only /var/backups/myapp
#
# Prerequisites: the `tar` and `gzip` binaries on PATH (present on every
# Linux distro and macOS by default; on Windows use WSL or Git Bash's tar).
#
# Exit codes:
#   0 - backup (and rotation) succeeded, checksum verified
#   1 - checksum verification failed (backup is untrustworthy - do not rely on it)
#   2 - usage / input error (bad paths, missing source dir, etc.)

require 'optparse'
require 'fileutils'
require 'digest'
require 'json'
require 'time'
require 'open3'

# One backup archive plus its checksum sidecar file.
BackupArtifact = Struct.new(:path, :checksum_path, :sha256, :bytes, :created_at)

class BackupError < StandardError; end

# Creates a compressed tar archive of `source_dir`, computes its SHA-256,
# writes a `.sha256` sidecar file next to it, and re-reads the archive to
# confirm the checksum matches what's on disk (catches truncated writes from
# a full disk or an interrupted process).
class BackupCreator
  def initialize(source_dir, dest_dir)
    @source_dir = source_dir
    @dest_dir = dest_dir
  end

  def create(timestamp: Time.now)
    validate_source!
    FileUtils.mkdir_p(@dest_dir)

    stamp = timestamp.strftime('%Y%m%d-%H%M%S')
    archive_name = "#{File.basename(@source_dir)}-#{stamp}.tar.gz"
    archive_path = File.join(@dest_dir, archive_name)

    run_tar(archive_path)
    sha256 = Digest::SHA256.file(archive_path).hexdigest
    checksum_path = "#{archive_path}.sha256"
    File.write(checksum_path, "#{sha256}  #{archive_name}\n")

    artifact = BackupArtifact.new(archive_path, checksum_path, sha256,
                                   File.size(archive_path), timestamp)
    verify(artifact) # raises BackupError if the just-written file is bad
    artifact
  end

  # Re-hashes the archive on disk and compares it to the recorded checksum.
  # Used both right after creation and later via --verify-only.
  def self.verify_file(archive_path)
    checksum_path = "#{archive_path}.sha256"
    raise BackupError, "no checksum sidecar found at #{checksum_path}" unless File.exist?(checksum_path)

    recorded = File.read(checksum_path).split(/\s+/).first
    actual = Digest::SHA256.file(archive_path).hexdigest
    recorded == actual
  end

  private

  def verify(artifact)
    return if self.class.verify_file(artifact.path)

    raise BackupError, "checksum mismatch immediately after writing #{artifact.path} - disk full or write error?"
  end

  def validate_source!
    raise BackupError, "source directory does not exist: #{@source_dir}" unless Dir.exist?(@source_dir)
  end

  def run_tar(archive_path)
    parent = File.dirname(@source_dir)
    base = File.basename(@source_dir)
    # -C cd's tar into the parent dir first, so the archive contains a
    # relative "myapp/..." path instead of an absolute path baked in -
    # standard practice so archives can be restored to any location.
    _out, err, status = Open3.capture3('tar', '-czf', archive_path, '-C', parent, base)
    raise BackupError, "tar failed: #{err.strip}" unless status.success?
  end
end

# Deletes the oldest backups (archive + sidecar together) once there are
# more than `keep` of them in the destination directory.
class RetentionPolicy
  def initialize(dest_dir, keep:)
    @dest_dir = dest_dir
    @keep = keep
  end

  # Returns the list of archive paths that were deleted.
  def enforce
    archives = Dir.glob(File.join(@dest_dir, '*.tar.gz')).sort_by { |p| File.mtime(p) }
    return [] if archives.size <= @keep

    to_delete = archives[0...(archives.size - @keep)]
    to_delete.each do |archive|
      File.delete(archive) if File.exist?(archive)
      sidecar = "#{archive}.sha256"
      File.delete(sidecar) if File.exist?(sidecar)
    end
    to_delete
  end
end

# ---- CLI -----------------------------------------------------------------

def parse_options(argv)
  opts = { keep: 7, json: false, verify_only: nil }
  parser = OptionParser.new do |o|
    o.banner = 'Usage: backup_rotate.rb SOURCE_DIR DEST_DIR [options]' \
               "\n       backup_rotate.rb --verify-only DEST_DIR"
    o.on('-k', '--keep N', Integer, 'Number of backups to retain (default 7)') { |v| opts[:keep] = v }
    o.on('-j', '--json', 'Emit machine-readable JSON instead of a text report') { opts[:json] = true }
    o.on('--verify-only DIR', 'Verify checksums of all archives in DIR, take no backup') { |v| opts[:verify_only] = v }
    o.on('-h', '--help', 'Show this help') { puts o; exit 0 }
  end
  parser.parse!(argv)
  [argv, opts, parser]
end

def run_verify_only(dir, json)
  archives = Dir.glob(File.join(dir, '*.tar.gz')).sort
  if archives.empty?
    warn "backup_rotate: no archives found in #{dir}"
    exit 2
  end

  results = archives.map do |path|
    ok =
      begin
        BackupCreator.verify_file(path)
      rescue BackupError
        false
      end
    { path: path, ok: ok }
  end

  if json
    puts JSON.pretty_generate(results: results)
  else
    results.each { |r| puts "#{r[:ok] ? 'OK    ' : 'FAILED'}  #{r[:path]}" }
  end
  exit(results.all? { |r| r[:ok] } ? 0 : 1)
end

if $PROGRAM_NAME == __FILE__
  argv, opts, parser = parse_options(ARGV.dup)

  if opts[:verify_only]
    run_verify_only(opts[:verify_only], opts[:json])
  end

  if argv.size != 2
    warn parser
    exit 2
  end
  source_dir, dest_dir = argv

  unless Dir.exist?(source_dir)
    warn "backup_rotate: source directory does not exist: #{source_dir}"
    exit 2
  end

  begin
    artifact = BackupCreator.new(source_dir, dest_dir).create
  rescue BackupError => e
    warn "backup_rotate: #{e.message}"
    exit 1
  end

  deleted = RetentionPolicy.new(dest_dir, keep: opts[:keep]).enforce

  if opts[:json]
    puts JSON.pretty_generate(
      archive: artifact.path,
      sha256: artifact.sha256,
      bytes: artifact.bytes,
      created_at: artifact.created_at.iso8601,
      rotated_out: deleted
    )
  else
    puts "backup_rotate: created #{artifact.path} (#{artifact.bytes} bytes)"
    puts "  sha256: #{artifact.sha256}"
    puts "  checksum verified OK"
    if deleted.any?
      puts "  rotated out #{deleted.size} old backup(s):"
      deleted.each { |d| puts "    - #{d}" }
    else
      puts "  no backups rotated out (#{Dir.glob(File.join(dest_dir, '*.tar.gz')).size}/#{opts[:keep]} kept)"
    end
  end

  exit 0
end
