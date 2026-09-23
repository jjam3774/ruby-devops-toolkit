#!/usr/bin/env ruby
# frozen_string_literal: true
#
# ftp_dir_sync.rb -- One-way directory sync from a local path up to a remote
# FTP server, using only Ruby's bundled net/ftp (no third-party gems).
#
# Solves a genuinely common ops task: shipping build artifacts, static site
# exports, or nightly report files up to a legacy FTP drop (many shared
# hosts, print vendors, and older EDI partners still only accept FTP).
# Skips files that are already present and unchanged (by size, then a byte
# comparison for same-size files) so re-runs are cheap, creates missing
# remote directories, retries transient failures, and supports a dry run.
#
# Usage:
#   ruby ftp_dir_sync.rb --host ftp.example.com --user deploy --local ./dist --remote /www/site
#   FTP_PASSWORD=secret ruby ftp_dir_sync.rb --host ftp.example.com --user deploy \
#       --local ./dist --remote /www/site --delete-orphans --dry-run
#
# Exit codes: 0 = sync completed (possibly with 0 files to do)
#             1 = fatal error (couldn't connect/login)
#             2 = one or more files failed to transfer after retries

require 'net/ftp'
require 'optparse'
require 'find'
require 'digest'

options = {
  host: nil, port: 21, user: 'anonymous', password: ENV['FTP_PASSWORD'],
  local: nil, remote: '/', passive: true, retries: 3, dry_run: false,
  delete_orphans: false
}

OptionParser.new do |o|
  o.banner = 'Usage: ftp_dir_sync.rb --host HOST --local DIR --remote DIR [options]'
  o.on('--host HOST', 'FTP server hostname') { |v| options[:host] = v }
  o.on('--port PORT', Integer, 'FTP port (default 21)') { |v| options[:port] = v }
  o.on('--user USER', 'FTP username (default anonymous)') { |v| options[:user] = v }
  o.on('--password PASS', 'FTP password (prefer FTP_PASSWORD env var instead)') { |v| options[:password] = v }
  o.on('--local DIR', 'Local directory to push') { |v| options[:local] = v }
  o.on('--remote DIR', 'Remote directory to push into') { |v| options[:remote] = v }
  o.on('--no-passive', 'Use active mode instead of passive') { options[:passive] = false }
  o.on('--retries N', Integer, 'Retry attempts per file (default 3)') { |v| options[:retries] = v }
  o.on('--delete-orphans', 'Delete remote files with no local counterpart') { options[:delete_orphans] = true }
  o.on('--dry-run', 'Show what would happen without transferring anything') { options[:dry_run] = true }
  o.on('-h', '--help', 'Show this help') { puts o; exit 0 }
end.parse!

if options[:host].nil? || options[:local].nil?
  warn 'Error: --host and --local are required (see --help)'
  exit 1
end

unless Dir.exist?(options[:local])
  warn "Error: local directory #{options[:local]} does not exist"
  exit 1
end

# Normalize away a trailing slash so path joins below never produce "//".
# (root "/" becomes "", so later "#{remote}/#{rel}" joins still come out as
# the correct single-leading-slash absolute path.)
options[:remote] = options[:remote].sub(%r{/+\z}, '')

# ---------------------------------------------------------------------------
# Walk the local tree and build a map of relative_path => {size:, abs_path:}
# ---------------------------------------------------------------------------
def local_manifest(root)
  manifest = {}
  Find.find(root) do |path|
    next if File.directory?(path)

    rel = path.sub(%r{\A#{Regexp.escape(root)}/?}, '')
    manifest[rel] = { abs_path: path, size: File.size(path) }
  end
  manifest
end

# Ensure every directory component of a remote relative path exists,
# creating them one level at a time (FTP has no `mkdir -p`).
def ensure_remote_dir(ftp, remote_root, rel_dir)
  return if rel_dir.empty? || rel_dir == '.'

  parts = rel_dir.split('/')
  current = remote_root
  parts.each do |part|
    current = "#{current}/#{part}"
    begin
      ftp.mkdir(current)
    rescue Net::FTPPermError => e
      # 550 "already exists" is expected and fine; anything else re-raises.
      raise unless e.message.include?('550')
    end
  end
end

# Compare local and remote by size first (cheap), and only fall back to a
# full byte-for-byte re-download-and-compare for same-size files, since FTP
# has no standard remote-checksum command.
def unchanged?(ftp, remote_path, local_info)
  remote_size = ftp.size(remote_path)
  return false unless remote_size == local_info[:size]

  tmp = "#{local_info[:abs_path]}.remote_check.tmp"
  begin
    ftp.getbinaryfile(remote_path, tmp)
    Digest::SHA256.file(tmp).hexdigest == Digest::SHA256.file(local_info[:abs_path]).hexdigest
  ensure
    File.delete(tmp) if File.exist?(tmp)
  end
rescue Net::FTPPermError
  false # remote file doesn't exist yet
end

# Recursively list every FILE (never directories) under a remote root, by
# walking with NLST + a directory-or-not probe. NLST alone is not recursive,
# and naively deleting whatever NLST returns at the top level can hand you a
# directory and blow up with "550 Is a directory" -- so we only ever collect
# and delete leaf files here, and existing subdirectories are simply left in
# place (deleting an emptied-out directory is a rmdir, not a delete, and
# isn't attempted by this script).
def remote_files_recursive(ftp, dir)
  files = []
  entries = begin
    ftp.nlst(dir)
  rescue Net::FTPPermError
    []
  end

  entries.each do |entry|
    name = File.basename(entry)
    next if %w[. ..].include?(name)

    full_path = entry.start_with?('/') ? entry : "#{dir}/#{name}"
    if directory?(ftp, full_path)
      files.concat(remote_files_recursive(ftp, full_path))
    else
      files << full_path
    end
  end
  files
end

def directory?(ftp, path)
  ftp.size(path)
  false
rescue Net::FTPPermError
  # Not sizeable -- almost always because it's a directory. A genuinely
  # missing path would already have been filtered out by the NLST above.
  true
end

def with_retries(retries)
  attempt = 0
  begin
    attempt += 1
    yield
  rescue Net::FTPTempError, Net::FTPConnectionError, Errno::ECONNRESET, EOFError => e
    if attempt <= retries
      warn "  retry #{attempt}/#{retries} after: #{e.message}"
      sleep(0.5 * attempt)
      retry
    end
    raise
  end
end

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
manifest = local_manifest(options[:local])
puts "Found #{manifest.size} local file(s) under #{options[:local]}"

uploaded = skipped = failed = deleted = 0

begin
  ftp = Net::FTP.new
  ftp.passive = options[:passive]
  ftp.connect(options[:host], options[:port])
  ftp.login(options[:user], options[:password])
  puts "Connected to #{options[:host]}:#{options[:port]} as #{options[:user]} (passive=#{options[:passive]})"
rescue StandardError => e
  warn "FATAL: could not connect/login: #{e.message}"
  exit 1
end

# Make sure the remote root itself exists before anything tries to upload
# into it -- ensure_remote_dir below only creates directories *under* a
# known-to-exist root, so the root is a special case handled once up front.
unless options[:dry_run] || options[:remote].empty?
  begin
    ensure_remote_dir(ftp, '', options[:remote].sub(%r{\A/}, ''))
  rescue StandardError => e
    warn "FATAL: could not create remote root #{options[:remote]}: #{e.message}"
    exit 1
  end
end

remote_seen = []

manifest.each do |rel, info|
  remote_path = "#{options[:remote]}/#{rel}"
  remote_seen << remote_path
  rel_dir = File.dirname(rel)

  if unchanged?(ftp, remote_path, info)
    skipped += 1
    next
  end

  if options[:dry_run]
    puts "[dry-run] would upload #{rel} -> #{remote_path}"
    uploaded += 1
    next
  end

  begin
    with_retries(options[:retries]) do
      ensure_remote_dir(ftp, options[:remote], rel_dir)
      ftp.putbinaryfile(info[:abs_path], remote_path)
    end
    puts "uploaded #{rel} (#{info[:size]} bytes)"
    uploaded += 1
  rescue StandardError => e
    warn "FAILED #{rel}: #{e.message}"
    failed += 1
  end
end

if options[:delete_orphans]
  begin
    remote_files = remote_files_recursive(ftp, options[:remote])
    orphans = remote_files - remote_seen
    orphans.each do |orphan|
      if options[:dry_run]
        puts "[dry-run] would delete orphan #{orphan}"
      else
        ftp.delete(orphan)
        puts "deleted orphan #{orphan}"
      end
      deleted += 1
    end
  rescue Net::FTPPermError => e
    warn "Could not list remote directory for orphan cleanup: #{e.message}"
  end
end

ftp.close

puts "Done. uploaded=#{uploaded} skipped=#{skipped} failed=#{failed} deleted=#{deleted}"
exit(failed.positive? ? 2 : 0)
