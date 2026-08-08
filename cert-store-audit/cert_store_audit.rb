#!/usr/bin/env ruby
# frozen_string_literal: true
#
# cert_store_audit.rb -- Local certificate & private-key store auditor.
#
# Live TLS checkers (openssl s_client, or a script that connects to host:443)
# only tell you about the ONE certificate a server happens to be presenting
# right now. They say nothing about the dozen other .pem/.crt/.key files
# sitting on that box: the old cert someone forgot to delete, the key file
# world-readable since the last deploy, the self-signed cert some app picked
# up as a "just get it working" default eighteen months ago. This script
# walks a directory tree, finds every certificate and private key it can
# read, and reports on all of them at once -- expiry, key strength,
# self-signed status, file permissions, and whether cert/key pairs actually
# match.
#
# No gems required -- everything here is Ruby stdlib (openssl, find,
# optparse, json).
#
# Usage:
#   ruby cert_store_audit.rb [dir ...] [options]
#
# Examples:
#   ruby cert_store_audit.rb /etc/ssl /etc/nginx /opt/app/certs
#   ruby cert_store_audit.rb /etc/ssl --json
#   ruby cert_store_audit.rb /etc/ssl --min-days 45 --min-key-bits 3072
#
# Exit codes (cron/CI friendly):
#   0 - everything OK
#   1 - warnings only (expiring soon, weak-but-not-broken key, etc.)
#   2 - critical findings (expired cert, key/cert mismatch, world-readable
#       private key, key below the minimum bit length)

require 'openssl'
require 'find'
require 'optparse'
require 'json'
require 'time'

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------

options = {
  min_days: 30,
  min_key_bits: 2048,
  extensions: %w[.pem .crt .cer .key],
  json: false,
  quiet: false
}

parser = OptionParser.new do |opts|
  opts.banner = "Usage: cert_store_audit.rb [dir ...] [options]"
  opts.on('--min-days N', Integer, 'Days-to-expiry warning threshold (default 30)') { |v| options[:min_days] = v }
  opts.on('--min-key-bits N', Integer, 'Minimum acceptable RSA key size (default 2048)') { |v| options[:min_key_bits] = v }
  opts.on('--ext LIST', String, 'Comma-separated extensions to scan (default .pem,.crt,.cer,.key)') do |v|
    options[:extensions] = v.split(',').map { |e| e.start_with?('.') ? e : ".#{e}" }
  end
  opts.on('--json', 'Emit machine-readable JSON instead of text') { options[:json] = true }
  opts.on('-q', '--quiet', 'Only print WARN/CRIT findings (text mode)') { options[:quiet] = true }
  opts.on('-h', '--help', 'Show this help') { puts opts; exit 0 }
end
parser.parse!

dirs = ARGV.empty? ? ['.'] : ARGV
dirs.each do |d|
  unless Dir.exist?(d)
    warn "cert_store_audit: no such directory: #{d}"
    exit 3
  end
end

# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def find_candidate_files(dirs, extensions)
  files = []
  dirs.each do |dir|
    Find.find(dir) do |path|
      next unless File.file?(path)
      next unless extensions.include?(File.extname(path).downcase)
      # Skip obviously-huge files (e.g. accidentally pointed at a data dir) --
      # certs/keys are always small text files.
      next if File.size(path) > 1_000_000

      files << path
    rescue Errno::EACCES, Errno::ENOENT
      next
    end
  end
  files.sort
end

# Split a PEM bundle into individual PEM blocks. A single .pem/.crt file can
# contain a full chain (leaf + intermediates), so we can't assume one
# object per file.
def split_pem_blocks(content)
  content.scan(/-----BEGIN ([A-Z ]+)-----.*?-----END \1-----/m)
         .map(&:to_s) # not used; kept for clarity
  content.scan(/-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----/m)
end

# ---------------------------------------------------------------------------
# Certificate analysis
# ---------------------------------------------------------------------------

def rsa_key_bits(pkey)
  return nil unless pkey.is_a?(OpenSSL::PKey::RSA)

  pkey.n.num_bits
end

def analyze_certificate(path, block, min_days)
  cert = OpenSSL::X509::Certificate.new(block)
  now = Time.now
  days_left = ((cert.not_after - now) / 86_400).floor

  status =
    if cert.not_after < now
      :crit
    elsif days_left <= min_days
      :warn
    else
      :ok
    end

  key_bits = rsa_key_bits(cert.public_key)
  weak_key = key_bits && key_bits < 2048

  self_signed = cert.issuer.to_s == cert.subject.to_s

  {
    file: path,
    type: 'certificate',
    subject: cert.subject.to_s,
    issuer: cert.issuer.to_s,
    not_before: cert.not_before.utc.iso8601,
    not_after: cert.not_after.utc.iso8601,
    days_left: days_left,
    self_signed: self_signed,
    key_algorithm: cert.public_key.class.to_s.split('::').last,
    key_bits: key_bits,
    weak_key: weak_key,
    serial: cert.serial.to_s,
    status: status,
    notes: build_cert_notes(status, days_left, self_signed, weak_key, min_days)
  }
rescue OpenSSL::X509::CertificateError, ArgumentError => e
  { file: path, type: 'certificate', status: :error, error: e.message }
end

def build_cert_notes(status, days_left, self_signed, weak_key, min_days)
  notes = []
  case status
  when :crit
    notes << "EXPIRED #{-days_left} day(s) ago"
  when :warn
    notes << "expires in #{days_left} day(s) (threshold: #{min_days})"
  end
  notes << 'self-signed' if self_signed
  notes << 'weak RSA key (<2048 bits)' if weak_key
  notes
end

def analyze_key(path, block, min_key_bits)
  pkey = OpenSSL::PKey.read(block)
  bits = rsa_key_bits(pkey)
  weak = bits && bits < min_key_bits

  perms = File.stat(path).mode & 0o777
  world_readable = (perms & 0o077) != 0

  status = :ok
  status = :warn if weak
  status = :crit if world_readable || (bits && bits < 1024)

  notes = []
  notes << "world/group-readable private key (mode #{format('%o', perms)})" if world_readable
  notes << "key size #{bits} bits below minimum #{min_key_bits}" if weak

  {
    file: path,
    type: 'private_key',
    key_algorithm: pkey.class.to_s.split('::').last,
    key_bits: bits,
    file_mode: format('%o', perms),
    world_readable: world_readable,
    status: status,
    notes: notes
  }
rescue OpenSSL::PKey::PKeyError, ArgumentError => e
  # Most common cause: password-protected key. We don't prompt for
  # passwords in an unattended audit script -- flag it as skipped instead
  # of crashing.
  { file: path, type: 'private_key', status: :skipped, error: "unreadable (#{e.message}); likely password-protected" }
end

# Match cert/key pairs by comparing RSA modulus (n). Two files whose base
# name matches (cert.pem / cert.key) but whose public keys DON'T match is a
# classic "wrong key got copied during deploy" bug.
def find_mismatches(cert_results, key_results)
  mismatches = []
  by_stem = Hash.new { |h, k| h[k] = { certs: [], keys: [] } }

  cert_results.each do |c|
    next unless c[:status] && c[:key_bits]

    stem = File.basename(c[:file], File.extname(c[:file]))
    by_stem[stem][:certs] << c
  end
  key_results.each do |k|
    next unless k[:status] && k[:key_bits]

    stem = File.basename(k[:file], File.extname(k[:file]))
    by_stem[stem][:keys] << k
  end

  by_stem.each do |stem, pair|
    next if pair[:certs].empty? || pair[:keys].empty?

    pair[:certs].each do |c|
      pair[:keys].each do |k|
        next unless c[:key_bits] == k[:key_bits] # cheap pre-filter

        cert_obj = OpenSSL::X509::Certificate.new(File.read(c[:file]))
        key_obj = OpenSSL::PKey.read(File.read(k[:file]))
        matches = cert_obj.check_private_key(key_obj)
        mismatches << { cert: c[:file], key: k[:file], stem: stem } unless matches
      rescue StandardError
        next
      end
    end
  end
  mismatches
end

# ---------------------------------------------------------------------------
# Run the audit
# ---------------------------------------------------------------------------

files = find_candidate_files(dirs, options[:extensions])

cert_results = []
key_results = []

files.each do |path|
  content = File.read(path)
  blocks = split_pem_blocks(content)

  if blocks.empty?
    next
  end

  blocks.each do |block|
    if block.include?('BEGIN CERTIFICATE')
      cert_results << analyze_certificate(path, block, options[:min_days])
    elsif block.include?('PRIVATE KEY')
      key_results << analyze_key(path, block, options[:min_key_bits])
    end
  end
rescue Errno::EACCES => e
  cert_results << { file: path, type: 'unknown', status: :error, error: e.message }
end

mismatches = find_mismatches(cert_results, key_results)

all_results = cert_results + key_results
worst = all_results.map { |r| r[:status] }.compact
exit_code =
  if !mismatches.empty? || worst.include?(:crit)
    2
  elsif worst.include?(:warn)
    1
  else
    0
  end

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

if options[:json]
  puts JSON.pretty_generate(
    scanned_dirs: dirs,
    files_scanned: files.size,
    certificates: cert_results,
    private_keys: key_results,
    key_mismatches: mismatches,
    exit_code: exit_code
  )
else
  puts "cert-store-audit: scanned #{files.size} file(s) under #{dirs.join(', ')}"
  puts

  cert_results.each do |c|
    next if options[:quiet] && c[:status] == :ok

    tag = c[:status].to_s.upcase.rjust(5)
    if c[:status] == :error
      puts "[ERROR] #{c[:file]} -- #{c[:error]}"
      next
    end
    puts "[#{tag}] #{c[:file]}"
    puts "        subject: #{c[:subject]}"
    puts "        expires: #{c[:not_after]} (#{c[:days_left]} days) | key: #{c[:key_algorithm]} #{c[:key_bits]}"
    c[:notes].each { |n| puts "        - #{n}" }
  end

  key_results.each do |k|
    next if options[:quiet] && k[:status] == :ok

    tag = k[:status].to_s.upcase.rjust(5)
    if k[:status] == :error || k[:status] == :skipped
      puts "[#{tag}] #{k[:file]} -- #{k[:error]}"
      next
    end
    puts "[#{tag}] #{k[:file]}"
    puts "        key: #{k[:key_algorithm]} #{k[:key_bits]} bits, mode #{k[:file_mode]}"
    k[:notes].each { |n| puts "        - #{n}" }
  end

  unless mismatches.empty?
    puts
    puts 'KEY/CERT MISMATCHES:'
    mismatches.each { |m| puts "  [CRIT] #{m[:cert]}  <->  #{m[:key]}  (public keys do not match)" }
  end

  puts
  puts "Summary: #{cert_results.count { |c| c[:status] == :ok }} OK certs, " \
       "#{cert_results.count { |c| c[:status] == :warn }} expiring soon, " \
       "#{cert_results.count { |c| c[:status] == :crit }} expired, " \
       "#{key_results.count { |k| k[:status] == :crit }} key issue(s), " \
       "#{mismatches.size} mismatch(es)"
end

exit exit_code
