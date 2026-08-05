#!/usr/bin/env ruby
# frozen_string_literal: true
#
# ssh_key_audit.rb -- Audits authorized_keys files across a fleet of home
# directories for SSH key hygiene problems, no gems required.
#
# Problem it solves: authorized_keys files accrete over years. People leave
# the company and their key never gets removed; someone pastes the same
# deploy key into five accounts because it was convenient; an old DSA or
# 1024-bit RSA key from 2011 is still accepted; a "svc-backup" automation
# account has an unrestricted key that can be used interactively from
# anywhere. None of this shows up until an audit or an incident. This script
# walks a set of home directories, parses every authorized_keys entry, and
# flags the specific hygiene problems above with a severity so you can wire
# it into a periodic security check.
#
# Usage:
#   ruby ssh_key_audit.rb /home /root
#   ruby ssh_key_audit.rb /home --denylist departed_users.json
#   ruby ssh_key_audit.rb /home --json
#
# Exit codes: 0 = no CRIT findings, 2 = one or more CRIT findings (cron/CI
# friendly), 1 = usage/config error.

require 'optparse'
require 'json'
require 'base64'
require 'stringio'

module SshKeyAudit
  Finding = Struct.new(:severity, :user, :file, :line, :message, keyword_init: true)

  # Accounts matching these patterns are treated as automation/service
  # accounts: they are held to a stricter standard (must have from= or
  # command= restrictions on every key).
  SERVICE_ACCOUNT_PATTERNS = [/\Asvc[-_]/, /\Adeploy/, /\Abackup/, /\Aci[-_]/, /\Aautomation/].freeze

  WEAK_TYPES = %w[ssh-dss ssh-dss-cert-v01@openssh.com].freeze
  MIN_RSA_BITS = 2048

  # Parses the base64 SSH wire-format blob to determine key type/strength
  # without shelling out to `ssh-keygen -l` (which may not be installed, and
  # this way the logic is fully testable without any external process).
  module KeyBlob
    module_function

    def bit_strength(key_type, blob_b64)
      raw = Base64.decode64(blob_b64)
      io = StringIO.new(raw)
      type_in_blob = read_string(io)

      case key_type
      when 'ssh-rsa'
        _e = read_mpint(io)
        n = read_mpint(io)
        bits_of(n)
      when 'ssh-dss'
        64 # DSA is capped at 1024-bit by the classic spec in practice; treat as weak regardless
      when /\Aecdsa-sha2-/
        # curve name tells us the strength directly
        curve = read_string(io)
        { 'nistp256' => 256, 'nistp384' => 384, 'nistp521' => 521 }[curve] || 256
      when 'ssh-ed25519'
        256
      else
        nil
      end
    rescue StandardError
      nil
    end

    def read_string(io)
      len = io.read(4)
      return nil unless len && len.bytesize == 4

      n = len.unpack1('N')
      io.read(n)
    end

    def read_mpint(io)
      read_string(io)
    end

    # Number of significant bits in a big-endian two's-complement-ish mpint
    # as SSH encodes it (leading 0x00 byte only present to keep it
    # non-negative when the high bit of the first real byte is set).
    def bits_of(bytes)
      return 0 unless bytes

      bytes = bytes.dup
      bytes = bytes[1..] while bytes.bytesize > 1 && bytes.getbyte(0) == 0
      return 0 if bytes.empty?

      top_byte = bytes.getbyte(0)
      (bytes.bytesize - 1) * 8 + bit_length(top_byte)
    end

    def bit_length(byte)
      len = 0
      len += 1 while byte >> len > 0
      len
    end
  end

  AuthorizedKeyLine = Struct.new(:options, :key_type, :key_blob, :comment, :raw, keyword_init: true)

  class Parser
    # Splits a single authorized_keys line into (options, type, blob, comment).
    # Handles the optional leading `options` field (comma-separated, with
    # quoted values like command="rsync --server ...") per sshd's format.
    def self.parse_line(line)
      return nil if line.nil?

      line = line.strip
      return nil if line.empty? || line.start_with?('#')

      tokens = tokenize(line)
      return nil if tokens.empty?

      key_types = %w[ssh-rsa ssh-dss ssh-ed25519] + %w[ecdsa-sha2-nistp256 ecdsa-sha2-nistp384 ecdsa-sha2-nistp521]

      if key_types.include?(tokens[0])
        AuthorizedKeyLine.new(options: '', key_type: tokens[0], key_blob: tokens[1], comment: tokens[2..]&.join(' ').to_s, raw: line)
      elsif tokens.size >= 2 && key_types.include?(tokens[1])
        AuthorizedKeyLine.new(options: tokens[0], key_type: tokens[1], key_blob: tokens[2], comment: tokens[3..]&.join(' ').to_s, raw: line)
      end
    end

    # Tokenizes respecting quoted strings so `command="foo bar",no-pty ssh-rsa AAAA... name@host`
    # splits into ['command="foo bar",no-pty', 'ssh-rsa', 'AAAA...', 'name@host'].
    def self.tokenize(line)
      tokens = []
      buf = +''
      in_quotes = false
      line.each_char do |c|
        if c == '"'
          in_quotes = !in_quotes
          buf << c
        elsif c == ' ' && !in_quotes
          unless buf.empty?
            tokens << buf
            buf = +''
          end
        else
          buf << c
        end
      end
      tokens << buf unless buf.empty?
      tokens
    end
  end

  class Auditor
    def initialize(home_dirs, denylist: [])
      @home_dirs = home_dirs
      @denylist = denylist
      @findings = []
      @seen_blobs = Hash.new { |h, k| h[k] = [] } # key_blob => [ "user:file", ... ]
    end

    def run
      each_authorized_keys_file do |user, path|
        check_permissions(user, path)
        parse_and_check_keys(user, path)
      end
      check_duplicates
      @findings
    end

    private

    def each_authorized_keys_file
      @home_dirs.each do |home_root|
        next unless Dir.exist?(home_root)

        Dir.children(home_root).sort.each do |user|
          user_home = File.join(home_root, user)
          next unless File.directory?(user_home)

          ak_path = File.join(user_home, '.ssh', 'authorized_keys')
          next unless File.exist?(ak_path)

          yield user, ak_path
        end
      end
    end

    def check_permissions(user, path)
      mode = format('%o', File.stat(path).mode & 0o777)
      if mode != '600' && mode != '400'
        add(:warn, user, path, nil, "authorized_keys mode is #{mode}, expected 600 (group/world access should be denied)")
      end

      ssh_dir = File.dirname(path)
      dir_mode = format('%o', File.stat(ssh_dir).mode & 0o777)
      unless %w[700 500].include?(dir_mode)
        add(:warn, user, ssh_dir, nil, ".ssh directory mode is #{dir_mode}, expected 700")
      end
    end

    def parse_and_check_keys(user, path)
      lines = File.readlines(path)
      lines.each_with_index do |raw_line, idx|
        parsed = Parser.parse_line(raw_line)
        next unless parsed

        line_no = idx + 1
        check_weak_type(user, path, line_no, parsed)
        check_service_account_restrictions(user, path, line_no, parsed)
        check_denylisted_comment(user, path, line_no, parsed)
        @seen_blobs[parsed.key_blob] << "#{user}:#{path}:#{line_no}" if parsed.key_blob
      end
    rescue Errno::EACCES
      add(:warn, user, path, nil, 'permission denied reading authorized_keys (audit ran as an unprivileged user)')
    end

    def check_weak_type(user, path, line_no, parsed)
      if WEAK_TYPES.include?(parsed.key_type)
        add(:crit, user, path, line_no, "#{parsed.key_type} key is cryptographically weak (DSA) -- should be replaced with ed25519 or rsa >= 2048")
        return
      end

      bits = KeyBlob.bit_strength(parsed.key_type, parsed.key_blob)
      return unless bits

      if parsed.key_type == 'ssh-rsa' && bits < MIN_RSA_BITS
        add(:crit, user, path, line_no, "ssh-rsa key is only #{bits}-bit (< #{MIN_RSA_BITS}); replace with ed25519 or a >= 2048-bit RSA key")
      end
    end

    def service_account?(user)
      SERVICE_ACCOUNT_PATTERNS.any? { |re| user.match?(re) }
    end

    def check_service_account_restrictions(user, path, line_no, parsed)
      return unless service_account?(user)

      has_restriction = parsed.options.include?('from=') || parsed.options.include?('command=')
      unless has_restriction
        add(:crit, user, path, line_no,
            "service account '#{user}' has a key with no from= or command= restriction -- " \
            'anyone holding the private key can log in interactively from anywhere')
      end
    end

    def check_denylisted_comment(user, path, line_no, parsed)
      return if @denylist.empty?

      hit = @denylist.find { |name| parsed.comment.to_s.include?(name) || user == name }
      add(:crit, user, path, line_no, "key comment/user matches denylisted (departed) identity '#{hit}'") if hit
    end

    def check_duplicates
      @seen_blobs.each do |blob, locations|
        next if blob.nil? || locations.size < 2

        users = locations.map { |l| l.split(':').first }.uniq
        next if users.size < 2

        add(:warn, users.join(','), locations.map { |l| l.split(':')[1] }.uniq.join(', '), nil,
            "identical public key is authorized for #{users.size} different accounts (#{users.join(', ')}) -- " \
            'shared keys make it impossible to attribute access to one person')
      end
    end

    def add(severity, user, file, line, message)
      @findings << Finding.new(severity: severity, user: user, file: file, line: line, message: message)
    end
  end
end

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  options = { denylist: [], json: false }

  parser = OptionParser.new do |opts|
    opts.banner = 'Usage: ssh_key_audit.rb HOME_DIR [HOME_DIR ...] [--denylist FILE] [--json]'
    opts.on('--denylist PATH', 'JSON array of departed usernames/comment fragments to flag') do |v|
      options[:denylist] = JSON.parse(File.read(v))
    end
    opts.on('--json', 'Emit machine-readable JSON instead of text') { options[:json] = true }
  end
  parser.parse!

  home_dirs = ARGV
  if home_dirs.empty?
    warn parser.banner
    exit 1
  end

  findings = SshKeyAudit::Auditor.new(home_dirs, denylist: options[:denylist]).run
  crit_count = findings.count { |f| f.severity == :crit }
  warn_count = findings.count { |f| f.severity == :warn }

  if options[:json]
    puts JSON.pretty_generate(findings.map(&:to_h))
  elsif findings.empty?
    puts 'No findings -- all authorized_keys entries look healthy.'
  else
    findings.sort_by { |f| [f.severity == :crit ? 0 : 1, f.user.to_s] }.each do |f|
      tag = f.severity == :crit ? 'CRIT' : 'WARN'
      loc = f.line ? "#{f.file}:#{f.line}" : f.file
      puts "[#{tag}] #{f.user} #{loc} -- #{f.message}"
    end
    puts "\n#{crit_count} critical, #{warn_count} warnings"
  end

  exit(crit_count.positive? ? 2 : 0)
end
