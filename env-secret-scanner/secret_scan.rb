#!/usr/bin/env ruby
# frozen_string_literal: true
#
# secret_scan.rb -- scan a config tree for hardcoded credentials.
#
# Finds secrets that were committed by accident: AWS keys in a deploy script,
# a database password in an .env that shipped inside a container image, a
# private key pasted into a systemd unit. Pure Ruby stdlib, no gems.
#
# Usage:
#   ruby secret_scan.rb /etc /srv/app
#   ruby secret_scan.rb --format json --min-severity high /srv/app
#   ruby secret_scan.rb --allow allowlist.txt /srv/app
#
# Exit codes:  0 = clean   1 = findings at/above --min-severity   2 = usage error
#
# Tested on Ruby 3.0+ (Linux). Works on Windows too; see README.

require 'optparse'
require 'json'
require 'find'
require 'digest'
require 'set'
require 'time'

module SecretScan
  VERSION = '1.0.0'

  SEVERITY_ORDER = { 'low' => 0, 'medium' => 1, 'high' => 2, 'critical' => 3 }.freeze

  # --------------------------------------------------------------------------
  # Detection rules.
  #
  # Each rule is a pattern plus metadata. `capture` names which regex group
  # holds the actual secret material, so we can redact precisely and (for the
  # generic rule) run an entropy test on just the value, not the whole line.
  # --------------------------------------------------------------------------
  RULES = [
    {
      id: 'aws-access-key-id',
      name: 'AWS Access Key ID',
      severity: 'critical',
      pattern: /\b((?:AKIA|ASIA|AGPA|AIDA)[0-9A-Z]{16})\b/,
      capture: 1,
      entropy: false
    },
    {
      id: 'private-key-block',
      name: 'PEM private key block',
      severity: 'critical',
      pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/,
      capture: 0,
      entropy: false,
      # The match is a banner, not the key material -- printing it leaks nothing
      # and is far more readable than a row of asterisks.
      redact: false
    },
    {
      id: 'slack-token',
      name: 'Slack token',
      severity: 'high',
      pattern: /\b(xox[baprs]-[0-9A-Za-z-]{10,})/,
      capture: 1,
      entropy: false
    },
    {
      id: 'jwt',
      name: 'JSON Web Token',
      severity: 'medium',
      pattern: /\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b/,
      capture: 1,
      entropy: false
    },
    {
      id: 'basic-auth-url',
      name: 'Credentials embedded in URL',
      severity: 'high',
      # scheme://user:password@host -- the password group is what we redact
      pattern: %r{\b[a-z][a-z0-9+.-]*://[^\s:/@]+:([^\s@/]{4,})@[^\s/]+}i,
      capture: 1,
      entropy: false
    },
    {
      id: 'generic-assignment',
      name: 'High-entropy value assigned to a secret-ish key',
      severity: 'high',
      # KEY = "value" / KEY: value / KEY=value, where KEY smells like a secret
      pattern: /\b([A-Za-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|
                 access[_-]?key|private[_-]?key|credential|auth)[A-Za-z0-9_.-]*)
                \s*[:=]\s*
                ["']?([^\s"'#,;]{8,})["']?/xi,
      capture: 2,
      entropy: true
    }
  ].freeze

  # Values that look secret-shaped but are obviously placeholders. Anything
  # matching here is dropped before it ever becomes a finding -- this is the
  # single biggest source of false positives in a real config tree.
  PLACEHOLDER = /\A(?:
      changeme|change_me|placeholder|example|examplekey|test|testing|dummy|
      none|null|nil|true|false|localhost|redacted|secret|password|xxx+|
      your[_-]?\w+|<[^>]+>|\$\{[^}]+\}|\$[A-Z_]+|%\([^)]+\)s|\{\{[^}]+\}\}|
      \*+|\.+|-+
    )\z/xi

  # Directories that are never worth scanning: huge, vendored, or self-inflicted.
  SKIP_DIRS = %w[
    .git .svn .hg node_modules vendor/bundle .bundle __pycache__
    .terraform .venv venv dist build coverage tmp/cache
  ].freeze

  # File extensions that are always binary -- cheap pre-filter before we do the
  # more expensive NUL-byte sniff.
  BINARY_EXT = %w[
    .png .jpg .jpeg .gif .bmp .ico .webp .pdf .zip .gz .bz2 .xz .tar .7z
    .so .dll .exe .bin .o .a .class .jar .pyc .woff .woff2 .ttf .eot .mp4 .mp3
  ].freeze

  MAX_FILE_BYTES = 2 * 1024 * 1024  # skip anything bigger than 2 MiB
  MAX_LINE_BYTES = 4_000            # minified JS etc. -- not worth scanning

  Finding = Struct.new(:path, :line_no, :rule_id, :rule_name, :severity,
                       :redacted, :entropy, :fingerprint, keyword_init: true)

  # --------------------------------------------------------------------------
  # Shannon entropy in bits per character. A base64-ish 32-char API key lands
  # around 4.5-5.5; an English word or a path lands around 2.5-3.5. We use
  # 3.5 as the floor for the generic rule.
  # --------------------------------------------------------------------------
  def self.entropy(str)
    return 0.0 if str.nil? || str.empty?

    counts = Hash.new(0)
    str.each_char { |c| counts[c] += 1 }
    len = str.length.to_f
    counts.values.reduce(0.0) do |sum, n|
      p = n / len
      sum - (p * Math.log2(p))
    end
  end

  # A stable ID for a finding so you can allowlist one specific hit without
  # muting the whole rule. Path + rule + secret digest -- never the secret.
  def self.fingerprint(path, rule_id, secret)
    Digest::SHA256.hexdigest("#{path}|#{rule_id}|#{secret}")[0, 12]
  end

  # Show enough to recognise the value, never enough to use it.
  def self.redact(secret)
    s = secret.to_s
    return '*' * s.length if s.length <= 8

    "#{s[0, 4]}#{'*' * [s.length - 8, 24].min}#{s[-4, 4]}"
  end

  def self.binary?(path)
    return true if BINARY_EXT.include?(File.extname(path).downcase)

    # A NUL byte in the first 4 KiB is the classic "this is binary" heuristic.
    File.open(path, 'rb') { |f| f.read(4096).to_s.include?("\0") }
  rescue SystemCallError
    true
  end

  class Scanner
    attr_reader :findings, :files_scanned, :bytes_scanned

    def initialize(allowlist: [], min_severity: 'low', verbose: false)
      @allowlist    = Set.new(allowlist)
      @min_severity = min_severity
      @verbose      = verbose
      @findings     = []
      @files_scanned = 0
      @bytes_scanned = 0
    end

    def scan(roots)
      roots.each { |root| scan_root(root) }
      @findings
    end

    private

    def scan_root(root)
      unless File.exist?(root)
        warn "secret_scan: #{root}: no such file or directory"
        return
      end

      if File.file?(root)
        scan_file(root)
        return
      end

      Find.find(root) do |path|
        if File.directory?(path)
          # Find.prune stops descent into this directory entirely.
          Find.prune if SecretScan::SKIP_DIRS.include?(File.basename(path))
          next
        end
        next unless File.file?(path)
        next if File.symlink?(path)

        scan_file(path)
      end
    end

    def scan_file(path)
      size = File.size(path)
      return if size.zero? || size > SecretScan::MAX_FILE_BYTES
      return if SecretScan.binary?(path)

      @files_scanned += 1
      @bytes_scanned += size

      # Read with invalid-byte replacement so one bad UTF-8 sequence in a log
      # file cannot abort the whole scan.
      File.open(path, 'r:UTF-8', invalid: :replace, undef: :replace) do |f|
        f.each_line.with_index(1) do |line, line_no|
          next if line.bytesize > SecretScan::MAX_LINE_BYTES

          inspect_line(path, line_no, line)
        end
      end
    rescue SystemCallError => e
      warn "secret_scan: #{path}: #{e.message}" if @verbose
    end

    def inspect_line(path, line_no, line)
      # Values already claimed by a *specific* rule on this line. RULES is
      # ordered specific-first, so by the time the fuzzy generic rule runs we
      # know whether a precise rule already owns the same string -- that stops
      # one AWS key from producing two near-identical findings.
      claimed = {}

      SecretScan::RULES.each do |rule|
        md = rule[:pattern].match(line)
        next unless md

        secret = md[rule[:capture]].to_s
        next if secret.empty?
        next if secret.match?(SecretScan::PLACEHOLDER)
        next if rule[:entropy] && claimed[secret]

        ent = SecretScan.entropy(secret).round(2)
        # Entropy gate applies only to the fuzzy generic rule. The specific
        # rules (AKIA..., xoxb-...) are already high-confidence on shape alone.
        next if rule[:entropy] && ent < 3.5

        fp = SecretScan.fingerprint(path, rule[:id], secret)
        next if @allowlist.include?(fp)

        claimed[secret] = true unless rule[:entropy]
        record(path, line_no, rule, secret, ent, fp)
      end
    end

    def record(path, line_no, rule, secret, ent, fp)
      return if SecretScan::SEVERITY_ORDER[rule[:severity]] <
                SecretScan::SEVERITY_ORDER[@min_severity]

      shown = rule.fetch(:redact, true) ? SecretScan.redact(secret) : secret

      @findings << SecretScan::Finding.new(
        path: path, line_no: line_no,
        rule_id: rule[:id], rule_name: rule[:name],
        severity: rule[:severity],
        redacted: shown,
        entropy: ent, fingerprint: fp
      )
    end
  end

  # --------------------------------------------------------------------------
  # Reporting
  # --------------------------------------------------------------------------
  module Report
    COLORS = { 'critical' => 31, 'high' => 33, 'medium' => 36, 'low' => 37 }.freeze

    def self.color(text, severity, enabled)
      return text unless enabled

      "\e[#{COLORS.fetch(severity, 37)}m#{text}\e[0m"
    end

    def self.text(scanner, roots, tty)
      out = []
      out << '=' * 74
      out << "  SECRET SCAN  --  #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}"
      out << "  roots: #{roots.join(', ')}"
      out << '=' * 74
      out << format('  files scanned: %-8d  bytes: %-12s  findings: %d',
                    scanner.files_scanned,
                    human(scanner.bytes_scanned),
                    scanner.findings.size)
      out << '-' * 74

      if scanner.findings.empty?
        out << '  No hardcoded secrets detected.'
      else
        grouped = scanner.findings.group_by(&:severity)
        %w[critical high medium low].each do |sev|
          hits = grouped[sev]
          next unless hits

          out << ''
          out << color("  [#{sev.upcase}]  #{hits.size} finding(s)", sev, tty)
          hits.each do |f|
            out << "    #{f.path}:#{f.line_no}"
            out << "      rule    : #{f.rule_name} (#{f.rule_id})"
            out << "      value   : #{f.redacted}   entropy=#{f.entropy}"
            out << "      id      : #{f.fingerprint}"
          end
        end
      end

      out << ''
      out << '-' * 74
      out << '  Allowlist a false positive:  echo <id> >> allowlist.txt'
      out << '=' * 74
      out.join("\n")
    end

    def self.json(scanner, roots)
      JSON.pretty_generate(
        scanned_at: Time.now.utc.iso8601,
        roots: roots,
        files_scanned: scanner.files_scanned,
        bytes_scanned: scanner.bytes_scanned,
        findings: scanner.findings.map(&:to_h)
      )
    end

    def self.human(bytes)
      units = %w[B KiB MiB GiB]
      i = 0
      b = bytes.to_f
      while b >= 1024 && i < units.size - 1
        b /= 1024
        i += 1
      end
      format('%.1f %s', b, units[i])
    end
  end
end

# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  options = { format: 'text', min_severity: 'low', allow: nil, verbose: false }

  parser = OptionParser.new do |o|
    o.banner = 'Usage: ruby secret_scan.rb [options] PATH [PATH...]'
    o.on('-f', '--format FORMAT', %w[text json], 'text (default) or json') do |v|
      options[:format] = v
    end
    o.on('-s', '--min-severity SEV', %w[low medium high critical],
         'only report at/above this severity (default: low)') do |v|
      options[:min_severity] = v
    end
    o.on('-a', '--allow FILE', 'file of finding IDs to ignore, one per line') do |v|
      options[:allow] = v
    end
    o.on('-v', '--verbose', 'report unreadable files') { options[:verbose] = true }
    o.on('--version', 'print version') { puts SecretScan::VERSION; exit 0 }
    o.on('-h', '--help', 'show this help') { puts o; exit 0 }
  end

  begin
    parser.parse!
  rescue OptionParser::ParseError => e
    warn "secret_scan: #{e.message}"
    warn parser.to_s
    exit 2
  end

  roots = ARGV.empty? ? ['.'] : ARGV

  allow = []
  if options[:allow]
    if File.readable?(options[:allow])
      allow = File.readlines(options[:allow], chomp: true)
                  .map { |l| l.sub(/#.*/, '').strip }
                  .reject(&:empty?)
    else
      warn "secret_scan: allowlist #{options[:allow]} not readable; continuing"
    end
  end

  scanner = SecretScan::Scanner.new(allowlist: allow,
                                    min_severity: options[:min_severity],
                                    verbose: options[:verbose])
  scanner.scan(roots)

  if options[:format] == 'json'
    puts SecretScan::Report.json(scanner, roots)
  else
    puts SecretScan::Report.text(scanner, roots, $stdout.tty?)
  end

  exit(scanner.findings.empty? ? 0 : 1)
end
