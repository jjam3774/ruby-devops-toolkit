#!/usr/bin/env ruby
# frozen_string_literal: true
#
# ca_trust_store_audit.rb -- audit the system CA trust store: what your boxes
#                            will believe, and who put it there.
#
# WHY THIS EXISTS
# ---------------
# Everyone monitors their *server* certificates. Almost nobody audits the
# other end of the trust relationship: the ~140 root CA certificates sitting
# in /etc/ssl/certs that decide which certificates your servers will accept
# when *they* are the client -- every outbound HTTPS call, every package
# fetch, every webhook, every database TLS handshake.
#
# That store is a single, unversioned, append-anything list. A contractor runs
# `update-ca-certificates` after dropping in a corporate proxy's MITM root. A
# five-year-old Docker base image ships a bundle with expired anchors and
# 1024-bit keys. A developer adds their own self-signed dev CA "temporarily"
# and it rides into the golden image. None of this produces an error message.
# It just quietly widens what the host will trust, forever.
#
# This script reads the trust store with Ruby's bundled OpenSSL bindings and
# reports what is in there: expired anchors, weak keys, SHA-1 signatures,
# non-CA certificates masquerading as anchors, and -- the finding that matters
# most -- every anchor that was added locally rather than shipped by the
# distribution.
#
# Ruby >= 2.7, standard library only (openssl is bundled with Ruby).
# Linux/macOS. Also works on Windows against an explicitly given PEM bundle.
#
# Usage:
#   ruby ca_trust_store_audit.rb
#   ruby ca_trust_store_audit.rb --bundle /etc/ssl/certs/ca-certificates.crt
#   ruby ca_trust_store_audit.rb --dir /etc/ssl/certs --expiry-days 180
#   ruby ca_trust_store_audit.rb --json --min-severity high
#
# Exit codes:
#   0 = clean at the reporting threshold
#   1 = warnings only (medium/low)
#   2 = at least one high or critical finding
#   3 = nothing to audit / bad arguments

require 'openssl'
require 'optparse'
require 'json'
require 'time'
require 'digest'
require 'set'

module Policy
  EXPIRY_WARN_DAYS = 90     # anchor expires this soon -> high
  MIN_RSA_BITS     = 2048   # below this -> high
  MIN_EC_BITS      = 224
  # A root valid for longer than this is not itself a vulnerability, but it
  # is a very long time to be trusting one key. Worth knowing about.
  LONG_VALIDITY_YEARS = 30
  WEAK_SIGNATURES = %w[md2 md4 md5 sha1].freeze
  # Where distributions put *locally* added anchors. Anything whose PEM lives
  # here did not come from the OS vendor -- a human put it there.
  LOCAL_ANCHOR_DIRS = [
    '/usr/local/share/ca-certificates',       # Debian/Ubuntu
    '/etc/pki/ca-trust/source/anchors',       # RHEL/Fedora
    '/etc/ca-certificates/trust-source/anchors' # Arch
  ].freeze
  DEFAULT_BUNDLES = [
    '/etc/ssl/certs/ca-certificates.crt',     # Debian/Ubuntu
    '/etc/pki/tls/certs/ca-bundle.crt',       # RHEL/Fedora
    '/etc/ssl/cert.pem'                       # Alpine/macOS
  ].freeze
end

SEVERITIES = %w[critical high medium low].freeze
SEV_RANK   = SEVERITIES.each_with_index.to_h.freeze

# ==========================================================================
# Anchor -- one trust anchor, with everything we care about pre-extracted.
#
# OpenSSL::X509::Certificate is lazy and a little awkward (extensions come
# back as objects you have to stringify, key sizes live on a different
# object). Normalising all of that once, here, keeps the rules readable.
# ==========================================================================
class Anchor
  attr_reader :subject, :issuer, :not_before, :not_after, :serial,
              :sig_alg, :key_type, :key_bits, :fingerprint,
              :is_ca, :has_basic_constraints, :path_len,
              :key_usage, :sources

  def initialize(cert, source)
    @cert       = cert
    @subject    = common_name(cert.subject) || cert.subject.to_s
    @issuer     = common_name(cert.issuer) || cert.issuer.to_s
    @not_before = cert.not_before
    @not_after  = cert.not_after
    @serial     = cert.serial.to_s(16)
    @sig_alg    = cert.signature_algorithm
    # SHA-256 over the DER is the stable identity of a certificate. The trust
    # store is full of the same CA appearing under several filenames (hashed
    # symlinks, cross-signed variants), so dedup has to key on this.
    @fingerprint = OpenSSL::Digest::SHA256.hexdigest(cert.to_der)
    @sources     = [source]

    extract_key(cert)
    extract_extensions(cert)
  end

  # Same certificate found in another file -- record where, do not duplicate.
  def add_source(source)
    @sources << source unless @sources.include?(source)
  end

  def self_signed?
    @cert.subject == @cert.issuer
  end

  def expired?(now = Time.now)
    @not_after < now
  end

  def days_until_expiry(now = Time.now)
    ((@not_after - now) / 86_400).floor
  end

  def validity_years
    ((@not_after - @not_before) / (86_400 * 365.25)).round(1)
  end

  # Was this anchor added by a human rather than shipped by the distro?
  def locally_added?(local_dirs)
    @sources.any? { |s| local_dirs.any? { |d| s.start_with?(d) } }
  end

  def weak_signature?
    Policy::WEAK_SIGNATURES.any? { |w| @sig_alg.downcase.include?(w) }
  end

  def weak_key?
    case @key_type
    when 'RSA', 'DSA' then @key_bits && @key_bits < Policy::MIN_RSA_BITS
    when 'EC'         then @key_bits && @key_bits < Policy::MIN_EC_BITS
    else false
    end
  end

  def can_sign_certs?
    # No keyUsage extension at all means "unrestricted" under RFC 5280, which
    # is legal for old roots. Only an explicit keyUsage that omits
    # certificate signing is a problem.
    @key_usage.nil? || @key_usage.include?('Certificate Sign')
  end

  def to_h
    {
      subject: @subject, issuer: @issuer, self_signed: self_signed?,
      not_before: @not_before.utc.iso8601, not_after: @not_after.utc.iso8601,
      days_until_expiry: days_until_expiry, validity_years: validity_years,
      signature_algorithm: @sig_alg, key_type: @key_type, key_bits: @key_bits,
      is_ca: @is_ca, has_basic_constraints: @has_basic_constraints,
      path_len: @path_len, key_usage: @key_usage,
      fingerprint_sha256: @fingerprint, sources: @sources
    }
  end

  private

  def common_name(name)
    name.to_a.reverse.each do |entry|
      return entry[1] if entry[0] == 'CN'
    end
    # Some roots (notably older ones) carry no CN, only OU/O.
    name.to_a.reverse.each do |entry|
      return entry[1] if %w[OU O].include?(entry[0])
    end
    nil
  end

  def extract_key(cert)
    key = cert.public_key
    case key
    when OpenSSL::PKey::RSA then @key_type = 'RSA'; @key_bits = key.n.num_bits
    when OpenSSL::PKey::DSA then @key_type = 'DSA'; @key_bits = key.p.num_bits
    when OpenSSL::PKey::EC  then @key_type = 'EC';  @key_bits = key.group.degree
    else @key_type = key.class.name.split('::').last; @key_bits = nil
    end
  rescue OpenSSL::PKey::PKeyError, OpenSSL::X509::CertificateError
    # Unsupported algorithm (or an OpenSSL 3 legacy-provider issue). Record
    # the failure rather than aborting the whole audit for one bad anchor.
    @key_type = 'unreadable'
    @key_bits = nil
  end

  def extract_extensions(cert)
    @is_ca = false
    @has_basic_constraints = false
    @path_len = nil
    @key_usage = nil

    cert.extensions.each do |ext|
      case ext.oid
      when 'basicConstraints'
        @has_basic_constraints = true
        val = ext.value             # e.g. "CA:TRUE, pathlen:0"
        @is_ca = val.include?('CA:TRUE')
        @path_len = val[/pathlen:(\d+)/, 1]&.to_i
      when 'keyUsage'
        @key_usage = ext.value.split(',').map(&:strip)
      end
    end
  end
end

# ==========================================================================
# TrustStore -- loading. PEM bundles and PEM directories, deduped.
# ==========================================================================
class TrustStore
  PEM_BLOCK = /-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m

  attr_reader :anchors, :parse_errors

  def initialize
    @by_fingerprint = {}
    @parse_errors = []
  end

  # A concatenated bundle can hold hundreds of PEM blocks. Scanning for the
  # delimiters and parsing each block on its own means one malformed entry
  # (they happen -- truncated writes, editors mangling line endings) costs us
  # that certificate and not the whole file.
  def load_bundle(path)
    body = File.read(path)
    blocks = body.scan(PEM_BLOCK)
    if blocks.empty?
      @parse_errors << "#{path}: no PEM certificate blocks found"
      return 0
    end
    blocks.each_with_index { |pem, i| ingest(pem, path, i) }
    blocks.length
  rescue Errno::ENOENT
    @parse_errors << "#{path}: no such file"
    0
  rescue Errno::EACCES
    @parse_errors << "#{path}: permission denied"
    0
  end

  # /etc/ssl/certs is mostly hash-named symlinks pointing at the same handful
  # of real files. We follow them and let fingerprint dedup sort it out.
  def load_dir(path)
    return 0 unless File.directory?(path)

    count = 0
    Dir.glob(File.join(path, '*')).sort.each do |file|
      next unless File.file?(file) # skips broken symlinks too
      next unless file =~ /\.(pem|crt|cer|\d+)\z/

      count += load_bundle(file)
    end
    count
  end

  private

  def ingest(pem, source, index)
    cert = OpenSSL::X509::Certificate.new(pem)
    fp = OpenSSL::Digest::SHA256.hexdigest(cert.to_der)
    if (existing = @by_fingerprint[fp])
      existing.add_source(source)
    else
      @by_fingerprint[fp] = Anchor.new(cert, source)
    end
  rescue OpenSSL::X509::CertificateError => e
    @parse_errors << "#{source}[block #{index}]: #{e.message}"
  end

  public

  def anchors
    @by_fingerprint.values
  end
end

# ==========================================================================
# Auditor -- the rules. Pure functions over Anchors.
# ==========================================================================
class Auditor
  Finding = Struct.new(:anchor, :severity, :code, :detail, :evidence, keyword_init: true)

  def initialize(expiry_days:, local_dirs:, now: Time.now)
    @expiry_days = expiry_days
    @local_dirs = local_dirs
    @now = now
  end

  def audit_all(anchors)
    findings = anchors.flat_map { |a| audit(a) }
    findings.concat(duplicate_subject_findings(anchors))
    findings
  end

  def audit(a)
    out = []

    # ---- lifetime --------------------------------------------------------
    if a.expired?(@now)
      out << f(a, 'critical', 'ANCHOR_EXPIRED',
               "trust anchor expired #{-a.days_until_expiry(@now)} day(s) ago but is still " \
               'in the store -- every chain that ends here now fails, usually as an ' \
               'unhelpful "unable to get local issuer certificate"',
               "notAfter=#{a.not_after.utc.strftime('%Y-%m-%d')}")
    elsif a.days_until_expiry(@now) <= @expiry_days
      out << f(a, 'high', 'ANCHOR_EXPIRING',
               "expires in #{a.days_until_expiry(@now)} day(s); if the distro bundle is not " \
               'updated before then, outbound TLS to anything under this root breaks',
               "notAfter=#{a.not_after.utc.strftime('%Y-%m-%d')}")
    end

    # ---- cryptography ----------------------------------------------------
    if a.weak_key?
      out << f(a, 'high', 'WEAK_KEY',
               "#{a.key_type}-#{a.key_bits} public key is below the #{Policy::MIN_RSA_BITS}-bit " \
               'floor -- a forged certificate under this anchor is a factoring problem, ' \
               'not an impossibility',
               "key=#{a.key_type}-#{a.key_bits}")
    end

    if a.weak_signature? && !a.self_signed?
      # A weak self-signature on a root is cosmetic (clients never verify it).
      # A weak signature on a *cross-signed* intermediate sitting in the trust
      # store is not: that one does get verified.
      out << f(a, 'high', 'WEAK_SIGNATURE',
               "signed with #{a.sig_alg} and is not self-signed, so this signature is " \
               'actually verified -- SHA-1 and MD5 collisions are practical',
               "sigalg=#{a.sig_alg}")
    elsif a.weak_signature?
      out << f(a, 'low', 'WEAK_SELF_SIGNATURE',
               "self-signed with #{a.sig_alg}; harmless in itself (the self-signature is " \
               'never checked) but a reliable marker of a legacy anchor',
               "sigalg=#{a.sig_alg}")
    end

    # ---- is it even a CA? ------------------------------------------------
    if a.has_basic_constraints && !a.is_ca
      out << f(a, 'high', 'NOT_A_CA',
               'basicConstraints says CA:FALSE -- this is a leaf certificate installed as a ' \
               'trust anchor, which is what "just trust this one server" usually turns into',
               'basicConstraints=CA:FALSE')
    elsif !a.has_basic_constraints
      out << f(a, 'medium', 'NO_BASIC_CONSTRAINTS',
               'no basicConstraints extension at all; permitted for pre-RFC-5280 roots but ' \
               'it means nothing in the certificate limits what it may issue',
               'basicConstraints=absent')
    end

    unless a.can_sign_certs?
      out << f(a, 'medium', 'NO_CERT_SIGN',
               "keyUsage (#{a.key_usage.join(', ')}) does not include Certificate Sign, so " \
               'this anchor cannot validate any chain -- it is dead weight at best',
               "keyUsage=#{a.key_usage.join(',')}")
    end

    # ---- provenance ------------------------------------------------------
    # The single most useful line of this report. Distro bundles are curated
    # by people who follow CA/Browser Forum removals. Locally added anchors
    # are curated by nobody.
    if a.locally_added?(@local_dirs)
      out << f(a, 'high', 'LOCALLY_ADDED',
               'added locally, not shipped by the distribution -- confirm this is an ' \
               'intentional corporate/internal CA and not a leftover dev or proxy root',
               "source=#{a.sources.join(', ')}")
    end

    if a.validity_years > Policy::LONG_VALIDITY_YEARS
      out << f(a, 'low', 'LONG_VALIDITY',
               "valid for #{a.validity_years} years; a very long time to be betting on " \
               'one key pair remaining uncompromised',
               "#{a.not_before.utc.strftime('%Y')}-#{a.not_after.utc.strftime('%Y')}")
    end

    out
  end

  private

  # Two different certificates claiming the same CA name. Usually legitimate
  # (a root rolled to a new key, both published during the overlap) but it is
  # also exactly what a spoofed anchor looks like, so it gets surfaced.
  def duplicate_subject_findings(anchors)
    anchors.group_by(&:subject).filter_map do |subject, group|
      next if group.length < 2

      Finding.new(
        anchor: subject, severity: 'low', code: 'DUPLICATE_SUBJECT',
        detail: "#{group.length} distinct certificates share this subject name -- normally a " \
                'key rollover, but verify the fingerprints are ones you expect',
        evidence: group.map { |a| a.fingerprint[0, 16] }.join(', ')
      )
    end
  end

  def f(anchor, severity, code, detail, evidence)
    Finding.new(anchor: anchor.subject, severity: severity, code: code,
                detail: detail, evidence: evidence)
  end
end

# ==========================================================================
# Reporting
# ==========================================================================
module Report
  COLORS = { 'critical' => "\e[1;31m", 'high' => "\e[31m",
             'medium' => "\e[33m", 'low' => "\e[36m" }.freeze
  RESET = "\e[0m"

  def self.tint(text, severity)
    return text unless $stdout.tty? && ENV['NO_COLOR'].nil?

    "#{COLORS.fetch(severity, '')}#{text}#{RESET}"
  end

  def self.text(anchors, findings, store, opts)
    lines = []
    lines << "CA trust store audit -- #{Time.now.strftime('%Y-%m-%d %H:%M:%S %Z')}"
    lines << "sources: #{opts[:bundles].concat(opts[:dirs]).join(', ')}"
    lines << '=' * 78
    lines << ''

    key_hist = anchors.group_by { |a| "#{a.key_type}-#{a.key_bits}" }
                      .transform_values(&:length).sort_by { |_, v| -v }
    sig_hist = anchors.group_by { |a| a.sig_alg }
                      .transform_values(&:length).sort_by { |_, v| -v }

    lines << "ANCHORS: #{anchors.length} unique"
    lines << "  keys:       #{key_hist.map { |k, v| "#{k}=#{v}" }.join('  ')}"
    lines << "  signatures: #{sig_hist.map { |k, v| "#{k}=#{v}" }.join('  ')}"
    lines << "  local:      #{anchors.count { |a| a.locally_added?(opts[:local_dirs]) }}"
    lines << "  expired:    #{anchors.count(&:expired?)}"
    soonest = anchors.reject(&:expired?).min_by(&:not_after)
    if soonest
      lines << "  next expiry: #{soonest.not_after.utc.strftime('%Y-%m-%d')} " \
               "(#{soonest.days_until_expiry}d) #{soonest.subject}"
    end
    lines << ''

    unless store.parse_errors.empty?
      lines << "PARSE ERRORS (#{store.parse_errors.length})"
      store.parse_errors.first(10).each { |e| lines << "  #{e}" }
      lines << ''
    end

    if findings.empty?
      lines << 'No findings at or above the configured severity threshold.'
    else
      lines << "FINDINGS (#{findings.length})"
      lines << '-' * 78
      findings.each do |fd|
        lines << tint("[#{fd.severity.upcase}] #{fd.code}", fd.severity)
        lines << "    anchor:   #{fd.anchor}"
        lines << "    #{fd.detail}"
        lines << "    evidence: #{fd.evidence}"
        lines << ''
      end
    end

    counts = findings.group_by(&:severity).transform_values(&:length)
    lines << '=' * 78
    lines << "#{anchors.length} anchor(s); " +
             SEVERITIES.map { |s| "#{counts.fetch(s, 0)} #{s}" }.join(', ')
    lines.join("\n")
  end

  def self.json(anchors, findings, store, opts)
    JSON.pretty_generate(
      generated_at: Time.now.utc.iso8601,
      sources: { bundles: opts[:bundles], dirs: opts[:dirs], local_dirs: opts[:local_dirs] },
      anchors: anchors.map(&:to_h),
      findings: findings.map(&:to_h),
      parse_errors: store.parse_errors,
      summary: {
        anchors: anchors.length,
        locally_added: anchors.count { |a| a.locally_added?(opts[:local_dirs]) },
        expired: anchors.count(&:expired?),
        findings: findings.group_by(&:severity).transform_values(&:length)
      }
    )
  end
end

# ==========================================================================
# CLI
# ==========================================================================
def parse_options(argv)
  opts = {
    bundles: [], dirs: [], local_dirs: Policy::LOCAL_ANCHOR_DIRS.dup,
    expiry_days: Policy::EXPIRY_WARN_DAYS, json: false, min_severity: 'low'
  }

  parser = OptionParser.new do |o|
    o.banner = 'Usage: ca_trust_store_audit.rb [options]'
    o.on('--bundle PATH', 'concatenated PEM bundle; repeatable') { |v| opts[:bundles] << v }
    o.on('--dir PATH', 'directory of PEM files; repeatable') { |v| opts[:dirs] << v }
    o.on('--local-dir PATH', 'treat anchors from PATH as locally added; repeatable') do |v|
      opts[:local_dirs] << v
    end
    o.on('--expiry-days N', Integer, "warn this far ahead (default #{Policy::EXPIRY_WARN_DAYS})") do |v|
      opts[:expiry_days] = v
    end
    o.on('--json', 'emit JSON instead of text') { opts[:json] = true }
    o.on('--min-severity SEV', SEVERITIES, "report SEV and above (#{SEVERITIES.join('|')})") do |v|
      opts[:min_severity] = v
    end
    o.on('-h', '--help') { puts o; exit 0 }
  end
  parser.parse!(argv)

  # Nothing specified? Find the distro bundle ourselves, and include the
  # local anchor directories so injected roots show up by default.
  if opts[:bundles].empty? && opts[:dirs].empty?
    found = Policy::DEFAULT_BUNDLES.select { |p| File.readable?(p) }
    opts[:bundles].concat(found)
    opts[:dirs].concat(opts[:local_dirs].select { |d| File.directory?(d) })
  end
  opts
rescue OptionParser::ParseError => e
  warn "argument error: #{e.message}"
  exit 3
end

def main(argv)
  opts = parse_options(argv)

  if opts[:bundles].empty? && opts[:dirs].empty?
    warn 'error: no CA bundle found. Tried:'
    Policy::DEFAULT_BUNDLES.each { |p| warn "  #{p}" }
    warn 'Pass one explicitly with --bundle PATH.'
    exit 3
  end

  store = TrustStore.new
  opts[:bundles].each { |p| store.load_bundle(p) }
  opts[:dirs].each { |p| store.load_dir(p) }

  anchors = store.anchors
  if anchors.empty?
    warn 'error: no certificates could be parsed from the given sources.'
    store.parse_errors.first(5).each { |e| warn "  #{e}" }
    exit 3
  end

  auditor  = Auditor.new(expiry_days: opts[:expiry_days], local_dirs: opts[:local_dirs])
  findings = auditor.audit_all(anchors)

  cutoff   = SEV_RANK.fetch(opts[:min_severity])
  findings = findings.select { |fd| SEV_RANK.fetch(fd.severity) <= cutoff }
  findings.sort_by! { |fd| [SEV_RANK.fetch(fd.severity), fd.code, fd.anchor.to_s] }

  puts(opts[:json] ? Report.json(anchors, findings, store, opts) \
                   : Report.text(anchors, findings, store, opts))

  worst = findings.map { |fd| SEV_RANK.fetch(fd.severity) }.min
  return 0 if worst.nil?
  return 2 if worst <= SEV_RANK.fetch('high')

  1
end

exit main(ARGV) if __FILE__ == $PROGRAM_NAME
