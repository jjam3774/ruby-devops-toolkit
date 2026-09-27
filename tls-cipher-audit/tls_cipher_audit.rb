#!/usr/bin/env ruby
# frozen_string_literal: true
#
# tls_cipher_audit.rb - fleet-wide TLS weak-protocol / weak-cipher auditor
#
# Pure Ruby stdlib (OpenSSL + Socket only, no gems). Concurrently connects to a
# list of host:port targets, performs REAL TLS handshakes at each protocol
# version to build a support matrix (SSLv3 .. TLSv1.3), then negotiates a
# "worst case" handshake to see which cipher suite the server would actually
# hand back to a permissive client. Flags weak protocols (SSLv3/TLSv1.0/
# TLSv1.1), weak ciphers (RC4, 3DES, EXPORT, NULL, anonymous, MD5) and weak
# key-exchange (short DHE moduli, no forward secrecy) and reports a
# Nagios-style OK/WARNING/CRITICAL/UNKNOWN status with matching exit code, so
# it drops straight into cron, Nagios/Icinga, or any check_mk-style poller.
#
# This is deliberately NOT the same job as cert-expiry-check / cert-expiry-monitor
# in this toolkit -- those look at certificate *expiry dates*. This script never
# looks at notAfter at all; it only cares about *transport* strength: which
# protocol versions the server will speak and how strong the negotiated
# cipher is.
#
# Usage:
#   ruby tls_cipher_audit.rb -t www.example.com:443,mail.example.com:993
#   ruby tls_cipher_audit.rb -f targets.txt --json
#   ruby tls_cipher_audit.rb -t internal-lb:8443 -v -T 3 -c 20
#
# Exit codes (Nagios convention): 0=OK 1=WARNING 2=CRITICAL 3=UNKNOWN
#
# Author: the-shed automation
# License: MIT (do whatever you want with it)

require 'openssl'
require 'socket'
require 'timeout'
require 'optparse'
require 'json'
require 'time' # Time#iso8601

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Nagios-style exit codes / severity ranking (higher = worse, except UNKNOWN
# which is deliberately ranked below WARNING/CRITICAL -- a host we couldn't
# even reach should not silently outrank one we proved is broken).
EXIT_OK       = 0
EXIT_WARNING  = 1
EXIT_CRITICAL = 2
EXIT_UNKNOWN  = 3

SEVERITY_RANK = { unknown: 0, ok: 1, warning: 2, critical: 3 }.freeze

# Protocol versions we probe, oldest to newest, with the OpenSSL::SSL symbol
# accepted by SSLContext#min_version=/#max_version=. SSLv2 is intentionally
# excluded -- it was ripped out of OpenSSL's TLS state machine entirely and
# every modern build refuses to even construct that context.
PROTOCOL_PROBES = [
  [:SSL3,   'SSLv3'],
  [:TLS1,   'TLSv1.0'],
  [:TLS1_1, 'TLSv1.1'],
  [:TLS1_2, 'TLSv1.2'],
  [:TLS1_3, 'TLSv1.3']
].freeze

WEAK_PROTOCOLS = %w[SSLv3 TLSv1.0 TLSv1.1].freeze
GOOD_PROTOCOLS = %w[TLSv1.2 TLSv1.3].freeze

# SSLv3 gets its own, worse, severity (POODLE): a server that still speaks it
# is treated as CRITICAL on its own. TLSv1.0/1.1 are "merely" deprecated
# (PCI-DSS forced their retirement in 2018) so they're WARNING unless
# something else on the host is already CRITICAL.
PROTOCOL_SEVERITY = {
  'SSLv3'   => :critical,
  'TLSv1.0' => :warning,
  'TLSv1.1' => :warning
}.freeze

# Cipher-name substrings that indicate a weak cipher, checked in order
# against the OpenSSL cipher name returned by SSLSocket#cipher. Order matters
# a little (NULL/EXPORT/anonymous are worse than 3DES/MD5) but every match is
# recorded, not just the first.
WEAK_CIPHER_RULES = [
  [/NULL/i,          :critical, 'NULL cipher -- no bulk encryption at all, traffic is plaintext on the wire'],
  [/EXPORT/i,        :critical, 'export-grade cipher -- deliberately weakened to <=40/56-bit under old US export law'],
  [/(^|[^0-9A-Z])RC4([^0-9A-Z]|$)/i, :critical, 'RC4 stream cipher -- biased keystream, broken (RFC 7465 forbids it in TLS)'],
  [/(^|-)A?ECDH(-|$)/i, :critical, 'anonymous (EC)DH key exchange -- no server authentication, trivially MITM-able'],
  [/ADH/i,           :critical, 'anonymous DH key exchange -- no server authentication, trivially MITM-able'],
  [/3DES|DES-CBC/i,  :warning,  '(3)DES block cipher -- 64-bit block size is vulnerable to Sweet32 birthday attacks'],
  [/(^|[^0-9A-Z])DES([^0-9A-Z]|$)/i, :critical, 'single DES -- 56-bit key, breakable in hours on commodity hardware'],
  [/(^|[^0-9A-Z])MD5([^0-9A-Z]|$)/i, :warning,  'MD5 MAC -- collision-weak integrity check'],
  [/(^|[^0-9A-Z])SEED([^0-9A-Z]|$)/i, :warning, 'legacy SEED cipher -- little independent cryptanalysis, rarely needed today'],
  [/(^|[^0-9A-Z])IDEA([^0-9A-Z]|$)/i, :warning, 'legacy IDEA cipher -- obsolete, essentially unused outside old PGP/TLS stacks'],
  [/(^|[^0-9A-Z])RC2([^0-9A-Z]|$)/i,  :warning, 'legacy RC2 cipher -- 40/128-bit, obsolete']
].freeze

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

# Runs +block+ with a hard wall-clock timeout. Timeout.timeout is not
# perfectly safe against arbitrary C extensions, but for a short-lived
# blocking TLS handshake in a one-shot CLI tool it is the standard, simple
# approach used throughout small sysadmin scripts -- the process exits right
# after anyway, so a leaked thread/fiber here is not a long-term leak.
def with_timeout(seconds)
  Timeout.timeout(seconds) { yield }
rescue Timeout::Error
  raise Timeout::Error, "timed out after #{seconds}s"
end

# Builds an SSLContext deliberately configured to be as permissive as
# possible for AUDIT purposes: security_level 0 and a cipher string that
# re-admits NULL/anonymous suites OpenSSL 1.1+/3.x otherwise strips out by
# default. This is the opposite of what you'd want for a client making a
# real connection -- it exists purely so this tool can find out whether a
# remote server *would* accept a weak handshake if a badly configured or
# outdated client asked for one. Without lowering the security level here,
# modern OpenSSL simply refuses to offer TLS 1.0/1.1 or NULL/export ciphers
# at all, and every weak server would look falsely "secure".
def permissive_context(min_sym: nil, max_sym: nil)
  ctx = OpenSSL::SSL::SSLContext.new
  ctx.security_level = 0
  # ALL + explicitly re-enabled eNULL/aNULL/EXPORT bucket, still gated by
  # SECLEVEL=0 above. COMPLEMENTOFALL pulls back ciphers OpenSSL marks as
  # "normally excluded" (anonymous/EXPORT) that plain ALL alone won't touch
  # on every OpenSSL build.
  begin
    ctx.ciphers = 'ALL:eNULL:aNULL:COMPLEMENTOFALL:@SECLEVEL=0'
  rescue OpenSSL::SSL::SSLError
    # Some builds reject an empty resulting cipher list for a given
    # min/max version pairing (e.g. nothing at SECLEVEL=0 matches TLS1.3
    # alone, since TLS1.3 ciphersuites aren't controlled by this string at
    # all). That's fine -- fall through with the default list.
    begin
      ctx.ciphers = 'ALL:@SECLEVEL=0'
    rescue OpenSSL::SSL::SSLError
      nil
    end
  end
  ctx.min_version = min_sym if min_sym
  ctx.max_version = max_sym if max_sym
  ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
  ctx
end

# Opens a TCP connection with a connect-timeout, wraps it in the given
# SSLContext, and performs the handshake, also under a timeout. Returns the
# connected SSLSocket. Caller is responsible for closing it.
def tls_connect(host, port, ctx, timeout)
  tcp = with_timeout(timeout) { TCPSocket.new(host, port) }
  ssl = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
  ssl.hostname = host if ssl.respond_to?(:hostname=) # SNI
  with_timeout(timeout) { ssl.connect }
  ssl
rescue StandardError
  tcp&.close rescue nil
  raise
end

# Tries to pull a human-readable "N bit" figure and key type out of an
# ephemeral key's OpenSSL text dump. SSLSocket#tmp_key returns a generic
# OpenSSL::PKey::PKey under OpenSSL 3.x providers rather than a typed
# subclass, so `to_text` is the one portable way left to see what it
# actually is (e.g. "DH Public-Key: (1024 bit)", "X25519 Public-Key",
# "EC Public-Key" for a named curve).
def describe_tmp_key(tmp_key)
  return nil unless tmp_key

  text = begin
    tmp_key.to_text
  rescue StandardError
    nil
  end
  return nil unless text

  bits = text[/\((\d+)\s*bit\)/, 1]&.to_i
  kind = text[/^(\S[^:\n]*?)(?:\s+Public-Key)?:/, 1] || text.lines.first&.strip
  { kind: kind, bits: bits, raw: text.lines.first&.strip }
end

# ---------------------------------------------------------------------------
# Per-target scan
# ---------------------------------------------------------------------------

# Scans one host:port target end to end and returns a result Hash. Never
# raises -- every failure mode is captured into the result so a batch of 500
# targets can't be taken down by one bad DNS name.
def scan_target(host, port, timeout)
  result = {
    'target'            => "#{host}:#{port}",
    'host'               => host,
    'port'               => port,
    'reachable'          => false,
    'protocol_support'   => {},
    'negotiated'         => nil,
    'modern_client_view' => nil,
    'findings'           => [],
    'status'             => 'unknown',
    'error'              => nil
  }

  # --- Step 1: build the protocol support matrix -------------------------
  # Each probe forces min_version == max_version == exactly one protocol, so
  # a successful connect proves the server is willing to complete that exact
  # version and nothing else influenced the outcome.
  any_connect_ever_worked = false
  PROTOCOL_PROBES.each do |sym, label|
    ctx = permissive_context(min_sym: sym, max_sym: sym)
    begin
      ssl = tls_connect(host, port, ctx, timeout)
      result['protocol_support'][label] = true
      any_connect_ever_worked = true
      ssl.close
    rescue OpenSSL::SSL::SSLError
      # Handshake reached the server and was refused/aborted for this
      # protocol version specifically (alert, "no protocols available",
      # version mismatch, etc). That's a normal, expected "no" answer.
      result['protocol_support'][label] = false
    rescue Errno::ECONNREFUSED, Errno::ECONNRESET, Errno::EHOSTUNREACH,
           Errno::ENETUNREACH, SocketError, Timeout::Error, IOError => e
      # Network-level failure. Record once; if EVERY probe fails this way
      # the host is simply unreachable (handled below).
      result['protocol_support'][label] = false
      result['error'] ||= "#{e.class}: #{e.message}"
    end
  end

  unless any_connect_ever_worked
    result['status'] = 'unknown'
    result['error'] ||= 'could not complete a TLS handshake at any protocol version'
    return result
  end

  result['reachable'] = true

  # --- Step 2: worst-case negotiated cipher ------------------------------
  # Connect with the permissive context across the FULL version range (no
  # min/max pin) so OpenSSL and the server negotiate whatever they'd
  # actually agree on when a permissive/legacy client shows up. This is
  # what reveals a server whose only listener is, say, a NULL cipher.
  begin
    ctx = permissive_context
    ssl = tls_connect(host, port, ctx, timeout)
    name, proto, secret_bits, alg_bits = ssl.cipher
    tmp = describe_tmp_key(ssl.tmp_key)
    ssl.close
    result['negotiated'] = {
      'protocol'    => proto,
      'cipher'      => name,
      'secret_bits' => secret_bits,
      'alg_bits'    => alg_bits,
      'tmp_key'     => tmp
    }
  rescue StandardError => e
    result['error'] ||= "worst-case negotiation failed: #{e.class}: #{e.message}"
  end

  # --- Step 3: what a normal, modern client sees today -------------------
  # Default security level, default cipher list, TLS1.2 minimum -- i.e. what
  # curl/a browser actually gets. Purely informational context, never used
  # to compute severity, so a server that hides its weak listener behind
  # SNI/ALPN dispatch doesn't get a false "all clear".
  begin
    modern_ctx = OpenSSL::SSL::SSLContext.new
    modern_ctx.min_version = :TLS1_2
    modern_ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
    ssl = tls_connect(host, port, modern_ctx, timeout)
    name, proto, = ssl.cipher
    ssl.close
    result['modern_client_view'] = { 'protocol' => proto, 'cipher' => name }
  rescue StandardError
    result['modern_client_view'] = nil
  end

  # --- Step 4: turn the raw data into findings ---------------------------
  WEAK_PROTOCOLS.each do |label|
    next unless result['protocol_support'][label]

    sev = PROTOCOL_SEVERITY.fetch(label, :warning)
    result['findings'] << {
      'severity' => sev.to_s,
      'category' => 'protocol',
      'detail'   => "server accepts #{label} (deprecated/weak protocol)"
    }
  end

  if result['negotiated']
    cname = result['negotiated']['cipher'].to_s
    WEAK_CIPHER_RULES.each do |pattern, sev, why|
      next unless cname =~ pattern

      result['findings'] << { 'severity' => sev.to_s, 'category' => 'cipher', 'detail' => "negotiated cipher #{cname}: #{why}" }
    end

    # Forward secrecy check: any modern cipher name starts with a kx prefix
    # (ECDHE-.../DHE-.../TLS_ for the TLS1.3 suites, which are always PFS).
    # A cipher with none of those prefixes -- and that isn't already an
    # anonymous suite (A(EC)DH is ephemeral by definition, its problem is
    # missing authentication, already flagged above, not missing PFS) -- is
    # doing static RSA key transport: no forward secrecy, so a captured
    # private key retroactively decrypts every past session.
    is_anonymous_kx = cname =~ /A?ECDH-|ADH-/i
    if !is_anonymous_kx && cname !~ /^(ECDHE|EECDH|DHE|EDH|TLS_AES|TLS_CHACHA20)/i
      result['findings'] << {
        'severity' => 'warning',
        'category' => 'key_exchange',
        'detail'   => "negotiated cipher #{cname} uses static key exchange -- no forward secrecy"
      }
    end

    tmp = result['negotiated']['tmp_key']
    if tmp && tmp[:kind].to_s =~ /^DH\b/i && tmp[:bits] && tmp[:bits] < 2048
      result['findings'] << {
        'severity' => 'critical',
        'category' => 'key_exchange',
        'detail'   => "ephemeral DH key exchange uses only #{tmp[:bits]}-bit modulus (< 2048, Logjam-class weakness)"
      }
    end
  end

  # --- Step 5: roll everything up into one status -------------------------
  worst = result['findings'].map { |f| f['severity'].to_sym }.max_by { |s| SEVERITY_RANK[s] }
  result['status'] = (worst || :ok).to_s
  result
end

# ---------------------------------------------------------------------------
# Concurrency: fixed worker-thread pool draining a shared Queue, same shape
# as the api-health-check / cert-expiry-check scripts elsewhere in this repo.
# ---------------------------------------------------------------------------

def run_scans(targets, concurrency, timeout)
  queue = Queue.new
  targets.each { |t| queue << t }
  concurrency.times { queue << nil } # one stop signal per worker

  results_mutex = Mutex.new
  results = []

  workers = Array.new(concurrency) do
    Thread.new do
      loop do
        target = queue.pop
        break if target.nil?

        r = scan_target(target[:host], target[:port], timeout)
        results_mutex.synchronize { results << r }
      end
    end
  end
  workers.each(&:join)

  # Preserve the order targets were given on the command line / in the file,
  # rather than whatever order threads happened to finish in.
  order = targets.each_with_index.to_h { |t, i| ["#{t[:host]}:#{t[:port]}", i] }
  results.sort_by { |r| order[r['target']] || 0 }
end

# ---------------------------------------------------------------------------
# Target parsing
# ---------------------------------------------------------------------------

def parse_target(spec)
  spec = spec.strip
  return nil if spec.empty? || spec.start_with?('#')

  host, _, port = spec.rpartition(':')
  if host.empty?
    { host: spec, port: 443 }
  else
    { host: host, port: Integer(port) }
  end
rescue ArgumentError
  warn "warning: skipping unparseable target #{spec.inspect} (expected host:port)"
  nil
end

def load_targets(list_opt, file_opt)
  targets = []
  targets.concat(list_opt.split(',').map { |s| parse_target(s) }) if list_opt
  if file_opt
    File.readlines(file_opt).each { |line| targets << parse_target(line) }
  end
  targets.compact
end

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def status_icon(status)
  { 'ok' => 'PASS', 'warning' => 'WARN', 'critical' => 'CRIT', 'unknown' => 'UNK ' }.fetch(status, 'UNK ')
end

def print_text_report(results, verbose)
  counts = Hash.new(0)
  results.each { |r| counts[r['status']] += 1 }

  overall = overall_status(results)
  puts '=' * 78
  puts "TLS CIPHER AUDIT -- #{results.size} target(s) -- overall: #{overall.upcase}"
  puts "critical=#{counts['critical']} warning=#{counts['warning']} ok=#{counts['ok']} unknown=#{counts['unknown']}"
  puts '=' * 78

  results.each do |r|
    puts
    puts "[#{status_icon(r['status'])}] #{r['target']}  (status: #{r['status'].upcase})"

    if !r['reachable']
      puts "  UNREACHABLE: #{r['error']}"
      next
    end

    supported = GOOD_PROTOCOLS.select { |p| r['protocol_support'][p] }
    weak_on   = WEAK_PROTOCOLS.select { |p| r['protocol_support'][p] }
    puts "  protocols ok:   #{supported.empty? ? '(none!)' : supported.join(', ')}"
    puts "  protocols weak: #{weak_on.join(', ')}" unless weak_on.empty?

    if verbose
      matrix = PROTOCOL_PROBES.map { |_, label| "#{label}=#{r['protocol_support'][label] ? 'yes' : 'no'}" }
      puts "  full matrix:    #{matrix.join('  ')}"
    end

    if r['negotiated']
      n = r['negotiated']
      puts "  worst-case negotiated: #{n['protocol']} / #{n['cipher']} (#{n['secret_bits']}-bit)"
      if n['tmp_key'] && n['tmp_key'][:raw]
        puts "  ephemeral key:  #{n['tmp_key'][:raw]}"
      end
    end

    if r['modern_client_view']
      m = r['modern_client_view']
      puts "  modern client sees: #{m['protocol']} / #{m['cipher']}"
    end

    if r['findings'].empty?
      puts '  findings: none'
    else
      r['findings'].sort_by { |f| -SEVERITY_RANK[f['severity'].to_sym] }.each do |f|
        puts "  #{f['severity'].upcase.ljust(8)} [#{f['category']}] #{f['detail']}"
      end
    end
  end
  puts
  puts '=' * 78
end

def overall_status(results)
  return 'unknown' if results.empty?

  # CRITICAL beats WARNING beats UNKNOWN beats OK -- an unreachable host
  # must never silently hide a critical finding on another host in the same
  # run, but should also not be reported as worse than a proven CRITICAL.
  order = %w[critical warning unknown ok]
  order.find { |s| results.any? { |r| r['status'] == s } } || 'unknown'
end

def exit_code_for(status)
  { 'ok' => EXIT_OK, 'warning' => EXIT_WARNING, 'critical' => EXIT_CRITICAL, 'unknown' => EXIT_UNKNOWN }.fetch(status, EXIT_UNKNOWN)
end

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_options(argv)
  opts = { concurrency: 10, timeout: 5.0, json: false, verbose: false }
  parser = OptionParser.new do |o|
    o.banner = 'Usage: tls_cipher_audit.rb -t host:port[,host:port,...] | -f targets.txt [options]'
    o.on('-t', '--targets LIST', 'Comma-separated host:port targets') { |v| opts[:targets] = v }
    o.on('-f', '--file FILE', 'File with one host:port target per line (# comments ok)') { |v| opts[:file] = v }
    o.on('-c', '--concurrency N', Integer, 'Worker threads scanning concurrently (default 10)') { |v| opts[:concurrency] = v }
    o.on('-T', '--timeout N', Float, 'Per-connection timeout in seconds (default 5.0)') { |v| opts[:timeout] = v }
    o.on('-j', '--json', 'Emit machine-readable JSON instead of the text report') { opts[:json] = true }
    o.on('-v', '--verbose', 'Show the full per-protocol support matrix for every host') { opts[:verbose] = true }
    o.on('-h', '--help', 'Show this help') do
      puts o
      exit EXIT_OK
    end
  end
  parser.parse!(argv)
  opts
end

def main
  opts = parse_options(ARGV)
  targets = load_targets(opts[:targets], opts[:file])

  if targets.empty?
    warn 'error: no targets given. Use -t host:port[,host:port,...] and/or -f targets.txt'
    exit EXIT_UNKNOWN
  end

  results = run_scans(targets, [opts[:concurrency], 1].max, opts[:timeout])
  overall = overall_status(results)

  if opts[:json]
    puts JSON.pretty_generate(
      'overall_status' => overall,
      'checked_at'     => Time.now.utc.iso8601,
      'targets'        => results
    )
  else
    print_text_report(results, opts[:verbose])
  end

  exit exit_code_for(overall)
end

main if __FILE__ == $PROGRAM_NAME
