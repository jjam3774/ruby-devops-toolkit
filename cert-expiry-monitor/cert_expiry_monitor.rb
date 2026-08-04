#!/usr/bin/env ruby
# frozen_string_literal: true
#
# cert_expiry_monitor.rb
#
# Pure Ruby TLS certificate expiry monitor. Connects to a list of
# host[:port] targets, pulls the live leaf certificate presented during
# the TLS handshake (NOT a cached/local copy), and reports how many days
# remain until it expires. No gems required -- just openssl and socket
# from the Ruby standard library.
#
# Exit codes (cron/monitoring friendly):
#   0 -> everything OK
#   1 -> at least one WARN (approaching expiry)
#   2 -> at least one CRIT (expired, about to expire, or unreachable)
#
# Usage:
#   ruby cert_expiry_monitor.rb HOST[:PORT] [HOST[:PORT] ...] [options]
#
# Options:
#   --warn-days N     Days-remaining threshold for WARN   (default: 30)
#   --crit-days N     Days-remaining threshold for CRIT   (default: 7)
#   --timeout N       Per-connection timeout in seconds   (default: 5)
#   --json            Emit machine-readable JSON instead of text
#
require 'openssl'
require 'socket'
require 'optparse'
require 'json'
require 'timeout'
require 'time'

# ---------------------------------------------------------------------------
# CertCheck: connects to a single host:port, performs a TLS handshake, and
# extracts expiry info from the certificate the server actually presents.
# ---------------------------------------------------------------------------
class CertCheck
  Result = Struct.new(:target, :host, :port, :status, :days_remaining,
                       :not_after, :subject, :issuer, :error, keyword_init: true)

  def initialize(target, timeout: 5)
    @target = target
    @host, port_str = target.split(':', 2)
    @port = (port_str || 443).to_i
    @timeout = timeout
  end

  # Opens a raw TCP socket, wraps it in an SSLSocket with SNI set (so
  # name-based virtual hosts serve the right cert), completes the
  # handshake, and reads back the peer certificate. Everything is
  # wrapped in Timeout so a single hung host can't stall the whole run.
  def call
    Timeout.timeout(@timeout) do
      tcp = TCPSocket.new(@host, @port)
      begin
        ctx = OpenSSL::SSL::SSLContext.new
        # We want the cert even if it's untrusted/self-signed/expired --
        # that's exactly the case this tool needs to detect and report,
        # not silently reject.
        ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE

        ssl = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
        ssl.hostname = @host # SNI
        ssl.connect

        cert = ssl.peer_cert
        ssl.sysclose
        return build_result(cert)
      ensure
        tcp.close unless tcp.closed?
      end
    end
  rescue StandardError, Timeout::Error => e
    Result.new(target: @target, host: @host, port: @port, status: 'CRIT',
               days_remaining: nil, not_after: nil, subject: nil, issuer: nil,
               error: "#{e.class}: #{e.message}")
  end

  private

  def build_result(cert)
    if cert.nil?
      return Result.new(target: @target, host: @host, port: @port, status: 'CRIT',
                         days_remaining: nil, not_after: nil, subject: nil, issuer: nil,
                         error: 'server presented no certificate')
    end

    days_remaining = ((cert.not_after - Time.now) / 86_400).floor

    Result.new(
      target: @target, host: @host, port: @port,
      status: nil, # classified by caller against thresholds
      days_remaining: days_remaining,
      not_after: cert.not_after.utc.iso8601,
      subject: cert.subject.to_a.find { |name, _, _| name == 'CN' }&.at(1) || cert.subject.to_s,
      issuer: cert.issuer.to_a.find { |name, _, _| name == 'CN' }&.at(1) || cert.issuer.to_s,
      error: nil
    )
  end
end

# ---------------------------------------------------------------------------
# Runner: fans checks out across a small thread pool (TLS handshakes are
# I/O-bound, so threads are a good fit and keep the total wall-clock time
# close to that of the single slowest host, not the sum of all hosts).
# ---------------------------------------------------------------------------
class Runner
  def initialize(targets, warn_days:, crit_days:, timeout:, concurrency: 8)
    @targets = targets
    @warn_days = warn_days
    @crit_days = crit_days
    @timeout = timeout
    @concurrency = concurrency
  end

  def run
    queue = Queue.new
    @targets.each { |t| queue << t }
    results = Queue.new

    workers = Array.new([@concurrency, @targets.size].min) do
      Thread.new do
        until queue.empty?
          target = begin
            queue.pop(true)
          rescue ThreadError
            nil
          end
          next unless target

          result = CertCheck.new(target, timeout: @timeout).call
          classify!(result)
          results << result
        end
      end
    end
    workers.each(&:join)

    drained = []
    drained << results.pop until results.empty?
    # Preserve the order the targets were given on the command line.
    @targets.map { |t| drained.find { |r| r.target == t } }
  end

  private

  def classify!(result)
    return if result.status == 'CRIT' && result.error # unreachable/handshake failure

    if result.days_remaining.nil?
      result.status = 'CRIT'
    elsif result.days_remaining <= @crit_days
      result.status = 'CRIT'
    elsif result.days_remaining <= @warn_days
      result.status = 'WARN'
    else
      result.status = 'OK'
    end
  end
end

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  options = { warn_days: 30, crit_days: 7, timeout: 5, json: false }

  parser = OptionParser.new do |opts|
    opts.banner = 'Usage: ruby cert_expiry_monitor.rb HOST[:PORT] [HOST[:PORT] ...] [options]'
    opts.on('--warn-days N', Integer, 'Days-remaining threshold for WARN (default: 30)') { |v| options[:warn_days] = v }
    opts.on('--crit-days N', Integer, 'Days-remaining threshold for CRIT (default: 7)') { |v| options[:crit_days] = v }
    opts.on('--timeout N', Integer, 'Per-connection timeout in seconds (default: 5)') { |v| options[:timeout] = v }
    opts.on('--json', 'Emit machine-readable JSON') { options[:json] = true }
    opts.on('-h', '--help', 'Show this help') do
      puts opts
      exit 0
    end
  end
  targets = parser.parse(ARGV)

  if targets.empty?
    warn parser
    exit 2
  end

  results = Runner.new(targets, warn_days: options[:warn_days],
                                 crit_days: options[:crit_days],
                                 timeout: options[:timeout]).run

  if options[:json]
    puts JSON.pretty_generate(results.map(&:to_h))
  else
    printf("%-32s %-6s %-8s %-22s %s\n", 'TARGET', 'STATUS', 'DAYS', 'EXPIRES (UTC)', 'SUBJECT / ERROR')
    puts '-' * 100
    results.each do |r|
      detail = r.error || r.subject
      printf("%-32s %-6s %-8s %-22s %s\n", r.target, r.status, r.days_remaining.nil? ? '-' : r.days_remaining,
             r.not_after || '-', detail)
    end
  end

  worst = results.map(&:status).max_by { |s| { 'OK' => 0, 'WARN' => 1, 'CRIT' => 2 }[s] }
  exit({ 'OK' => 0, 'WARN' => 1, 'CRIT' => 2 }[worst] || 2)
end
