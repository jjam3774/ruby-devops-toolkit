#!/usr/bin/env ruby
# frozen_string_literal: true
# tls_cert_expiry.rb - check TLS certificate expiry for a list of host:port endpoints.
# Pure stdlib (socket, openssl, optparse, json, timeout). Ruby 2.7+.
# Exit codes: 0 all OK, 1 warning, 2 critical/expired/error  (Nagios-style, cron friendly)
require 'socket'
require 'openssl'
require 'optparse'
require 'json'
require 'timeout'

Result = Struct.new(:target, :status, :days_left, :not_after, :subject, :issuer, :error, keyword_init: true)

# Fetch the peer certificate. We disable chain verification ON PURPOSE:
# we want to report on expired/self-signed certs rather than fail the handshake.
def fetch_cert(host, port, timeout)
  Timeout.timeout(timeout) do
    tcp = TCPSocket.new(host, port)
    ctx = OpenSSL::SSL::SSLContext.new
    ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
    ssl = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
    ssl.hostname = host # SNI, required by most shared hosts
    ssl.connect
    cert = ssl.peer_cert
    ssl.close
    tcp.close
    cert
  end
end

def classify(days, warn, crit)
  return 'EXPIRED' if days < 0
  return 'CRITICAL' if days <= crit
  return 'WARNING' if days <= warn

  'OK'
end

def check(target, warn:, crit:, timeout:, now: Time.now)
  host, port = target.split(':')
  port = (port || 443).to_i
  cert = fetch_cert(host, port, timeout)
  days = ((cert.not_after - now) / 86_400).floor
  Result.new(target: target, status: classify(days, warn, crit), days_left: days,
             not_after: cert.not_after.utc.strftime('%Y-%m-%d'),
             subject: cert.subject.to_s, issuer: cert.issuer.to_s)
rescue StandardError, Timeout::Error => e
  Result.new(target: target, status: 'ERROR', error: "#{e.class}: #{e.message}")
end

if $PROGRAM_NAME == __FILE__
  opts = { warn: 30, crit: 14, timeout: 5, json: false }
  OptionParser.new do |o|
    o.banner = 'Usage: tls_cert_expiry.rb [options] host[:port] ...'
    o.on('-w', '--warn DAYS', Integer, 'warning threshold (default 30)') { |v| opts[:warn] = v }
    o.on('-c', '--crit DAYS', Integer, 'critical threshold (default 14)') { |v| opts[:crit] = v }
    o.on('-t', '--timeout SEC', Integer, 'connect timeout (default 5)') { |v| opts[:timeout] = v }
    o.on('-j', '--json', 'JSON output') { opts[:json] = true }
  end.parse!
  abort 'no targets given' if ARGV.empty?

  # One thread per endpoint so a slow host cannot stall the whole run.
  results = ARGV.map { |t| Thread.new { check(t, **opts.slice(:warn, :crit, :timeout)) } }.map(&:value)
  results.sort_by! { |r| r.days_left || -99_999 }

  if opts[:json]
    puts JSON.pretty_generate(results.map(&:to_h))
  else
    printf("%-10s %-24s %6s  %s\n", 'STATUS', 'TARGET', 'DAYS', 'EXPIRES')
    results.each do |r|
      printf("%-10s %-24s %6s  %s\n", r.status, r.target, r.days_left || '-', r.not_after || r.error)
    end
  end
  worst = results.map(&:status)
  exit(worst.any? { |s| %w[CRITICAL EXPIRED ERROR].include?(s) } ? 2 : (worst.include?('WARNING') ? 1 : 0))
end
