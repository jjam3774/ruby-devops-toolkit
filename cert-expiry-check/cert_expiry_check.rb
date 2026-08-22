#!/usr/bin/env ruby
# frozen_string_literal: true
#
# cert_expiry_check.rb -- TLS certificate expiry auditor for a fleet of endpoints.
#
# Connects to each host:port over TLS (with SNI), reads the presented leaf
# certificate, and reports days until expiry. Endpoints are checked
# concurrently with a bounded thread pool, so a 200-host fleet finishes in
# seconds instead of minutes.
#
# Severity model (Nagios-style, cron/CI friendly):
#   OK    -> more days left than --warn
#   WARN  -> expires within --warn days      (exit code 1)
#   CRIT  -> expires within --crit days,     (exit code 2)
#            already expired, or unreachable
#
# Usage:
#   ruby cert_expiry_check.rb example.com google.com:443 internal.host:8443
#   ruby cert_expiry_check.rb --file endpoints.txt --warn 30 --crit 7 --json
#
# Only the Ruby standard library is used: openssl, socket, json, optparse,
# timeout. No gems to install on the box you are auditing.

require "openssl"
require "socket"
require "json"
require "optparse"
require "timeout"
require "time"

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
options = {
  warn: 30,          # days -> WARN at or below this
  crit: 7,           # days -> CRIT at or below this
  timeout: 10,       # seconds per endpoint (connect + handshake)
  threads: 8,        # concurrent checks
  json: false,
  file: nil,
  insecure_ok: true  # we do NOT verify the chain -- we only read expiry.
}

OptionParser.new do |o|
  o.banner = "Usage: ruby cert_expiry_check.rb [options] host[:port] ..."
  o.on("--warn DAYS",  Integer, "WARN threshold in days (default 30)")  { |v| options[:warn]  = v }
  o.on("--crit DAYS",  Integer, "CRIT threshold in days (default 7)")   { |v| options[:crit]  = v }
  o.on("--timeout SEC", Integer, "Per-endpoint timeout (default 10)")   { |v| options[:timeout] = v }
  o.on("--threads N",  Integer, "Concurrent checks (default 8)")        { |v| options[:threads] = v }
  o.on("--file PATH",  "Read endpoints from a file (one per line, # comments allowed)") { |v| options[:file] = v }
  o.on("--json", "Emit JSON instead of the text table") { options[:json] = true }
end.parse!

# Collect endpoints from --file and/or argv. Default port is 443.
endpoints = []
if options[:file]
  File.readlines(options[:file]).each do |line|
    line = line.strip
    next if line.empty? || line.start_with?("#")
    endpoints << line
  end
end
endpoints.concat(ARGV)
abort("No endpoints given. Try: ruby cert_expiry_check.rb example.com") if endpoints.empty?

# ---------------------------------------------------------------------------
# The actual check: TCP connect -> TLS handshake (SNI) -> read peer cert.
# ---------------------------------------------------------------------------
def check_endpoint(spec, opts)
  host, port = spec.split(":", 2)
  port = (port || 443).to_i
  result = { endpoint: spec, host: host, port: port }

  begin
    Timeout.timeout(opts[:timeout]) do
      tcp = TCPSocket.new(host, port)
      ctx = OpenSSL::SSL::SSLContext.new
      # VERIFY_NONE on purpose: an auditor must still read the expiry date of
      # a broken/self-signed chain instead of erroring out before the check.
      ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
      ssl = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
      ssl.hostname = host          # SNI -- required for shared-IP hosting
      ssl.sync_close = true
      ssl.connect

      cert = ssl.peer_cert
      raise "no certificate presented" unless cert

      not_after  = cert.not_after
      days_left  = ((not_after - Time.now) / 86_400).floor
      result.merge!(
        subject:    cert.subject.to_s,
        issuer:     cert.issuer.to_s.split("CN=").last.to_s.strip,
        not_after:  not_after.utc.iso8601,
        days_left:  days_left,
        status:     if days_left < 0 then "CRIT"       # already expired
                    elsif days_left <= opts[:crit] then "CRIT"
                    elsif days_left <= opts[:warn] then "WARN"
                    else "OK"
                    end
      )
      ssl.close
    end
  rescue StandardError, Timeout::Error => e
    # Unreachable or broken TLS is CRIT: a cert you cannot check is a cert
    # you cannot trust to be valid.
    result.merge!(status: "CRIT", error: "#{e.class}: #{e.message}")
  end
  result
end

# ---------------------------------------------------------------------------
# Bounded thread pool: a work queue drained by N worker threads.
# ---------------------------------------------------------------------------
queue   = Queue.new
endpoints.each { |e| queue << e }
results = Queue.new

workers = Array.new([options[:threads], endpoints.size].min) do
  Thread.new do
    while (spec = queue.pop(true) rescue nil)
      results << check_endpoint(spec, options)
    end
  end
end
workers.each(&:join)

rows = []
rows << results.pop until results.empty?
rows.sort_by! { |r| [r[:days_left] || -999, r[:endpoint]] }

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
worst = rows.map { |r| r[:status] }
exit_code = worst.include?("CRIT") ? 2 : (worst.include?("WARN") ? 1 : 0)

if options[:json]
  puts JSON.pretty_generate(
    generated_at: Time.now.utc.iso8601,
    warn_days: options[:warn], crit_days: options[:crit],
    summary: { ok:   worst.count("OK"),
               warn: worst.count("WARN"),
               crit: worst.count("CRIT") },
    results: rows
  )
else
  puts format("%-30s %-6s %10s  %-25s %s", "ENDPOINT", "STATUS", "DAYS LEFT", "EXPIRES (UTC)", "ISSUER")
  puts "-" * 100
  rows.each do |r|
    if r[:error]
      puts format("%-30s %-6s %10s  %-25s %s", r[:endpoint], r[:status], "-", "-", r[:error])
    else
      puts format("%-30s %-6s %10d  %-25s %s", r[:endpoint], r[:status], r[:days_left], r[:not_after], r[:issuer])
    end
  end
  puts "-" * 100
  puts "ok=#{worst.count('OK')} warn=#{worst.count('WARN')} crit=#{worst.count('CRIT')}  (warn<=#{options[:warn]}d crit<=#{options[:crit]}d)"
end

exit exit_code
