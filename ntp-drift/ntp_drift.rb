#!/usr/bin/env ruby
# frozen_string_literal: true
#
# ntp_drift.rb -- NTP Time Drift Monitoring & Alerting Across a Server Fleet
#
# Speaks just enough of the SNTP client protocol (RFC 4330 / RFC 5905)
# over a raw UDP socket to ask a list of NTP sources "how far off is my
# clock?" and turns the answer into WARN/CRIT alerts. No gems, no
# shelling out to `ntpdate`/`chronyc` (which aren't always installed,
# and whose text output changes between distros) -- just Socket from
# the standard library.
#
# Why this matters for DevOps: clock drift silently breaks Kerberos
# auth, TLS certificate validation, distributed log correlation, and
# cron-based SLAs. A drift monitor that runs from a central box against
# every NTP source (or every host's local NTP relay) in the fleet is
# one of the cheapest early-warning systems you can build.
#
# Usage:
#   ruby ntp_drift.rb pool.ntp.org time.google.com time.cloudflare.com
#   ruby ntp_drift.rb --warn-ms 200 --crit-ms 1000 10.0.0.5 10.0.0.6
#   ruby ntp_drift.rb --json ntp1.internal ntp2.internal
#
require 'socket'
require 'optparse'
require 'json'
require 'timeout'

NTP_PORT = 123
NTP_EPOCH_OFFSET = 2_208_988_800 # seconds between 1900-01-01 and the Unix epoch

# One 48-byte SNTP client request: LI=0 (no warning), VN=4, Mode=3 (client).
# Everything else can be zero for a basic client query.
def build_request_packet
  li_vn_mode = 0b00_100_011 # LI=0, VN=4, Mode=3
  [li_vn_mode].pack('C') + ("\0" * 47)
end

# Convert a Float unix timestamp -> 8-byte NTP timestamp (32-bit seconds
# since 1900 + 32-bit fraction). Not strictly required for a basic
# client query, but including a real Transmit Timestamp is good
# practice and lets a server that supports it validate round-trips.
def to_ntp_timestamp(unix_time)
  ntp_seconds = unix_time.to_i + NTP_EPOCH_OFFSET
  fraction = ((unix_time - unix_time.to_i) * (2**32)).to_i
  [ntp_seconds, fraction].pack('N2')
end

# Convert an 8-byte NTP timestamp field back to a Float unix timestamp.
def from_ntp_timestamp(bytes)
  seconds, fraction = bytes.unpack('N2')
  (seconds - NTP_EPOCH_OFFSET) + (fraction.to_f / (2**32))
end

Result = Struct.new(:host, :ok, :offset_ms, :delay_ms, :stratum, :error)

# Query one NTP source and compute clock offset using the classic
# four-timestamp NTP algorithm:
#   T1 = client send time         T2 = server receive time
#   T3 = server transmit time     T4 = client receive time
#   offset = ((T2 - T1) + (T3 - T4)) / 2
#   delay  = (T4 - T1) - (T3 - T2)
def query_ntp(host, port: NTP_PORT, timeout: 3)
  socket = UDPSocket.new
  packet = build_request_packet

  t1 = Time.now.to_f
  # Stamp our own transmit timestamp into the request (bytes 40-47) --
  # optional, but several public NTP servers echo it back for sanity
  # checking, and it costs nothing.
  packet = packet[0, 40] + to_ntp_timestamp(t1)

  Timeout.timeout(timeout) do
    socket.connect(host, port)
    socket.send(packet, 0)
    response, = socket.recvfrom(48)
    t4 = Time.now.to_f

    raise 'short response (not a valid NTP packet)' if response.bytesize < 48

    stratum = response[1].unpack1('C')
    t2 = from_ntp_timestamp(response[32, 8])  # Receive Timestamp
    t3 = from_ntp_timestamp(response[40, 8])  # Transmit Timestamp

    offset = ((t2 - t1) + (t3 - t4)) / 2.0
    delay  = (t4 - t1) - (t3 - t2)

    Result.new(host, true, (offset * 1000).round(2), (delay * 1000).round(2), stratum, nil)
  end
rescue StandardError => e
  Result.new(host, false, nil, nil, nil, "#{e.class}: #{e.message}")
ensure
  socket&.close
end

# Query every host concurrently -- with a fleet of NTP sources, doing
# this serially means one slow/unreachable host stalls the whole run.
# Accepts "host" or "host:port" so internal NTP relays on non-standard
# ports can be mixed with public pool servers in the same run.
def parse_target(spec)
  if spec.include?(':')
    host, port = spec.split(':', 2)
    [host, port.to_i]
  else
    [spec, NTP_PORT]
  end
end

def query_fleet(hosts, warn_ms:, crit_ms:, timeout: 3)
  threads = hosts.map do |spec|
    host, port = parse_target(spec)
    Thread.new { query_ntp(host, port: port, timeout: timeout) }
  end
  results = threads.map(&:value)

  results.map do |r|
    severity =
      if !r.ok then 'CRIT'
      elsif r.offset_ms.abs >= crit_ms then 'CRIT'
      elsif r.offset_ms.abs >= warn_ms then 'WARN'
      else 'OK'
      end
    [r, severity]
  end
end

def print_report(scored, warn_ms, crit_ms)
  puts '=' * 72
  puts "NTP DRIFT CHECK  (warn >= #{warn_ms}ms, crit >= #{crit_ms}ms)"
  puts '=' * 72
  scored.each do |r, sev|
    if r.ok
      printf("[%-4s] %-24s offset=%9.2fms  delay=%7.2fms  stratum=%s\n",
             sev, r.host, r.offset_ms, r.delay_ms, r.stratum)
    else
      printf("[%-4s] %-24s UNREACHABLE  (%s)\n", sev, r.host, r.error)
    end
  end
  puts '-' * 72
  crit = scored.count { |_, s| s == 'CRIT' }
  warn = scored.count { |_, s| s == 'WARN' }
  puts "Summary: #{crit} CRIT, #{warn} WARN, #{scored.size - crit - warn} OK"
  puts '=' * 72
  crit
end

if $PROGRAM_NAME == __FILE__
  options = { warn_ms: 200.0, crit_ms: 1000.0, json: false, timeout: 3 }
  parser = OptionParser.new do |o|
    o.banner = 'Usage: ntp_drift.rb [options] HOST [HOST ...]'
    o.on('--warn-ms N', Float, 'Offset threshold for WARN (default 200)') { |v| options[:warn_ms] = v }
    o.on('--crit-ms N', Float, 'Offset threshold for CRIT (default 1000)') { |v| options[:crit_ms] = v }
    o.on('--timeout N', Float, 'Per-host UDP timeout in seconds (default 3)') { |v| options[:timeout] = v }
    o.on('--json', 'Emit JSON instead of a text report') { options[:json] = true }
  end
  parser.parse!

  hosts = ARGV.empty? ? ['pool.ntp.org'] : ARGV
  scored = query_fleet(hosts, warn_ms: options[:warn_ms], crit_ms: options[:crit_ms], timeout: options[:timeout])

  if options[:json]
    puts JSON.pretty_generate(
      warn_ms: options[:warn_ms], crit_ms: options[:crit_ms],
      results: scored.map { |r, sev| r.to_h.merge(severity: sev) }
    )
  else
    print_report(scored, options[:warn_ms], options[:crit_ms])
  end

  exit(scored.any? { |_, s| s == 'CRIT' } ? 2 : 0)
end
