#!/usr/bin/env ruby
# frozen_string_literal: true
#
# net_iface_monitor.rb - Sample /proc/net/dev and report per-interface
# throughput, packet rates and (most importantly) error/drop deltas, with
# optional threshold alerts and a Nagios-style exit code.
#
# Why not just run `ip -s link`? Because that prints lifetime counters.
# The number you care about at 3 AM is "how many packets did eth0 DROP in
# the last 10 seconds", and that requires two samples and a subtraction.
#
# Usage:
#   ruby net_iface_monitor.rb                       # one 5-second sample, all real NICs
#   ruby net_iface_monitor.rb -i eth0 -n 3 -s 10    # eth0 only, three 10s windows
#   ruby net_iface_monitor.rb --drop-threshold 0 --err-threshold 0   # alert on ANY drop/err
#   ruby net_iface_monitor.rb --json                # machine-readable, one object per window
#   ruby net_iface_monitor.rb --link-state          # add carrier/speed/mtu from sysfs
#
# Exit codes (last window wins): 0 OK, 1 WARNING (drops), 2 CRITICAL (errors), 3 usage error.
#
# Tested with Ruby 3.0+ on Ubuntu 22.04. No gems required.

require 'optparse'
require 'json'
require 'time'

# Column order in /proc/net/dev, after the "iface:" token.
RX_FIELDS = %i[rx_bytes rx_packets rx_errs rx_drop rx_fifo rx_frame rx_compressed rx_multicast].freeze
TX_FIELDS = %i[tx_bytes tx_packets tx_errs tx_drop tx_fifo tx_colls tx_carrier tx_compressed].freeze
FIELDS = (RX_FIELDS + TX_FIELDS).freeze

opts = {
  ifaces: nil, interval: 5, count: 1, json: false, link: false,
  drop_threshold: 10, err_threshold: 0, include_virtual: false,
  proc_path: '/proc/net/dev'
}

OptionParser.new do |o|
  o.banner = 'Usage: net_iface_monitor.rb [options]'
  o.on('-i', '--iface LIST', Array, 'Comma-separated interfaces (default: all physical)') { |v| opts[:ifaces] = v }
  o.on('-s', '--interval SEC', Float, 'Seconds per sample window (default 5)') { |v| opts[:interval] = v }
  o.on('-n', '--count N', Integer, 'Number of windows to sample (default 1, 0 = forever)') { |v| opts[:count] = v }
  o.on('--drop-threshold N', Integer, 'WARNING if rx+tx drops in a window exceed N (default 10)') { |v| opts[:drop_threshold] = v }
  o.on('--err-threshold N', Integer, 'CRITICAL if rx+tx errors in a window exceed N (default 0)') { |v| opts[:err_threshold] = v }
  o.on('--include-virtual', 'Also show lo, docker*, veth*, br-*, virbr*') { opts[:include_virtual] = true }
  o.on('--link-state', 'Read carrier/speed/mtu/operstate from /sys/class/net') { opts[:link] = true }
  o.on('--json', 'Emit one JSON document per window') { opts[:json] = true }
  o.on('--proc-path PATH', 'Alternate /proc/net/dev (for testing)') { |v| opts[:proc_path] = v }
  o.on('-h', '--help') { puts o; exit 3 }
end.parse!

VIRTUAL = /\A(lo|docker\d*|veth|br-|virbr|tun|tap|wg\d|flannel|cni|kube)/.freeze

# ---------------------------------------------------------------------------
# Reading counters
# ---------------------------------------------------------------------------
def read_counters(path)
  File.readlines(path).drop(2).each_with_object({}) do |line, h|
    name, rest = line.split(':', 2)
    next unless rest
    values = rest.split.map(&:to_i)
    next unless values.size >= FIELDS.size
    h[name.strip] = FIELDS.zip(values).to_h
  end
rescue Errno::ENOENT, Errno::EACCES => e
  warn "cannot read #{path}: #{e.message}"
  exit 3
end

def link_state(iface)
  base = "/sys/class/net/#{iface}"
  read = ->(f) { File.read("#{base}/#{f}").strip rescue 'n/a' }
  { operstate: read.call('operstate'), carrier: read.call('carrier'),
    speed_mbps: read.call('speed'), mtu: read.call('mtu') }
end

# ---------------------------------------------------------------------------
# Delta maths
# ---------------------------------------------------------------------------
# Counters are unsigned 64-bit and can wrap; a negative delta means a wrap
# (or an interface reset), so clamp to zero rather than reporting nonsense.
def delta(after, before)
  FIELDS.each_with_object({}) { |f, h| h[f] = [after[f] - before[f], 0].max }
end

def human_rate(bytes, secs)
  bps = bytes * 8.0 / secs
  units = %w[bps Kbps Mbps Gbps Tbps]
  i = 0
  while bps >= 1000 && i < units.size - 1
    bps /= 1000
    i += 1
  end
  format('%6.1f %-4s', bps, units[i])
end

def select_ifaces(counters, opts)
  names = counters.keys
  names = names.reject { |n| n.match?(VIRTUAL) } unless opts[:include_virtual]
  names &= opts[:ifaces] if opts[:ifaces]
  names.sort
end

def status_for(d, opts)
  errs = d[:rx_errs] + d[:tx_errs]
  drops = d[:rx_drop] + d[:tx_drop]
  return [2, 'CRIT'] if errs > opts[:err_threshold]
  return [1, 'WARN'] if drops > opts[:drop_threshold]
  [0, 'OK']
end

# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
def render_text(rows, secs, window_no)
  puts "window #{window_no}  (#{secs}s)  #{Time.now.strftime('%H:%M:%S')}"
  puts format('  %-10s %-6s %12s %12s %8s %8s %6s %6s %6s %6s', 'IFACE', 'STATE', 'RX', 'TX', 'RX pkt/s', 'TX pkt/s', 'RXerr', 'TXerr', 'RXdrp', 'TXdrp')
  rows.each do |r|
    d = r[:delta]
    puts format('  %-10s %-6s %12s %12s %8.0f %8.0f %6d %6d %6d %6d',
                r[:iface], r[:status], human_rate(d[:rx_bytes], secs), human_rate(d[:tx_bytes], secs),
                d[:rx_packets] / secs, d[:tx_packets] / secs,
                d[:rx_errs], d[:tx_errs], d[:rx_drop], d[:tx_drop])
    next unless r[:link]
    l = r[:link]
    puts format('  %-10s link: %s carrier=%s speed=%sMb mtu=%s', '', l[:operstate], l[:carrier], l[:speed_mbps], l[:mtu])
  end
  puts
end

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
worst = 0
window = 0
before = read_counters(opts[:proc_path])

loop do
  window += 1
  sleep opts[:interval]
  after = read_counters(opts[:proc_path])
  secs = opts[:interval]

  rows = select_ifaces(after, opts).filter_map do |iface|
    next unless before[iface]
    d = delta(after[iface], before[iface])
    code, label = status_for(d, opts)
    worst = [worst, code].max
    { iface: iface, status: label, code: code, delta: d,
      link: opts[:link] ? link_state(iface) : nil }
  end

  if opts[:json]
    puts JSON.generate(window: window, seconds: secs, at: Time.now.iso8601,
                       interfaces: rows.map { |r| r.reject { |k, _| k == :code } })
  else
    render_text(rows, secs, window)
  end

  before = after
  break if opts[:count].positive? && window >= opts[:count]
end

exit worst
