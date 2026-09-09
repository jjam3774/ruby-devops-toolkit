#!/usr/bin/env ruby
# frozen_string_literal: true
#
# tcp_conn_monitor.rb -- TCP connection-state monitor for Linux, written in
# pure Ruby (no gems, no netstat/ss binaries required).
#
# It reads /proc/net/tcp and /proc/net/tcp6 directly, decodes the kernel's
# hex-encoded socket table, and reports:
#   * a count of every TCP state (ESTABLISHED, TIME_WAIT, SYN_RECV, ...)
#   * which local ports are listening, and how many connections each has
#   * the top remote peers by connection count (who is hammering us?)
#   * threshold alerts (too many TIME_WAIT, SYN flood signs, one noisy peer)
#
# Usage:
#   ruby tcp_conn_monitor.rb                 # human-readable report
#   ruby tcp_conn_monitor.rb --json          # machine-readable JSON
#   ruby tcp_conn_monitor.rb --top 5         # show top 5 peers/ports
#   ruby tcp_conn_monitor.rb --watch 10      # refresh every 10 seconds
#   ruby tcp_conn_monitor.rb --proc-dir DIR  # read fixtures instead of /proc
#
# Exit codes: 0 = healthy, 1 = warnings, 2 = critical (useful for cron/Nagios).

require 'json'
require 'optparse'
require 'ipaddr'

# Kernel socket-state codes from include/net/tcp_states.h
TCP_STATES = {
  '01' => 'ESTABLISHED', '02' => 'SYN_SENT',  '03' => 'SYN_RECV',
  '04' => 'FIN_WAIT1',   '05' => 'FIN_WAIT2', '06' => 'TIME_WAIT',
  '07' => 'CLOSE',       '08' => 'CLOSE_WAIT', '09' => 'LAST_ACK',
  '0A' => 'LISTEN',      '0B' => 'CLOSING',   '0C' => 'NEW_SYN_RECV'
}.freeze

# Tunable alert thresholds. Override with --warn-*/--crit-* flags if you like,
# or just edit these to taste for your workload.
DEFAULT_THRESHOLDS = {
  time_wait_warn: 5_000,   # lots of short-lived connections; consider reuse
  time_wait_crit: 20_000,  # ephemeral port exhaustion is near
  syn_recv_warn:  200,     # half-open backlog growing -> possible SYN flood
  syn_recv_crit:  1_000,
  peer_warn:      200,     # a single remote IP holding this many connections
  peer_crit:      1_000,
  close_wait_warn: 100     # app is not closing sockets it was handed (leak)
}.freeze

# One row from /proc/net/tcp{,6}. We keep only what we need.
Conn = Struct.new(:local_ip, :local_port, :remote_ip, :remote_port, :state, :uid, :inode)

class ProcNetParser
  def initialize(proc_dir: '/proc')
    @proc_dir = proc_dir
  end

  # Returns an Array<Conn> for both IPv4 and IPv6 tables.
  def connections
    conns = []
    %w[tcp tcp6].each do |table|
      path = File.join(@proc_dir, 'net', table)
      next unless File.readable?(path)

      File.foreach(path).with_index do |line, idx|
        next if idx.zero? # header row: "sl local_address rem_address st ..."

        conn = parse_line(line, table == 'tcp6')
        conns << conn if conn
      end
    end
    conns
  end

  private

  # Example /proc/net/tcp row (fields are whitespace separated):
  #   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000  0 12345 ...
  #      ^local       ^remote       ^state                                     ^uid    ^inode
  def parse_line(line, ipv6)
    f = line.split
    return nil if f.size < 10

    lip, lport = decode_addr(f[1], ipv6)
    rip, rport = decode_addr(f[2], ipv6)
    Conn.new(lip, lport, rip, rport, TCP_STATES.fetch(f[3], "UNKNOWN(#{f[3]})"), f[7].to_i, f[9].to_i)
  end

  # "0100007F:1F90" -> ["127.0.0.1", 8080]
  # The kernel writes IPv4 as a little-endian 32-bit hex word, and IPv6 as four
  # little-endian 32-bit words, so we have to byte-swap each 4-byte group.
  def decode_addr(field, ipv6)
    hex, port = field.split(':')
    bytes = [hex].pack('H*')                    # hex string -> raw bytes
    swapped = bytes.unpack('V*').pack('N*')     # LE words -> BE words
    ip = ipv6 ? IPAddr.new_ntoh(swapped) : IPAddr.new_ntoh(swapped[0, 4])
    ip = ip.ipv4_mapped? ? ip.native : ip if ipv6 # ::ffff:1.2.3.4 -> 1.2.3.4
    [ip.to_s, port.to_i(16)]
  end
end

class TcpReport
  attr_reader :conns, :thresholds

  def initialize(conns, thresholds: DEFAULT_THRESHOLDS, top: 10)
    @conns = conns
    @thresholds = thresholds
    @top = top
  end

  def state_counts
    conns.group_by(&:state).transform_values(&:size).sort_by { |_, v| -v }.to_h
  end

  # Listening sockets, plus how many non-LISTEN connections target each port.
  def listeners
    listen = conns.select { |c| c.state == 'LISTEN' }
    active = conns.reject { |c| c.state == 'LISTEN' }
    listen.map do |l|
      hits = active.count { |c| c.local_port == l.local_port }
      { port: l.local_port, bind: l.local_ip, uid: l.uid, connections: hits }
    end.uniq { |h| [h[:port], h[:bind]] }.sort_by { |h| -h[:connections] }
  end

  def top_peers
    conns.reject { |c| c.state == 'LISTEN' || c.remote_ip == '0.0.0.0' || c.remote_ip == '::' }
         .group_by(&:remote_ip)
         .map { |ip, list| { ip: ip, connections: list.size, states: list.group_by(&:state).transform_values(&:size) } }
         .sort_by { |h| -h[:connections] }
         .first(@top)
  end

  # Returns [severity_symbol, [messages]] where severity is :ok/:warn/:crit
  def alerts
    sc = state_counts
    msgs = []
    sev = :ok
    bump = ->(level) { sev = level if level == :crit || (level == :warn && sev == :ok) }

    tw = sc.fetch('TIME_WAIT', 0)
    if tw >= thresholds[:time_wait_crit]
      bump.(:crit); msgs << "CRIT TIME_WAIT=#{tw} (ephemeral port exhaustion likely)"
    elsif tw >= thresholds[:time_wait_warn]
      bump.(:warn); msgs << "WARN TIME_WAIT=#{tw} (consider keep-alive / net.ipv4.tcp_tw_reuse)"
    end

    sr = sc.fetch('SYN_RECV', 0)
    if sr >= thresholds[:syn_recv_crit]
      bump.(:crit); msgs << "CRIT SYN_RECV=#{sr} (SYN flood or overwhelmed accept queue)"
    elsif sr >= thresholds[:syn_recv_warn]
      bump.(:warn); msgs << "WARN SYN_RECV=#{sr} (half-open backlog growing)"
    end

    cw = sc.fetch('CLOSE_WAIT', 0)
    if cw >= thresholds[:close_wait_warn]
      bump.(:warn); msgs << "WARN CLOSE_WAIT=#{cw} (application is not closing sockets)"
    end

    top_peers.each do |p|
      if p[:connections] >= thresholds[:peer_crit]
        bump.(:crit); msgs << "CRIT peer #{p[:ip]} holds #{p[:connections]} connections"
      elsif p[:connections] >= thresholds[:peer_warn]
        bump.(:warn); msgs << "WARN peer #{p[:ip]} holds #{p[:connections]} connections"
      end
    end
    [sev, msgs]
  end

  def to_h
    sev, msgs = alerts
    {
      timestamp: Time.now.utc.iso8601,
      host: (File.read('/etc/hostname').strip rescue 'unknown'),
      total: conns.size,
      states: state_counts,
      listeners: listeners.first(@top),
      top_peers: top_peers,
      severity: sev,
      alerts: msgs
    }
  end

  def to_text
    h = to_h
    out = []
    out << "TCP connection report  #{h[:host]}  #{h[:timestamp]}"
    out << ('=' * 64)
    out << format('%-14s %6s', 'STATE', 'COUNT')
    h[:states].each { |s, n| out << format('%-14s %6d', s, n) }
    out << format('%-14s %6d', 'TOTAL', h[:total])
    out << ''
    out << format('%-6s %-24s %5s %6s', 'PORT', 'BIND', 'UID', 'CONNS')
    h[:listeners].each { |l| out << format('%-6d %-24s %5d %6d', l[:port], l[:bind], l[:uid], l[:connections]) }
    out << ''
    out << format('%-40s %6s  %s', 'REMOTE PEER', 'CONNS', 'STATES')
    h[:top_peers].each do |p|
      states = p[:states].map { |s, n| "#{s}=#{n}" }.join(' ')
      out << format('%-40s %6d  %s', p[:ip], p[:connections], states)
    end
    out << ''
    out << "severity: #{h[:severity].to_s.upcase}"
    h[:alerts].each { |m| out << "  #{m}" }
    out << '  no threshold breached' if h[:alerts].empty?
    out.join("\n")
  end
end

def exit_code_for(sev)
  { ok: 0, warn: 1, crit: 2 }.fetch(sev)
end

if __FILE__ == $PROGRAM_NAME
  require 'time'
  opts = { json: false, top: 10, watch: nil, proc_dir: '/proc' }
  thresholds = DEFAULT_THRESHOLDS.dup
  OptionParser.new do |o|
    o.banner = 'Usage: tcp_conn_monitor.rb [options]'
    o.on('--json', 'Emit JSON instead of text') { opts[:json] = true }
    o.on('--top N', Integer, 'Rows to show for ports/peers (default 10)') { |n| opts[:top] = n }
    o.on('--watch SEC', Integer, 'Re-run every SEC seconds') { |n| opts[:watch] = n }
    o.on('--proc-dir DIR', 'Alternate /proc root (for testing)') { |d| opts[:proc_dir] = d }
    thresholds.each_key do |k|
      o.on("--#{k.to_s.tr('_', '-')} N", Integer, "Threshold (default #{thresholds[k]})") { |n| thresholds[k] = n }
    end
  end.parse!

  last_severity = :ok
  loop do
    conns = ProcNetParser.new(proc_dir: opts[:proc_dir]).connections
    report = TcpReport.new(conns, thresholds: thresholds, top: opts[:top])
    last_severity = report.alerts.first
    if opts[:json]
      puts JSON.pretty_generate(report.to_h)
    else
      print "\e[2J\e[H" if opts[:watch] # clear screen in watch mode
      puts report.to_text
    end
    break unless opts[:watch]

    sleep opts[:watch]
  end
  exit exit_code_for(last_severity)
end
