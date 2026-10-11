#!/usr/bin/env ruby
# frozen_string_literal: true
# route_table_audit.rb - audit the Linux IPv4 routing table from /proc/net/route.
# Pure stdlib. Usage: ruby route_table_audit.rb [--file PATH] [--json]
require 'json'
require 'optparse'

Route = Struct.new(:iface, :dest, :gateway, :flags, :metric, :mask, keyword_init: true) do
  def prefix_len = mask.to_s(2).count('1')
  def default? = dest.zero? && mask.zero?
  def up? = flags.anybits?(0x1)
  def via_gateway? = flags.anybits?(0x2)
end

# /proc/net/route stores addresses as little-endian hex; convert to Integer
# in network (big-endian) order so normal bit math works.
def le_hex_to_int(hex) = [hex.to_i(16)].pack('L<').unpack1('N')

def ip(int) = [int].pack('N').unpack('C4').join('.')

def parse(path)
  File.readlines(path, chomp: true).drop(1).filter_map do |line|
    f = line.split
    next if f.size < 8
    Route.new(iface: f[0], dest: le_hex_to_int(f[1]), gateway: le_hex_to_int(f[2]),
              flags: f[3].to_i(16), metric: f[6].to_i, mask: le_hex_to_int(f[7]))
  end
end

def audit(routes)
  findings = []
  add = ->(sev, msg) { findings << { severity: sev, message: msg } }
  defaults = routes.select { |r| r.default? && r.up? }
  add.(:high, 'No default route: host cannot reach anything off-link') if defaults.empty?
  defaults.group_by(&:metric).each do |m, rs|
    add.(:medium, "#{rs.size} default routes share metric #{m} (#{rs.map(&:iface).join(', ')}): path choice is ambiguous") if rs.size > 1
  end
  routes.group_by { |r| [r.dest, r.mask, r.metric] }.each do |(d, m, me), rs|
    add.(:medium, "Duplicate route #{ip(d)}/#{m.to_s(2).count('1')} metric #{me} on #{rs.map(&:iface).join(', ')}") if rs.size > 1
  end
  connected = routes.select { |r| !r.via_gateway? && !r.default? }
  routes.select(&:via_gateway?).each do |r|
    ok = connected.any? { |c| c.iface == r.iface && (r.gateway & c.mask) == c.dest }
    add.(:high, "Gateway #{ip(r.gateway)} for #{ip(r.dest)}/#{r.prefix_len} is not inside any connected subnet on #{r.iface}") unless ok
  end
  routes.reject(&:up?).each { |r| add.(:low, "Route #{ip(r.dest)}/#{r.prefix_len} on #{r.iface} is marked down") }
  findings
end

opts = { file: '/proc/net/route', json: false }
OptionParser.new do |o|
  o.on('--file PATH') { |v| opts[:file] = v }
  o.on('--json') { opts[:json] = true }
end.parse!

routes = parse(opts[:file])
findings = audit(routes)
if opts[:json]
  puts JSON.pretty_generate(routes: routes.size, findings: findings)
else
  puts "Routes parsed: #{routes.size}"
  routes.each { |r| puts format('  %-16s %-8s via %-15s metric %d', "#{ip(r.dest)}/#{r.prefix_len}", r.iface, r.via_gateway? ? ip(r.gateway) : 'on-link', r.metric) }
  puts findings.empty? ? 'OK: no routing problems found' : findings.map { |f| "[#{f[:severity].upcase}] #{f[:message]}" }
end
exit(findings.any? { |f| f[:severity] == :high } ? 2 : (findings.empty? ? 0 : 1))
