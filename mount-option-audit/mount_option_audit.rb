#!/usr/bin/env ruby
# frozen_string_literal: true
#
# mount_option_audit.rb - Audit LIVE mount options of sensitive Linux mount points.
#
# Reads /proc/self/mountinfo (what the kernel actually enforces right now, not
# what /etc/fstab says) and checks that world-writable locations such as /tmp,
# /var/tmp and /dev/shm are mounted with nosuid, nodev and noexec.
#
# Usage:  ruby mount_option_audit.rb [--json] [--mountinfo FILE]
# Exit:   0 = all good, 1 = findings, 2 = usage error
require 'json'
require 'optparse'

# mount point => options that SHOULD be present, plus severity if missing
POLICY = {
  '/tmp'     => { need: %w[nosuid nodev noexec], sev: 'HIGH' },
  '/var/tmp' => { need: %w[nosuid nodev noexec], sev: 'HIGH' },
  '/dev/shm' => { need: %w[nosuid nodev noexec], sev: 'HIGH' },
  '/home'    => { need: %w[nosuid nodev],        sev: 'MEDIUM' },
  '/boot'    => { need: %w[nosuid nodev],        sev: 'MEDIUM' }
}.freeze

Mount = Struct.new(:mount_point, :fstype, :source, :options)

# mountinfo line format (man 5 proc):
# 36 35 98:0 /root /mnt1 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
# Fields before " - " are variable; the mount point is field 5 and per-mount
# options field 6. After the "-" separator: fstype, source, super options.
def parse_mountinfo(text)
  text.each_line.filter_map do |line|
    pre, post = line.chomp.split(' - ', 2)
    next unless post
    pf = pre.split(' ')
    qf = post.split(' ')
    # Octal escapes (\040 = space) are used in paths
    mp = pf[4].to_s.gsub(/\\([0-7]{3})/) { Regexp.last_match(1).to_i(8).chr }
    Mount.new(mp, qf[0], qf[1], pf[5].to_s.split(','))
  end
end

def audit(mounts)
  by_mp = {}
  mounts.each { |m| by_mp[m.mount_point] = m } # later entries shadow earlier ones
  POLICY.filter_map do |mp, rule|
    m = by_mp[mp]
    next({ mount: mp, status: 'NOT_SEPARATE', severity: 'INFO', missing: [],
           note: 'not a separate mount; inherits options of parent filesystem' }) unless m
    missing = rule[:need] - m.options
    { mount: mp, status: missing.empty? ? 'OK' : 'FAIL',
      severity: missing.empty? ? 'OK' : rule[:sev], missing: missing,
      fstype: m.fstype, options: m.options }
  end
end

opts = { json: false, file: '/proc/self/mountinfo' }
OptionParser.new do |o|
  o.banner = 'Usage: mount_option_audit.rb [options]'
  o.on('--json') { opts[:json] = true }
  o.on('--mountinfo FILE', 'read a saved mountinfo file (testing)') { |f| opts[:file] = f }
end.parse!

begin
  results = audit(parse_mountinfo(File.read(opts[:file])))
rescue Errno::ENOENT, Errno::EACCES => e
  warn "cannot read mountinfo: #{e.message}"
  exit 2
end

if opts[:json]
  puts JSON.pretty_generate(results)
else
  puts format('%-10s %-13s %-8s %s', 'MOUNT', 'STATUS', 'SEVERITY', 'DETAIL')
  results.each do |r|
    detail = r[:missing].empty? ? (r[:note] || r[:options].join(',')) : "missing: #{r[:missing].join(', ')}"
    puts format('%-10s %-13s %-8s %s', r[:mount], r[:status], r[:severity], detail)
  end
end
exit(results.any? { |r| r[:status] == 'FAIL' } ? 1 : 0)
