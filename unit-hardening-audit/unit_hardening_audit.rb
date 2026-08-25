#!/usr/bin/env ruby
# frozen_string_literal: true
#
# unit_hardening_audit.rb -- score the sandboxing/hardening of systemd service
# units, in pure standard-library Ruby. `systemd-analyze security` exists on
# modern systemd, but it needs a running systemd and DBus; this script only
# needs the unit FILES, so it works in containers, chroots, image builds and
# CI -- anywhere you can read /lib/systemd/system.
#
# Each [Service] section is checked against a weighted hardening checklist
# (User=, NoNewPrivileges=, ProtectSystem=, ProtectHome=, PrivateTmp=,
# PrivateDevices=, ProtectKernel*, RestrictSUIDSGID=, CapabilityBoundingSet=,
# SystemCallFilter=, RestrictAddressFamilies=) and scored 0-100.
#
# Usage:
#   ruby unit_hardening_audit.rb                          # scan default dirs
#   ruby unit_hardening_audit.rb /etc/systemd/system      # scan specific dirs
#   ruby unit_hardening_audit.rb --min-score 50           # exit 1 if any unit scores below
#   ruby unit_hardening_audit.rb --unit ssh.service --json
#
# Exit codes: 0 ok, 1 at least one audited unit below --min-score.
#
require 'optparse'
require 'json'
require 'time'

DEFAULT_DIRS = ['/etc/systemd/system', '/lib/systemd/system', '/usr/lib/systemd/system'].freeze

# Weighted checklist. Each entry: key, points, predicate on the value, and the
# advice shown when the check fails. Weights roughly follow the impact ranking
# systemd-analyze security uses.
CHECKS = [
  { key: 'User',                    pts: 20, ok: ->(v) { v && v != 'root' },
    advice: 'runs as root -- set User= to a service account' },
  { key: 'NoNewPrivileges',         pts: 12, ok: ->(v) { v == 'true' || v == 'yes' },
    advice: 'child processes can gain privileges (setuid binaries); set NoNewPrivileges=true' },
  { key: 'ProtectSystem',           pts: 12, ok: ->(v) { %w[strict full true yes].include?(v.to_s) },
    advice: '/usr and /etc are writable; set ProtectSystem=strict (or full)' },
  { key: 'ProtectHome',             pts: 8,  ok: ->(v) { %w[true yes read-only tmpfs].include?(v.to_s) },
    advice: 'home directories are visible; set ProtectHome=true' },
  { key: 'PrivateTmp',              pts: 8,  ok: ->(v) { v == 'true' || v == 'yes' },
    advice: 'shares /tmp with every other process; set PrivateTmp=true' },
  { key: 'PrivateDevices',          pts: 8,  ok: ->(v) { v == 'true' || v == 'yes' },
    advice: 'raw device access allowed; set PrivateDevices=true' },
  { key: 'ProtectKernelTunables',   pts: 6,  ok: ->(v) { v == 'true' || v == 'yes' },
    advice: 'can write /proc/sys; set ProtectKernelTunables=true' },
  { key: 'ProtectKernelModules',    pts: 6,  ok: ->(v) { v == 'true' || v == 'yes' },
    advice: 'can load kernel modules; set ProtectKernelModules=true' },
  { key: 'RestrictSUIDSGID',        pts: 6,  ok: ->(v) { v == 'true' || v == 'yes' },
    advice: 'can create setuid files; set RestrictSUIDSGID=true' },
  { key: 'CapabilityBoundingSet',   pts: 6,  ok: ->(v) { !v.nil? },
    advice: 'full capability set available; set CapabilityBoundingSet= to the minimum' },
  { key: 'SystemCallFilter',        pts: 5,  ok: ->(v) { !v.nil? },
    advice: 'no syscall filter; set SystemCallFilter=@system-service' },
  { key: 'RestrictAddressFamilies', pts: 3,  ok: ->(v) { !v.nil? },
    advice: 'all socket families allowed; set RestrictAddressFamilies=' }
].freeze
MAX_PTS = CHECKS.sum { |c| c[:pts] } # 100

# Minimal unit-file parser: sections, Key=Value, line continuations with '\',
# comments (#/;). A repeated key overrides earlier ones EXCEPT list-like keys,
# where systemd appends -- for scoring we only need "was it set at all".
def parse_unit(path)
  section = nil
  data = Hash.new { |h, k| h[k] = {} }
  pending = nil
  File.foreach(path, encoding: 'UTF-8') do |raw|
    line = raw.scrub.strip
    next if line.empty? || line.start_with?('#', ';')
    if pending
      pending[1] << ' ' << line.delete_suffix('\\').strip
      pending = nil unless line.end_with?('\\')
      next
    end
    if line =~ /\A\[(.+)\]\z/
      section = Regexp.last_match(1)
    elsif section && line.include?('=')
      k, v = line.split('=', 2).map(&:strip)
      v = v.delete_suffix('\\').strip if (cont = v.end_with?('\\'))
      data[section][k] = v
      pending = [k, data[section][k]] if cont
    end
  end
  data
rescue Errno::EACCES
  nil
end

def audit(path)
  unit = parse_unit(path)
  return nil unless unit
  svc = unit['Service']
  return nil if svc.nil? || svc.empty?
  # oneshot units that just run a script get a pass on User= sometimes; still scored.
  earned = 0
  missing = []
  CHECKS.each do |c|
    if c[:ok].call(svc[c[:key]])
      earned += c[:pts]
    else
      missing << { key: c[:key], pts: c[:pts], advice: c[:advice] }
    end
  end
  { unit: File.basename(path), path: path, score: (earned * 100.0 / MAX_PTS).round,
    exec: (svc['ExecStart'] || '')[0, 60], missing: missing }
end

def grade(score)
  case score
  when 80.. then '[ OK ]'
  when 50..79 then '[MED ]'
  else '[EXPOSED]'
  end
end

opts = { min: 0, unit: nil, json: false, top: 12 }
OptionParser.new do |o|
  o.banner = 'Usage: unit_hardening_audit.rb [options] [DIR...]'
  o.on('--min-score N', Integer, 'Exit 1 if any unit scores below N') { |v| opts[:min] = v }
  o.on('--unit NAME', 'Audit only this unit (e.g. ssh.service)') { |v| opts[:unit] = v }
  o.on('--top N', Integer, 'Show the N worst units in text mode (default 12)') { |v| opts[:top] = v }
  o.on('--json', 'Emit JSON instead of text') { opts[:json] = true }
end.parse!

dirs = ARGV.empty? ? DEFAULT_DIRS.select { |d| Dir.exist?(d) } : ARGV
files = dirs.flat_map { |d| Dir.glob(File.join(d, '*.service')) }
            .reject { |f| File.symlink?(f) || File.basename(f).include?('@') } # skip aliases/templates
            .uniq { |f| File.basename(f) } # /etc overrides /lib: first dir wins
files.select! { |f| File.basename(f) == opts[:unit] } if opts[:unit]

results = files.filter_map { |f| audit(f) }.sort_by { |r| r[:score] }
worst = results.select { |r| r[:score] < opts[:min] }

if opts[:json]
  puts JSON.pretty_generate(generated_at: Time.now.utc.iso8601, scanned: files.size,
                            audited: results.size, min_score: opts[:min],
                            below_min: worst.size, units: results)
else
  puts "== unit hardening audit -- #{results.size} service unit(s) from: #{dirs.join(', ')} =="
  results.first(opts[:top]).each do |r|
    puts format('%-9s %3d/100  %-32s %s', grade(r[:score]), r[:score], r[:unit], r[:exec])
    r[:missing].first(3).each { |m| puts format('             -%2dpt  %s', m[:pts], m[:advice]) }
  end
  if results.size > opts[:top]
    puts "  ... #{results.size - opts[:top]} more (use --top/--json for all)"
  end
  avg = results.empty? ? 0 : results.sum { |r| r[:score] } / results.size
  puts format('average score: %d/100 -- %d unit(s) below --min-score %d', avg, worst.size, opts[:min])
end
exit worst.empty? ? 0 : 1
