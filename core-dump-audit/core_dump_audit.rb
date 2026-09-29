#!/usr/bin/env ruby
# frozen_string_literal: true
# core_dump_audit.rb - audit how a Linux host handles crashes / core dumps.
# Checks: core_pattern handler, suid_dumpable, ulimit -c in limits.d, and how
# much disk existing dump directories consume (a crash loop can fill /var).
# Usage: ruby core_dump_audit.rb [--root DIR] [--json] [--dump-warn-mb N]
# --root prefixes every path, so a captured tree can be audited anywhere.
# Exit: 0 OK, 1 WARN, 2 CRIT.  Stdlib only.
require 'optparse'
require 'json'

opts = { root: '', json: false, dump_warn_mb: 1024, dump_crit_mb: 5120 }
OptionParser.new do |o|
  o.on('--root DIR') { |v| opts[:root] = v.chomp('/') }
  o.on('--json') { opts[:json] = true }
  o.on('--dump-warn-mb N', Integer) { |v| opts[:dump_warn_mb] = v }
  o.on('--dump-crit-mb N', Integer) { |v| opts[:dump_crit_mb] = v }
end.parse!

def path(opts, p) = "#{opts[:root]}#{p}"
def slurp(opts, p) = (File.read(path(opts, p)).strip rescue nil)

Finding = Struct.new(:sev, :check, :detail, :fix)
findings = []

# 1. Where do cores go?
pattern = slurp(opts, '/proc/sys/kernel/core_pattern')
if pattern.nil?
  findings << Finding.new('WARN', 'core_pattern', 'unreadable', nil)
elsif pattern.start_with?('|')
  handler = pattern[1..].split.first
  base = File.basename(handler)
  known = %w[systemd-coredump apport abrt-hook-ccpp].any? { |k| base.include?(k) }
  if known then findings << Finding.new('OK', 'core_pattern', "piped to #{base} (managed)", nil)
  else findings << Finding.new('WARN', 'core_pattern', "piped to unrecognised handler #{handler}",
                               'confirm the handler is trusted and runs as an unprivileged user')
  end
elsif !pattern.start_with?('/')
  findings << Finding.new('WARN', 'core_pattern',
    "relative pattern '#{pattern}': cores land in each crashing process's cwd (possibly world-readable)",
    'sysctl -w kernel.core_pattern=/var/lib/coredumps/core.%e.%p.%t')
else
  findings << Finding.new('OK', 'core_pattern', "absolute path #{pattern}", nil)
end

# 2. SUID programs dumping core can leak root-only memory.
sd = slurp(opts, '/proc/sys/fs/suid_dumpable')
case sd
when '0' then findings << Finding.new('OK', 'suid_dumpable', '0 (setuid programs never dump)', nil)
when '2' then findings << Finding.new('WARN', 'suid_dumpable', '2 (suidsafe: only safe if core_pattern is piped or absolute)', 'sysctl -w fs.suid_dumpable=0')
when '1' then findings << Finding.new('CRIT', 'suid_dumpable', '1 (setuid processes dump readable by the user)', 'sysctl -w fs.suid_dumpable=0')
else findings << Finding.new('WARN', 'suid_dumpable', "unexpected value #{sd.inspect}", nil)
end

# 3. limits.conf / limits.d "core" lines - effective ulimit -c for logins.
limit_files = Dir[path(opts, '/etc/security/limits.conf'), path(opts, '/etc/security/limits.d/*.conf')].sort
core_lines = limit_files.flat_map do |f|
  File.readlines(f).map(&:strip).reject { |l| l.empty? || l.start_with?('#') }
      .map(&:split).select { |a| a[2] == 'core' }.map { |a| [File.basename(f), a] }
end
unlimited = core_lines.select { |_, a| a[3] == 'unlimited' && a[1] == 'soft' || a[3] == 'unlimited' && a[1] == '-' }
if unlimited.any?
  findings << Finding.new('WARN', 'limits', "unlimited core size set in #{unlimited.map(&:first).uniq.join(', ')}", 'use a finite cap, e.g. "* hard core 0" on non-debug hosts')
elsif core_lines.empty?
  findings << Finding.new('OK', 'limits', 'no core overrides (distro default: soft limit 0)', nil)
else
  findings << Finding.new('OK', 'limits', "#{core_lines.size} core limit line(s), none unlimited", nil)
end

# 4. Disk consumed by existing dumps.
dump_dirs = %w[/var/lib/systemd/coredump /var/crash /var/lib/apport/coredump /var/spool/abrt]
dump_dirs.each do |d|
  full = path(opts, d)
  next unless Dir.exist?(full)
  files = Dir.glob("#{full}/**/*").select { |f| File.file?(f) }
  mb = files.sum { |f| File.size(f) } / 1_048_576.0
  sev = mb >= opts[:dump_crit_mb] ? 'CRIT' : mb >= opts[:dump_warn_mb] ? 'WARN' : 'OK'
  newest = files.map { |f| File.mtime(f) }.max
  detail = format('%d dump(s), %.1f MB%s', files.size, mb, newest ? ", newest #{newest.strftime('%Y-%m-%d %H:%M')}" : '')
  findings << Finding.new(sev, "dumps:#{d}", detail, sev == 'OK' ? nil : 'coredumpctl / rm old dumps; set MaxUse= in coredump.conf')
end

worst = (%w[CRIT WARN OK] & findings.map(&:sev)).first
if opts[:json]
  puts JSON.pretty_generate(overall: worst, findings: findings.map(&:to_h))
else
  puts "core-dump-audit: #{worst}"
  findings.each do |f|
    puts format('  [%-4s] %-28s %s', f.sev, f.check, f.detail)
    puts "         fix: #{f.fix}" if f.fix
  end
end
exit({ 'OK' => 0, 'WARN' => 1, 'CRIT' => 2 }[worst])
