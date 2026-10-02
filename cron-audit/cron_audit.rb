#!/usr/bin/env ruby
# frozen_string_literal: true
#
# cron_audit.rb - audit Linux cron tables for broken or risky jobs.
# Ruby 3.0+, stdlib only. Usage: ruby cron_audit.rb [--json] [--root DIR]
require 'optparse'
require 'json'
require 'time'

Finding = Struct.new(:severity, :file, :line, :rule, :message, keyword_init: true)

FIELD_RANGES = { minute: 0..59, hour: 0..23, dom: 1..31, month: 1..12, dow: 0..7 }.freeze
MACROS = %w[@reboot @yearly @annually @monthly @weekly @daily @midnight @hourly].freeze

# Expand one cron field ("*/15", "1-5", "1,3,7") into a sorted array of ints.
# Raises ArgumentError for anything out of range or malformed.
def expand_field(text, range)
  values = text.split(',').flat_map do |part|
    base, step = part.split('/', 2)
    step = step ? Integer(step, 10) : 1
    raise ArgumentError, "step must be > 0 in '#{part}'" if step < 1
    lo, hi = if base == '*' then [range.min, range.max]
             elsif base.include?('-') then base.split('-', 2).map { |n| Integer(n, 10) }
             else v = Integer(base, 10); [v, step > 1 ? range.max : v]
             end
    raise ArgumentError, "'#{part}' outside #{range}" unless range.cover?(lo) && range.cover?(hi) && lo <= hi
    (lo..hi).step(step).to_a
  end
  values.uniq.sort
end

# Parse a crontab line. system_table => has a user column (/etc/crontab, cron.d).
def parse_line(raw, system_table)
  line = raw.strip
  return nil if line.empty? || line.start_with?('#')
  return [:env, line] if line =~ /\A[A-Za-z_][A-Za-z0-9_]*\s*=/
  parts = line.split(/\s+/, line.start_with?('@') ? 2 : 6)
  if line.start_with?('@')
    sched = [parts[0]]
    rest = parts[1].to_s
  else
    sched = parts[0, 5]
    rest = parts[5].to_s
  end
  user = nil
  if system_table
    user, rest = rest.split(/\s+/, 2)
  end
  [:job, { schedule: sched, user: user, command: rest.to_s }]
end

def next_run(sched, from = Time.now)
  return nil if sched.size == 1
  m, h, dom, mon, dow = FIELD_RANGES.keys.zip(sched).map { |k, f| expand_field(f, FIELD_RANGES[k]) }
  dow = dow.map { |d| d % 7 }.uniq
  dom_star = sched[2] == '*'
  dow_star = sched[4] == '*'
  t = Time.at((from.to_i / 60 + 1) * 60)
  # Walk forward minute by minute for up to ~1 year; fine for an audit tool.
  (366 * 24 * 60).times do
    day_ok = if dom_star && dow_star then true
             elsif dom_star then dow.include?(t.wday)
             elsif dow_star then dom.include?(t.day)
             else dom.include?(t.day) || dow.include?(t.wday) # cron ORs when both restricted
             end
    return t if mon.include?(t.month) && day_ok && h.include?(t.hour) && m.include?(t.min)
    t += 60
  end
  nil
end

def audit_file(path, system_table)
  findings = []
  File.readlines(path, chomp: true).each_with_index do |raw, i|
    kind, data = parse_line(raw, system_table)
    next unless kind == :job
    n = i + 1
    add = ->(sev, rule, msg) { findings << Finding.new(severity: sev, file: path, line: n, rule: rule, message: msg) }
    sched = data[:schedule]
    if sched.size == 1
      add.(:error, 'bad-macro', "unknown macro #{sched[0]}") unless MACROS.include?(sched[0])
    else
      begin
        FIELD_RANGES.keys.zip(sched).each { |k, f| expand_field(f, FIELD_RANGES[k]) }
        nr = next_run(sched)
        add.(:warn, 'never-runs', 'schedule never fires within a year (e.g. Feb 31)') if nr.nil?
        add.(:info, 'every-minute', 'runs every minute') if sched.first(5).all? { |f| f == '*' }
      rescue ArgumentError => e
        add.(:error, 'bad-schedule', e.message)
        next
      end
    end
    cmd = data[:command]
    add.(:error, 'no-command', 'job has no command') if cmd.empty?
    add.(:error, 'bad-user', "no such user '#{data[:user]}'") if data[:user] && !user_exists?(data[:user])
    exe = cmd.split(/\s+/).first.to_s
    if exe.start_with?('/')
      if !File.exist?(exe)
        add.(:error, 'missing-binary', "#{exe} does not exist")
      else
        add.(:warn, 'not-executable', "#{exe} is not executable") unless File.executable?(exe)
        add.(:error, 'world-writable', "#{exe} is world-writable (root cron can be hijacked)") if File.world_writable?(exe)
      end
    end
    add.(:info, 'no-redirect', 'output not redirected: cron will mail or drop it') unless cmd =~ />|\|\s*(logger|mail)|MAILTO/
  end
  findings
end

def user_exists?(name)
  File.readlines('/etc/passwd').any? { |l| l.start_with?("#{name}:") }
rescue Errno::ENOENT
  true
end

options = { root: '/etc', json: false }
OptionParser.new do |o|
  o.on('--root DIR', 'directory holding crontab, cron.d (default /etc)') { |v| options[:root] = v }
  o.on('--json', 'emit JSON') { options[:json] = true }
end.parse!

targets = []
tab = File.join(options[:root], 'crontab')
targets << [tab, true] if File.file?(tab)
Dir.glob(File.join(options[:root], 'cron.d', '*')).sort.each { |f| targets << [f, true] if File.file?(f) }
%w[/var/spool/cron/crontabs /var/spool/cron].each do |d|
  Dir.glob(File.join(d, '*')).sort.each { |f| targets << [f, false] if File.file?(f) && File.readable?(f) }
end if options[:root] == '/etc'

findings = targets.flat_map { |f, sys| audit_file(f, sys) }
if options[:json]
  puts JSON.pretty_generate(findings.map(&:to_h))
else
  puts "Scanned #{targets.size} cron file(s), #{findings.size} finding(s)"
  findings.sort_by { |f| [{ error: 0, warn: 1, info: 2 }[f.severity], f.file, f.line] }.each do |f|
    puts format('%-5s %-14s %s:%d  %s', f.severity.to_s.upcase, f.rule, f.file, f.line, f.message)
  end
end
exit(findings.any? { |f| f.severity == :error } ? 2 : 0)
