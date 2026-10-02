#!/usr/bin/env ruby
# frozen_string_literal: true
#
# cron_audit.rb — inventory, validate, and risk-check cron jobs.
#
# Cron is where automation goes to be forgotten. This script walks the
# system cron surface (/etc/crontab, /etc/cron.d/*, optionally user spool
# files), and for every job:
#
#   * validates the schedule (5-field syntax, ranges, steps, @aliases)
#   * computes the NEXT RUN time with a small pure-Ruby cron matcher
#   * risk-checks the command line:
#       - script referenced by the job is missing            -> BROKEN
#       - script is world/group-writable or not owned root   -> RISK
#       - `curl ... | sh` style pipe-to-shell                -> RISK
#       - relative path in command (PATH surprises)          -> WARN
#
# Stdlib only. Text and --json output. Exit codes: 0 clean, 1 warnings,
# 2 broken/risky findings — drop it straight into cron itself or CI.
#
# Usage:
#   ruby cron_audit.rb                        # /etc/crontab + /etc/cron.d
#   ruby cron_audit.rb --file mycrontab --no-system --json

require 'json'
require 'optparse'
require 'time'
require 'etc'

options = { system: true, files: [], spool: nil, json: false, horizon_days: 8 }

OptionParser.new do |o|
  o.banner = 'Usage: cron_audit.rb [options]'
  o.on('--file FILE', 'Audit an extra crontab file (repeatable)') { |v| options[:files] << v }
  o.on('--spool DIR', 'Also read user spool dir (e.g. /var/spool/cron/crontabs)') { |v| options[:spool] = v }
  o.on('--no-system', 'Skip /etc/crontab and /etc/cron.d') { options[:system] = false }
  o.on('--json', 'Emit JSON instead of text') { options[:json] = true }
end.parse!

# ---------------------------------------------------------------------------
# Schedule parsing. Each of the 5 fields expands to a Set of allowed values;
# validation and next-run matching then both fall out of the same structure.
# ---------------------------------------------------------------------------
FIELD_RANGES = [0..59, 0..23, 1..31, 1..12, 0..7].freeze # min hour dom mon dow
MONTH_NAMES = %w[jan feb mar apr may jun jul aug sep oct nov dec].freeze
DAY_NAMES   = %w[sun mon tue wed thu fri sat].freeze
ALIASES = {
  '@hourly'   => '0 * * * *',   '@daily'  => '0 0 * * *',
  '@midnight' => '0 0 * * *',   '@weekly' => '0 0 * * 0',
  '@monthly'  => '0 0 1 * *',   '@yearly' => '0 0 1 1 *',
  '@annually' => '0 0 1 1 *'
}.freeze

# Expand one cron field ("*/15", "1-5", "mon,wed", "3") into a sorted array.
# Returns nil if the field is invalid — that's how validation reports errors.
def expand_field(field, idx)
  range = FIELD_RANGES[idx]
  values = []
  field.downcase.split(',').each do |part|
    step = 1
    if part.include?('/')
      part, step_s = part.split('/', 2)
      step = step_s.to_i
      return nil if step < 1
    end
    # translate month/day names into numbers where the field allows them
    part = (MONTH_NAMES.index(part) + 1).to_s if idx == 3 && MONTH_NAMES.include?(part)
    part = DAY_NAMES.index(part).to_s        if idx == 4 && DAY_NAMES.include?(part)

    lo, hi =
      if part == '*'
        [range.first, range.last]
      elsif part =~ /\A(\d+)-(\d+)\z/
        [Regexp.last_match(1).to_i, Regexp.last_match(2).to_i]
      elsif part =~ /\A\d+\z/
        [part.to_i, part.to_i]
      else
        return nil
      end
    return nil if lo < range.first || hi > range.last || lo > hi
    lo.step(hi, step) { |v| values << v }
  end
  # cron treats dow 7 as sunday
  values.map! { |v| idx == 4 && v == 7 ? 0 : v }
  values.uniq.sort
end

def parse_schedule(sched)
  sched = ALIASES.fetch(sched, sched)
  return { reboot: true } if sched == '@reboot'
  fields = sched.split
  return nil unless fields.size == 5
  expanded = fields.each_with_index.map { |f, i| expand_field(f, i) }
  return nil if expanded.any?(&:nil?)
  { min: expanded[0], hour: expanded[1], dom: expanded[2], mon: expanded[3], dow: expanded[4] }
end

# Walk forward minute-by-minute until the schedule matches. Cron semantics:
# if BOTH dom and dow are restricted, a match on either one fires the job.
def next_run(sched, from = Time.now, horizon_days = 8)
  return nil if sched[:reboot]
  t = Time.new(from.year, from.month, from.day, from.hour, from.min) + 60
  dom_restricted = sched[:dom].size < 31
  dow_restricted = sched[:dow].size < 7
  (horizon_days * 1440).times do
    if sched[:min].include?(t.min) && sched[:hour].include?(t.hour) && sched[:mon].include?(t.month)
      day_ok =
        if dom_restricted && dow_restricted
          sched[:dom].include?(t.day) || sched[:dow].include?(t.wday)
        else
          sched[:dom].include?(t.day) && sched[:dow].include?(t.wday)
        end
      return t if day_ok
    end
    t += 60
  end
  nil
end

# ---------------------------------------------------------------------------
# Command risk checks
# ---------------------------------------------------------------------------
def first_script(command)
  # strip env assignments (FOO=bar cmd) and leading wrappers we can see through
  tokens = command.strip.split(/\s+/)
  tokens.shift while tokens.first =~ /\A\w+=/
  tokens.shift if %w[nice ionice timeout flock].include?(tokens.first) # skip common wrappers + their flag args crudely
  tok = tokens.find { |t| t.start_with?('/') }
  tok
end

def check_command(command)
  findings = []
  findings << ['RISK', 'pipe-to-shell (curl|wget piped into a shell)'] if command =~ /\b(curl|wget)\b[^|;]*\|\s*(ba|z|da)?sh\b/
  script = first_script(command)
  if script.nil?
    findings << ['WARN', 'no absolute path in command — relies on cron PATH (often just /usr/bin:/bin)']
  elsif !File.exist?(script)
    findings << ['BROKEN', "referenced file missing: #{script}"]
  else
    st = File.stat(script)
    findings << ['RISK', "#{script} is world-writable"] if st.mode & 0o002 != 0
    findings << ['RISK', "#{script} is group-writable"] if st.mode & 0o020 != 0
    if st.uid != 0
      owner = (Etc.getpwuid(st.uid).name rescue st.uid.to_s)
      findings << ['WARN', "#{script} not owned by root (owner: #{owner}) — anyone with that account can change what cron runs"]
    end
  end
  findings
end

# ---------------------------------------------------------------------------
# Crontab file parsing. system_format=true means 6th column is the user.
# ---------------------------------------------------------------------------
def parse_crontab(path, system_format:, default_user: nil)
  jobs = []
  return jobs unless File.readable?(path)
  File.foreach(path).with_index(1) do |line, ln|
    line = line.strip
    next if line.empty? || line.start_with?('#') || line =~ /\A\w+=/ # skip env lines
    if line.start_with?('@')
      sched_s, rest = line.split(/\s+/, 2)
    else
      parts = line.split(/\s+/, 6)
      next if parts.size < 6
      sched_s = parts[0, 5].join(' ')
      rest = parts[5]
    end
    if system_format && !sched_s.start_with?('@reboot')
      user, command = rest.split(/\s+/, 2)
    elsif system_format
      user, command = rest.split(/\s+/, 2)
    else
      user = default_user
      command = rest
    end
    next if command.nil? || command.empty?
    jobs << { file: path, line: ln, user: user, schedule: sched_s, command: command }
  end
  jobs
end

jobs = []
if options[:system]
  jobs.concat parse_crontab('/etc/crontab', system_format: true)
  Dir.glob('/etc/cron.d/*').sort.each do |f|
    next unless File.file?(f)
    jobs.concat parse_crontab(f, system_format: true)
  end
end
options[:files].each { |f| jobs.concat parse_crontab(f, system_format: false, default_user: Etc.getlogin) }
if options[:spool]
  Dir.glob(File.join(options[:spool], '*')).sort.each do |f|
    jobs.concat parse_crontab(f, system_format: false, default_user: File.basename(f))
  end
end

now = Time.now
results = jobs.map do |job|
  sched = parse_schedule(job[:schedule])
  findings = []
  nxt = nil
  if sched.nil?
    findings << ['BROKEN', "invalid schedule: '#{job[:schedule]}'"]
  else
    nxt = next_run(sched, now, options[:horizon_days])
    findings << ['WARN', "schedule never fires in next #{options[:horizon_days]} days"] if nxt.nil? && !sched[:reboot]
  end
  findings.concat check_command(job[:command])
  sev_rank = { 'BROKEN' => 2, 'RISK' => 2, 'WARN' => 1 }
  worst = findings.map { |s, _| sev_rank[s] }.max || 0
  job.merge(next_run: nxt&.strftime('%Y-%m-%d %H:%M'), findings: findings, worst: worst)
end

overall = results.map { |r| r[:worst] }.max || 0

if options[:json]
  puts JSON.pretty_generate(
    'generated_at' => now.iso8601,
    'status' => %w[OK WARN CRIT][overall],
    'jobs' => results.map do |r|
      { 'file' => r[:file], 'line' => r[:line], 'user' => r[:user],
        'schedule' => r[:schedule], 'command' => r[:command],
        'next_run' => r[:next_run],
        'findings' => r[:findings].map { |s, m| { 'severity' => s, 'message' => m } } }
    end
  )
else
  puts "cron audit — #{now.strftime('%Y-%m-%d %H:%M')}  jobs: #{results.size}  [#{%w[OK WARN CRIT][overall]}]"
  results.each do |r|
    mark = r[:worst] == 2 ? '!!' : r[:worst] == 1 ? ' !' : '  '
    puts
    puts "#{mark} #{r[:file]}:#{r[:line]}  (user: #{r[:user]})"
    puts "     #{r[:schedule]}  ->  next run: #{r[:next_run] || 'n/a'}"
    puts "     #{r[:command]}"
    r[:findings].each { |sev, msg| puts "       [#{sev}] #{msg}" }
  end
end

exit(overall == 2 ? 2 : overall == 1 ? 1 : 0)
