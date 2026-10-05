#!/usr/bin/env ruby
# frozen_string_literal: true
#
# cron_job_auditor.rb - Parse crontab files, compute next run times and flag risky jobs.
# Pure Ruby stdlib. Linux/macOS.
#
# Usage:
#   cron_job_auditor.rb [--now "2026-10-05 16:00"] [--json] FILE...
# FILE is a crontab. Files under /etc/cron.d and /etc/crontab have a user column;
# per-user crontabs (crontab -l > file) do not - pass --user-column=false for those.

require 'time'
require 'json'
require 'optparse'

MONTHS = %w[jan feb mar apr may jun jul aug sep oct nov dec].freeze
DAYS   = %w[sun mon tue wed thu fri sat].freeze
FIELDS = [
  { name: :minute, range: 0..59 },
  { name: :hour,   range: 0..23 },
  { name: :dom,    range: 1..31 },
  { name: :month,  range: 1..12, names: MONTHS, offset: 1 },
  { name: :dow,    range: 0..7,  names: DAYS,   offset: 0 }
].freeze
MACROS = {
  '@hourly' => '0 * * * *', '@daily' => '0 0 * * *', '@midnight' => '0 0 * * *',
  '@weekly' => '0 0 * * 0', '@monthly' => '0 0 1 * *', '@yearly' => '0 0 1 1 *',
  '@annually' => '0 0 1 1 *'
}.freeze

class CronParseError < StandardError; end

# Expand one cron field ("*/15", "1-5", "mon,wed", "0-30/10") into a sorted Array of Integers.
def expand_field(text, spec)
  values = []
  text.split(',').each do |part|
    base, step = part.split('/', 2)
    step = step ? Integer(step, 10) : 1
    raise CronParseError, "step must be > 0 in '#{part}'" if step < 1

    lo, hi =
      if base == '*'
        [spec[:range].min, spec[:range].max]
      elsif base.include?('-')
        base.split('-', 2).map { |x| to_num(x, spec) }
      else
        n = to_num(base, spec)
        step > 1 ? [n, spec[:range].max] : [n, n]
      end
    raise CronParseError, "#{spec[:name]} value out of range in '#{part}'" unless spec[:range].cover?(lo) && spec[:range].cover?(hi) && lo <= hi

    values.concat((lo..hi).step(step).to_a)
  end
  values = values.map { |v| v == 7 ? 0 : v } if spec[:name] == :dow # 7 == Sunday
  values.uniq.sort
end

def to_num(token, spec)
  if spec[:names] && (i = spec[:names].index(token.downcase))
    return i + spec[:offset]
  end
  Integer(token, 10)
rescue ArgumentError
  raise CronParseError, "bad value '#{token}' for #{spec[:name]}"
end

Job = Struct.new(:file, :line_no, :schedule, :user, :command, :sets, :dom_star, :dow_star, :problem, keyword_init: true)

def parse_line(file, line_no, raw, user_column)
  line = raw.strip
  return nil if line.empty? || line.start_with?('#') || line =~ /\A[A-Za-z_][A-Za-z0-9_]*\s*=/ # comments / env vars

  tokens = line.split(/\s+/)
  sched_tokens =
    if MACROS.key?(tokens[0])
      tokens.shift
      MACROS[line.split(/\s+/)[0]].split
    else
      tokens.shift(5)
    end
  raise CronParseError, 'fewer than 5 schedule fields' if sched_tokens.size < 5

  user = user_column ? tokens.shift : nil
  command = tokens.join(' ')
  raise CronParseError, 'no command' if command.empty?

  sets = FIELDS.each_with_index.map { |spec, i| expand_field(sched_tokens[i], spec) }
  Job.new(file: file, line_no: line_no, schedule: sched_tokens.join(' '), user: user, command: command,
          sets: sets, dom_star: sched_tokens[2].start_with?('*'), dow_star: sched_tokens[4].start_with?('*'))
rescue CronParseError, ArgumentError => e
  Job.new(file: file, line_no: line_no, schedule: raw.strip, command: '', problem: e.message)
end

# Does time t match the job? Vixie cron rule: if BOTH dom and dow are restricted, either may match.
def matches?(job, t)
  m, h, dom, mon, dow = job.sets
  return false unless m.include?(t.min) && h.include?(t.hour) && mon.include?(t.month)

  dom_ok = dom.include?(t.day)
  dow_ok = dow.include?(t.wday)
  if !job.dom_star && !job.dow_star
    dom_ok || dow_ok
  else
    dom_ok && dow_ok
  end
end

# Walk forward minute by minute (max ~5 years) until the schedule matches.
def next_run(job, from)
  t = Time.at((from.to_i / 60 + 1) * 60) # next whole minute
  limit = from + 5 * 366 * 86_400
  while t < limit
    return t if matches?(job, t)

    t += 60
  end
  nil
end

def runs_per_day(job)
  job.sets[0].size * job.sets[1].size
end

# Returns an Array of [severity, message].
def audit(job)
  return [[:error, "unparseable: #{job.problem}"]] if job.problem

  findings = []
  findings << [:warn, "runs #{runs_per_day(job)}x/day (every minute-level schedule is rarely intentional)"] if runs_per_day(job) >= 288
  unless job.command =~ />\s*\S|\|\s*\S|logger|MAILTO/
    findings << [:info, 'no output redirection: output is mailed to the user (or silently lost)']
  end
  exe = job.command.split(/\s+/).first.to_s
  if !exe.start_with?('/') && exe !~ /\A(cd|test|\[|\.)\z/ && !exe.include?('=')
    findings << [:warn, "relative command '#{exe}': cron has a minimal PATH, use an absolute path"]
  end
  if exe.start_with?('/') && File.file?(exe)
    mode = File.stat(exe).mode
    findings << [:error, "#{exe} is world-writable: any local user can hijack this job"] if mode & 0o002 != 0
  elsif exe.start_with?('/') && !exe.include?('$')
    findings << [:warn, "#{exe} does not exist on this host"]
  end
  findings << [:info, 'uses unescaped % (cron turns % into a newline)'] if job.command =~ /(?<!\\)%/ && job.command !~ /date\s+\+/ 
  findings << [:warn, 'runs as root from a writable-looking path (/tmp, /home)'] if job.user == 'root' && exe =~ %r{\A/(tmp|home|var/tmp)/}
  findings
end

if $PROGRAM_NAME == __FILE__
  opts = { user_column: true, json: false, now: Time.now }
  OptionParser.new do |op|
    op.on('--now T', 'pretend it is T (for repeatable output)') { |v| opts[:now] = Time.parse(v) }
    op.on('--[no-]user-column', 'files have a user column (default yes)') { |v| opts[:user_column] = v }
    op.on('--json') { opts[:json] = true }
  end.parse!(ARGV)
  abort 'Give at least one crontab file' if ARGV.empty?

  report = []
  ARGV.each do |file|
    File.readlines(file).each_with_index do |raw, i|
      job = parse_line(file, i + 1, raw, opts[:user_column])
      next unless job

      nxt = job.problem ? nil : next_run(job, opts[:now])
      report << { job: job, next: nxt, findings: audit(job) }
    end
  end

  if opts[:json]
    puts JSON.pretty_generate(report.map { |r|
      { file: r[:job].file, line: r[:job].line_no, schedule: r[:job].schedule, user: r[:job].user,
        command: r[:job].command, next_run: r[:next]&.iso8601,
        findings: r[:findings].map { |s, m| { severity: s, message: m } } }
    })
  else
    report.each do |r|
      j = r[:job]
      puts "#{File.basename(j.file)}:#{j.line_no}  [#{j.schedule}]  #{j.user}  #{j.command}"
      puts "    next run: #{r[:next] ? r[:next].strftime('%a %Y-%m-%d %H:%M') : 'never'}" unless j.problem
      r[:findings].each { |sev, msg| puts "    #{sev.to_s.upcase.ljust(5)} #{msg}" }
    end
    c = report.flat_map { |r| r[:findings].map(&:first) }.tally
    puts "\nSummary: #{report.size} jobs, #{c[:error].to_i} errors, #{c[:warn].to_i} warnings, #{c[:info].to_i} notes"
  end
  exit(report.any? { |r| r[:findings].any? { |s, _| s == :error } } ? 2 : 0)
end
