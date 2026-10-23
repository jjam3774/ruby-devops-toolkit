#!/usr/bin/env ruby
# frozen_string_literal: true
# cron_audit.rb - Lint a crontab file and preview upcoming run times.
# Usage: ruby cron_audit.rb CRONTAB_FILE [--next N] [--from "YYYY-MM-DD HH:MM"]
require 'optparse'
require 'time'

FIELD_RANGES = { minute: 0..59, hour: 0..23, dom: 1..31, month: 1..12, dow: 0..7 }.freeze
MACROS = { '@hourly' => '0 * * * *', '@daily' => '0 0 * * *', '@midnight' => '0 0 * * *',
           '@weekly' => '0 0 * * 0', '@monthly' => '0 0 1 * *', '@yearly' => '0 0 1 1 *',
           '@annually' => '0 0 1 1 *' }.freeze

class CronError < StandardError; end

# Expand one cron field ("*/15", "1-5", "1,3,7") into a sorted array of ints.
def expand_field(text, range)
  values = text.split(',').flat_map do |part|
    base, step = part.split('/')
    step = step ? Integer(step, exception: false) : 1
    raise CronError, "bad step in '#{part}'" if step.nil? || step < 1
    lo, hi = if base == '*' then [range.min, range.max]
             elsif base =~ /\A(\d+)-(\d+)\z/ then [$1.to_i, $2.to_i]
             elsif base =~ /\A\d+\z/ then [base.to_i, step > 1 ? range.max : base.to_i]
             else raise CronError, "cannot parse '#{part}'"
             end
    raise CronError, "'#{part}' outside #{range}" unless range.cover?(lo) && range.cover?(hi) && lo <= hi
    (lo..hi).step(step).to_a
  end
  values.uniq.sort
end

CronEntry = Struct.new(:line_no, :schedule, :command, :sets, :dom_star, :dow_star)

def parse_line(line, line_no)
  text = line.strip
  fields = text.split(/\s+/, 6)
  if fields[0].start_with?('@')
    expansion = MACROS[fields[0]] or raise CronError, "unknown macro #{fields[0]}"
    fields = expansion.split + [text.split(/\s+/, 2)[1].to_s]
  end
  raise CronError, 'expected 5 time fields and a command' if fields.size < 6 || fields[5].to_s.empty?
  sets = FIELD_RANGES.keys.zip(fields[0, 5]).to_h { |name, f| [name, expand_field(f, FIELD_RANGES[name])] }
  sets[:dow] = sets[:dow].map { |d| d % 7 }.uniq.sort # 7 == Sunday == 0
  CronEntry.new(line_no, fields[0, 5].join(' '), fields[5], sets, fields[2] == '*', fields[4] == '*')
end

# Standard cron rule: if both dom and dow are restricted, EITHER may match.
def matches?(e, t)
  s = e.sets
  return false unless s[:minute].include?(t.min) && s[:hour].include?(t.hour) && s[:month].include?(t.month)
  dom_ok = s[:dom].include?(t.day)
  dow_ok = s[:dow].include?(t.wday)
  e.dom_star || e.dow_star ? (dom_ok && dow_ok) : (dom_ok || dow_ok)
end

def next_runs(entry, from, count)
  t = Time.at((from.to_i / 60 + 1) * 60)
  runs = []
  limit = 366 * 24 * 60 # search at most one year of minutes
  limit.times do
    runs << t if matches?(entry, t)
    break if runs.size >= count
    t += 60
  end
  runs
end

# Heuristics a sysadmin would care about.
def warnings_for(entry)
  w = []
  w << 'runs every minute' if entry.sets[:minute].size == 60 && entry.sets[:hour].size == 24
  w << 'command does not start with an absolute path (cron has a minimal PATH)' unless entry.command.start_with?('/')
  w << 'no output redirection: cron will try to e-mail output' unless entry.command.include?('>')
  w << 'day-of-month and day-of-week both set: cron ORs them' unless entry.dom_star || entry.dow_star
  w
end

opts = { next: 3, from: Time.now }
parser = OptionParser.new do |o|
  o.banner = 'Usage: cron_audit.rb CRONTAB_FILE [options]'
  o.on('--next N', Integer) { |v| opts[:next] = v }
  o.on('--from TIME') { |v| opts[:from] = Time.parse(v) }
end
parser.parse!
abort(parser.to_s) if ARGV.empty?

errors = 0
File.readlines(ARGV[0]).each_with_index do |line, i|
  next if line.strip.empty? || line.strip.start_with?('#') || line =~ /\A\s*[A-Z_]+=/ # comments, VAR=value
  begin
    e = parse_line(line, i + 1)
    puts "line #{e.line_no}: OK   #{e.schedule}  #{e.command}"
    warnings_for(e).each { |m| puts "          warn: #{m}" }
    next_runs(e, opts[:from], opts[:next]).each { |t| puts "          next: #{t.strftime('%a %Y-%m-%d %H:%M')}" }
  rescue CronError => ex
    errors += 1
    puts "line #{i + 1}: FAIL #{ex.message}  <= #{line.strip}"
  end
end
exit(errors.zero? ? 0 : 1)
