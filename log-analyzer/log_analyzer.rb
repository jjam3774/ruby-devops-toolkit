#!/usr/bin/env ruby
# frozen_string_literal: true
#
# log_analyzer.rb - Parse application/syslog-style log files, bucket
# events into time windows, and flag windows where the error rate spikes
# above a configurable threshold. Designed to be dropped into cron or a
# CI pipeline and alert (via non-zero exit code + JSON output) when a
# service is misbehaving.
#
# Usage:
#   ruby log_analyzer.rb /var/log/app.log
#   ruby log_analyzer.rb /var/log/app.log --window 5 --threshold 10
#   ruby log_analyzer.rb /var/log/app.log --json
#   ruby log_analyzer.rb /var/log/app.log --since "2026-07-27 00:00:00"
#
# Exit codes:
#   0 - no spike windows found
#   1 - one or more spike windows found (use in cron/monitoring)
#   2 - usage / input error

require 'optparse'
require 'time'
require 'json'

# Matches a common syslog-ish line format:
#   2026-07-27 14:03:01 ERROR PaymentService: timeout connecting to db
# Also tolerant of a leading rsyslog-style timestamp without a year, e.g.:
#   Jul 27 14:03:01 host app[1234]: ERROR ...
LOG_LINE_RE = %r{
  ^\s*
  (?<timestamp>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}|
    [A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})
  \s+
  (?:\S+[\s:]+){0,3}?                            # optional host/process/pid fields (rsyslog style), non-greedy
  (?<level>DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRIT|CRITICAL)
  \b
  [:\s]*
  (?<message>.*)$
}x.freeze

SEVERITY_ORDER = %w[DEBUG INFO WARN WARNING ERROR FATAL CRIT CRITICAL].freeze
ERROR_LEVELS = %w[ERROR FATAL CRIT CRITICAL].freeze

# One parsed log entry.
LogEntry = Struct.new(:time, :level, :message) do
  def error?
    ERROR_LEVELS.include?(level)
  end
end

# Parses raw log text into LogEntry objects, silently skipping lines that
# don't match the expected format (blank lines, stack trace continuations,
# etc.) rather than aborting the whole run.
class LogParser
  def initialize(reference_year: Time.now.year)
    @reference_year = reference_year
  end

  # Returns an Array<LogEntry>, sorted by time.
  def parse(io)
    entries = []
    io.each_line do |line|
      match = LOG_LINE_RE.match(line)
      next unless match

      time = parse_timestamp(match[:timestamp])
      next unless time

      entries << LogEntry.new(time, normalize_level(match[:level]), match[:message].to_s.strip)
    end
    entries.sort_by(&:time)
  end

  private

  def normalize_level(level)
    level == 'WARNING' ? 'WARN' : (level == 'CRITICAL' ? 'CRIT' : level)
  end

  def parse_timestamp(raw)
    if raw =~ /^\d{4}-/
      Time.parse(raw)
    else
      # rsyslog-style "Jul 27 14:03:01" has no year; assume the reference year,
      # but roll back a year if that would put the timestamp in the future
      # (handles logs that span a New Year's Eve rotation).
      candidate = Time.parse("#{@reference_year} #{raw}")
      candidate > Time.now + 3600 ? Time.parse("#{@reference_year - 1} #{raw}") : candidate
    end
  rescue ArgumentError
    nil
  end
end

# Groups entries into fixed-size time windows and computes per-window
# totals and error rates.
class WindowAnalyzer
  Window = Struct.new(:start_time, :end_time, :total, :errors, :by_level) do
    def error_rate
      total.zero? ? 0.0 : (errors.to_f / total * 100).round(2)
    end
  end

  def initialize(window_minutes:, threshold_pct:, min_events: 1)
    # Must be an Integer: Integer / Float division below would produce a
    # unique Float bucket key for nearly every entry instead of grouping them.
    @window_seconds = (window_minutes * 60).to_i
    @threshold_pct = threshold_pct
    @min_events = min_events
  end

  # Returns [Array<Window>, Array<Window> (spikes only)]
  def analyze(entries)
    return [[], []] if entries.empty?

    windows = {}
    epoch_start = entries.first.time.to_i
    entries.each do |entry|
      bucket = (entry.time.to_i - epoch_start) / @window_seconds
      w = (windows[bucket] ||= { total: 0, errors: 0, by_level: Hash.new(0) })
      w[:total] += 1
      w[:by_level][entry.level] += 1
      w[:errors] += 1 if entry.error?
    end

    all_windows = windows.sort.map do |bucket, data|
      start_time = Time.at(epoch_start + bucket * @window_seconds)
      Window.new(start_time, start_time + @window_seconds, data[:total], data[:errors], data[:by_level])
    end

    spikes = all_windows.select { |w| w.total >= @min_events && w.error_rate >= @threshold_pct }
    [all_windows, spikes]
  end
end

# ---- CLI ----------------------------------------------------------------

def parse_options(argv)
  opts = { window: 5, threshold: 10.0, json: false, since: nil, min_events: 3 }
  parser = OptionParser.new do |o|
    o.banner = 'Usage: log_analyzer.rb LOGFILE [options]'
    o.on('-w', '--window MINUTES', Float, 'Time window size in minutes (default 5)') { |v| opts[:window] = v }
    o.on('-t', '--threshold PCT', Float, 'Error-rate %% that counts as a spike (default 10)') { |v| opts[:threshold] = v }
    o.on('-m', '--min-events N', Integer, 'Minimum events in a window before it can spike (default 3)') { |v| opts[:min_events] = v }
    o.on('-s', '--since TIME', 'Only consider entries at/after this time (parseable by Time.parse)') { |v| opts[:since] = Time.parse(v) }
    o.on('-j', '--json', 'Emit machine-readable JSON instead of a text report') { opts[:json] = true }
    o.on('-h', '--help', 'Show this help') { puts o; exit 0 }
  end
  parser.parse!(argv)

  if argv.empty?
    warn parser
    exit 2
  end
  [argv.first, opts]
end

def print_text_report(all_windows, spikes, path)
  puts "log_analyzer report for #{path}"
  puts "windows analyzed: #{all_windows.size}, spikes: #{spikes.size}"
  puts '-' * 60
  all_windows.each do |w|
    marker = spikes.include?(w) ? '!! SPIKE' : ''
    puts format('%-20s total=%-4d errors=%-4d rate=%6.2f%% %s',
                w.start_time.strftime('%Y-%m-%d %H:%M'), w.total, w.errors, w.error_rate, marker)
  end
  return if spikes.empty?

  puts '-' * 60
  puts 'Spike detail:'
  spikes.each do |w|
    puts "  #{w.start_time.strftime('%Y-%m-%d %H:%M')} - #{w.by_level.map { |lvl, n| "#{lvl}:#{n}" }.join(', ')}"
  end
end

def build_json_report(all_windows, spikes, path)
  {
    file: path,
    windows_analyzed: all_windows.size,
    spike_count: spikes.size,
    windows: all_windows.map do |w|
      { start: w.start_time.iso8601, total: w.total, errors: w.errors,
        error_rate_pct: w.error_rate, by_level: w.by_level, spike: spikes.include?(w) }
    end
  }
end

if $PROGRAM_NAME == __FILE__
  path, opts = parse_options(ARGV)

  unless File.readable?(path)
    warn "log_analyzer: cannot read #{path}"
    exit 2
  end

  entries = File.open(path, 'r') { |io| LogParser.new.parse(io) }
  entries = entries.select { |e| e.time >= opts[:since] } if opts[:since]

  if entries.empty?
    warn "log_analyzer: no parseable log lines found in #{path}"
    exit 2
  end

  all_windows, spikes = WindowAnalyzer.new(
    window_minutes: opts[:window], threshold_pct: opts[:threshold], min_events: opts[:min_events]
  ).analyze(entries)

  if opts[:json]
    puts JSON.pretty_generate(build_json_report(all_windows, spikes, path))
  else
    print_text_report(all_windows, spikes, path)
  end

  exit(spikes.empty? ? 0 : 1)
end
