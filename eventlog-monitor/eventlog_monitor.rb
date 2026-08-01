#!/usr/bin/env ruby
# frozen_string_literal: true
#
# eventlog_monitor.rb — poll the Windows Event Log (System/Application, or
# any log you name) via WMI for new Error/Warning/Audit-Failure events since
# the last run, classify them, and report — cron/Task-Scheduler friendly.
#
# Why this exists: `Get-WinEvent` in PowerShell is the modern way to read
# the event log interactively, but a lot of shops still run scheduled Ruby
# tooling alongside PowerShell, and WMI's Win32_NTLogEvent class is exactly
# as readable from Ruby (via WIN32OLE) as it is from PowerShell or VBScript
# — no gems required, just the win32ole standard library that ships with
# Ruby on Windows. This script tracks "last seen" state between runs so a
# 5-minute cron job only ever reports genuinely new events, not the same
# noisy log spam every single run.
#
# Usage (run ON a Windows host, from an elevated prompt is not required to
# *read* the event log, only to clear it):
#   ruby eventlog_monitor.rb --logs System,Application
#   ruby eventlog_monitor.rb --logs System --since-minutes 120 --json
#   ruby eventlog_monitor.rb --logs System,Application --exclude-source "Print Spooler"
#
# Exit codes (cron/Task Scheduler-friendly):
#   0 = no new Error/Warning/Audit-Failure events
#   1 = new Warning events only
#   2 = new Error or Audit-Failure events

require 'optparse'
require 'json'
require 'time'
require 'fileutils'

# ---------------------------------------------------------------------------
# EventRecord: one normalized row out of Win32_NTLogEvent.
# ---------------------------------------------------------------------------
EventRecord = Struct.new(:log, :record_number, :event_code, :event_type, :source,
                          :computer, :generated_at, :message, :level, keyword_init: true) do
  def to_h
    h = super
    h[:generated_at] = generated_at.is_a?(Time) ? generated_at.iso8601 : generated_at
    h
  end
end

# EventType, per the Win32_NTLogEvent WMI class:
#   1 = Error, 2 = Warning, 3 = Information, 4 = Security Audit Success,
#   5 = Security Audit Failure
EVENT_TYPE_NAMES = {
  1 => 'Error', 2 => 'Warning', 3 => 'Information',
  4 => 'AuditSuccess', 5 => 'AuditFailure'
}.freeze

# ---------------------------------------------------------------------------
# WmiDateTime: converts between Ruby Time and the WMI CIM_DATETIME string
# format (yyyymmddHHMMSS.mmmmmm+UUU, where UUU is the UTC offset in minutes).
# Pulled out as its own module because it's pure string logic that both the
# real WMI query and the test suite need, with no WIN32OLE dependency.
# ---------------------------------------------------------------------------
module WmiDateTime
  # NOTE: deliberately named `to_wmi`, not `format` — a module method named
  # `format` shadows Kernel#format for every other `self.`-method in this
  # same module (self inside a module method IS the module, so a bare
  # `format(...)` call resolves to the module's own singleton method
  # first). Learned that the hard way while writing this script: `parse`
  # below silently returned nil because its `format(...)` call was being
  # routed into this method instead of Kernel#format. Use `sprintf` for
  # string interpolation instead of `format`/`Kernel#format` inside this
  # module to keep that footgun from coming back.
  def self.to_wmi(time)
    utc = time.getutc
    "#{utc.strftime('%Y%m%d%H%M%S')}.000000+000"
  end

  def self.parse(wmi_str)
    # e.g. "20260801143022.500000-300" -> 2026-08-01 14:30:22 local, UTC-300min
    m = wmi_str.to_s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\.\d+([+-]\d{3})$/)
    return nil unless m

    year, mon, day, hour, min, sec, offset_min = m.captures
    offset_min = offset_min.to_i
    sign = offset_min.negative? ? '-' : '+'
    offset_min = offset_min.abs
    offset_str = sprintf('%s%02d:%02d', sign, offset_min / 60, offset_min % 60)
    Time.new(year.to_i, mon.to_i, day.to_i, hour.to_i, min.to_i, sec.to_i, offset_str)
  rescue ArgumentError
    nil
  end
end

# ---------------------------------------------------------------------------
# EventClassifier: pure logic — turns a raw WMI-shaped record into an
# EventRecord with a severity level. No WIN32OLE dependency, fully unit
# testable on any platform.
# ---------------------------------------------------------------------------
class EventClassifier
  def initialize(exclude_sources: [], include_types: [1, 2, 5])
    @exclude_sources = exclude_sources.map(&:downcase)
    @include_types = include_types
  end

  # `raw` only needs to respond to the Win32_NTLogEvent property names we
  # use: LogFile, RecordNumber, EventCode, EventType, SourceName,
  # ComputerName, TimeGenerated, Message.
  def classify(raw)
    return nil unless @include_types.include?(raw.EventType.to_i)
    return nil if @exclude_sources.include?(raw.SourceName.to_s.downcase)

    level = case raw.EventType.to_i
            when 1, 5 then :crit
            when 2 then :warn
            else :info
            end

    EventRecord.new(
      log: raw.LogFile,
      record_number: raw.RecordNumber.to_i,
      event_code: raw.EventCode.to_i,
      event_type: EVENT_TYPE_NAMES[raw.EventType.to_i] || raw.EventType.to_s,
      source: raw.SourceName,
      computer: raw.ComputerName,
      generated_at: WmiDateTime.parse(raw.TimeGenerated) || raw.TimeGenerated,
      message: raw.Message.to_s.split("\n").first.to_s.strip,
      level: level
    )
  end
end

# ---------------------------------------------------------------------------
# EventLogMonitor: connects to WMI (root/cimv2), runs the WQL query, tracks
# "since" state between runs, and returns classified EventRecords.
# ---------------------------------------------------------------------------
class EventLogMonitor
  def initialize(logs:, since_minutes: 60, exclude_sources: [], state_file: nil,
                 wmi_connector: nil, logger: $stderr)
    @logs = logs
    @since_minutes = since_minutes
    @classifier = EventClassifier.new(exclude_sources: exclude_sources)
    @state_file = state_file || default_state_file
    # `wmi_connector` is injected in tests; in production it's built lazily
    # so requiring this file on a non-Windows host (e.g. to run rubocop or
    # the unit tests in CI) doesn't blow up on a missing win32ole.
    @wmi_connector = wmi_connector
    @logger = logger
  end

  def run
    since = load_since_time
    raw_events = query_events(since)
    events = raw_events.map { |r| @classifier.classify(r) }.compact
                        .sort_by(&:record_number)

    save_since_time(events)
    events
  end

  private

  def connector
    @wmi_connector ||= build_real_wmi_connector
  end

  def build_real_wmi_connector
    begin
      require 'win32ole'
    rescue LoadError
      raise "win32ole is not available (this script must run on Windows with a stock " \
            "Ruby install — see the tutorial's Troubleshooting section)"
    end
    WIN32OLE.connect('winmgmts://./root/cimv2')
  end

  def query_events(since)
    log_clause = @logs.map { |l| "Logfile='#{l}'" }.join(' OR ')
    wql = "SELECT * FROM Win32_NTLogEvent WHERE (#{log_clause}) " \
          "AND TimeGenerated >= '#{WmiDateTime.to_wmi(since)}'"
    log("query: #{wql}")
    connector.ExecQuery(wql).to_a
  end

  def load_since_time
    return Time.now - (@since_minutes * 60) unless File.exist?(@state_file)

    data = JSON.parse(File.read(@state_file))
    Time.parse(data['last_seen'])
  rescue JSON::ParserError, TypeError, ArgumentError
    Time.now - (@since_minutes * 60)
  end

  def save_since_time(events)
    latest = events.map(&:generated_at).select { |t| t.is_a?(Time) }.max || Time.now
    FileUtils.mkdir_p(File.dirname(@state_file))
    File.write(@state_file, JSON.pretty_generate(last_seen: latest.iso8601))
  rescue StandardError => e
    log("could not persist state file #{@state_file}: #{e.message}")
  end

  def default_state_file
    base = ENV['ProgramData'] || ENV['TEMP'] || '.'
    File.join(base, 'eventlog_monitor', 'state.json')
  end

  def log(msg)
    @logger.puts("[eventlog_monitor] #{msg}")
  end
end

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if $PROGRAM_NAME == __FILE__
  options = {
    logs: %w[System Application],
    since_minutes: 60,
    exclude_sources: [],
    json: false,
    state_file: nil
  }

  OptionParser.new do |opts|
    opts.banner = 'Usage: eventlog_monitor.rb [options]'
    opts.on('--logs LIST', 'Comma-separated log names (default: System,Application)') do |v|
      options[:logs] = v.split(',').map(&:strip)
    end
    opts.on('--since-minutes N', Integer, 'Lookback window on first run (default 60)') do |v|
      options[:since_minutes] = v
    end
    opts.on('--exclude-source NAME', 'Ignore events from this SourceName (repeatable)') do |v|
      options[:exclude_sources] << v
    end
    opts.on('--state-file PATH', 'Where to persist the last-seen timestamp') { |v| options[:state_file] = v }
    opts.on('--json', 'Emit machine-readable JSON instead of text') { options[:json] = true }
    opts.on('-h', '--help') { puts opts; exit 0 }
  end.parse!

  monitor = EventLogMonitor.new(
    logs: options[:logs],
    since_minutes: options[:since_minutes],
    exclude_sources: options[:exclude_sources],
    state_file: options[:state_file]
  )

  begin
    events = monitor.run
  rescue StandardError => e
    warn "eventlog_monitor: #{e.message}"
    exit 3
  end

  crit = events.count { |e| e.level == :crit }
  warn_count = events.count { |e| e.level == :warn }

  if options[:json]
    puts JSON.pretty_generate(
      generated_at: Time.now.iso8601,
      crit: crit,
      warn: warn_count,
      events: events.map(&:to_h)
    )
  else
    events.each do |e|
      tag = { crit: 'CRIT', warn: 'WARN' }[e.level]
      ts = e.generated_at.is_a?(Time) ? e.generated_at.strftime('%Y-%m-%d %H:%M:%S') : e.generated_at
      puts "#{tag} [#{e.log}] #{ts} #{e.source} (##{e.event_code}): #{e.message}"
    end
    puts "\n#{events.size} new event(s): #{crit} crit, #{warn_count} warn"
  end

  exit(crit.positive? ? 2 : (warn_count.positive? ? 1 : 0))
end
