#!/usr/bin/env ruby
# frozen_string_literal: true
#
# eventlog_monitor_test.rb — stub harness for eventlog_monitor.rb.
#
# Honest note on test coverage: Win32_NTLogEvent and WIN32OLE only exist on
# Windows, so the WMI query itself can't run in this Linux sandbox — the
# same constraint the repo's other WMI-based scripts (service-audit,
# registry-drift, scheduled-task-audit) already document. What CAN be, and
# is, tested live on any platform: WmiDateTime's format/parse round-trip
# (pure string/Time logic) and EventClassifier's severity rules (pure
# logic operating on anything that duck-types the handful of
# Win32_NTLogEvent properties we read). For the "since state" file
# handling and full run() pipeline, we inject a fake `wmi_connector` that
# responds to ExecQuery exactly like a real WIN32OLE WMI connection would,
# returning OpenStruct fixtures shaped like real Win32_NTLogEvent rows
# captured from a real Windows box's `Get-CimInstance Win32_NTLogEvent`
# output.

require 'ostruct'
require 'time'
require 'tmpdir'
require_relative 'eventlog_monitor'

$failures = 0

def check(desc)
  yield
  puts "PASS  #{desc}"
rescue StandardError => e
  $failures += 1
  puts "FAIL  #{desc} -- #{e.class}: #{e.message}\n#{e.backtrace.first(3).join("\n")}"
end

# --- WmiDateTime round-trip (pure logic, real on any platform) -------------
check('WmiDateTime.to_wmi produces a valid CIM_DATETIME string') do
  t = Time.new(2026, 8, 1, 14, 30, 22, '+00:00')
  s = WmiDateTime.to_wmi(t)
  raise "unexpected format: #{s}" unless s == '20260801143022.000000+000'
end

check('WmiDateTime.parse round-trips a real Win32_NTLogEvent TimeGenerated value') do
  parsed = WmiDateTime.parse('20260801143022.500000-300')
  raise 'parse returned nil' if parsed.nil?
  raise "wrong year #{parsed.year}" unless parsed.year == 2026
  raise "wrong hour #{parsed.hour}" unless parsed.hour == 14
  raise "wrong utc_offset #{parsed.utc_offset}" unless parsed.utc_offset == -300 * 60
end

check('WmiDateTime.parse returns nil for garbage input') do
  raise 'expected nil' unless WmiDateTime.parse('not-a-timestamp').nil?
end

# --- Fixture matching a real Win32_NTLogEvent row's shape -------------------
def fixture(overrides = {})
  OpenStruct.new({
                   LogFile: 'System',
                   RecordNumber: 1001,
                   EventCode: 41,
                   EventType: 1, # Error
                   SourceName: 'Microsoft-Windows-Kernel-Power',
                   ComputerName: 'WIN-DB01',
                   TimeGenerated: '20260801143022.000000+000',
                   Message: "The system has rebooted without cleanly shutting down first.\nExtra detail line."
                 }.merge(overrides))
end

# --- EventClassifier severity rules -----------------------------------------
check('EventType 1 (Error) classifies as :crit') do
  rec = EventClassifier.new.classify(fixture(EventType: 1))
  raise "expected :crit, got #{rec.level}" unless rec.level == :crit
  raise 'expected event_type Error' unless rec.event_type == 'Error'
end

check('EventType 2 (Warning) classifies as :warn') do
  rec = EventClassifier.new.classify(fixture(EventType: 2))
  raise "expected :warn, got #{rec.level}" unless rec.level == :warn
end

check('EventType 5 (Audit Failure) classifies as :crit') do
  rec = EventClassifier.new.classify(fixture(EventType: 5))
  raise "expected :crit, got #{rec.level}" unless rec.level == :crit
end

check('EventType 3 (Information) is filtered out entirely (nil)') do
  rec = EventClassifier.new.classify(fixture(EventType: 3))
  raise 'expected nil for Information events' unless rec.nil?
end

check('excluded source names are filtered out') do
  rec = EventClassifier.new(exclude_sources: ['Print Spooler']).classify(
    fixture(EventType: 1, SourceName: 'Print Spooler')
  )
  raise 'expected nil for excluded source' unless rec.nil?
end

check('classify() only keeps the first line of a multi-line Message') do
  rec = EventClassifier.new.classify(fixture)
  raise "message not trimmed: #{rec.message.inspect}" unless
    rec.message == 'The system has rebooted without cleanly shutting down first.'
end

# --- Fake WMI connector for full run() pipeline tests -----------------------
class FakeWmiConnector
  def initialize(rows)
    @rows = rows
    @last_query = nil
  end

  attr_reader :last_query

  def ExecQuery(wql)
    @last_query = wql
    @rows
  end
end

Dir.mktmpdir do |dir|
  state_file = File.join(dir, 'state.json')

  # --- full pipeline: mixed severities, correct counts and ordering -------
  check('run() returns events sorted by record number with correct levels') do
    rows = [
      fixture(RecordNumber: 3, EventType: 2, SourceName: 'Disk'),
      fixture(RecordNumber: 1, EventType: 1, SourceName: 'Kernel-Power'),
      fixture(RecordNumber: 2, EventType: 3, SourceName: 'Service Control Manager') # filtered
    ]
    connector = FakeWmiConnector.new(rows)
    monitor = EventLogMonitor.new(logs: %w[System], state_file: state_file, wmi_connector: connector)
    events = monitor.run
    raise "expected 2 events (Information filtered), got #{events.size}" unless events.size == 2
    raise 'expected sorted by record number' unless events.map(&:record_number) == [1, 3]
    raise 'query missing Logfile clause' unless connector.last_query.include?("Logfile='System'")
  end

  # --- state file persists the newest TimeGenerated between runs ----------
  check('state file is written with the latest generated_at after a run') do
    File.delete(state_file) if File.exist?(state_file)
    rows = [fixture(RecordNumber: 5, EventType: 1, TimeGenerated: '20260801150000.000000+000')]
    connector = FakeWmiConnector.new(rows)
    monitor = EventLogMonitor.new(logs: %w[System], state_file: state_file, wmi_connector: connector)
    monitor.run
    raise 'state file was not written' unless File.exist?(state_file)
    saved = JSON.parse(File.read(state_file))
    raise "unexpected last_seen: #{saved['last_seen']}" unless saved['last_seen'].start_with?('2026-08-01T15:00:00')
  end

  # --- a second run only asks WMI for events after the saved state --------
  check('a second run queries TimeGenerated using the persisted state, not the default lookback') do
    connector2 = FakeWmiConnector.new([])
    monitor2 = EventLogMonitor.new(logs: %w[System], state_file: state_file, wmi_connector: connector2,
                                    since_minutes: 60)
    monitor2.run
    raise 'expected query to reference 2026 (persisted state), not "now"' unless
      connector2.last_query.include?('20260801')
  end
end

puts "\n#{$failures.zero? ? 'ALL TESTS PASSED' : "#{$failures} TEST(S) FAILED"}"
exit($failures.zero? ? 0 : 1)
