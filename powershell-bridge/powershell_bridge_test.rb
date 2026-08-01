#!/usr/bin/env ruby
# frozen_string_literal: true
#
# powershell_bridge_test.rb
#
# Stub/mock test harness for powershell_bridge.rb.
#
# IMPORTANT -- read this before trusting the green output below:
# `powershell.exe` does not exist on this machine (and generally does not
# exist anywhere outside Windows), so none of the tests below launch a
# real PowerShell process or touch a real Windows host. Instead, a fake
# "shell runner" object is injected in place of Open3 that returns
# hand-written strings shaped exactly like real `ConvertTo-Json -Compress`
# output for Get-Service / Get-CimInstance Win32_LogicalDisk / Get-WinEvent.
#
# What this DOES prove:
#   - JSON parsing (single-object vs array quirk, BOM stripping, empty
#     output) is correct
#   - retry-with-backoff and timeout handling behave as designed
#   - the AdminTasks helpers (disk % free math, service restart check,
#     event log "no events" handling) produce correct Ruby data
#   - the CLI wiring (arg parsing, --json vs text rendering, exit codes)
#     is correct
#
# What this does NOT prove:
#   - that `powershell.exe -Command "..."` actually behaves the way the
#     stubbed strings assume on a real Windows box
#   - PowerShell version/locale/culture quirks in real ConvertTo-Json
#     output (date formats, culture-specific number formatting, etc.)
#
# Run it: ruby powershell_bridge_test.rb
# Exits 0 and prints "ALL PASSED" if every check passes, otherwise prints
# each failure and exits 1 -- deliberately dependency-free (no test gem)
# so it runs anywhere Ruby runs.

require_relative 'powershell_bridge'

# ---------------------------------------------------------------------------
# Fake shell runner -- drop-in replacement for Open3 in tests. Responds to
# the same #capture3(*args) signature PowerShellBridge calls, but instead
# of spawning a process it looks up a canned response by matching a
# substring against the '-Command' argument, and can simulate hangs
# (via a fake Timeout::Error) or transient/permanent failures.
# ---------------------------------------------------------------------------
class FakeShellRunner
  Response = Struct.new(:stdout, :stderr, :exitstatus) do
    def success?
      exitstatus.zero?
    end
  end

  def initialize
    @rules = []       # [{match:, stdout:, stderr:, exitstatus:, hang: , fail_times:}]
    @call_log = []
    @call_counts = Hash.new(0)
  end

  # match: String/Regexp tested against the -Command payload.
  # fail_times: number of times to return a transient failure before
  #             succeeding (simulates a flaky WMI/RPC call).
  # hang: if true, sleeps longer than any sane timeout to force Timeout::Error.
  def stub(match, stdout: '', stderr: '', exitstatus: 0, fail_times: 0, hang: false)
    @rules << { match: match, stdout: stdout, stderr: stderr, exitstatus: exitstatus,
                fail_times: fail_times, hang: hang }
    self
  end

  def call_count(match)
    @call_counts[match]
  end

  def capture3(*args)
    command = args.last
    rule = @rules.find { |r| command.match?(r[:match]) } || @rules.find { |r| command.include?(r[:match].to_s) }
    raise "FakeShellRunner: no stub matched command: #{command}" unless rule

    @call_log << command
    @call_counts[rule[:match]] += 1

    if rule[:hang]
      sleep(5) # long enough to blow through the test's short timeouts
      return [rule[:stdout], rule[:stderr], Response.new('', '', 0)]
    end

    attempt_n = @call_counts[rule[:match]]
    if attempt_n <= rule[:fail_times]
      return ['', 'RPC server is unavailable. (Exception from HRESULT: 0x800706BA)', Response.new('', '', 1)]
    end

    [rule[:stdout], rule[:stderr], Response.new(rule[:stdout], rule[:stderr], rule[:exitstatus])]
  end
end

# ---------------------------------------------------------------------------
# Canned ConvertTo-Json-shaped fixtures, modeled on real PowerShell output.
# ---------------------------------------------------------------------------
module Fixtures
  # Get-Service -Name spooler | ConvertTo-Json -Compress  (single object!
  # PowerShell does NOT wrap a single pipeline object in a JSON array)
  SERVICE_SINGLE = '{"Name":"Spooler","DisplayName":"Print Spooler","Status":4,"StartType":2}'
  # NOTE: real Get-Service Status is actually an enum that ConvertTo-Json
  # renders as an integer (4 = Running) unless you Select-Object a
  # calculated string field first. Realistic bridge code selects a
  # human string; our stub returns the friendlier text form the same way
  # AdminTasks would want to render it, since real installs typically
  # pipe `Select-Object Name,DisplayName,@{N='Status';E={$_.Status.ToString()}}`.
  SERVICE_SINGLE_STR_STATUS = '{"Name":"Spooler","DisplayName":"Print Spooler","Status":"Running"}'

  SERVICE_LIST = '[' \
    '{"Name":"Spooler","DisplayName":"Print Spooler","Status":"Running"},' \
    '{"Name":"BITS","DisplayName":"Background Intelligent Transfer Service","Status":"Running"},' \
    '{"Name":"wuauserv","DisplayName":"Windows Update","Status":"Stopped"}' \
    ']'

  SERVICE_RESTARTED = '{"Name":"Spooler","DisplayName":"Print Spooler","Status":"Running"}'

  # Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" |
  #   Select-Object DeviceID,VolumeName,Size,FreeSpace | ConvertTo-Json -Compress
  DISKS = '[' \
    '{"DeviceID":"C:","VolumeName":"OS","Size":255935373312,"FreeSpace":18296123392},' \
    '{"DeviceID":"D:","VolumeName":"Data","Size":1073741824000,"FreeSpace":536870912000}' \
    ']'

  # Get-WinEvent -FilterHashtable @{LogName='System';Level=1,2;StartTime=...} |
  #   Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message | ConvertTo-Json -Compress
  EVENTS = '[' \
    '{"TimeCreated":"\/Date(1753900800000)\/","Id":7031,"LevelDisplayName":"Error",' \
    '"ProviderName":"Service Control Manager",' \
    '"Message":"The Print Spooler service terminated unexpectedly."},' \
    '{"TimeCreated":"\/Date(1753897200000)\/","Id":41,"LevelDisplayName":"Critical",' \
    '"ProviderName":"Microsoft-Windows-Kernel-Power",' \
    '"Message":"The system has rebooted without cleanly shutting down first."}' \
    ']'

  EMPTY = ''
end

# ---------------------------------------------------------------------------
# Minimal assertion framework (no external test gem, stdlib only).
# ---------------------------------------------------------------------------
class T
  def self.results
    @results ||= []
  end

  def self.test(name)
    yield
    results << [:pass, name, nil]
  rescue => e
    results << [:fail, name, "#{e.class}: #{e.message}\n    #{e.backtrace&.first}"]
  end

  def self.assert(cond, msg = 'assertion failed')
    raise msg unless cond
  end

  def self.assert_eq(expected, actual, label = nil)
    return if expected == actual

    raise "#{label ? "#{label}: " : ''}expected #{expected.inspect}, got #{actual.inspect}"
  end

  def self.summary
    passed = results.count { |r| r[0] == :pass }
    failed = results.count { |r| r[0] == :fail }
    results.each do |status, name, detail|
      if status == :pass
        puts "  PASS  #{name}"
      else
        puts "  FAIL  #{name}"
        puts "        #{detail}"
      end
    end
    puts ''
    puts "#{passed}/#{passed + failed} tests passed"
    failed
  end
end

puts '=' * 72
puts 'powershell_bridge_test.rb -- stub harness (no real powershell.exe)'
puts '=' * 72
puts ''

# ---------------------------------------------------------------------------
# 1. JSON parsing behavior
# ---------------------------------------------------------------------------
puts '-- JSON parsing --'
T.test('run_json returns a Hash for a single-object cmdlet result') do
  runner = FakeShellRunner.new.stub('Get-Service', stdout: Fixtures::SERVICE_SINGLE_STR_STATUS)
  bridge = PowerShellBridge.new(shell_runner: runner, retries: 0)
  result = bridge.run_json('Get-Service -Name spooler')
  T.assert(result.is_a?(Hash), "expected Hash, got #{result.class}")
  T.assert_eq('Spooler', result['Name'])
end

T.test('run_json returns an Array for a multi-object cmdlet result') do
  runner = FakeShellRunner.new.stub('Get-Service', stdout: Fixtures::SERVICE_LIST)
  bridge = PowerShellBridge.new(shell_runner: runner, retries: 0)
  result = bridge.run_json('Get-Service')
  T.assert(result.is_a?(Array), "expected Array, got #{result.class}")
  T.assert_eq(3, result.length)
end

T.test('run_json_array normalizes a single Hash result into a one-element Array') do
  runner = FakeShellRunner.new.stub('Get-Service', stdout: Fixtures::SERVICE_SINGLE_STR_STATUS)
  bridge = PowerShellBridge.new(shell_runner: runner, retries: 0)
  result = bridge.run_json_array('Get-Service -Name spooler')
  T.assert_eq(1, result.length)
  T.assert_eq('Spooler', result.first['Name'])
end

T.test('run_json_array returns [] for empty PowerShell output ($null pipeline)') do
  runner = FakeShellRunner.new.stub('Get-Service', stdout: Fixtures::EMPTY)
  bridge = PowerShellBridge.new(shell_runner: runner, retries: 0)
  result = bridge.run_json_array('Get-Service -Name doesnotexist')
  T.assert_eq([], result)
end

T.test('malformed JSON raises PowerShellBridge::CommandError, not a raw JSON::ParserError') do
  runner = FakeShellRunner.new.stub('Get-Service', stdout: '{not valid json')
  bridge = PowerShellBridge.new(shell_runner: runner, retries: 0)
  begin
    bridge.run_json('Get-Service')
    raise 'expected CommandError to be raised'
  rescue PowerShellBridge::CommandError => e
    T.assert(e.message.include?('could not parse'), e.message)
  end
end

# ---------------------------------------------------------------------------
# 2. Retry / backoff behavior
# ---------------------------------------------------------------------------
puts ''
puts '-- retry / backoff --'
T.test('transient failure (RPC server unavailable) is retried and eventually succeeds') do
  runner = FakeShellRunner.new.stub('Get-Service', stdout: Fixtures::SERVICE_LIST, fail_times: 2)
  bridge = PowerShellBridge.new(shell_runner: runner, retries: 3, backoff: 0.01)
  result = bridge.run_json('Get-Service')
  T.assert_eq(3, result.length)
  T.assert_eq(3, runner.call_count('Get-Service')) # 2 failures + 1 success
end

T.test('permanent failure (cmdlet not found) is NOT retried') do
  runner = FakeShellRunner.new.stub(
    'Get-BogusCmdlet',
    stdout: '',
    stderr: "The term 'Get-BogusCmdlet' is not recognized as the name of a cmdlet, function...",
    exitstatus: 1
  )
  bridge = PowerShellBridge.new(shell_runner: runner, retries: 3, backoff: 0.01)
  begin
    bridge.run_raw('Get-BogusCmdlet')
    raise 'expected CommandError'
  rescue PowerShellBridge::CommandError
    T.assert_eq(1, runner.call_count('Get-BogusCmdlet'), 'should not have retried a permanent error')
  end
end

T.test('exhausting retries on a persistent transient failure raises CommandError') do
  runner = FakeShellRunner.new.stub('Get-Service', stdout: Fixtures::SERVICE_LIST, fail_times: 99)
  bridge = PowerShellBridge.new(shell_runner: runner, retries: 2, backoff: 0.01)
  begin
    bridge.run_json('Get-Service')
    raise 'expected CommandError'
  rescue PowerShellBridge::CommandError
    T.assert_eq(3, runner.call_count('Get-Service')) # 1 try + 2 retries
  end
end

# ---------------------------------------------------------------------------
# 3. Timeout behavior
# ---------------------------------------------------------------------------
puts ''
puts '-- timeout handling --'
T.test('a hung powershell.exe call raises PowerShellBridge::TimeoutError after retries') do
  runner = FakeShellRunner.new.stub('Get-Service', hang: true)
  bridge = PowerShellBridge.new(shell_runner: runner, timeout: 0.2, retries: 1, backoff: 0.01)
  begin
    bridge.run_json('Get-Service')
    raise 'expected TimeoutError'
  rescue PowerShellBridge::TimeoutError => e
    T.assert(e.message.include?('timed out'), e.message)
  end
end

# ---------------------------------------------------------------------------
# 4. AdminTasks helpers
# ---------------------------------------------------------------------------
puts ''
puts '-- AdminTasks helpers --'
T.test('AdminTasks.disk_report computes GB and PercentFree correctly') do
  runner = FakeShellRunner.new.stub('Win32_LogicalDisk', stdout: Fixtures::DISKS)
  bridge = PowerShellBridge.new(shell_runner: runner, retries: 0)
  report = AdminTasks.disk_report(bridge)
  c = report.find { |d| d['DeviceID'] == 'C:' }
  T.assert_eq(238.36, c['SizeGB'])
  T.assert_eq(17.04, c['FreeGB'])
  T.assert_eq(7.1, c['PercentFree']) # low disk space case, should trip [LOW] flag
end

T.test('AdminTasks.restart_service re-queries status after restarting') do
  runner = FakeShellRunner.new
            .stub('Restart-Service', stdout: '')
            .stub('Get-Service', stdout: Fixtures::SERVICE_RESTARTED)
  bridge = PowerShellBridge.new(shell_runner: runner, retries: 0)
  result = AdminTasks.restart_service(bridge, name: 'Spooler')
  T.assert_eq('Running', result['Status'])
end

T.test('AdminTasks.recent_critical_events parses events with .NET /Date()/ timestamps intact') do
  runner = FakeShellRunner.new.stub('Get-WinEvent', stdout: Fixtures::EVENTS)
  bridge = PowerShellBridge.new(shell_runner: runner, retries: 0)
  events = AdminTasks.recent_critical_events(bridge, log_name: 'System')
  T.assert_eq(2, events.length)
  T.assert_eq('Critical', events.last['LevelDisplayName'])
end

T.test('AdminTasks.recent_critical_events treats "No events were found" as an empty result, not an error') do
  runner = FakeShellRunner.new.stub(
    'Get-WinEvent',
    stdout: '',
    stderr: 'No events were found that match the specified selection criteria.',
    exitstatus: 1
  )
  bridge = PowerShellBridge.new(shell_runner: runner, retries: 0)
  events = AdminTasks.recent_critical_events(bridge, log_name: 'Application')
  T.assert_eq([], events)
end

# ---------------------------------------------------------------------------
# 5. CLI wiring (text + JSON rendering, exit codes)
# ---------------------------------------------------------------------------
puts ''
puts '-- CLI wiring --'
require 'stringio'

T.test('CLI service-status --json prints valid JSON and exits 0') do
  runner = FakeShellRunner.new.stub('Get-Service', stdout: Fixtures::SERVICE_LIST)
  factory = ->(opts) { PowerShellBridge.new(shell_runner: runner, **opts) }
  out = StringIO.new
  err = StringIO.new
  code = CLI.new(['service-status', '--json'], bridge_factory: factory, stdout: out, stderr: err).run
  T.assert_eq(CLI::EXIT_OK, code)
  parsed = JSON.parse(out.string)
  T.assert_eq(3, parsed.length)
end

T.test('CLI disk-report text mode flags low free space and exits non-zero') do
  runner = FakeShellRunner.new.stub('Win32_LogicalDisk', stdout: Fixtures::DISKS)
  factory = ->(opts) { PowerShellBridge.new(shell_runner: runner, **opts) }
  out = StringIO.new
  err = StringIO.new
  code = CLI.new(['disk-report'], bridge_factory: factory, stdout: out, stderr: err).run
  T.assert(out.string.include?('[LOW]'), out.string)
  T.assert_eq(CLI::EXIT_GENERAL_ERROR, code) # C: is below the 10% free threshold
end

T.test('CLI service-restart without --name exits with usage error') do
  runner = FakeShellRunner.new
  factory = ->(opts) { PowerShellBridge.new(shell_runner: runner, **opts) }
  out = StringIO.new
  err = StringIO.new
  code = CLI.new(['service-restart'], bridge_factory: factory, stdout: out, stderr: err).run
  T.assert_eq(CLI::EXIT_USAGE, code)
  T.assert(err.string.include?('--name'), err.string)
end

T.test('CLI events command exits non-zero when critical events are present (alerting use case)') do
  runner = FakeShellRunner.new.stub('Get-WinEvent', stdout: Fixtures::EVENTS)
  factory = ->(opts) { PowerShellBridge.new(shell_runner: runner, **opts) }
  out = StringIO.new
  err = StringIO.new
  code = CLI.new(['events', '--log-name', 'System'], bridge_factory: factory, stdout: out, stderr: err).run
  T.assert_eq(CLI::EXIT_GENERAL_ERROR, code)
  T.assert(out.string.include?('Kernel-Power'), out.string)
end

T.test('CLI unknown command exits usage error') do
  runner = FakeShellRunner.new
  factory = ->(opts) { PowerShellBridge.new(shell_runner: runner, **opts) }
  out = StringIO.new
  err = StringIO.new
  code = CLI.new(['not-a-real-command'], bridge_factory: factory, stdout: out, stderr: err).run
  T.assert_eq(CLI::EXIT_USAGE, code)
end

# ---------------------------------------------------------------------------
puts ''
puts '=' * 72
failed = T.summary
puts '=' * 72

if failed.zero?
  puts 'ALL PASSED'
  puts ''
  puts 'Reminder: this proves parsing/retry/timeout/CLI logic only. The'
  puts 'actual `powershell.exe` invocation has not been exercised against a'
  puts 'real Windows host in this run -- see README Troubleshooting.'
  exit 0
else
  puts "#{failed} TEST(S) FAILED"
  exit 1
end
