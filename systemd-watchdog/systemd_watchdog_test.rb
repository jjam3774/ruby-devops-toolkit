#!/usr/bin/env ruby
# frozen_string_literal: true
#
# systemd_watchdog_test.rb — stub harness for the CRIT / restart / rate-limit
# path of systemd_watchdog.rb.
#
# Querying real *healthy* units (cron, ssh, apparmor, a nonexistent unit) was
# verified live against the sandbox's actual systemd instance. But putting a
# unit into `failed` state and repeatedly restarting it requires root and a
# writable /etc/systemd/system, which this sandbox doesn't have. So instead
# we monkey-patch Open3.capture3 to return the exact text systemctl prints
# for a failed unit, and drive SystemdWatchdog's private methods directly.
# This exercises the classification logic and the restart-rate-limit state
# machine exactly as real CRIT output would, without needing a real failure.

require 'open3'
require_relative 'systemd_watchdog'

$failures = 0

def check(desc)
  yield
  puts "PASS  #{desc}"
rescue StandardError => e
  $failures += 1
  puts "FAIL  #{desc} -- #{e.class}: #{e.message}"
end

# --- Fixture: canned `systemctl show` output for a failed unit -------------
FAILED_SHOW_OUTPUT = <<~OUT
  ActiveState=failed
  SubState=failed
  LoadState=loaded
  Result=exit-code
OUT

OK_SHOW_OUTPUT = <<~OUT
  ActiveState=active
  SubState=running
  LoadState=loaded
  Result=success
OUT

# Fake Process::Status-like object with just what we call: .success?
FakeStatus = Struct.new(:ok) do
  def success?
    ok
  end
end

# Records every command that would have been run, so we can assert on it.
$commands_run = []

Open3.define_singleton_method(:capture3) do |*args|
  $commands_run << args
  if args[0..1] == ['systemctl', 'show']
    unit = args[2]
    out = unit == 'flaky-app.service' ? FAILED_SHOW_OUTPUT : OK_SHOW_OUTPUT
    [out, '', FakeStatus.new(true)]
  elsif args[0..1] == ['systemctl', 'restart']
    ['', '', FakeStatus.new(true)]
  else
    ['', 'unexpected command', FakeStatus.new(false)]
  end
end

tmp_state = File.join((ENV['TMPDIR'] || '/tmp'), 'tmp_watchdog_state_test.json')
File.delete(tmp_state) if File.exist?(tmp_state)

# --- Test 1: healthy unit classifies OK -------------------------------------
check('healthy unit classifies as :ok') do
  wd = SystemdWatchdog.new(units: ['nginx.service'], state_file: tmp_state)
  results = wd.run
  raise "expected :ok, got #{results.first.level}" unless results.first.level == :ok
end

# --- Test 2: failed unit classifies CRIT, restart attempted and succeeds ---
check('failed unit classifies as :crit and gets restarted') do
  $commands_run.clear
  wd = SystemdWatchdog.new(units: ['flaky-app.service'], restart: true, state_file: tmp_state)
  results = wd.run
  status = results.first
  raise "expected :crit, got #{status.level}" unless status.level == :crit
  raise 'expected restarted=true' unless status.restarted == true
  raise 'expected a systemctl restart call' unless $commands_run.any? { |c| c[0..1] == ['systemctl', 'restart'] }
end

# --- Test 3: rate limiting stops restarts after max_restarts in window -----
check('rate limiter refuses restart #4 within the window') do
  File.delete(tmp_state) if File.exist?(tmp_state)
  wd = SystemdWatchdog.new(units: ['flaky-app.service'], restart: true, max_restarts: 3, window: 600,
                            state_file: tmp_state)
  3.times { wd.run }
  fourth = wd.run.first
  raise 'expected restarted=false on 4th attempt' if fourth.restarted != false
end

# --- Test 4: dry-run never actually calls `systemctl restart` --------------
check('dry-run mode logs but does not restart') do
  File.delete(tmp_state) if File.exist?(tmp_state)
  $commands_run.clear
  wd = SystemdWatchdog.new(units: ['flaky-app.service'], restart: true, dry_run: true, state_file: tmp_state)
  result = wd.run.first
  raise 'expected restarted=false in dry-run' if result.restarted != false
  raise 'dry-run must not call systemctl restart' if $commands_run.any? { |c| c[0..1] == ['systemctl', 'restart'] }
end

# --- Test 5: unit with LoadState=not-found is CRIT --------------------------
check('unit that does not exist (not-found) classifies as :crit') do
  Open3.define_singleton_method(:capture3) do |*args|
    ["ActiveState=inactive\nSubState=dead\nLoadState=not-found\nResult=success\n", '', FakeStatus.new(true)]
  end
  wd = SystemdWatchdog.new(units: ['ghost.service'], state_file: tmp_state)
  result = wd.run.first
  raise "expected :crit for not-found unit, got #{result.level}" unless result.level == :crit
end

File.delete(tmp_state) if File.exist?(tmp_state)

puts "\n#{$failures.zero? ? 'ALL TESTS PASSED' : "#{$failures} TEST(S) FAILED"}"
exit($failures.zero? ? 0 : 1)
