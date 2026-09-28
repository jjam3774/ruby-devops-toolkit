#!/usr/bin/env ruby
# frozen_string_literal: true
#
# watchdog_test.rb — mock test harness for wmi_process_watchdog.rb.
#
# win32ole and the Win32_Process WMI class are Windows-only and cannot
# execute in this Linux sandbox, so we stub WmiBackend with a FakeWmi that
# simulates a process going down, a restart succeeding, a restart failing,
# and a restart-storm hitting its budget. This exercises every branch of
# Watchdog#check — the part of the script with real decision logic — without
# needing a Windows host. Run with: ruby watchdog_test.rb

require_relative 'wmi_process_watchdog'

class FakeWmi
  def initialize(running: true, start_succeeds: true, start_pid: 4242)
    @running = running
    @start_succeeds = start_succeeds
    @start_pid = start_pid
    @start_calls = 0
  end

  attr_reader :start_calls
  attr_writer :running

  def process_running?(_name)
    @running
  end

  def start_process(_cmd)
    @start_calls += 1
    raise 'access denied creating process' unless @start_succeeds

    @start_pid
  end
end

class FakeAlerter
  attr_reader :messages

  def initialize
    @messages = []
  end

  def notify(message)
    @messages << message
  end
end

def assert(desc, cond)
  if cond
    puts "PASS  #{desc}"
  else
    puts "FAIL  #{desc}"
    exit 1
  end
end

# --- Test 1: healthy process -> :running, no restart, no alert ----------
wmi = FakeWmi.new(running: true)
alerter = FakeAlerter.new
wd = Watchdog.new(process_name: 'worker.exe', start_cmd: 'C:\app\worker.exe',
                   wmi: wmi, alerter: alerter, max_restarts: 3, window_seconds: 60)
outcome = wd.check
assert('healthy process reports :running', outcome == :running)
assert('healthy process triggers no restart', wmi.start_calls.zero?)
assert('healthy process triggers no alert', alerter.messages.empty?)

# --- Test 2: process down, restart succeeds -> :restarted, one alert ----
wmi = FakeWmi.new(running: false, start_succeeds: true, start_pid: 9001)
alerter = FakeAlerter.new
wd = Watchdog.new(process_name: 'worker.exe', start_cmd: 'C:\app\worker.exe',
                   wmi: wmi, alerter: alerter, max_restarts: 3, window_seconds: 60)
outcome = wd.check
assert('down process gets restarted', outcome == :restarted)
assert('restart was actually attempted once', wmi.start_calls == 1)
assert('restart alert mentions the pid', alerter.messages.last.include?('9001'))
assert('one restart is logged', wd.restart_log.size == 1)

# --- Test 3: process down, start_process raises -> :start_failed --------
wmi = FakeWmi.new(running: false, start_succeeds: false)
alerter = FakeAlerter.new
wd = Watchdog.new(process_name: 'worker.exe', start_cmd: 'bad-cmd',
                   wmi: wmi, alerter: alerter, max_restarts: 3, window_seconds: 60)
outcome = wd.check
assert('failed restart reports :start_failed', outcome == :start_failed)
assert('failed restart is not counted toward the restart budget', wd.restart_log.empty?)
assert('failed restart still alerts', alerter.messages.any? { |m| m.include?('access denied') })

# --- Test 4: restart-storm cooldown once the budget is exhausted --------
wmi = FakeWmi.new(running: false, start_succeeds: true)
alerter = FakeAlerter.new
fake_now = Time.now
clock = -> { fake_now }
wd = Watchdog.new(process_name: 'worker.exe', start_cmd: 'C:\app\worker.exe',
                   wmi: wmi, alerter: alerter, max_restarts: 2, window_seconds: 300, clock: clock)

outcomes = 4.times.map { wd.check }
assert('first two checks within budget both restart', outcomes[0] == :restarted && outcomes[1] == :restarted)
assert('third check hits the budget and cools down instead of restarting again', outcomes[2] == :cooldown)
assert('fourth check also cools down (budget still exhausted)', outcomes[3] == :cooldown)
assert('only 2 real restart attempts were made, not 4', wmi.start_calls == 2)
assert('cooldown alert says a human is needed', alerter.messages.last.include?('needs a human'))

# --- Test 5: restart budget rolls off after the window elapses ----------
wmi = FakeWmi.new(running: false, start_succeeds: true)
alerter = FakeAlerter.new
t = Time.now
clock = -> { t }
wd = Watchdog.new(process_name: 'worker.exe', start_cmd: 'C:\app\worker.exe',
                   wmi: wmi, alerter: alerter, max_restarts: 1, window_seconds: 100, clock: clock)
first = wd.check
t += 50 # still inside the 100s window
still_cooldown = wd.check
t += 60 # now the first restart (t+0) has rolled off a 100s window at t+110
recovered = wd.check
assert('first restart within budget succeeds', first == :restarted)
assert('second attempt still inside window cools down', still_cooldown == :cooldown)
assert('once the window rolls past, the budget frees up again', recovered == :restarted)

puts "\nAll watchdog decision-logic tests passed (WmiBackend itself calls into"
puts 'win32ole/Win32_Process and can only run on Windows; this harness stubs it'
puts 'out since win32ole is not available on this Linux sandbox).'
