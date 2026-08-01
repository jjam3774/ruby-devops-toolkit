#!/usr/bin/env ruby
# frozen_string_literal: true
#
# ssh_fleet_runner_test.rb — stub harness for SSHFleetRunner's concurrency,
# retry, and command-building logic.
#
# Honest note on test coverage: this sandbox blocks processes from binding
# a listening socket (any attempt to run a real sshd here gets the whole
# process group killed by the sandbox's network policy), so we can't stand
# up a real loopback SSH server the way the NTP-drift script in this repo
# tested against a real UDP socket. `Target.parse` and `build_ssh_command`
# are pure string logic and ARE exercised directly below with no stubbing.
# The parts that would normally touch the network (retries, timeouts,
# concurrency, exit-code handling) are verified by injecting a fake
# `runner:` object in place of ShellRunner — SSHFleetRunner never talks to
# Open3 directly, it always goes through that injected object, so this
# exercises the exact same code path a real SSH failure would hit.

require_relative 'ssh_fleet_runner'

$failures = 0

def check(desc)
  yield
  puts "PASS  #{desc}"
rescue StandardError => e
  $failures += 1
  puts "FAIL  #{desc} -- #{e.class}: #{e.message}"
end

# --- Target.parse: pure logic, no stub needed -------------------------------
check('Target.parse handles bare hostname') do
  t = Target.parse('web1.example.com', default_user: 'root', default_port: nil)
  raise "bad host #{t.host}" unless t.host == 'web1.example.com'
  raise "bad user #{t.user}" unless t.user == 'root'
  raise "expected nil port, got #{t.port}" unless t.port.nil?
end

check('Target.parse handles user@host:port') do
  t = Target.parse('deploy@db1.internal:2222', default_user: 'root', default_port: nil)
  raise "bad host #{t.host}"   unless t.host == 'db1.internal'
  raise "bad user #{t.user}"   unless t.user == 'deploy'
  raise "bad port #{t.port}"   unless t.port == '2222'
  raise "bad label #{t.label}" unless t.label == 'deploy@db1.internal:2222'
end

# --- A fake transport that stands in for the real `ssh` subprocess ---------
# Scripted per-host so we can force success / failure / timeout / flaky
# (fails once then succeeds) sequences deterministically.
class FakeRunner
  def initialize(scripts)
    @scripts = scripts # host => array of outcomes, consumed in order
    @calls = Hash.new(0)
    @recorded_cmds = []
  end

  attr_reader :recorded_cmds

  def run(cmd_array, _timeout_s)
    @recorded_cmds << cmd_array
    host_label = cmd_array.last(2).first # the "user@host" argv entry
    outcomes = @scripts.fetch(host_label) { [[:ok, 0, 'default output', '']] }
    idx = [@calls[host_label], outcomes.size - 1].min
    @calls[host_label] += 1
    kind, code, out, err = outcomes[idx]

    case kind
    when :ok, :fail
      [code, out, err, false, 0.05]
    when :timeout
      [-1, '', '', true, 15.0]
    end
  end
end

# --- build_ssh_command: verify argv shape via a recording FakeRunner -------
check('build_ssh_command includes BatchMode, identity, port, and command') do
  fake = FakeRunner.new({})
  target = Target.new('db1.internal', 'deploy', '2222')
  runner = SSHFleetRunner.new(targets: [target], command: 'uptime', identity: '/home/x/.ssh/key',
                               runner: fake, retries: 0)
  runner.run
  cmd = fake.recorded_cmds.first
  raise 'missing BatchMode=yes' unless cmd.include?('BatchMode=yes')
  raise 'missing identity flag' unless cmd.include?('/home/x/.ssh/key')
  raise 'missing port flag' unless cmd.include?('2222')
  raise 'command not last arg' unless cmd.last == 'uptime'
  raise 'wrong target label' unless cmd[-2] == 'deploy@db1.internal'
end

# --- Retry logic: fails once, succeeds on attempt 2 -------------------------
check('a host that fails once then succeeds is retried and reported ok') do
  fake = FakeRunner.new({
                          'root@flaky-host' => [[:fail, 255, '', 'Connection refused'],
                                                 [:ok, 0, 'uptime output', '']]
                        })
  target = Target.new('flaky-host', 'root', nil)
  runner = SSHFleetRunner.new(targets: [target], command: 'uptime', runner: fake, retries: 2)
  # avoid slowing the test suite down with the real exponential backoff sleep
  runner.define_singleton_method(:sleep) { |_n| nil }
  result = runner.run.first
  raise "expected ok, got #{result.ok}" unless result.ok
  raise "expected 2 attempts, got #{result.attempts}" unless result.attempts == 2
end

# --- Exhausted retries: every attempt fails ---------------------------------
check('a host that always fails is reported failed after exhausting retries') do
  fake = FakeRunner.new({
                          'root@dead-host' => [[:fail, 255, '', 'No route to host']]
                        })
  target = Target.new('dead-host', 'root', nil)
  runner = SSHFleetRunner.new(targets: [target], command: 'uptime', runner: fake, retries: 2)
  runner.define_singleton_method(:sleep) { |_n| nil }
  result = runner.run.first
  raise 'expected ok=false' if result.ok
  raise "expected 3 attempts (1 + 2 retries), got #{result.attempts}" unless result.attempts == 3
end

# --- Timeout is reported distinctly from a plain failure --------------------
check('a host that times out is flagged timed_out=true') do
  fake = FakeRunner.new({ 'root@slow-host' => [[:timeout]] })
  target = Target.new('slow-host', 'root', nil)
  runner = SSHFleetRunner.new(targets: [target], command: 'uptime', runner: fake, retries: 0)
  result = runner.run.first
  raise 'expected timed_out=true' unless result.timed_out
  raise 'expected ok=false' if result.ok
end

# --- Concurrency: a bounded pool still processes every host exactly once ---
check('20 targets with concurrency=3 all get processed exactly once') do
  targets = (1..20).map { |i| Target.new("host#{i}", 'root', nil) }
  fake = FakeRunner.new({})
  runner = SSHFleetRunner.new(targets: targets, command: 'true', runner: fake, concurrency: 3, retries: 0)
  results = runner.run
  raise "expected 20 results, got #{results.size}" unless results.size == 20
  raise 'duplicate or missing host in results' unless results.map(&:host).sort == targets.map(&:label).sort
  raise 'not all ok' unless results.all?(&:ok)
end

puts "\n#{$failures.zero? ? 'ALL TESTS PASSED' : "#{$failures} TEST(S) FAILED"}"
exit($failures.zero? ? 0 : 1)
