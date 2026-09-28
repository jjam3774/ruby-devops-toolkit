#!/usr/bin/env ruby
# frozen_string_literal: true
#
# fleet_runner_test.rb — mock test harness for ssh_fleet_runner.rb.
#
# The real SshBackend requires the net-ssh gem, which needs outbound network
# access to rubygems.org — not available in every CI/sandbox environment.
# This harness stubs SshBackend#run with a FakeBackend that simulates a mix
# of successes, non-zero exits, slow hosts, and unreachable hosts, so the
# thread-pool orchestration and summary formatting in run_fleet/print_summary
# get exercised without a real SSH server. Run with: ruby fleet_runner_test.rb

require_relative 'ssh_fleet_runner'

class FakeBackend
  Outcome = SshBackend::Outcome

  # scenarios: { "host" => { ok:, exit_code:, stdout:, stderr:, error:, sleep: } }
  def initialize(scenarios)
    @scenarios = scenarios
    @calls = []
    @mutex = Mutex.new
  end

  attr_reader :calls

  def run(host, command)
    @mutex.synchronize { @calls << [host, command] }
    s = @scenarios.fetch(host)
    sleep(s[:sleep]) if s[:sleep]
    Outcome.new(host: host, ok: s[:ok], exit_code: s[:exit_code], stdout: s[:stdout].to_s,
                stderr: s[:stderr].to_s, error: s[:error])
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

# --- Test 1: mixed success/failure/unreachable, order preserved ---------
scenarios = {
  'web01' => { ok: true, exit_code: 0, stdout: "active\n" },
  'web02' => { ok: false, exit_code: 3, stdout: '', stderr: "unit not found\n" },
  'web03' => { ok: false, exit_code: nil, error: 'Net::SSH::ConnectionTimeout' },
  'web04' => { ok: true, exit_code: 0, stdout: "active\n", sleep: 0.05 }
}
backend = FakeBackend.new(scenarios)
results = run_fleet(%w[web01 web02 web03 web04], 'systemctl is-active nginx', backend: backend, parallelism: 2)

assert('returns one result per host', results.size == 4)
assert('preserves original host order regardless of completion order',
       results.map(&:host) == %w[web01 web02 web03 web04])
assert('web01 succeeded', results[0].ok)
assert('web02 failed with exit_code captured', !results[1].ok && results[1].exit_code == 3)
assert('web03 failed with error captured (no exit_code)', !results[2].ok && results[2].error == 'Net::SSH::ConnectionTimeout')
assert('web04 (slow host) still completes and succeeds', results[3].ok)
assert('every host was actually called exactly once', backend.calls.map(&:first).tally == { 'web01' => 1, 'web02' => 1, 'web03' => 1, 'web04' => 1 })

# --- Test 2: parallelism cap is respected (never more than N in-flight) --
max_concurrent = 0
current = 0
mutex = Mutex.new
tracking_scenarios = (1..6).to_h { |i| ["h#{i}", { ok: true, exit_code: 0, stdout: '', sleep: 0.03 }] }

class TrackingBackend
  def initialize(scenarios, mutex, counter_ref)
    @scenarios = scenarios
    @mutex = mutex
    @counter_ref = counter_ref
  end

  def run(host, _command)
    @mutex.synchronize { @counter_ref[:current] += 1; @counter_ref[:max] = [@counter_ref[:max], @counter_ref[:current]].max }
    sleep(@scenarios[host][:sleep])
    @mutex.synchronize { @counter_ref[:current] -= 1 }
    SshBackend::Outcome.new(host: host, ok: true, exit_code: 0, stdout: '', stderr: '', error: nil)
  end
end

counter = { current: 0, max: 0 }
tb = TrackingBackend.new(tracking_scenarios, mutex, counter)
run_fleet(tracking_scenarios.keys, 'true', backend: tb, parallelism: 3)
assert('parallelism=3 never runs more than 3 hosts concurrently', counter[:max] <= 3)
assert('parallelism cap is actually exercised (not trivially under-subscribed)', counter[:max] == 3)

# --- Test 3: exit status reflects overall fleet health -------------------
all_ok = run_fleet(%w[a b], 'true', backend: FakeBackend.new(
  'a' => { ok: true, exit_code: 0 }, 'b' => { ok: true, exit_code: 0 }
), parallelism: 2)
assert('all-success fleet reports overall success', all_ok.all?(&:ok))

one_fail = run_fleet(%w[a b], 'true', backend: FakeBackend.new(
  'a' => { ok: true, exit_code: 0 }, 'b' => { ok: false, exit_code: 1 }
), parallelism: 2)
assert('any-failure fleet reports overall failure', !one_fail.all?(&:ok))

# --- Test 4: host-file parsing (comments/blank lines ignored) -----------
require 'tempfile'
Tempfile.create('hosts') do |f|
  f.write("web01\n# comment\n\nweb02\n  web03  \n")
  f.flush
  opts = OpenStruct.new(hosts: nil, hosts_file: f.path)
  hosts = load_hosts(opts)
  assert('host file parsing skips comments/blanks and strips whitespace',
         hosts == %w[web01 web02 web03])
end

# --- Test 5: print_summary renders without raising, for a human eyeball -
puts "\n--- sample rendered summary (for the tutorial's output tab) ---"
print_summary(results)

puts "\nAll fleet-orchestration tests passed (SshBackend itself talks to a real"
puts 'SSH server and was verified by reading net-ssh usage; this harness stubs'
puts 'it out since installing gems is blocked by network policy in this sandbox).'
