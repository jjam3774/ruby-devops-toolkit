#!/usr/bin/env ruby
# frozen_string_literal: true
#
# ssh_fleet_runner.rb — Run one shell command across a fleet of Linux hosts
# concurrently over SSH, and print a pass/fail summary.
#
# Solves the "I have a text file of 40 hostnames and need to run one command
# on all of them, tonight" problem, without pulling in Ansible/Fabric for a
# one-off. Uses net-ssh for the transport and a small thread pool so all
# hosts are contacted in parallel (bounded by --parallelism).
#
# Usage:
#   ruby ssh_fleet_runner.rb -f hosts.txt -u deploy -i ~/.ssh/id_ed25519 -- 'uptime'
#   ruby ssh_fleet_runner.rb -H web01,web02,web03 -u deploy -- 'systemctl is-active nginx'
#
# Exit status: 0 if every host succeeded (exit 0 and no SSH error), 1 otherwise.
#
# Author: tha-shed.com Ruby-for-DevOps series
# Ruby: 3.0+ | Gems: net-ssh (~> 7.0)

require 'optparse'
require 'ostruct'

# --- SSH backend --------------------------------------------------------
#
# We isolate the one call that actually touches the network behind
# SshBackend so the orchestration logic (thread pool, timeouts, summary)
# can be unit-tested without a real SSH server — see fleet_runner_test.rb.
# In production this wraps Net::SSH; only this class requires the gem.
class SshBackend
  Outcome = Struct.new(:host, :ok, :exit_code, :stdout, :stderr, :error, keyword_init: true)

  def initialize(user:, identity: nil, timeout: 10, port: 22)
    @user = user
    @identity = identity
    @timeout = timeout
    @port = port
  end

  # Runs +command+ on +host+ and returns an Outcome. Never raises — network
  # and auth failures are captured into Outcome#error so the caller can
  # keep going with the rest of the fleet.
  def run(host, command)
    require 'net/ssh' # deferred so hosts that never call this can skip the dependency
    stdout = +''
    stderr = +''
    exit_code = nil

    opts = { timeout: @timeout, non_interactive: true, verify_host_key: :never }
    opts[:keys] = [@identity] if @identity
    opts[:port] = @port

    Net::SSH.start(host, @user, **opts) do |ssh|
      ssh.open_channel do |channel|
        channel.exec(command) do |_ch, success|
          raise "could not execute command on #{host}" unless success

          channel.on_data { |_c, data| stdout << data }
          channel.on_extended_data { |_c, _type, data| stderr << data }
          channel.on_request('exit-status') { |_c, data| exit_code = data.read_long }
        end
      end
      ssh.loop
    end

    Outcome.new(host: host, ok: exit_code.zero?, exit_code: exit_code, stdout: stdout, stderr: stderr, error: nil)
  rescue StandardError => e
    Outcome.new(host: host, ok: false, exit_code: nil, stdout: stdout, stderr: stderr, error: e.message)
  end
end

# --- Orchestration -------------------------------------------------------

# Runs +command+ against every host in +hosts+ using +backend+, at most
# +parallelism+ at a time, and returns an Array<Outcome> in the original
# host order (not completion order, so output is stable/diffable).
def run_fleet(hosts, command, backend:, parallelism: 10)
  queue = hosts.each_with_index.to_a # [[host, idx], ...]
  results = Array.new(hosts.size)
  mutex = Mutex.new

  workers = Array.new([parallelism, hosts.size].min) do
    Thread.new do
      loop do
        host, idx = mutex.synchronize { queue.shift }
        break unless host

        results[idx] = backend.run(host, command)
      end
    end
  end
  workers.each(&:join)
  results
end

def print_summary(results)
  ok = results.count(&:ok)
  results.each do |r|
    status = r.ok ? 'OK  ' : 'FAIL'
    detail =
      if r.error
        "error: #{r.error}"
      else
        "exit=#{r.exit_code}"
      end
    puts format('[%s] %-24s %s', status, r.host, detail)
    unless r.stdout.to_s.strip.empty?
      r.stdout.strip.each_line { |line| puts "        #{line}" }
    end
    next if r.ok || r.stderr.to_s.strip.empty?

    r.stderr.strip.each_line { |line| puts "        stderr: #{line}" }
  end
  puts
  puts "#{ok}/#{results.size} hosts succeeded"
end

def parse_options(argv)
  opts = OpenStruct.new(user: ENV['USER'], identity: nil, hosts_file: nil, hosts: nil,
                         parallelism: 10, timeout: 10, port: 22)

  parser = OptionParser.new do |o|
    o.banner = "Usage: ssh_fleet_runner.rb [options] -- 'command to run'"
    o.on('-f', '--hosts-file PATH', 'File with one hostname per line (# comments allowed)') { |v| opts.hosts_file = v }
    o.on('-H', '--hosts LIST', 'Comma-separated list of hosts (alternative to -f)') { |v| opts.hosts = v.split(',') }
    o.on('-u', '--user USER', "SSH user (default: #{ENV['USER']})") { |v| opts.user = v }
    o.on('-i', '--identity PATH', 'Path to SSH private key') { |v| opts.identity = v }
    o.on('-p', '--parallelism N', Integer, 'Max concurrent connections (default 10)') { |v| opts.parallelism = v }
    o.on('-t', '--timeout SECONDS', Integer, 'Per-host connect timeout (default 10)') { |v| opts.timeout = v }
    o.on('--port N', Integer, 'SSH port (default 22)') { |v| opts.port = v }
    o.on('-h', '--help', 'Show this help') { puts o; exit 0 }
  end
  parser.parse!(argv)

  opts.command = argv.join(' ')
  opts
end

def load_hosts(opts)
  if opts.hosts
    opts.hosts
  elsif opts.hosts_file
    File.readlines(opts.hosts_file, chomp: true)
        .map(&:strip)
        .reject { |l| l.empty? || l.start_with?('#') }
  else
    []
  end
end

if __FILE__ == $PROGRAM_NAME
  opts = parse_options(ARGV)
  hosts = load_hosts(opts)

  if hosts.empty?
    warn 'No hosts given. Use -H host1,host2 or -f hosts.txt.'
    exit 2
  end
  if opts.command.strip.empty?
    warn "No command given. Usage: ssh_fleet_runner.rb -H h1,h2 -- 'command'"
    exit 2
  end

  backend = SshBackend.new(user: opts.user, identity: opts.identity, timeout: opts.timeout, port: opts.port)
  results = run_fleet(hosts, opts.command, backend: backend, parallelism: opts.parallelism)
  print_summary(results)

  exit(results.all?(&:ok) ? 0 : 1)
end
