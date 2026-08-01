#!/usr/bin/env ruby
# frozen_string_literal: true
#
# ssh_fleet_runner.rb — run the same command across a fleet of Linux hosts
# concurrently, with per-host timeouts, bounded retries, and a clean
# pass/fail report you can pipe into cron, CI, or a monitoring pipeline.
#
# Why this exists: `for h in $(cat hosts.txt); do ssh $h "$cmd"; done` is
# the classic bash one-liner, but it's serial (one slow/dead host stalls
# everything behind it), has no timeout, no retry, and no structured
# output. This script fixes all four in pure Ruby stdlib — it shells out to
# the system `ssh` binary (so it uses your existing ~/.ssh/config, agent,
# and known_hosts) instead of depending on the net-ssh gem, which keeps it
# installable on a bare box with nothing but Ruby and OpenSSH.
#
# Usage:
#   ruby ssh_fleet_runner.rb --hosts web1,web2,db1 --command "uptime"
#   ruby ssh_fleet_runner.rb --hosts-file fleet.txt --command "systemctl is-active nginx" \
#        --user deploy --identity ~/.ssh/deploy_key --concurrency 10 --json
#
# fleet.txt format (one host per line, optional user@ and :port):
#   web1.example.com
#   deploy@web2.example.com:2222
#
# Exit codes (cron/CI-friendly):
#   0 = every host succeeded
#   1 = at least one host failed or timed out after retries

require 'optparse'
require 'open3'
require 'json'
require 'timeout'

# ---------------------------------------------------------------------------
# HostResult: outcome of running the command on a single host.
# ---------------------------------------------------------------------------
HostResult = Struct.new(:host, :ok, :exit_code, :stdout, :stderr, :attempts,
                         :duration_s, :timed_out, keyword_init: true) do
  def to_h
    super
  end
end

# ---------------------------------------------------------------------------
# Target: a parsed `user@host:port` entry.
# ---------------------------------------------------------------------------
Target = Struct.new(:host, :user, :port) do
  def label
    port ? "#{user}@#{host}:#{port}" : "#{user}@#{host}"
  end

  def self.parse(spec, default_user:, default_port:)
    user = default_user
    rest = spec
    if rest.include?('@')
      user, rest = rest.split('@', 2)
    end
    host, port = rest.split(':', 2)
    new(host, user, (port || default_port))
  end
end

# ---------------------------------------------------------------------------
# ShellRunner: the *real* transport — shells out to the system `ssh` binary
# via Open3, with a hard wall-clock timeout enforced from the Ruby side
# (SSH's own ConnectTimeout only covers the initial TCP handshake, not a
# hung remote command, so we still need our own watchdog).
# ---------------------------------------------------------------------------
class ShellRunner
  def run(cmd_array, timeout_s)
    start = Time.now
    stdout = +''
    stderr = +''
    exit_code = nil
    timed_out = false

    Open3.popen3(*cmd_array) do |stdin, stdout_io, stderr_io, wait_thr|
      stdin.close
      begin
        Timeout.timeout(timeout_s) do
          stdout << stdout_io.read
          stderr << stderr_io.read
          exit_code = wait_thr.value.exitstatus
        end
      rescue Timeout::Error
        timed_out = true
        Process.kill('TERM', wait_thr.pid) rescue nil
        sleep 0.2
        Process.kill('KILL', wait_thr.pid) rescue nil
        exit_code = -1
      end
    end

    [exit_code, stdout, stderr, timed_out, Time.now - start]
  end
end

# ---------------------------------------------------------------------------
# SSHFleetRunner: builds ssh commands, fans them out across a thread pool,
# retries failures, and collects HostResults.
# ---------------------------------------------------------------------------
class SSHFleetRunner
  def initialize(targets:, command:, concurrency: 5, timeout: 15, retries: 1,
                 identity: nil, ssh_extra_opts: [], runner: ShellRunner.new, logger: $stderr)
    @targets = targets
    @command = command
    @concurrency = [concurrency, 1].max
    @timeout = timeout
    @retries = retries
    @identity = identity
    @ssh_extra_opts = ssh_extra_opts
    @runner = runner
    @logger = logger
  end

  # Fans work out across a bounded thread pool (a simple work queue, not one
  # thread per host) so "--concurrency 5" against a 500-host fleet.txt
  # doesn't try to open 500 sockets at once.
  def run
    queue = Queue.new
    @targets.each { |t| queue << t }
    results = Concurrent_results.new

    workers = Array.new(@concurrency) do
      Thread.new do
        loop do
          target = begin
            queue.pop(true)
          rescue ThreadError
            nil
          end
          break unless target

          results.add(run_with_retries(target))
        end
      end
    end
    workers.each(&:join)

    results.to_a
  end

  private

  # Minimal thread-safe accumulator (Mutex + Array) — avoids pulling in the
  # `concurrent-ruby` gem for something this small.
  class Concurrent_results
    def initialize
      @mutex = Mutex.new
      @items = []
    end

    def add(item)
      @mutex.synchronize { @items << item }
    end

    def to_a
      @mutex.synchronize { @items.dup }
    end
  end

  def run_with_retries(target)
    attempts = 0
    last = nil

    loop do
      attempts += 1
      last = run_once(target, attempts)
      break if last.ok || attempts > @retries

      backoff = 2**(attempts - 1) * 0.5
      log("#{target.label}: attempt #{attempts} failed, retrying in #{backoff}s")
      sleep(backoff)
    end

    last
  end

  def run_once(target, attempt)
    cmd = build_ssh_command(target)
    exit_code, stdout, stderr, timed_out, duration = @runner.run(cmd, @timeout)

    HostResult.new(
      host: target.label,
      ok: exit_code == 0,
      exit_code: exit_code,
      stdout: stdout.to_s.strip,
      stderr: stderr.to_s.strip,
      attempts: attempt,
      duration_s: duration.round(2),
      timed_out: timed_out
    )
  end

  # Builds the argv array for the `ssh` binary. Using an array (not a shell
  # string) means no shell-injection risk from host names — Open3 execs it
  # directly, never through /bin/sh.
  def build_ssh_command(target)
    cmd = ['ssh',
           '-o', 'BatchMode=yes',            # never prompt for a password
           '-o', 'StrictHostKeyChecking=accept-new', # don't hang on unknown hosts
           '-o', "ConnectTimeout=#{[@timeout, 10].min}"]
    cmd += ['-i', @identity] if @identity
    cmd += ['-p', target.port.to_s] if target.port
    @ssh_extra_opts.each { |o| cmd += ['-o', o] }
    cmd += ["#{target.user}@#{target.host}", @command]
    cmd
  end

  def log(msg)
    @logger.puts("[ssh_fleet_runner] #{msg}")
  end
end

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if $PROGRAM_NAME == __FILE__
  options = {
    hosts: nil,
    hosts_file: nil,
    command: nil,
    user: ENV['USER'] || 'root',
    port: nil,
    identity: nil,
    concurrency: 5,
    timeout: 15,
    retries: 1,
    json: false
  }

  OptionParser.new do |opts|
    opts.banner = 'Usage: ssh_fleet_runner.rb --hosts h1,h2 --command "CMD" [options]'
    opts.on('--hosts LIST', 'Comma-separated host list (user@host:port supported)') { |v| options[:hosts] = v }
    opts.on('--hosts-file PATH', 'File with one host per line') { |v| options[:hosts_file] = v }
    opts.on('-c', '--command CMD', 'Command to run on every host') { |v| options[:command] = v }
    opts.on('-u', '--user USER', 'Default SSH user (default: $USER)') { |v| options[:user] = v }
    opts.on('-p', '--port PORT', Integer, 'Default SSH port') { |v| options[:port] = v }
    opts.on('-i', '--identity PATH', 'SSH private key file') { |v| options[:identity] = v }
    opts.on('--concurrency N', Integer, 'Max hosts in flight at once (default 5)') { |v| options[:concurrency] = v }
    opts.on('--timeout SECONDS', Integer, 'Per-host wall-clock timeout (default 15)') { |v| options[:timeout] = v }
    opts.on('--retries N', Integer, 'Retries per host after the first attempt (default 1)') { |v| options[:retries] = v }
    opts.on('--json', 'Emit machine-readable JSON instead of text') { options[:json] = true }
    opts.on('-h', '--help') { puts opts; exit 0 }
  end.parse!

  if options[:command].nil? || (options[:hosts].nil? && options[:hosts_file].nil?)
    warn 'error: --command and one of --hosts/--hosts-file are required'
    exit 3
  end

  raw_hosts = options[:hosts] ? options[:hosts].split(',') : File.readlines(options[:hosts_file], chomp: true)
  raw_hosts = raw_hosts.map(&:strip).reject(&:empty?)

  targets = raw_hosts.map do |spec|
    Target.parse(spec, default_user: options[:user], default_port: options[:port])
  end

  runner = SSHFleetRunner.new(
    targets: targets,
    command: options[:command],
    concurrency: options[:concurrency],
    timeout: options[:timeout],
    retries: options[:retries],
    identity: options[:identity]
  )

  results = runner.run
  failures = results.reject(&:ok)

  if options[:json]
    puts JSON.pretty_generate(
      generated_at: Time.now.iso8601,
      total: results.size,
      succeeded: results.size - failures.size,
      failed: failures.size,
      results: results.sort_by(&:host).map(&:to_h)
    )
  else
    results.sort_by(&:host).each do |r|
      tag = r.ok ? 'OK  ' : (r.timed_out ? 'TIME' : 'FAIL')
      puts "#{tag} #{r.host.ljust(28)} (#{r.attempts} attempt#{'s' if r.attempts > 1}, #{r.duration_s}s)"
      puts "     #{r.stdout.lines.first&.strip}" if r.ok && !r.stdout.empty?
      puts "     stderr: #{r.stderr.lines.first&.strip}" if !r.ok && !r.stderr.empty?
    end
    puts "\n#{results.size - failures.size}/#{results.size} hosts succeeded"
  end

  exit(failures.empty? ? 0 : 1)
end
