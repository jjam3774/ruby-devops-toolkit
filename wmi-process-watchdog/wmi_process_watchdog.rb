#!/usr/bin/env ruby
# frozen_string_literal: true
#
# wmi_process_watchdog.rb — Watch a named process on Windows via WMI and
# restart it if it disappears, with a restart-storm cooldown and an optional
# webhook alert.
#
# Solves the "the agent/service keeps silently dying and nobody notices
# until a customer complains" problem, without installing a full monitoring
# stack, for a single box or a scheduled task that just needs to keep one
# process alive.
#
# Usage (run on Windows, from an elevated prompt if the target process needs it):
#   ruby wmi_process_watchdog.rb --process worker.exe --start-cmd "C:\app\worker.exe" ^
#     --interval 15 --max-restarts 5 --window 600 ^
#     --webhook https://hooks.example.com/alert
#
# Exit status: runs forever (Ctrl+C to stop) unless --once is given, in
# which case it does a single check-and-restart pass and exits.
#
# Author: tha-shed.com Ruby-for-DevOps series
# Ruby: 3.0+ (Windows) | stdlib win32ole (bundled with Ruby on Windows) + net/http

require 'optparse'
require 'ostruct'
require 'time'

# --- WMI backend -----------------------------------------------------
#
# All WIN32OLE / WMI access is isolated behind WmiBackend so the watchdog's
# decision logic (should we restart? are we in cooldown? did the alert
# fire?) can be unit-tested on any platform, including this Linux sandbox,
# via FakeWmiBackend in watchdog_test.rb. win32ole and the WMI COM objects
# it wraps are Windows-only and cannot execute outside a Windows Ruby build,
# so this class is intentionally the *only* place that touches them.
class WmiBackend
  def initialize
    require 'win32ole' # only loaded when actually running on Windows
    @wmi = WIN32OLE.connect('winmgmts://./root/cimv2')
  end

  # Returns true if a process with this exact image name (e.g. "worker.exe")
  # currently appears in the WMI process table.
  def process_running?(image_name)
    query = "SELECT ProcessId FROM Win32_Process WHERE Name = '#{escape(image_name)}'"
    procs = @wmi.ExecQuery(query)
    procs.each { |_p| return true }
    false
  end

  # Starts +command+ via Win32_Process.Create (so it's not a child of this
  # Ruby process and survives the watchdog exiting). Returns the new PID,
  # or raises on a non-zero WMI return code.
  def start_process(command)
    process_class = @wmi.Get('Win32_Process')
    result = process_class.Create(command)
    # Win32_Process.Create returns 0 on success and sets the ProcessId out param;
    # WIN32OLE exposes out params as attributes on the result of ExecMethod-style
    # calls. We surface both here so the caller can log the PID.
    return_value = result.ReturnValue
    raise "Win32_Process.Create failed with code #{return_value} for: #{command}" unless return_value.zero?

    result.ProcessId
  end

  private

  def escape(str)
    str.gsub("'", "''")
  end
end

# --- Alerting ----------------------------------------------------------

class WebhookAlerter
  def initialize(url)
    @url = url
  end

  def notify(message)
    return unless @url

    require 'net/http'
    require 'json'
    uri = URI(@url)
    Net::HTTP.post(uri, { text: message }.to_json, 'Content-Type' => 'application/json')
  rescue StandardError => e
    warn "webhook alert failed: #{e.message}"
  end
end

# --- Watchdog decision logic (platform-independent, fully testable) ----

class Watchdog
  attr_reader :restart_log

  def initialize(process_name:, start_cmd:, wmi:, alerter:, max_restarts:, window_seconds:, clock: -> { Time.now })
    @process_name = process_name
    @start_cmd = start_cmd
    @wmi = wmi
    @alerter = alerter
    @max_restarts = max_restarts
    @window_seconds = window_seconds
    @clock = clock
    @restart_log = [] # timestamps of restarts we've performed
  end

  # Runs one check. Returns a symbol describing what happened, so the CLI
  # loop and the test suite can both assert on outcomes:
  #   :running       - process was already up, nothing done
  #   :restarted     - process was down, we started it
  #   :cooldown      - process was down, but we're over the restart budget
  #                    in the trailing window, so we skipped and alerted
  #   :start_failed  - process was down, we tried to start it, and that failed
  def check
    prune_restart_log

    if @wmi.process_running?(@process_name)
      return :running
    end

    if @restart_log.size >= @max_restarts
      @alerter.notify(
        "#{@process_name} is down and the watchdog hit its restart budget " \
        "(#{@max_restarts} restarts in #{@window_seconds}s) — needs a human."
      )
      return :cooldown
    end

    begin
      pid = @wmi.start_process(@start_cmd)
      @restart_log << @clock.call
      @alerter.notify("#{@process_name} was down; restarted it (pid #{pid}).")
      :restarted
    rescue StandardError => e
      @alerter.notify("#{@process_name} is down and the restart attempt failed: #{e.message}")
      :start_failed
    end
  end

  private

  def prune_restart_log
    cutoff = @clock.call - @window_seconds
    @restart_log.reject! { |t| t < cutoff }
  end
end

def parse_options(argv)
  opts = OpenStruct.new(interval: 15, max_restarts: 5, window: 600, once: false, webhook: nil)

  parser = OptionParser.new do |o|
    o.banner = 'Usage: wmi_process_watchdog.rb --process NAME --start-cmd "CMD" [options]'
    o.on('--process NAME', 'Exact image name to watch, e.g. worker.exe') { |v| opts.process = v }
    o.on('--start-cmd CMD', 'Command line used to relaunch the process') { |v| opts.start_cmd = v }
    o.on('--interval SECONDS', Integer, 'Seconds between checks (default 15)') { |v| opts.interval = v }
    o.on('--max-restarts N', Integer, 'Max restarts allowed per window before giving up (default 5)') { |v| opts.max_restarts = v }
    o.on('--window SECONDS', Integer, 'Rolling window for the restart budget, seconds (default 600)') { |v| opts.window = v }
    o.on('--webhook URL', 'POST a JSON alert here on restart/cooldown/failure') { |v| opts.webhook = v }
    o.on('--once', 'Do a single check-and-restart pass, then exit') { opts.once = true }
    o.on('-h', '--help', 'Show this help') { puts o; exit 0 }
  end
  parser.parse!(argv)
  opts
end

if __FILE__ == $PROGRAM_NAME
  opts = parse_options(ARGV)

  if opts.process.nil? || opts.start_cmd.nil?
    warn 'Both --process and --start-cmd are required. See --help.'
    exit 2
  end

  watchdog = Watchdog.new(
    process_name: opts.process,
    start_cmd: opts.start_cmd,
    wmi: WmiBackend.new,
    alerter: WebhookAlerter.new(opts.webhook),
    max_restarts: opts.max_restarts,
    window_seconds: opts.window
  )

  loop do
    outcome = watchdog.check
    puts "#{Time.now.iso8601}  #{opts.process}  #{outcome}"
    break if opts.once

    sleep opts.interval
  end
end
