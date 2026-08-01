#!/usr/bin/env ruby
# frozen_string_literal: true
#
# powershell_bridge.rb
#
# A reusable Ruby "bridge" for driving Windows administration through
# PowerShell, without writing whole scripts in PowerShell itself.
#
# WHY THIS EXISTS
# ----------------
# A lot of Windows admin surface (services, WMI/CIM classes, the event log,
# local users/groups) is only cleanly reachable from PowerShell -- Ruby on
# Windows doesn't have a first-class WMI/registry story the way PowerShell
# does. But PowerShell is a clumsy language for the *orchestration* layer:
# retries, timeouts, JSON reshaping, gluing several admin steps together,
# writing cron/Task-Scheduler-friendly CLIs with proper exit codes. Ruby is
# much nicer at that.
#
# So: shell out to `powershell.exe`, ask it to serialize structured cmdlet
# output with `ConvertTo-Json`, parse that JSON back into plain Ruby
# objects, and wrap the whole thing in the timeout/retry/error-handling
# PowerShell doesn't give you for free.
#
# STDLIB ONLY. No gems. Requires Ruby on Windows with `powershell.exe`
# (Windows PowerShell 5.1) or `pwsh.exe` (PowerShell 7+) on PATH.
#
# CAVEAT (read the README before relying on this in production): the
# PowerShell-calling code paths in this file have NOT been exercised
# against a real Windows host in this repo's CI -- only the parsing,
# retry, timeout, and CLI logic have been verified, using a stub that
# fakes Open3 with canned ConvertTo-Json-shaped output. See
# powershell_bridge_test.rb and the README's Troubleshooting section.

require 'open3'
require 'json'
require 'optparse'
require 'timeout'

# ---------------------------------------------------------------------------
# PowerShellBridge
#
# Thin wrapper around Open3 that knows how to:
#   - invoke powershell.exe/pwsh.exe non-interactively
#   - append `| ConvertTo-Json -Depth N` to "structured" queries
#   - enforce a timeout, killing the child process if it hangs
#   - retry transient failures with exponential backoff
#   - parse the resulting JSON into Ruby (Hash/Array), handling the
#     single-object-vs-array quirk of ConvertTo-Json
# ---------------------------------------------------------------------------
class PowerShellBridge
  # Raised when the PowerShell process could not be run at all, exited
  # non-zero after retries were exhausted, or timed out on every attempt.
  class CommandError < StandardError
    attr_reader :stderr, :exit_code

    def initialize(message, stderr: nil, exit_code: nil)
      super(message)
      @stderr = stderr
      @exit_code = exit_code
    end
  end

  # Raised specifically when every retry attempt hit the timeout.
  class TimeoutError < CommandError; end

  DEFAULT_TIMEOUT   = 30   # seconds, per attempt
  DEFAULT_RETRIES   = 2    # retry attempts *after* the first try
  DEFAULT_BACKOFF   = 1.0  # seconds, doubled on each retry
  DEFAULT_JSON_DEPTH = 4

  # executable: 'powershell.exe' (Windows PowerShell 5.1, ships with every
  # modern Windows box) or 'pwsh.exe' (PowerShell 7+, install separately).
  # shell_runner: dependency-injection seam for tests -- anything that
  # responds to #capture3(*cmd) the way Open3 does. Defaults to Open3
  # itself so production code needs zero changes.
  def initialize(executable: 'powershell.exe',
                 timeout: DEFAULT_TIMEOUT,
                 retries: DEFAULT_RETRIES,
                 backoff: DEFAULT_BACKOFF,
                 json_depth: DEFAULT_JSON_DEPTH,
                 shell_runner: Open3,
                 logger: nil)
    @executable  = executable
    @timeout     = timeout
    @retries     = retries
    @backoff     = backoff
    @json_depth  = json_depth
    @shell_runner = shell_runner
    @logger      = logger
  end

  # Run a PowerShell command that is expected to emit structured objects,
  # append ConvertTo-Json, and parse the result back into Ruby.
  #
  # Returns:
  #   - an Array of Hashes for multi-object results
  #   - a single Hash for a single-object result
  #   - [] for empty/no output (ConvertTo-Json emits nothing for $null)
  #
  # PowerShell's ConvertTo-Json collapses a one-item pipeline into a bare
  # JSON object instead of a one-element array -- callers who always want
  # an Array should use #run_json_array instead.
  def run_json(cmdlet, depth: @json_depth)
    full_command = "#{cmdlet} | ConvertTo-Json -Depth #{depth} -Compress"
    raw = run_raw(full_command)
    parse_json(raw)
  end

  # Same as #run_json but always normalizes the result to an Array,
  # which is what most CLI reporting code wants.
  def run_json_array(cmdlet, depth: @json_depth)
    result = run_json(cmdlet, depth: depth)
    case result
    when Array then result
    when nil then []
    else [result]
    end
  end

  # Run an arbitrary PowerShell command and return raw stdout (String),
  # with retry-with-backoff and a per-attempt timeout. Does NOT append
  # ConvertTo-Json -- use this for commands like Restart-Service that
  # don't return structured data we care about.
  def run_raw(command)
    attempt = 0
    delay = @backoff

    begin
      attempt += 1
      log(:debug, "attempt #{attempt}/#{@retries + 1}: #{command}")
      execute_with_timeout(command)
    rescue Timeout::Error => e
      if attempt <= @retries
        log(:warn, "timed out after #{@timeout}s, retrying in #{delay}s (#{e.message})")
        sleep(delay)
        delay *= 2
        retry
      end
      raise TimeoutError, "powershell command timed out after #{attempt} attempt(s): #{command}"
    rescue CommandError => e
      if attempt <= @retries && transient?(e)
        log(:warn, "command failed (#{e.message}), retrying in #{delay}s")
        sleep(delay)
        delay *= 2
        retry
      end
      raise
    end
  end

  private

  # Treat non-zero exit as retryable unless it smells like a permanent
  # problem (bad syntax, cmdlet not found, access denied) -- those won't
  # be fixed by trying again. Everything else (transient WMI/RPC hiccups,
  # "server too busy", timeouts inside PowerShell itself) is retried.
  def transient?(error)
    permanent_markers = [
      'is not recognized as the name of a cmdlet',
      'ParserError',
      'Access is denied',
      'AuthorizationManager check failed',
    ]
    permanent_markers.none? { |marker| error.stderr.to_s.include?(marker) }
  end

  def execute_with_timeout(command)
    args = build_args(command)

    stdout = +''
    stderr = +''
    status = nil

    Timeout.timeout(@timeout, Timeout::Error) do
      stdout, stderr, status = @shell_runner.capture3(*args)
    end

    unless status && status.success?
      raise CommandError.new(
        "powershell exited #{status && status.exitstatus} for: #{command}",
        stderr: stderr,
        exit_code: status && status.exitstatus
      )
    end

    stdout
  rescue Timeout::Error
    # NOTE: Open3.capture3 blocks until the child exits; Ruby's Timeout
    # module raises inside this thread but cannot itself kill the
    # grandchild powershell.exe process. In production, pair this with
    # Open3.popen3 + Process.kill(pid) if you need a hard kill of a wedged
    # powershell.exe -- see README "Extending" section. The stub test
    # harness simulates the killed-process case explicitly.
    raise
  end

  def build_args(command)
    [
      @executable,
      '-NoProfile',       # don't load user PS profile scripts (speed + determinism)
      '-NonInteractive',  # never prompt, fail fast instead
      '-ExecutionPolicy', 'Bypass',
      '-Command', command
    ]
  end

  # ConvertTo-Json quirks we defend against:
  #   - empty pipeline => empty string from PowerShell => nil in Ruby
  #   - single object   => bare JSON object (not wrapped in an array)
  #   - BOM / trailing whitespace some PS builds emit
  def parse_json(raw)
    text = raw.to_s.strip
    return nil if text.empty?

    text = text.sub(/\A\xEF\xBB\xBF/, '') # strip UTF-8 BOM if present
    begin
      JSON.parse(text)
    rescue JSON::ParserError => e
      raise CommandError, "could not parse PowerShell JSON output: #{e.message}\nraw: #{text[0, 300]}"
    end
  end

  def log(level, message)
    return unless @logger

    @logger.call(level, message)
  end
end

# ---------------------------------------------------------------------------
# Small Ruby-side domain helpers built on top of PowerShellBridge. Each
# returns plain Ruby data (Array<Hash>) so the CLI layer below can render
# it as text or JSON identically.
# ---------------------------------------------------------------------------
module AdminTasks
  module_function

  # Get-Service status for one service, or all services if name is nil.
  def service_status(bridge, name: nil)
    cmdlet = name ? "Get-Service -Name #{quote(name)}" : 'Get-Service'
    bridge.run_json_array(cmdlet)
  end

  # Restart-Service -- not "structured" output, so we just run it and
  # report success/failure, then re-query status to confirm.
  def restart_service(bridge, name:)
    bridge.run_raw("Restart-Service -Name #{quote(name)} -Force -ErrorAction Stop")
    service_status(bridge, name: name).first
  end

  # Get-CimInstance Win32_LogicalDisk free-space report for fixed drives
  # (DriveType 3). Adds a computed PercentFree since PowerShell won't.
  def disk_report(bridge)
    cmdlet = 'Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" ' \
             '| Select-Object DeviceID, VolumeName, Size, FreeSpace'
    disks = bridge.run_json_array(cmdlet)
    disks.map do |d|
      size = d['Size'].to_i
      free = d['FreeSpace'].to_i
      pct_free = size.positive? ? ((free.to_f / size) * 100).round(1) : 0.0
      {
        'DeviceID'   => d['DeviceID'],
        'VolumeName' => d['VolumeName'],
        'SizeGB'     => gb(size),
        'FreeGB'     => gb(free),
        'PercentFree' => pct_free
      }
    end
  end

  # Recent error/critical events from a given log (default: System).
  # Level 1 = Critical, 2 = Error in the Windows event schema.
  def recent_critical_events(bridge, log_name: 'System', max_events: 20, hours: 24)
    start_time = "(Get-Date).AddHours(-#{hours})"
    filter = "@{LogName='#{ps_escape(log_name)}';Level=1,2;StartTime=#{start_time}}"
    cmdlet = "Get-WinEvent -FilterHashtable #{filter} -MaxEvents #{max_events} -ErrorAction Stop " \
             '| Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message'
    bridge.run_json_array(cmdlet)
  rescue PowerShellBridge::CommandError => e
    # Get-WinEvent throws (not just warns) when zero events match the
    # filter -- that's a normal "all clear" outcome, not a real failure.
    return [] if e.stderr.to_s.include?('No events were found')

    raise
  end

  def gb(bytes)
    (bytes.to_f / (1024**3)).round(2)
  end

  def quote(value)
    "'#{ps_escape(value)}'"
  end

  def ps_escape(value)
    value.to_s.gsub("'", "''")
  end
end

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
class CLI
  EXIT_OK = 0
  EXIT_GENERAL_ERROR = 1
  EXIT_BRIDGE_ERROR = 2
  EXIT_USAGE = 64

  def initialize(argv, bridge_factory: ->(opts) { PowerShellBridge.new(**opts) }, stdout: $stdout, stderr: $stderr)
    @argv = argv
    @bridge_factory = bridge_factory
    @stdout = stdout
    @stderr = stderr
    @options = {
      json: false,
      timeout: PowerShellBridge::DEFAULT_TIMEOUT,
      retries: PowerShellBridge::DEFAULT_RETRIES,
      log_name: 'System',
      hours: 24,
      max_events: 20
    }
  end

  def run
    command = parse!
    bridge = @bridge_factory.call(timeout: @options[:timeout], retries: @options[:retries])

    case command
    when 'service-status'
      cmd_service_status(bridge)
    when 'service-restart'
      cmd_service_restart(bridge)
    when 'disk-report'
      cmd_disk_report(bridge)
    when 'events'
      cmd_events(bridge)
    else
      @stderr.puts "unknown command: #{command.inspect}"
      EXIT_USAGE
    end
  rescue PowerShellBridge::TimeoutError => e
    @stderr.puts "TIMEOUT: #{e.message}"
    EXIT_BRIDGE_ERROR
  rescue PowerShellBridge::CommandError => e
    @stderr.puts "ERROR: #{e.message}"
    @stderr.puts "stderr: #{e.stderr}" if e.stderr && !e.stderr.strip.empty?
    EXIT_BRIDGE_ERROR
  rescue OptionParser::ParseError => e
    @stderr.puts "usage error: #{e.message}"
    EXIT_USAGE
  end

  private

  def parse!
    command = @argv.shift
    parser = OptionParser.new do |o|
      o.banner = 'Usage: powershell_bridge.rb COMMAND [options]'
      o.separator ''
      o.separator 'Commands: service-status, service-restart, disk-report, events'
      o.separator ''
      o.on('--name NAME', 'Service name (service-status / service-restart)') { |v| @options[:name] = v }
      o.on('--log-name NAME', "Event log name for 'events' (default: System)") { |v| @options[:log_name] = v }
      o.on('--hours N', Integer, "Look back N hours for 'events' (default: 24)") { |v| @options[:hours] = v }
      o.on('--max-events N', Integer, 'Max events to return (default: 20)') { |v| @options[:max_events] = v }
      o.on('--timeout N', Integer, "Per-attempt timeout in seconds (default: #{PowerShellBridge::DEFAULT_TIMEOUT})") { |v| @options[:timeout] = v }
      o.on('--retries N', Integer, "Retry attempts after first try (default: #{PowerShellBridge::DEFAULT_RETRIES})") { |v| @options[:retries] = v }
      o.on('--json', 'Emit machine-readable JSON instead of text') { @options[:json] = true }
      o.on('-h', '--help', 'Show this help') { @stdout.puts o; exit(EXIT_OK) }
    end
    parser.parse!(@argv)
    command
  end

  def cmd_service_status(bridge)
    result = AdminTasks.service_status(bridge, name: @options[:name])
    if result.empty?
      emit(result) { @stdout.puts 'no matching services found' }
    else
      emit(result) { render_services(result) }
    end
    EXIT_OK
  end

  def cmd_service_restart(bridge)
    unless @options[:name]
      @stderr.puts 'service-restart requires --name SERVICE_NAME'
      return EXIT_USAGE
    end

    result = AdminTasks.restart_service(bridge, name: @options[:name])
    ok = result && result['Status'] == 'Running'
    emit(result) do
      if ok
        @stdout.puts "OK  #{result['Name']} is Running"
      else
        @stdout.puts "WARN  #{@options[:name]} status: #{result && result['Status'] || 'unknown'}"
      end
    end
    ok ? EXIT_OK : EXIT_GENERAL_ERROR
  end

  def cmd_disk_report(bridge)
    result = AdminTasks.disk_report(bridge)
    low = result.select { |d| d['PercentFree'] < 10.0 }
    emit(result) { render_disks(result) }
    low.empty? ? EXIT_OK : EXIT_GENERAL_ERROR
  end

  def cmd_events(bridge)
    result = AdminTasks.recent_critical_events(
      bridge,
      log_name: @options[:log_name],
      max_events: @options[:max_events],
      hours: @options[:hours]
    )
    emit(result) { render_events(result) }
    result.empty? ? EXIT_OK : EXIT_GENERAL_ERROR
  end

  # Shared "emit either JSON or the block's text rendering" helper. Always
  # returns whatever the caller returns as the process exit code, JSON mode
  # just replaces the human text with a JSON dump of the same data.
  def emit(data)
    if @options[:json]
      @stdout.puts JSON.pretty_generate(data)
    else
      yield
    end
  end

  def render_services(services)
    services.each do |s|
      @stdout.printf("%-25s %-10s %s\n", s['Name'], s['Status'], s['DisplayName'])
    end
  end

  def render_disks(disks)
    disks.each do |d|
      flag = d['PercentFree'] < 10.0 ? '[LOW]' : '     '
      @stdout.printf("%s %-4s %-20s %8.2f GB free / %8.2f GB total (%.1f%%)\n",
                      flag, d['DeviceID'], d['VolumeName'], d['FreeGB'], d['SizeGB'], d['PercentFree'])
    end
  end

  def render_events(events)
    if events.empty?
      @stdout.puts 'no matching critical/error events in window'
      return
    end
    events.each do |e|
      @stdout.puts "[#{e['TimeCreated']}] #{e['LevelDisplayName']} id=#{e['Id']} src=#{e['ProviderName']}"
      @stdout.puts "    #{e['Message'].to_s.lines.first&.strip}"
    end
  end
end

if $PROGRAM_NAME == __FILE__
  exit(CLI.new(ARGV).run)
end
