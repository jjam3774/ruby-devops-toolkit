#!/usr/bin/env ruby
# frozen_string_literal: true
#
# systemd_watchdog.rb — watch a list of systemd units, classify their health,
# and (optionally) auto-restart failed units with a rate-limited backoff so a
# crash-looping service can't be restarted into oblivion by cron.
#
# Why this exists: `systemctl status` is fine for a human staring at one box,
# but it doesn't give you a machine-readable health check you can drop into
# cron/Nagios/Prometheus textfile collectors, and it doesn't protect you from
# a service that fails, gets restarted, fails again, forever. This script is
# that missing piece: a few hundred lines of pure Ruby stdlib, no gems.
#
# Usage:
#   ruby systemd_watchdog.rb --units nginx,sshd,cron
#   ruby systemd_watchdog.rb --units nginx,sshd --restart --max-restarts 3 --window 600
#   ruby systemd_watchdog.rb --units nginx --json
#
# Exit codes (cron/Nagios-friendly):
#   0 = all units OK
#   1 = at least one unit WARN (activating/reloading/unknown)
#   2 = at least one unit CRIT (failed, or inactive when it should be running)

require 'optparse'
require 'open3'
require 'json'
require 'time'
require 'fileutils'

# ---------------------------------------------------------------------------
# UnitStatus: the result of inspecting a single systemd unit.
# ---------------------------------------------------------------------------
UnitStatus = Struct.new(:name, :active_state, :sub_state, :load_state, :result,
                         :level, :restarted, :message, keyword_init: true) do
  def to_h
    super.reject { |k, _| k == :message } .merge(message: message)
  end
end

# ---------------------------------------------------------------------------
# SystemdWatchdog: queries systemctl, classifies units, and drives restarts.
# ---------------------------------------------------------------------------
class SystemdWatchdog
  # Properties we pull from `systemctl show`. Keeping this list short keeps
  # each subprocess call fast — we only ask for what we actually use.
  PROPERTIES = %w[ActiveState SubState LoadState Result].freeze

  def initialize(units:, restart: false, max_restarts: 3, window: 600,
                 state_file: nil, dry_run: false, logger: $stderr)
    @units = units
    @restart = restart
    @max_restarts = max_restarts
    @window = window # seconds
    @state_file = state_file || default_state_file
    @dry_run = dry_run
    @logger = logger
    @state = load_state
  end

  # Runs the check (and restarts, if enabled) for every configured unit.
  # Returns an array of UnitStatus.
  def run
    @units.map { |unit| check_unit(unit) }
  ensure
    save_state
  end

  private

  # --- inspection ----------------------------------------------------------

  def check_unit(unit)
    props = show_properties(unit)

    if props.empty?
      return UnitStatus.new(name: unit, active_state: 'unknown', sub_state: 'unknown',
                             load_state: 'unknown', result: 'unknown', level: :warn,
                             restarted: false, message: 'systemctl returned no data (unit may not exist)')
    end

    status = classify(unit, props)

    if status.level == :crit && @restart
      status.restarted = attempt_restart(unit)
    end

    status
  end

  # Runs `systemctl show <unit> -p Prop1 -p Prop2 ...` and parses the
  # `Key=Value` lines it prints (one per requested property, in order).
  def show_properties(unit)
    args = ['systemctl', 'show', unit]
    PROPERTIES.each { |p| args += ['-p', p] }

    stdout, stderr, status = Open3.capture3(*args)
    unless status.success?
      log("systemctl show #{unit} failed: #{stderr.strip}")
      return {}
    end

    stdout.each_line.each_with_object({}) do |line, h|
      key, _, value = line.strip.partition('=')
      h[key] = value unless key.empty?
    end
  end

  # Turns the raw ActiveState/SubState/Result into an OK/WARN/CRIT verdict.
  # This is deliberately conservative: anything we don't recognize is WARN,
  # never silently OK, so unexpected systemd output can't hide a problem.
  def classify(unit, props)
    active = props['ActiveState'] || 'unknown'
    sub    = props['SubState'] || 'unknown'
    load_s = props['LoadState'] || 'unknown'
    result = props['Result'] || 'unknown'

    level, message =
      case active
      when 'active'
        [:ok, "#{unit} is active (#{sub})"]
      when 'activating', 'reloading', 'deactivating'
        [:warn, "#{unit} is transitioning (#{active}/#{sub})"]
      when 'failed'
        [:crit, "#{unit} has FAILED (result=#{result})"]
      when 'inactive'
        # `inactive` isn't automatically bad — plenty of oneshot/timer units
        # are supposed to be inactive between runs. We only flag it CRIT if
        # systemd itself recorded a non-success Result for the last run.
        if %w[success start-limit-hit exec-condition].include?(result) && result != 'success'
          [:crit, "#{unit} is inactive with result=#{result}"]
        elsif result == 'success' || result == 'unknown'
          [:ok, "#{unit} is inactive (result=#{result})"]
        else
          [:crit, "#{unit} is inactive with result=#{result}"]
        end
      else
        [:warn, "#{unit} reported unrecognized ActiveState=#{active}"]
      end

    level = :crit if load_s == 'not-found'
    message = "#{unit} unit file not found" if load_s == 'not-found'

    UnitStatus.new(name: unit, active_state: active, sub_state: sub, load_state: load_s,
                    result: result, level: level, restarted: false, message: message)
  end

  # --- restart / rate limiting ---------------------------------------------

  # Restarts a failed unit unless it has already been restarted
  # @max_restarts times within the trailing @window seconds — that guard is
  # what stops this script from turning a crash-looping service into a
  # restart-looping cron job that hammers the box every minute forever.
  def attempt_restart(unit)
    history = (@state[unit] ||= [])
    now = Time.now
    history.reject! { |t| now - Time.parse(t) > @window }

    if history.size >= @max_restarts
      log("#{unit}: hit #{@max_restarts} restarts within #{@window}s, refusing to restart again " \
          '(manual intervention needed)')
      return false
    end

    if @dry_run
      log("[dry-run] would run: systemctl restart #{unit}")
      return false
    end

    log("#{unit}: attempting restart (#{history.size + 1}/#{@max_restarts} in window)")
    _out, err, status = Open3.capture3('systemctl', 'restart', unit)
    if status.success?
      history << now.iso8601
      log("#{unit}: restart succeeded")
      true
    else
      log("#{unit}: restart command failed: #{err.strip}")
      false
    end
  end

  # --- state persistence -----------------------------------------------------

  def default_state_file
    File.join((ENV['TMPDIR'] || '/tmp'), 'systemd_watchdog_state.json')
  end

  def load_state
    return {} unless File.exist?(@state_file)

    JSON.parse(File.read(@state_file))
  rescue JSON::ParserError
    {}
  end

  def save_state
    FileUtils.mkdir_p(File.dirname(@state_file))
    File.write(@state_file, JSON.pretty_generate(@state))
  rescue StandardError => e
    log("could not persist state file #{@state_file}: #{e.message}")
  end

  def log(msg)
    @logger.puts("[systemd_watchdog] #{msg}")
  end
end

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if $PROGRAM_NAME == __FILE__
  options = {
    units: [],
    restart: false,
    max_restarts: 3,
    window: 600,
    json: false,
    dry_run: false,
    state_file: nil
  }

  OptionParser.new do |opts|
    opts.banner = 'Usage: systemd_watchdog.rb --units UNIT1,UNIT2 [options]'

    opts.on('-u', '--units UNITS', 'Comma-separated list of unit names to check') do |v|
      options[:units] = v.split(',').map(&:strip)
    end
    opts.on('-r', '--restart', 'Auto-restart units found in CRIT state') { options[:restart] = true }
    opts.on('--max-restarts N', Integer, 'Max restarts per unit within --window (default 3)') do |v|
      options[:max_restarts] = v
    end
    opts.on('--window SECONDS', Integer, 'Rate-limit window in seconds (default 600)') do |v|
      options[:window] = v
    end
    opts.on('--state-file PATH', 'Where to persist restart history (default /tmp)') do |v|
      options[:state_file] = v
    end
    opts.on('--dry-run', 'Log what would be restarted without doing it') { options[:dry_run] = true }
    opts.on('--json', 'Emit machine-readable JSON instead of text') { options[:json] = true }
    opts.on('-h', '--help', 'Show this help') do
      puts opts
      exit 0
    end
  end.parse!

  if options[:units].empty?
    warn 'error: --units is required, e.g. --units nginx,sshd,cron'
    exit 3
  end

  watchdog = SystemdWatchdog.new(
    units: options[:units],
    restart: options[:restart],
    max_restarts: options[:max_restarts],
    window: options[:window],
    state_file: options[:state_file],
    dry_run: options[:dry_run]
  )

  results = watchdog.run
  worst = results.map(&:level).max_by { |l| { ok: 0, warn: 1, crit: 2 }[l] }

  if options[:json]
    puts JSON.pretty_generate(
      generated_at: Time.now.iso8601,
      overall: worst.to_s,
      units: results.map(&:to_h)
    )
  else
    results.each do |r|
      tag = { ok: 'OK  ', warn: 'WARN', crit: 'CRIT' }[r.level]
      restarted = r.restarted ? ' [restarted]' : ''
      puts "#{tag} #{r.name.ljust(20)} #{r.message}#{restarted}"
    end
    puts "\noverall: #{worst}"
  end

  exit({ ok: 0, warn: 1, crit: 2 }[worst])
end
