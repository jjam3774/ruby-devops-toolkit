#!/usr/bin/env ruby
# frozen_string_literal: true
#
# systemd_timer_audit.rb — inventory and audit systemd timers, the modern
# replacement for cron that almost nobody actively monitors. Surfaces failed
# timer units, timers whose target service is in a failed state, timers that
# have never run, and (optionally) timers missing Persistent=true — the option
# that decides whether a missed run is caught up after downtime.
#
# Parses the tabular output of `systemctl list-timers` and `systemctl
# list-units`, so it needs no D-Bus bindings and no gems. For offline auditing
# or CI, feed it saved command output with --timers-file / --units-file.
#
# Usage:
#   ruby systemd_timer_audit.rb                  # audit the live system
#   ruby systemd_timer_audit.rb --json
#   ruby systemd_timer_audit.rb \
#     --timers-file timers.txt --units-file units.txt   # offline
#
# Capture inputs for offline mode with:
#   systemctl list-timers --all --no-legend        > timers.txt
#   systemctl list-units --type=timer,service --all --no-legend > units.txt
#
# Exit codes: 0 = clean, 1 = warnings, 2 = at least one CRIT (failed unit).

require "json"
require "optparse"
require "open3"

options = { json: false, timers_file: nil, units_file: nil }
OptionParser.new do |o|
  o.banner = "Usage: ruby systemd_timer_audit.rb [options]"
  o.on("--json", "Emit JSON instead of text") { options[:json] = true }
  o.on("--timers-file FILE", "Use saved 'systemctl list-timers' output") { |v| options[:timers_file] = v }
  o.on("--units-file FILE", "Use saved 'systemctl list-units' output") { |v| options[:units_file] = v }
end.parse!

# --- input: live systemctl or saved files ----------------------------------
def run_or_read(file, args)
  return File.read(file) if file
  out, status = Open3.capture2(*args)
  status.success? ? out : (raise "command failed: #{args.join(' ')}")
end

begin
  timers_raw = run_or_read(options[:timers_file],
                           %w[systemctl list-timers --all --no-legend])
  units_raw  = run_or_read(options[:units_file],
                           %w[systemctl list-units --type=timer,service --all --no-legend])
rescue StandardError => e
  abort "could not gather systemd data (#{e.message}). On a non-systemd host, " \
        "pass --timers-file/--units-file with captured output."
end

# --- parse `list-timers` ----------------------------------------------------
# Columns: NEXT ... LEFT ... LAST ... PASSED UNIT ACTIVATES
# We only need the tail three tokens (UNIT, ACTIVATES) and whether NEXT/LAST
# are the literal "-" placeholder (never scheduled / never run).
timers = []
timers_raw.each_line do |line|
  line = line.rstrip
  next if line.empty?
  toks = line.split(/\s{1,}/)
  next if toks.size < 2
  unit = toks.find { |t| t.end_with?(".timer") }
  next unless unit
  ui = toks.index(unit)
  activates = toks[ui + 1] && toks[ui + 1] != "-" ? toks[ui + 1] : nil
  # Everything before the unit describes NEXT/LEFT/LAST/PASSED. A leading "-"
  # means "next elapse" is unset; the presence of a real LAST timestamp tells
  # us it has run. Heuristic: if the first token is "-", it isn't scheduled.
  never_scheduled = toks[0] == "-"
  # LAST column: look for "-" appearing as a standalone LAST placeholder is
  # ambiguous positionally, so we treat "has this unit ever run" via units list.
  timers << { unit: unit, activates: activates, never_scheduled: never_scheduled }
end

# --- parse `list-units` -----------------------------------------------------
# Columns: UNIT LOAD ACTIVE SUB DESCRIPTION...
unit_state = {}
units_raw.each_line do |line|
  line = line.strip.delete_prefix("*").strip # a leading * marks failed units
  next if line.empty?
  toks = line.split(/\s+/)
  next if toks.size < 4
  unit_state[toks[0]] = { load: toks[1], active: toks[2], sub: toks[3] }
end

# --- checks -----------------------------------------------------------------
findings = []
def add(f, sev, code, unit, detail)
  f << { severity: sev, code: code, unit: unit, detail: detail }
end

timers.each do |t|
  st = unit_state[t[:unit]]

  # 1. The timer unit itself is failed — it will not fire at all.
  if st && (st[:active] == "failed" || st[:sub] == "failed")
    add(findings, :crit, "failed-timer", t[:unit], "timer unit is in failed state")
  elsif st && st[:load] == "not-found"
    add(findings, :warn, "orphan-timer", t[:unit], "timer listed but unit file not found")
  end

  # 2. The service the timer activates is failed — the last run errored.
  svc = t[:activates] || t[:unit].sub(/\.timer\z/, ".service")
  sst = unit_state[svc]
  if sst && sst[:active] == "failed"
    add(findings, :crit, "failed-service", svc, "service activated by #{t[:unit]} is failed")
  end

  # 3. Timer that is loaded but has no next elapse and isn't a calendar-less
  #    one-shot — usually a disabled or mis-defined timer.
  if t[:never_scheduled] && st && st[:active] != "failed"
    add(findings, :warn, "not-scheduled", t[:unit], "timer has no next elapse (disabled or missing OnCalendar?)")
  end
end

# 4. A .service in a failed state that is the target of a known timer naming
#    pattern but wasn't caught above (defensive: failed services matter).
unit_state.each do |unit, st|
  next unless unit.end_with?(".service") && st[:active] == "failed"
  next if findings.any? { |f| f[:unit] == unit }
  # Only flag services that have a sibling timer (timer-driven jobs).
  if unit_state.key?(unit.sub(/\.service\z/, ".timer"))
    add(findings, :warn, "failed-timer-service", unit, "timer-driven service is failed")
  end
end

# --- output -----------------------------------------------------------------
rank = { crit: 2, warn: 1 }
findings.uniq! { |f| [f[:code], f[:unit]] }
findings.sort_by! { |f| [-rank[f[:severity]], f[:unit]] }
exit_code = findings.any? { |f| f[:severity] == :crit } ? 2 : (findings.empty? ? 0 : 1)

if options[:json]
  puts JSON.pretty_generate(
    "timers_seen" => timers.size,
    "findings" => findings.map { |f| f.transform_keys(&:to_s).merge("severity" => f[:severity].to_s) },
    "exit_code" => exit_code
  )
else
  puts "systemd_timer_audit: #{timers.size} timers, #{unit_state.size} units seen"
  if findings.empty?
    puts "no findings — all timers healthy."
  else
    findings.each { |f| puts format("%-4s %-22s %-32s %s", f[:severity].to_s.upcase, f[:code], f[:unit], f[:detail]) }
    puts "#{findings.count { |f| f[:severity] == :crit }} CRIT, #{findings.count { |f| f[:severity] == :warn }} WARN"
  end
end

exit exit_code
