#!/usr/bin/env ruby
# frozen_string_literal: true
#
# mem_pressure_monitor.rb -- Memory & swap pressure monitor for Linux.
#
# `free -h` tells you a number. It does not tell you whether that number is
# actually a problem right now. A box can sit at 90% memory "used" forever
# because the kernel is using the rest for page cache -- totally fine. The
# thing that actually predicts an OOM kill or a latency cliff is: is memory
# genuinely SCARCE (MemAvailable, which already accounts for reclaimable
# cache), is the box actively swapping, is the kernel scheduler stalling
# tasks waiting on memory (PSI), and has the OOM killer already fired.
# This script pulls all four signals into one WARN/CRIT report so it can
# drop into cron or an alerting pipeline instead of a human staring at `free`.
#
# No gems required -- everything here is Ruby stdlib.
#
# Usage:
#   ruby mem_pressure_monitor.rb [options]
#
# Examples:
#   ruby mem_pressure_monitor.rb
#   ruby mem_pressure_monitor.rb --json
#   ruby mem_pressure_monitor.rb --mem-warn 20 --mem-crit 8 --swap-crit 80
#
# Exit codes (cron/CI friendly):
#   0 - OK
#   1 - WARN (memory or swap pressure building)
#   2 - CRIT (memory critically low, heavy swapping, PSI saturated, or a
#       recent OOM kill was found)

require 'optparse'
require 'json'
require 'open3'

options = {
  mem_warn_pct: 15,   # WARN if MemAvailable < 15% of MemTotal
  mem_crit_pct: 5,    # CRIT if MemAvailable < 5%
  swap_warn_pct: 50,  # WARN if swap used > 50% of SwapTotal
  swap_crit_pct: 90,  # CRIT if swap used > 90%
  psi_warn: 10.0,     # WARN if PSI "some avg60" > 10%
  psi_crit: 30.0,     # CRIT if PSI "some avg60" > 30%
  oom_lookback_min: 60,
  json: false,
  meminfo_path: '/proc/meminfo',
  psi_path: '/proc/pressure/memory'
}

OptionParser.new do |opts|
  opts.banner = 'Usage: mem_pressure_monitor.rb [options]'
  opts.on('--mem-warn PCT', Float, 'MemAvailable %% WARN threshold (default 15)') { |v| options[:mem_warn_pct] = v }
  opts.on('--mem-crit PCT', Float, 'MemAvailable %% CRIT threshold (default 5)') { |v| options[:mem_crit_pct] = v }
  opts.on('--swap-warn PCT', Float, 'Swap-used %% WARN threshold (default 50)') { |v| options[:swap_warn_pct] = v }
  opts.on('--swap-crit PCT', Float, 'Swap-used %% CRIT threshold (default 90)') { |v| options[:swap_crit_pct] = v }
  opts.on('--psi-warn PCT', Float, 'PSI "some avg60" %% WARN threshold (default 10)') { |v| options[:psi_warn] = v }
  opts.on('--psi-crit PCT', Float, 'PSI "some avg60" %% CRIT threshold (default 30)') { |v| options[:psi_crit] = v }
  opts.on('--oom-lookback MIN', Integer, 'Minutes of journal/dmesg history to scan for OOM kills (default 60)') { |v| options[:oom_lookback_min] = v }
  opts.on('--meminfo-path PATH', String, 'Path to meminfo file (default /proc/meminfo; useful in containers with /host/proc mounted, and for testing)') { |v| options[:meminfo_path] = v }
  opts.on('--psi-path PATH', String, 'Path to PSI memory file (default /proc/pressure/memory)') { |v| options[:psi_path] = v }
  opts.on('--json', 'Emit machine-readable JSON instead of text') { options[:json] = true }
  opts.on('-h', '--help', 'Show this help') { puts opts; exit 0 }
end.parse!

SEVERITY_RANK = { ok: 0, warn: 1, crit: 2, unknown: 0 }.freeze

def worse(a, b)
  SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b
end

# ---------------------------------------------------------------------------
# /proc/meminfo
# ---------------------------------------------------------------------------

def read_meminfo(path = '/proc/meminfo')
  fields = {}
  File.foreach(path) do |line|
    # Lines look like: "MemTotal:        4009408 kB"
    if line =~ /^(\w+):\s+(\d+)(?:\s+(\w+))?/
      fields[Regexp.last_match(1)] = Regexp.last_match(2).to_i
    end
  end
  fields
end

def analyze_memory(meminfo, warn_pct, crit_pct)
  total = meminfo['MemTotal'].to_f
  available = meminfo['MemAvailable'].to_f
  return { status: :unknown, error: 'MemTotal missing from /proc/meminfo' } if total.zero?

  available_pct = (available / total * 100).round(1)
  status =
    if available_pct <= crit_pct
      :crit
    elsif available_pct <= warn_pct
      :warn
    else
      :ok
    end

  {
    status: status,
    total_mb: (total / 1024).round,
    available_mb: (available / 1024).round,
    available_pct: available_pct,
    used_pct: (100 - available_pct).round(1)
  }
end

def analyze_swap(meminfo, warn_pct, crit_pct)
  total = meminfo['SwapTotal'].to_f
  free = meminfo['SwapFree'].to_f

  return { status: :ok, total_mb: 0, used_mb: 0, used_pct: 0.0, note: 'no swap configured' } if total.zero?

  used = total - free
  used_pct = (used / total * 100).round(1)
  status =
    if used_pct >= crit_pct
      :crit
    elsif used_pct >= warn_pct
      :warn
    else
      :ok
    end

  { status: status, total_mb: (total / 1024).round, used_mb: (used / 1024).round, used_pct: used_pct }
end

# ---------------------------------------------------------------------------
# /proc/pressure/memory (PSI -- Pressure Stall Information, Linux 4.20+)
# ---------------------------------------------------------------------------

def read_psi(path = '/proc/pressure/memory')
  return nil unless File.readable?(path)

  lines = File.read(path)
  parsed = {}
  lines.each_line do |line|
    kind = line[/^(some|full)/, 1]
    next unless kind

    values = {}
    line.scan(/(\w+)=([\d.]+)/) { |k, v| values[k] = v.to_f }
    parsed[kind] = values
  end
  parsed
rescue Errno::ENOENT, Errno::EACCES
  nil
end

def analyze_psi(psi, warn_pct, crit_pct)
  return { status: :unknown, note: 'PSI not available on this kernel/cgroup (needs Linux 4.20+, CONFIG_PSI=y)' } if psi.nil? || psi.empty?

  some_avg60 = psi.dig('some', 'avg60') || 0.0
  status =
    if some_avg60 >= crit_pct
      :crit
    elsif some_avg60 >= warn_pct
      :warn
    else
      :ok
    end

  { status: status, some_avg10: psi.dig('some', 'avg10'), some_avg60: some_avg60, some_avg300: psi.dig('some', 'avg300') }
end

# ---------------------------------------------------------------------------
# OOM killer detection -- try journalctl first, fall back to dmesg. Both can
# legitimately be unavailable (no systemd, no CAP_SYSLOG) -- that's reported
# as :unknown, not treated as a hard failure.
# ---------------------------------------------------------------------------

def scan_for_oom(lookback_min)
  patterns = [/Out of memory/i, /oom[-_ ]kill/i, /Killed process/i]

  out, status = try_journalctl(lookback_min)
  source = 'journalctl'
  if status.nil? || !status.success?
    out, status = try_dmesg
    source = 'dmesg'
  end

  return { status: :unknown, note: 'neither journalctl nor dmesg were readable in this environment (needs root/CAP_SYSLOG)' } if status.nil? || !status.success?

  hits = out.lines.select { |l| patterns.any? { |p| l =~ p } }
  { status: hits.empty? ? :ok : :crit, source: source, oom_events_found: hits.size, sample: hits.first(3).map(&:strip) }
end

def try_journalctl(lookback_min)
  # capture3 so journalctl's permission-hint noise on stderr doesn't leak
  # onto our stdout report -- we only care whether it actually worked.
  out, _err, status = Open3.capture3('journalctl', '-k', "--since=-#{lookback_min}min", '--no-pager', '-q')
  [out, status]
rescue Errno::ENOENT, Errno::EACCES
  [nil, nil]
end

def try_dmesg
  out, _err, status = Open3.capture3('dmesg')
  [out, status]
rescue Errno::ENOENT, Errno::EACCES
  [nil, nil]
end

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

meminfo = read_meminfo(options[:meminfo_path])
mem = analyze_memory(meminfo, options[:mem_warn_pct], options[:mem_crit_pct])
swap = analyze_swap(meminfo, options[:swap_warn_pct], options[:swap_crit_pct])
psi = analyze_psi(read_psi(options[:psi_path]), options[:psi_warn], options[:psi_crit])
oom = scan_for_oom(options[:oom_lookback_min])

overall = [mem[:status], swap[:status], psi[:status], oom[:status]].reduce(:ok) { |acc, s| worse(acc, s || :ok) }
exit_code = { ok: 0, unknown: 0, warn: 1, crit: 2 }[overall]

if options[:json]
  puts JSON.pretty_generate(memory: mem, swap: swap, psi: psi, oom: oom, overall: overall, exit_code: exit_code)
else
  fmt = ->(s) { s.to_s.upcase.rjust(5) }
  puts "mem-pressure-monitor: #{Time.now}"
  puts
  puts "[#{fmt.call(mem[:status])}] memory available: #{mem[:available_mb]} MB / #{mem[:total_mb]} MB (#{mem[:available_pct]}% free, #{mem[:used_pct]}% used)"
  if swap[:total_mb].zero?
    puts "[#{fmt.call(swap[:status])}] swap: not configured"
  else
    puts "[#{fmt.call(swap[:status])}] swap used: #{swap[:used_mb]} MB / #{swap[:total_mb]} MB (#{swap[:used_pct]}%)"
  end
  if psi[:status] == :unknown
    puts "[UNKWN] PSI: #{psi[:note]}"
  else
    puts "[#{fmt.call(psi[:status])}] PSI memory pressure: some avg10=#{psi[:some_avg10]} avg60=#{psi[:some_avg60]} avg300=#{psi[:some_avg300]}"
  end
  if oom[:status] == :unknown
    puts "[UNKWN] OOM scan: #{oom[:note]}"
  elsif oom[:status] == :crit
    puts "[ CRIT] OOM scan (#{oom[:source]}): #{oom[:oom_events_found]} event(s) in last #{options[:oom_lookback_min]}m"
    oom[:sample].each { |l| puts "        #{l}" }
  else
    puts "[   OK] OOM scan (#{oom[:source]}): no OOM-kill events in last #{options[:oom_lookback_min]}m"
  end
  puts
  puts "Overall: #{overall.to_s.upcase}"
end

exit exit_code
