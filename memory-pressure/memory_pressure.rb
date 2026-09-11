#!/usr/bin/env ruby
# frozen_string_literal: true
#
# memory_pressure.rb — Linux memory-pressure and OOM-kill detector in pure Ruby.
#
# What it answers, in one run:
#   1. How much memory is *really* available (MemAvailable, not "free")?
#   2. Is the kernel already stalling tasks on memory (PSI /proc/pressure/memory)?
#   3. Has the OOM killer fired recently, and what did it kill?
#   4. Which processes are eating the RAM right now (top-N by RSS)?
#
# Usage:
#   ruby memory_pressure.rb                 # human-readable report
#   ruby memory_pressure.rb --json          # machine-readable, for cron/alerting
#   ruby memory_pressure.rb --warn 15 --crit 5 --top 8
#   PROC_ROOT=/path/to/fixtures ruby memory_pressure.rb   # test against captured /proc
#
# Exit codes: 0 = OK, 1 = WARN, 2 = CRIT (cron / Nagios friendly)
#
# Stdlib only — no gems.

require 'optparse'
require 'json'
require 'open3'

PROC_ROOT = ENV.fetch('PROC_ROOT', '/proc')

# ---------------------------------------------------------------------------
# 1. /proc/meminfo — the source of truth for "how much RAM is left"
# ---------------------------------------------------------------------------
module MemInfo
  # Returns a Hash of key => kilobytes, e.g. { "MemTotal" => 16297244, ... }
  def self.read(path = File.join(PROC_ROOT, 'meminfo'))
    File.readlines(path).each_with_object({}) do |line, h|
      # Lines look like:  "MemAvailable:   12345678 kB"
      next unless line =~ /\A(\w+(?:\(\w+\))?):\s+(\d+)/
      h[Regexp.last_match(1)] = Regexp.last_match(2).to_i
    end
  end

  def self.summarize(mi)
    total     = mi.fetch('MemTotal')
    # MemAvailable (kernel >= 3.14) already accounts for reclaimable cache.
    # Fall back to free+cached for very old kernels.
    available = mi['MemAvailable'] || (mi.fetch('MemFree', 0) + mi.fetch('Cached', 0))
    swap_total = mi.fetch('SwapTotal', 0)
    swap_free  = mi.fetch('SwapFree', 0)
    {
      total_kb:        total,
      available_kb:    available,
      available_pct:   (available * 100.0 / total).round(1),
      swap_total_kb:   swap_total,
      swap_used_kb:    swap_total - swap_free,
      swap_used_pct:   swap_total.zero? ? 0.0 : ((swap_total - swap_free) * 100.0 / swap_total).round(1),
      dirty_kb:        mi.fetch('Dirty', 0),
      committed_pct:   mi['CommitLimit'] && mi['CommitLimit'] > 0 ? (mi.fetch('Committed_AS', 0) * 100.0 / mi['CommitLimit']).round(1) : nil
    }
  end
end

# ---------------------------------------------------------------------------
# 2. PSI — /proc/pressure/memory (kernel >= 4.20, CONFIG_PSI=y)
#    "some avg10=0.00 avg60=0.00 avg300=0.00 total=0"
#    "full avg10=0.00 avg60=0.00 avg300=0.00 total=0"
#    'some' = % of time at least one task stalled on memory
#    'full' = % of time *all* non-idle tasks stalled (much worse)
# ---------------------------------------------------------------------------
module Psi
  def self.read(path = File.join(PROC_ROOT, 'pressure', 'memory'))
    return nil unless File.exist?(path)
    File.readlines(path).each_with_object({}) do |line, h|
      kind, *fields = line.split
      next unless %w[some full].include?(kind)
      h[kind] = fields.map { |f| k, v = f.split('='); [k, v.to_f] }.to_h
    end
  rescue Errno::EACCES, Errno::ENOENT
    nil
  end
end

# ---------------------------------------------------------------------------
# 3. OOM kills — scrape the kernel ring buffer (dmesg) or a saved kernel log.
#    Canonical line (kernel >= 4.x):
#    "Out of memory: Killed process 12345 (java) total-vm:8123456kB, anon-rss:4123456kB, ..."
# ---------------------------------------------------------------------------
module OomKills
  LINE_RE = /Out of memory: Killed process (\d+) \(([^)]+)\)(?:.*?anon-rss:(\d+)kB)?/

  # Prefer an explicit log file (fixtures / journald export); else run dmesg.
  def self.read(log_path: ENV['OOM_LOG'])
    text =
      if log_path && File.exist?(log_path)
        File.read(log_path)
      else
        dmesg_text
      end
    return { available: false, kills: [] } if text.nil?
    kills = text.each_line.filter_map do |line|
      next unless (m = LINE_RE.match(line))
      ts = line[/\[\s*(\d+\.\d+)\]/, 1] # dmesg uptime stamp, if present
      { pid: m[1].to_i, comm: m[2], anon_rss_kb: m[3]&.to_i, uptime_s: ts&.to_f, raw: line.strip }
    end
    { available: true, kills: kills }
  end

  def self.dmesg_text
    out, status = Open3.capture2e('dmesg', '--kernel', '--notime') rescue [nil, nil]
    # Unprivileged users often get "dmesg: read kernel buffer failed: Operation not permitted"
    return nil unless status&.success?
    out
  rescue Errno::ENOENT
    nil
  end
end

# ---------------------------------------------------------------------------
# 4. Top consumers — walk /proc/[pid]/status for VmRSS (fast; no ps fork)
# ---------------------------------------------------------------------------
module TopRss
  def self.read(limit: 10)
    procs = Dir.glob(File.join(PROC_ROOT, '[0-9]*')).filter_map do |dir|
      status = File.read(File.join(dir, 'status'))
      rss  = status[/^VmRSS:\s+(\d+)/, 1]
      next unless rss # kernel threads have no VmRSS
      name = status[/^Name:\s+(.+)$/, 1]
      oom  = File.read(File.join(dir, 'oom_score')).to_i rescue nil
      { pid: File.basename(dir).to_i, name: name, rss_kb: rss.to_i, oom_score: oom }
    rescue Errno::ENOENT, Errno::EACCES, Errno::ESRCH
      nil # process exited mid-scan, or not ours to read
    end
    procs.sort_by { |p| -p[:rss_kb] }.first(limit)
  end
end

# ---------------------------------------------------------------------------
# Verdict — turn the numbers into OK / WARN / CRIT with reasons
# ---------------------------------------------------------------------------
def evaluate(mem, psi, oom, opts)
  reasons = []
  level = 0
  bump = ->(lvl, msg) { level = [level, lvl].max; reasons << msg }

  if mem[:available_pct] <= opts[:crit]
    bump.(2, "MemAvailable #{mem[:available_pct]}% <= crit #{opts[:crit]}%")
  elsif mem[:available_pct] <= opts[:warn]
    bump.(1, "MemAvailable #{mem[:available_pct]}% <= warn #{opts[:warn]}%")
  end

  bump.(1, "swap #{mem[:swap_used_pct]}% used") if mem[:swap_used_pct] >= opts[:swap_warn]

  if psi
    full10 = psi.dig('full', 'avg10').to_f
    some10 = psi.dig('some', 'avg10').to_f
    bump.(2, "PSI full avg10=#{full10}% (all tasks stalling)") if full10 >= opts[:psi_full_crit]
    bump.(1, "PSI some avg10=#{some10}% (tasks stalling on memory)") if some10 >= opts[:psi_some_warn]
  end

  if oom[:available] && !oom[:kills].empty?
    last = oom[:kills].last
    bump.(2, "OOM killer fired #{oom[:kills].size}x; last victim pid #{last[:pid]} (#{last[:comm]})")
  end

  [level, reasons]
end

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
def human_kb(kb)
  return "#{kb} kB" if kb < 1024
  mb = kb / 1024.0
  return format('%.1f MB', mb) if mb < 1024
  format('%.2f GB', mb / 1024.0)
end

def hostname
  return ENV['HOSTNAME'] if ENV['HOSTNAME']
  require 'socket'
  Socket.gethostname
rescue StandardError, LoadError
  'unknown'
end

def print_text(mem, psi, oom, top, level, reasons)
  label = %w[OK WARN CRIT][level]
  puts "memory_pressure  #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}  host=#{hostname}"
  puts '-' * 72
  puts format('%-14s %s / %s available (%.1f%%)', 'RAM', human_kb(mem[:available_kb]), human_kb(mem[:total_kb]), mem[:available_pct])
  puts format('%-14s %s / %s used (%.1f%%)', 'Swap', human_kb(mem[:swap_used_kb]), human_kb(mem[:swap_total_kb]), mem[:swap_used_pct])
  puts format('%-14s %s dirty pages waiting for writeback', 'Dirty', human_kb(mem[:dirty_kb]))
  puts format('%-14s %s%% of CommitLimit', 'Committed', mem[:committed_pct]) if mem[:committed_pct]
  if psi
    puts format('%-14s some avg10=%.2f avg60=%.2f | full avg10=%.2f avg60=%.2f', 'PSI', psi.dig('some','avg10'), psi.dig('some','avg60'), psi.dig('full','avg10'), psi.dig('full','avg60'))
  else
    puts format('%-14s not available (kernel < 4.20, CONFIG_PSI off, or psi=0)', 'PSI')
  end
  if oom[:available]
    puts format('%-14s %d kill(s) in kernel log', 'OOM', oom[:kills].size)
    oom[:kills].last(3).each { |k| puts "               pid #{k[:pid]} #{k[:comm]} anon-rss=#{k[:anon_rss_kb] ? human_kb(k[:anon_rss_kb]) : '?'}" }
  else
    puts format('%-14s kernel log unreadable (run as root or set OOM_LOG=)', 'OOM')
  end
  puts
  puts format('%-8s %-24s %12s %8s', 'PID', 'NAME', 'RSS', 'OOM_SCR')
  top.each { |p| puts format('%-8d %-24s %12s %8s', p[:pid], p[:name][0, 24], human_kb(p[:rss_kb]), p[:oom_score] || '-') }
  puts
  puts "#{label}: #{reasons.empty? ? 'memory looks healthy' : reasons.join('; ')}"
end

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
opts = { warn: 15.0, crit: 5.0, swap_warn: 50.0, psi_some_warn: 10.0, psi_full_crit: 5.0, top: 10, json: false }
OptionParser.new do |o|
  o.banner = 'Usage: memory_pressure.rb [options]'
  o.on('--warn PCT', Float, 'WARN when MemAvailable %% <= PCT (default 15)') { |v| opts[:warn] = v }
  o.on('--crit PCT', Float, 'CRIT when MemAvailable %% <= PCT (default 5)') { |v| opts[:crit] = v }
  o.on('--swap-warn PCT', Float, 'WARN when swap used %% >= PCT (default 50)') { |v| opts[:swap_warn] = v }
  o.on('--psi-some-warn PCT', Float, 'WARN when PSI some avg10 >= PCT (default 10)') { |v| opts[:psi_some_warn] = v }
  o.on('--psi-full-crit PCT', Float, 'CRIT when PSI full avg10 >= PCT (default 5)') { |v| opts[:psi_full_crit] = v }
  o.on('--top N', Integer, 'Show top N processes by RSS (default 10)') { |v| opts[:top] = v }
  o.on('--json', 'Emit JSON instead of text') { opts[:json] = true }
end.parse!

mem  = MemInfo.summarize(MemInfo.read)
psi  = Psi.read
oom  = OomKills.read
top  = TopRss.read(limit: opts[:top])
level, reasons = evaluate(mem, psi, oom, opts)

if opts[:json]
  puts JSON.pretty_generate(status: %w[OK WARN CRIT][level], reasons: reasons, memory: mem, psi: psi, oom: oom, top: top)
else
  print_text(mem, psi, oom, top, level, reasons)
end
exit level
