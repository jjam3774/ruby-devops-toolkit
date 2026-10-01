#!/usr/bin/env ruby
# frozen_string_literal: true
# cpu_saturation_monitor.rb - tell "busy" from "starved" using /proc/stat deltas,
# load average per core and (when available) kernel PSI. Stdlib only.
#
#   ruby cpu_saturation_monitor.rb [--interval 2] [--json]
#   ruby cpu_saturation_monitor.rb --stat-a a.txt --stat-b b.txt [--loadavg f] [--psi f]
# Exit: 0 OK, 1 WARN, 2 CRIT
require 'optparse'
require 'json'
require 'etc'

FIELDS = %i[user nice system idle iowait irq softirq steal].freeze
THRESH = { iowait: [10.0, 25.0], steal: [5.0, 15.0], busy: [85.0, 95.0], load_per_core: [1.0, 2.0] }.freeze

# First "cpu " line of /proc/stat -> hash of jiffies per state
def parse_stat(text)
  line = text.lines.find { |l| l.start_with?('cpu ') } or raise 'no aggregate cpu line'
  FIELDS.zip(line.split[1..8].map(&:to_i)).to_h
end

# Percent of elapsed jiffies spent in each state between two samples
def percentages(a, b)
  delta = FIELDS.to_h { |f| [f, b[f] - a[f]] }
  total = delta.values.sum
  raise 'no CPU time elapsed between samples' if total <= 0
  pct = delta.transform_values { |v| (v * 100.0 / total).round(1) }
  pct[:busy] = (100.0 - pct[:idle] - pct[:iowait]).round(1)
  pct
end

def level(metric, value)
  warn_at, crit_at = THRESH.fetch(metric)
  return 2 if value >= crit_at
  value >= warn_at ? 1 : 0
end

def psi_cpu(text)
  return nil unless text
  some = text.lines.find { |l| l.start_with?('some') } or return nil
  some[/avg10=([\d.]+)/, 1].to_f
end

def evaluate(pct, load1, cores, psi)
  checks = {
    busy:          [pct[:busy], level(:busy, pct[:busy])],
    iowait:        [pct[:iowait], level(:iowait, pct[:iowait])],
    steal:         [pct[:steal], level(:steal, pct[:steal])],
    load_per_core: [(load1 / cores).round(2), level(:load_per_core, load1 / cores)]
  }
  checks[:psi_some_avg10] = [psi, psi >= 40 ? 2 : (psi >= 10 ? 1 : 0)] if psi
  checks
end

HINT = {
  iowait: 'CPUs are waiting on disk/NFS - look at iostat, not at the CPU',
  steal: 'hypervisor is taking cycles - noisy neighbour or oversold host',
  busy: 'genuinely CPU-bound - find the hot process (top / pidstat)',
  load_per_core: 'more runnable tasks than cores',
  psi_some_avg10: 'tasks are stalling waiting for CPU time'
}.freeze

if $PROGRAM_NAME == __FILE__
  o = { interval: 2.0, json: false }
  OptionParser.new do |op|
    op.on('--interval N', Float) { |v| o[:interval] = v }
    op.on('--json') { o[:json] = true }
    op.on('--stat-a F') { |v| o[:a] = v }
    op.on('--stat-b F') { |v| o[:b] = v }
    op.on('--loadavg F') { |v| o[:load] = v }
    op.on('--psi F') { |v| o[:psi] = v }
    op.on('--cores N', Integer) { |v| o[:cores] = v }
  end.parse!
  if o[:a]
    a = parse_stat(File.read(o[:a]))
    b = parse_stat(File.read(o[:b]))
  else
    a = parse_stat(File.read('/proc/stat'))
    sleep o[:interval]
    b = parse_stat(File.read('/proc/stat'))
  end
  pct = percentages(a, b)
  load1 = File.read(o[:load] || '/proc/loadavg').split[0].to_f
  cores = o[:cores] || Etc.nprocessors
  psi_path = o[:psi] || '/proc/pressure/cpu'
  psi = psi_cpu(File.exist?(psi_path) ? File.read(psi_path) : nil)
  checks = evaluate(pct, load1, cores, psi)
  worst = checks.values.map(&:last).max
  if o[:json]
    puts JSON.pretty_generate(status: %w[OK WARN CRIT][worst], cores: cores, percent: pct, checks: checks)
  else
    puts format('CPU saturation (%d cores, load1 %.2f)', cores, load1)
    checks.each do |name, (val, lvl)|
      puts format('  %-4s %-15s %6.2f  %s', %w[OK WARN CRIT][lvl], name, val, lvl.zero? ? '' : HINT[name])
    end
    puts "RESULT: #{%w[OK WARN CRIT][worst]}"
  end
  exit worst
end
