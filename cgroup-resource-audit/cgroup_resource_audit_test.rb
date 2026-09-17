#!/usr/bin/env ruby
# frozen_string_literal: true
#
# cgroup_resource_audit_test.rb -- builds a synthetic cgroup v2 tree covering
# every rule in the auditor, then asserts the expected finding codes fire.
#
# Real /sys/fs/cgroup on a healthy box is boring on purpose: nothing is at its
# limit, nothing has been OOM-killed. That is exactly why the interesting code
# paths need a fixture. Because CgroupReader only ever reads plain files, a
# directory of ordinary text files under /tmp is indistinguishable from the
# real thing as far as the auditor is concerned.
#
#   ruby cgroup_resource_audit_test.rb

require 'fileutils'
require 'tmpdir'
require 'json'

SCRIPT = File.join(__dir__, 'cgroup_resource_audit.rb')

# Each fixture is a unit name => hash of control-file contents.
FIXTURES = {
  # Healthy: well under a real limit, no events. Should produce nothing.
  'api-healthy.service' => {
    'cgroup.controllers' => "cpu memory pids\n",
    'cgroup.procs' => "1001\n1002\n",
    'memory.current' => "268435456\n",             # 256M
    'memory.max' => "1073741824\n",                # 1G  -> 25%
    'memory.high' => "max\n",
    'memory.events' => "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n",
    'pids.current' => "12\n",
    'pids.max' => "512\n",
    'cpu.max' => "max 100000\n",
    'cpu.stat' => "usage_usec 500000\nthrottled_usec 0\nnr_throttled 0\n",
    'memory.pressure' => "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n" \
                         "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"
  },

  # Has been OOM-killed and is pinned at its cap -> critical x2.
  'importer.service' => {
    'cgroup.controllers' => "cpu memory pids\n",
    'cgroup.procs' => "2001\n",
    'memory.current' => "1020000000\n",
    'memory.max' => "1073741824\n",                # ~95%
    'memory.high' => "max\n",
    'memory.events' => "low 0\nhigh 0\nmax 412\noom 7\noom_kill 7\n",
    'pids.current' => "4\n",
    'pids.max' => "512\n",
    'cpu.max' => "max 100000\n",
    'cpu.stat' => "usage_usec 90000000\nthrottled_usec 0\nnr_throttled 0\n",
    'memory.pressure' => "some avg10=41.00 avg60=38.20 avg300=30.00 total=9911\n" \
                         "full avg10=22.00 avg60=18.40 avg300=12.00 total=4410\n"
  },

  # Tight CPUQuota -> heavy throttling.
  'renderer.service' => {
    'cgroup.controllers' => "cpu memory pids\n",
    'cgroup.procs' => "3001\n3002\n3003\n",
    'memory.current' => "134217728\n",
    'memory.max' => "536870912\n",                 # 25%
    'memory.high' => "max\n",
    'memory.events' => "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n",
    'pids.current' => "20\n",
    'pids.max' => "512\n",
    'cpu.max' => "10000 100000\n",                 # 10% of one core
    'cpu.stat' => "usage_usec 60000000\nthrottled_usec 25000000\nnr_throttled 8123\n",
    'memory.pressure' => "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n" \
                         "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"
  },

  # Thread leak marching toward TasksMax.
  'worker-pool.service' => {
    'cgroup.controllers' => "cpu memory pids\n",
    'cgroup.procs' => "4001\n",
    'memory.current' => "201326592\n",
    'memory.max' => "1073741824\n",
    'memory.high' => "805306368\n",
    'memory.events' => "low 0\nhigh 96\nmax 0\noom 0\noom_kill 0\n",
    'pids.current' => "463\n",
    'pids.max' => "512\n",                         # ~90%
    'cpu.max' => "max 100000\n",
    'cpu.stat' => "usage_usec 12000000\nthrottled_usec 400000\nnr_throttled 31\n",
    'memory.pressure' => "some avg10=6.00 avg60=4.10 avg300=2.00 total=812\n" \
                         "full avg10=3.90 avg60=3.10 avg300=1.00 total=411\n"
  },

  # No limits at all and holding a large slice of host RAM.
  'search-index.service' => {
    'cgroup.controllers' => "memory pids\n",       # cpu NOT delegated
    'cgroup.procs' => "5001\n",
    'memory.current' => "2500000000\n",            # ~62% of a 4G host
    'memory.max' => "max\n",
    'memory.high' => "max\n",
    'memory.events' => "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n",
    'pids.current' => "37\n",
    'pids.max' => "max\n",
    'cpu.stat' => "usage_usec 800000000\n",
    'memory.pressure' => "some avg10=0.10 avg60=0.05 avg300=0.00 total=90\n" \
                         "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"
  },

  # Stopped unit: empty procs, zero memory. Must be skipped entirely.
  'oneshot-stale.service' => {
    'cgroup.controllers' => "cpu memory pids\n",
    'cgroup.procs' => "",
    'memory.current' => "0\n",
    'memory.max' => "max\n",
    'memory.events' => "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n",
    'pids.current' => "0\n",
    'pids.max' => "max\n",
    'cpu.stat' => "usage_usec 0\n"
  }
}.freeze

EXPECTED = {
  'api-healthy.service'    => [],
  'importer.service'       => %w[OOM_KILLED MEM_AT_LIMIT MEM_PRESSURE],
  'renderer.service'       => %w[CPU_THROTTLED],
  'worker-pool.service'    => %w[PIDS_AT_LIMIT MEM_HIGH_THROTTLED MEM_PRESSURE_MILD CPU_THROTTLED_MILD],
  'search-index.service'   => %w[MEM_UNBOUNDED CPU_CTRL_MISSING],
  'oneshot-stale.service'  => :absent
}.freeze

def build_tree(root)
  # Root marker files: this is what CgroupReader#unified? looks for.
  File.write(File.join(root, 'cgroup.controllers'), "cpu io memory pids\n")
  slice = File.join(root, 'system.slice')
  FileUtils.mkdir_p(slice)
  File.write(File.join(slice, 'cgroup.controllers'), "cpu io memory pids\n")

  FIXTURES.each do |unit, files|
    dir = File.join(slice, unit)
    FileUtils.mkdir_p(dir)
    files.each { |name, body| File.write(File.join(dir, name), body) }
  end
  root
end

failures = []
def check(failures, label)
  ok = yield
  puts format('  %-58s %s', label, ok ? 'PASS' : 'FAIL')
  failures << label unless ok
end

Dir.mktmpdir('cgfix') do |root|
  build_tree(root)
  puts "fixture tree: #{root}"
  puts

  json_out = `ruby #{SCRIPT} --root #{root} --json 2>&1`
  status   = $?.exitstatus
  begin
    data = JSON.parse(json_out)
  rescue JSON::ParserError
    puts 'FATAL: script did not emit valid JSON:'
    puts json_out
    exit 1
  end

  by_unit = data['findings'].group_by { |f| f['unit'] }

  puts 'per-unit expectations'
  EXPECTED.each do |unit, expected|
    if expected == :absent
      check(failures, "#{unit} skipped as inactive") do
        data['units'].none? { |u| u['unit'] == unit }
      end
      next
    end

    got = (by_unit[unit] || []).map { |f| f['code'] }.sort
    check(failures, "#{unit} -> #{expected.empty? ? '(clean)' : expected.sort.join(',')}") do
      got == expected.sort
    end
  end

  puts
  puts 'parsing and reporting behaviour'
  importer = data['units'].find { |u| u['unit'] == 'importer.service' }
  check(failures, 'memory percentage computed from current/max') do
    (importer['memory_pct'] - 95.0).abs < 0.5
  end
  check(failures, '"max" sentinel parsed as no-limit (nil), not 0') do
    idx = data['units'].find { |u| u['unit'] == 'search-index.service' }
    idx['memory_max'].nil? && idx['pids_max'].nil?
  end
  check(failures, 'cpu.max "10000 100000" read as a 10% quota') do
    r = data['units'].find { |u| u['unit'] == 'renderer.service' }
    (r['cpu_quota_pct'] - 10.0).abs < 0.01
  end
  check(failures, 'throttle share = throttled/(usage+throttled)') do
    r = data['units'].find { |u| u['unit'] == 'renderer.service' }
    (r['cpu_throttle_pct'] - 29.4).abs < 0.2
  end
  check(failures, 'PSI "full avg60" extracted from memory.pressure') do
    importer['memory_pressure_full_avg60'] == 18.4
  end
  check(failures, 'missing cpu.stat fields degrade to nil, not a crash') do
    idx = data['units'].find { |u| u['unit'] == 'search-index.service' }
    idx['cpu_throttle_pct'].nil?
  end
  check(failures, 'exit code 2 when a critical finding exists') { status == 2 }

  puts
  puts 'severity filtering'
  high_only = JSON.parse(`ruby #{SCRIPT} --root #{root} --json --min-severity high 2>&1`)
  check(failures, '--min-severity high drops medium and low findings') do
    high_only['findings'].map { |f| f['severity'] }.uniq.sort == %w[critical high]
  end
  clean = JSON.parse(`ruby #{SCRIPT} --root #{root} --json --slice nonexistent.slice 2>&1`)
  check(failures, 'missing slice yields zero units, exit 0') do
    clean['units'].empty? && $?.exitstatus.zero?
  end

  puts
  puts 'text renderer'
  text = `ruby #{SCRIPT} --root #{root} 2>&1`
  check(failures, 'text table lists every active unit') do
    FIXTURES.keys.reject { |k| k == 'oneshot-stale.service' }.all? { |u| text.include?(u[0, 30]) }
  end
  check(failures, 'unbounded limits render as "unset", never "0.0B"') do
    text.match?(/search-index.service\s+2\.3G\s+unset/)
  end
end

puts
if failures.empty?
  puts "ALL CHECKS PASSED (#{EXPECTED.size} units, every rule exercised)"
  exit 0
else
  puts "#{failures.length} FAILURE(S):"
  failures.each { |f| puts "  - #{f}" }
  exit 1
end
