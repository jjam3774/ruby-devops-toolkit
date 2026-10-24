#!/usr/bin/env ruby
# frozen_string_literal: true
# thp_memory_audit.rb - report Transparent Huge Pages (THP) settings and usage,
# and flag configurations that commonly hurt databases (Redis, MongoDB, etc.).
# Usage: ruby thp_memory_audit.rb [--root /]   (--root lets tests point at a fake tree)
require 'optparse'

root = '/'
OptionParser.new { |o| o.on('--root DIR', 'filesystem root (default /)') { |v| root = v } }.parse!

# The active value in these files is wrapped in brackets: "always [madvise] never"
def active_mode(path)
  raw = File.read(path).strip
  raw[/\[(\w+)\]/, 1] || raw
rescue Errno::ENOENT
  nil
end

def meminfo(path)
  File.readlines(path).each_with_object({}) do |l, h|
    k, v = l.split(':', 2)
    h[k] = v.to_i # kB for most fields; page counts for HugePages_*
  end
end

thp = File.join(root, 'sys/kernel/mm/transparent_hugepage')
enabled = active_mode(File.join(thp, 'enabled'))
defrag  = active_mode(File.join(thp, 'defrag'))
mi      = meminfo(File.join(root, 'proc/meminfo'))

if enabled.nil?
  puts 'THP not exposed by this kernel (no /sys/kernel/mm/transparent_hugepage).'
  exit 0
end

anon_mb = mi.fetch('AnonHugePages', 0) / 1024.0
total_mb = mi.fetch('MemTotal', 1) / 1024.0
puts format('THP enabled : %s', enabled)
puts format('THP defrag  : %s', defrag || 'n/a')
puts format('AnonHugePages: %.0f MB of %.0f MB (%.1f%%)', anon_mb, total_mb, anon_mb * 100 / total_mb)
puts format('Static HugePages: total=%d free=%d size=%d kB', mi.fetch('HugePages_Total', 0), mi.fetch('HugePages_Free', 0), mi.fetch('Hugepagesize', 0))

findings = []
findings << 'THP is "always": latency spikes from compaction are common on databases; prefer "madvise" or "never".' if enabled == 'always'
findings << 'defrag is "always": allocations can stall while the kernel compacts memory; prefer "madvise" or "defer+madvise".' if defrag == 'always'
if mi.fetch('HugePages_Total', 0).positive? && mi['HugePages_Free'] == mi['HugePages_Total']
  findings << 'Static hugepages are reserved but completely unused: that memory is wasted.'
end

if findings.empty?
  puts 'OK: no THP concerns found.'
else
  findings.each { |f| puts "WARN: #{f}" }
  exit 1
end
