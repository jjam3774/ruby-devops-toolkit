#!/usr/bin/env ruby
# frozen_string_literal: true
# kernel_hw_error_report.rb - classify hardware-related kernel log errors
# (MCE, EDAC memory, disk I/O, filesystem, PCIe AER, NVMe) from dmesg/journalctl.
# Usage: kernel_hw_error_report.rb [--file FILE] [--json]
# Exit: 0 clean, 1 warnings, 2 critical.
require 'optparse'
require 'json'
require 'open3'

RULES = [
  { cls: 'memory',     sev: 'CRIT', re: /Machine Check|mce:.*(Hardware Error|Uncorrected)|EDAC.*UE\b/i, advice: 'Uncorrected memory/CPU error: schedule hardware replacement.' },
  { cls: 'memory',     sev: 'WARN', re: /EDAC.*\bCE\b/,                                 advice: 'Corrected ECC errors: watch the rate; replace DIMM if climbing.' },
  { cls: 'disk',       sev: 'CRIT', re: /Buffer I\/O error|blk_update_request: I\/O error|medium error/i, advice: 'Block I/O failure: run smartctl and check cabling.' },
  { cls: 'disk',       sev: 'WARN', re: /ata\d+(\.\d+)?: (exception|hard resetting|failed command)/i,   advice: 'ATA link trouble: reseat/replace SATA cable.' },
  { cls: 'filesystem', sev: 'CRIT', re: /(EXT4|XFS|BTRFS).*(error|corruption)|Remounting filesystem read-only/i, advice: 'Filesystem error: schedule fsck/xfs_repair.' },
  { cls: 'pcie',       sev: 'WARN', re: /AER:.*(error|Corrected)|PCIe Bus Error/i,                      advice: 'PCIe AER events: reseat card or update firmware.' },
  { cls: 'nvme',       sev: 'WARN', re: /nvme\d+:.*(timeout|reset|I\/O error)/i,                        advice: 'NVMe timeouts: check firmware and nvme smart-log.' }
].freeze

Finding = Struct.new(:cls, :sev, :advice, :count, :sample)

def classify(lines)
  found = {}
  lines.each do |line|
    RULES.each do |r|
      next unless line =~ r[:re]
      key = [r[:cls], r[:sev]]
      f = (found[key] ||= Finding.new(r[:cls], r[:sev], r[:advice], 0, line.strip))
      f.count += 1
      break # first (most severe) matching rule wins per line
    end
  end
  found.values.sort_by { |f| [f.sev == 'CRIT' ? 0 : 1, f.cls] }
end

def read_log(file)
  return File.readlines(file, chomp: true) if file
  [%w[dmesg --ctime], %w[journalctl -k -b --no-pager]].each do |cmd|
    out, _e, st = Open3.capture3(*cmd)
    return out.lines if st.success? && !out.empty?
  rescue Errno::ENOENT
    next
  end
  warn 'no readable kernel log (try root, or --file)'
  exit 3
end

if $PROGRAM_NAME == __FILE__
  opts = {}
  OptionParser.new { |o| o.on('--file F') { |v| opts[:file] = v }; o.on('--json') { opts[:json] = true } }.parse!
  findings = classify(read_log(opts[:file]))
  if opts[:json]
    puts JSON.pretty_generate(findings.map(&:to_h))
  elsif findings.empty?
    puts 'OK: no hardware errors in kernel log'
  else
    findings.each { |f| puts format('[%-4s] %-10s x%-3d %s', f.sev, f.cls, f.count, f.advice); puts "       e.g. #{f.sample[0, 110]}" }
  end
  exit(findings.any? { |f| f.sev == 'CRIT' } ? 2 : (findings.any? ? 1 : 0))
end
