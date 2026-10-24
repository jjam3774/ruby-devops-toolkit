#!/usr/bin/env ruby
# frozen_string_literal: true
# win_eventlog_size_audit.rb - audit Windows Event Log size and retention via WMI
# (Win32_NTEventlogFile). Flags logs that are too small, nearly full, or set to
# never overwrite (which stops logging when full).
# Requires: Windows, Ruby 3.x (win32ole is bundled with RubyInstaller). Run elevated.
# Usage: ruby win_eventlog_size_audit.rb [--min-mb 64] [--full-pct 90]
require 'optparse'

MIN_MB_DEFAULT = 64

# Pure logic, kept separate from WMI so it can be unit-tested on any OS.
# entry: { name:, max_bytes:, file_bytes:, overwrite_policy:, overwrite_outdated: }
def evaluate(entry, min_mb:, full_pct:)
  issues = []
  max_mb = entry[:max_bytes] / 1_048_576.0
  pct = entry[:max_bytes].zero? ? 0 : entry[:file_bytes] * 100.0 / entry[:max_bytes]
  issues << format('max size %.0f MB < %d MB (history is lost quickly)', max_mb, min_mb) if max_mb < min_mb
  issues << format('%.0f%% full', pct) if pct >= full_pct
  # WMI: OverWritePolicy is "WhenNeeded", "OutDated" or "Never"
  issues << 'overwrite policy is Never: logging stops when the log fills' if entry[:overwrite_policy] == 'Never'
  { name: entry[:name], max_mb: max_mb.round, pct: pct.round(1), issues: issues }
end

def wmi_entries(computer)
  require 'win32ole'
  wmi = WIN32OLE.connect("winmgmts:\\\\#{computer}\\root\\cimv2")
  wmi.ExecQuery('SELECT * FROM Win32_NTEventlogFile').each.map do |f|
    { name: f.LogfileName, max_bytes: f.MaxFileSize.to_i, file_bytes: f.FileSize.to_i,
      overwrite_policy: f.OverWritePolicy.to_s }
  end
end

if $PROGRAM_NAME == __FILE__
  opts = { min_mb: MIN_MB_DEFAULT, full_pct: 90.0, computer: '.' }
  OptionParser.new do |o|
    o.on('--min-mb N', Integer) { |v| opts[:min_mb] = v }
    o.on('--full-pct N', Float) { |v| opts[:full_pct] = v }
    o.on('--computer NAME') { |v| opts[:computer] = v }
  end.parse!
  results = wmi_entries(opts[:computer]).map { |e| evaluate(e, min_mb: opts[:min_mb], full_pct: opts[:full_pct]) }
  puts format('%-22s %8s %7s  %s', 'LOG', 'MAX(MB)', 'FULL', 'STATUS')
  results.each do |r|
    puts format('%-22s %8d %6.1f%%  %s', r[:name], r[:max_mb], r[:pct], r[:issues].empty? ? 'OK' : r[:issues].join('; '))
  end
  exit(results.any? { |r| r[:issues].any? } ? 1 : 0)
end
