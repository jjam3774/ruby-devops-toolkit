# Mock harness: exercises evaluate() with canned WMI-shaped data (no win32ole needed).
require_relative 'win_eventlog_size_audit'
MB = 1_048_576
data = [
  { name: 'Security',    max_bytes: 20 * MB,  file_bytes: 5 * MB,   overwrite_policy: 'WhenNeeded' },
  { name: 'System',      max_bytes: 128 * MB, file_bytes: 120 * MB, overwrite_policy: 'WhenNeeded' },
  { name: 'Application', max_bytes: 256 * MB, file_bytes: 10 * MB,  overwrite_policy: 'Never' },
  { name: 'Setup',       max_bytes: 256 * MB, file_bytes: 1 * MB,   overwrite_policy: 'WhenNeeded' }
]
puts format('%-22s %8s %7s  %s', 'LOG', 'MAX(MB)', 'FULL', 'STATUS')
res = data.map { |e| evaluate(e, min_mb: 64, full_pct: 90.0) }
res.each { |r| puts format('%-22s %8d %6.1f%%  %s', r[:name], r[:max_mb], r[:pct], r[:issues].empty? ? 'OK' : r[:issues].join('; ')) }
raise 'Security should flag' unless res[0][:issues].size == 1
raise 'System should flag' unless res[1][:issues].size == 1
raise 'Application should flag' unless res[2][:issues].size == 1
raise 'Setup should be OK' unless res[3][:issues].empty?
puts 'ALL ASSERTIONS PASSED'
