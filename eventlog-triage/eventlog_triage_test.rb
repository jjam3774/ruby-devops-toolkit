#!/usr/bin/env ruby
# frozen_string_literal: true
#
# eventlog_triage_test.rb — stub test harness for the Triage class.
#
# WMI (win32ole) only exists on Windows, so this harness feeds the Triage
# class realistic Win32_NTLogEvent fixtures as plain hashes — exactly the
# shape EventSource#events_since produces — and asserts the classifications.
# Runs on any OS: ruby eventlog_triage_test.rb

require_relative 'eventlog_triage'

FIXTURES = [
  # unexpected shutdown
  { 'log' => 'System', 'code' => 6008, 'time' => '20260824T031502',
    'source' => 'EventLog', 'message' => 'The previous system shutdown was unexpected.', 'strings' => [] },
  # service crash x2 (Spooler)
  { 'log' => 'System', 'code' => 7034, 'time' => '20260824T031604',
    'source' => 'Service Control Manager', 'message' => 'The Print Spooler service terminated unexpectedly.',
    'strings' => ['Print Spooler', '1'] },
  { 'log' => 'System', 'code' => 7034, 'time' => '20260824T041604',
    'source' => 'Service Control Manager', 'message' => 'The Print Spooler service terminated unexpectedly.',
    'strings' => ['Print Spooler', '2'] },
  # new service installed
  { 'log' => 'System', 'code' => 7045, 'time' => '20260824T100000',
    'source' => 'Service Control Manager', 'message' => 'A service was installed in the system.',
    'strings' => ['UpdaterSvc', '%SystemRoot%\\Temp\\updater.exe', 'user mode service', 'auto start', 'LocalSystem'] },
  # planned restart
  { 'log' => 'System', 'code' => 1074, 'time' => '20260824T110000',
    'source' => 'User32', 'message' => 'The process msiexec.exe has initiated a restart.',
    'strings' => ['msiexec.exe', 'HOST01', 'Operating System: Service pack', '0x80020010', 'restart', '', 'HOST01\\svc_deploy'] },
  # 6 failed logons for Administrator (>= default threshold 5 -> CRIT)
  *6.times.map do |i|
    { 'log' => 'Security', 'code' => 4625, 'time' => "20260824T12000#{i}",
      'source' => 'Microsoft-Windows-Security-Auditing',
      'message' => 'An account failed to log on. Account Name: Administrator',
      'strings' => ['S-1-0-0', '-', '-', '0x0', 'S-1-0-0', 'Administrator', 'HOST01', '0xC000006D'] }
  end,
  # 1 failed logon for jsmith (below threshold -> WARN)
  { 'log' => 'Security', 'code' => 4625, 'time' => '20260824T121500',
    'source' => 'Microsoft-Windows-Security-Auditing',
    'message' => 'An account failed to log on. Account Name: jsmith',
    'strings' => ['S-1-0-0', '-', '-', '0x0', 'S-1-0-0', 'jsmith', 'HOST01', '0xC000006A'] },
  # account lockout
  { 'log' => 'Security', 'code' => 4740, 'time' => '20260824T121600',
    'source' => 'Microsoft-Windows-Security-Auditing',
    'message' => 'A user account was locked out.', 'strings' => ['svc_backup', 'HOST01'] }
].freeze

findings = Triage.new(logon_threshold: 5).run(FIXTURES)

puts "stub harness: #{FIXTURES.size} fixture events -> #{findings.size} findings"
findings.each { |sev, msg| puts format('  [%-4s] %s', sev, msg) }
puts

# ---- assertions -----------------------------------------------------------
fails = 0
def assert(desc, cond, fails)
  if cond
    puts "  PASS  #{desc}"
    fails
  else
    puts "  FAIL  #{desc}"
    fails + 1
  end
end

sevs = findings.map(&:first)
msgs = findings.map(&:last)

fails = assert('6008 classified CRIT',            msgs.any? { |m| m.include?('unexpected shutdown') }, fails)
fails = assert('4740 lockout names svc_backup',   msgs.any? { |m| m.include?("lockout: svc_backup") }, fails)
fails = assert('Administrator spray is CRIT',     findings.any? { |s, m| s == 'CRIT' if m.include?("'Administrator'") }, fails)
fails = assert('jsmith single failure is WARN',   findings.any? { |s, m| s == 'WARN' if m.include?("'jsmith'") }, fails)
fails = assert('7034 spooler crash reported x2',  msgs.count { |m| m.include?('Print Spooler') } == 2, fails)
fails = assert('7045 new service flagged',        msgs.any? { |m| m.include?('UpdaterSvc') }, fails)
fails = assert('1074 restart is INFO',            findings.any? { |s, m| s == 'INFO' if m.include?('msiexec') || m.include?('svc_deploy') }, fails)
fails = assert('CRIT findings sort first',        sevs.first == 'CRIT', fails)

puts
if fails.zero?
  puts "ALL #{8} ASSERTIONS PASSED"
  exit 0
else
  puts "#{fails} ASSERTION(S) FAILED"
  exit 1
end
