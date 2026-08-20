#!/usr/bin/env ruby
# frozen_string_literal: true
#
# test_defender_status_audit.rb — stub tests for the Defender audit rules.
# Get-MpComputerStatus only exists on Windows, so this feeds the normalizer +
# rule engine realistic Get-MpComputerStatus JSON fixtures (including the
# WCF "/Date(ms)/" timestamp format PowerShell emits) and asserts each rule
# fires where expected. Runs on any OS: ruby test_defender_status_audit.rb

require_relative 'defender_status_audit'

$fail = 0
def assert(label, cond)
  puts format('  %-62s %s', label, cond ? 'PASS' : 'FAIL')
  $fail += 1 unless cond
end

NOW = Time.utc(2026, 8, 20, 12, 0, 0)
def ms(t) = "/Date(#{(t.to_f * 1000).to_i})/"

# A healthy host: everything on, fresh signatures, recent scan.
healthy = {
  'RealTimeProtectionEnabled' => true, 'AntivirusEnabled' => true,
  'AMServiceEnabled' => true, 'BehaviorMonitorEnabled' => true,
  'IsTamperProtected' => true,
  'AntivirusSignatureLastUpdated' => ms(NOW - 1 * 86_400),
  'FullScanEndTime' => ms(NOW - 3 * 86_400),
  'AntivirusSignatureVersion' => '1.415.99.0'
}

# A degraded host: RTP off, tamper off, signatures 10 days stale, scan 30 days old.
degraded = healthy.merge(
  'RealTimeProtectionEnabled' => false,
  'IsTamperProtected' => false,
  'AntivirusSignatureLastUpdated' => ms(NOW - 10 * 86_400),
  'FullScanEndTime' => ms(NOW - 30 * 86_400)
)

puts 'normalize():'
h = DefenderStatusAudit.normalize(healthy, now: NOW)
assert 'parses /Date(ms)/ signature age to 1 day', h[:sig_age_days] == 1
assert 'real_time boolean true', h[:real_time] == true
assert 'handles ISO date too',
       DefenderStatusAudit.age_in_days('2026-08-13T12:00:00Z', NOW) == 7
assert 'string "false" is falsey', DefenderStatusAudit.truthy('false') == false

puts 'audit() — healthy host:'
fh = DefenderStatusAudit.audit(DefenderStatusAudit.normalize(healthy, now: NOW),
                               warn_age: 3, crit_age: 7, scan_age: 14)
assert 'healthy host has zero findings', fh.empty?
assert 'healthy host exit 0', DefenderStatusAudit.exit_code(fh) == 0

puts 'audit() — degraded host:'
fd = DefenderStatusAudit.audit(DefenderStatusAudit.normalize(degraded, now: NOW),
                               warn_age: 3, crit_age: 7, scan_age: 14)
rules = fd.map(&:rule)
assert 'CRIT realtime-protection-off',      rules.include?('realtime-protection-off')
assert 'CRIT signatures-critically-stale (10>=7)', rules.include?('signatures-critically-stale')
assert 'WARN tamper-protection-off',        rules.include?('tamper-protection-off')
assert 'INFO full-scan-overdue (30>=14)',   rules.include?('full-scan-overdue')
assert 'degraded host exit 2 (has CRIT)',   DefenderStatusAudit.exit_code(fd) == 2

puts 'signature age boundary:'
warnish = healthy.merge('AntivirusSignatureLastUpdated' => ms(NOW - 4 * 86_400))
fw = DefenderStatusAudit.audit(DefenderStatusAudit.normalize(warnish, now: NOW),
                               warn_age: 3, crit_age: 7, scan_age: 14)
assert '4-day sigs -> WARN not CRIT',
       fw.any? { |x| x.rule == 'signatures-stale' } &&
       fw.none? { |x| x.rule == 'signatures-critically-stale' }

puts
puts $fail.zero? ? 'all assertions passed' : "#{$fail} FAILED"
exit($fail.zero? ? 0 : 1)
