#!/usr/bin/env ruby
# frozen_string_literal: true
#
# test_package_drift_audit.rb — unit tests for the diff logic, no real package DB.
# Runs on any OS: ruby test_package_drift_audit.rb

require_relative 'package_drift_audit'

$fail = 0
def assert(label, cond)
  puts format('  %-64s %s', label, cond ? 'PASS' : 'FAIL')
  $fail += 1 unless cond
end

installed = PackageDriftAudit.parse_dpkg(<<~DPKG)
  nginx 1.18.0-6ubuntu14
  openssl 3.0.2-0ubuntu1.15
  curl 7.81.0-1ubuntu1.15
  netcat-openbsd 1.218-4ubuntu1
DPKG

manifest = PackageDriftAudit.parse_manifest(<<~MAN)
  # web tier baseline
  nginx 1.18.0-6ubuntu14
  openssl 3.0.2-0ubuntu1.15
  curl 7.79.0-1        # pinned to an older version -> VERSION drift
  fail2ban            # required but absent -> MISSING (no version pinned)
MAN

puts 'parsing:'
assert 'dpkg parse yields 4 packages', installed.size == 4
assert 'manifest parse strips comments/inline-comments to 4 entries', manifest.size == 4
assert 'unpinned manifest entry has nil version', manifest['fail2ban'].nil?

f = PackageDriftAudit.diff(installed: installed, manifest: manifest)
by = ->(s) { f.select { |x| x[:status] == s }.map { |x| x[:name] }.sort }

puts 'diff rules:'
assert 'OK: nginx + openssl match', by.call('OK') == %w[nginx openssl]
assert 'VERSION: curl pinned-mismatch', by.call('VERSION') == %w[curl]
assert 'MISSING: fail2ban absent', by.call('MISSING') == %w[fail2ban]
assert 'UNEXPECTED: netcat-openbsd not in manifest', by.call('UNEXPECTED') == %w[netcat-openbsd]

puts 'exit codes:'
assert 'UNEXPECTED present -> exit 2', PackageDriftAudit.exit_code(f) == 2
clean = PackageDriftAudit.diff(installed: { 'a' => '1' }, manifest: { 'a' => '1' })
assert 'no drift -> exit 0', PackageDriftAudit.exit_code(clean) == 0
missing_only = PackageDriftAudit.diff(installed: {}, manifest: { 'a' => '1' })
assert 'missing only -> exit 1', PackageDriftAudit.exit_code(missing_only) == 1

puts 'presence-only mode:'
f2 = PackageDriftAudit.diff(installed: installed, manifest: manifest, check_versions: false)
assert 'curl no longer VERSION drift when --no-versions', f2.none? { |x| x[:status] == 'VERSION' }

puts
puts $fail.zero? ? 'all assertions passed' : "#{$fail} FAILED"
exit($fail.zero? ? 0 : 1)
