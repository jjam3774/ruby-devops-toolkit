#!/usr/bin/env ruby
# frozen_string_literal: true
#
# bitlocker_compliance_audit_test.rb
#
# A stub/mock test harness for bitlocker_compliance_audit.rb. Win32_EncryptableVolume
# and WMI only exist on Windows, so this harness fakes the connector so the
# real compliance policy in BitLockerAuditor can be verified on any
# platform, including this Linux sandbox. This does NOT test the real
# WmiVolumeConnector class -- that class is a thin wrapper around a WMI
# query and two COM method calls, and is documented as untested-on-Linux in
# the tutorial itself.
#
# Run with: ruby bitlocker_compliance_audit_test.rb

require_relative 'bitlocker_compliance_audit'

# A trivial stand-in for WmiVolumeConnector: just hands back whatever
# volume hashes were configured, in the same shape the real connector
# would produce from Win32_EncryptableVolume.
class FakeVolumeConnector
  def initialize(volumes)
    @volumes = volumes
  end

  def volumes
    @volumes
  end
end

$failures = 0
$passes = 0

def check(description)
  result = yield
  if result
    $passes += 1
    puts "  PASS  #{description}"
  else
    $failures += 1
    puts "  FAIL  #{description}"
  end
end

puts 'Test 1: fully encrypted, protected, with recovery password -> compliant'
fake = FakeVolumeConnector.new([
  { drive_letter: 'C:', protection_status: 1, conversion_status: 1, encryption_method: 4, key_protector_types: [1, 3] }
])
auditor = BitLockerAuditor.new(connector: fake)
result = auditor.audit.first
check('compliant is true') { result.compliant == true }
check('severity is :ok') { result.severity == :ok }
check('no reasons listed') { result.reasons.empty? }
check('encryption_method resolved to AES_256') { result.encryption_method == 'AES_256' }

puts "\nTest 2: completely unencrypted volume -> critical, non-compliant"
fake = FakeVolumeConnector.new([
  { drive_letter: 'D:', protection_status: 0, conversion_status: 0, encryption_method: 0, key_protector_types: [] }
])
result = BitLockerAuditor.new(connector: fake).audit.first
check('compliant is false') { result.compliant == false }
check('severity is :critical') { result.severity == :critical }
check('reasons mention protection') { result.reasons.any? { |r| r.include?('protection is Unprotected') } }
check('reasons mention conversion') { result.reasons.any? { |r| r.include?('FullyDecrypted') } }
check('reasons mention missing recovery password') { result.reasons.any? { |r| r.include?('RecoveryPassword') } }

puts "\nTest 3: encrypted and protected, but no recovery-password protector -> warning, non-compliant"
fake = FakeVolumeConnector.new([
  { drive_letter: 'C:', protection_status: 1, conversion_status: 1, encryption_method: 4, key_protector_types: [1] } # TPM only
])
result = BitLockerAuditor.new(connector: fake).audit.first
check('compliant is false') { result.compliant == false }
check('severity is :warning, not :critical') { result.severity == :warning }
check('exactly one reason (missing recovery password)') { result.reasons.size == 1 }

puts "\nTest 4: encryption in progress -> critical (not yet fully encrypted)"
fake = FakeVolumeConnector.new([
  { drive_letter: 'E:', protection_status: 1, conversion_status: 2, encryption_method: 4, key_protector_types: [3] }
])
result = BitLockerAuditor.new(connector: fake).audit.first
check('compliant is false') { result.compliant == false }
check('severity is :critical') { result.severity == :critical }
check('reason mentions EncryptionInProgress') { result.reasons.any? { |r| r.include?('EncryptionInProgress') } }

puts "\nTest 5: unknown/unrecognized WMI status codes render gracefully, no crash"
fake = FakeVolumeConnector.new([
  { drive_letter: 'F:', protection_status: 99, conversion_status: 42, encryption_method: 123, key_protector_types: [] }
])
result = BitLockerAuditor.new(connector: fake).audit.first
check('protection_status renders as Unknown(99)') { result.protection_status == 'Unknown(99)' }
check('conversion_status renders as Unknown(42)') { result.conversion_status == 'Unknown(42)' }
check('encryption_method renders as Unknown(123)') { result.encryption_method == 'Unknown(123)' }
check('still classified non-compliant, not raised') { result.compliant == false }

puts "\nTest 6: audit handles a mixed multi-volume fleet and preserves order"
fake = FakeVolumeConnector.new([
  { drive_letter: 'C:', protection_status: 1, conversion_status: 1, encryption_method: 4, key_protector_types: [1, 3] },
  { drive_letter: 'D:', protection_status: 0, conversion_status: 0, encryption_method: 0, key_protector_types: [] },
  { drive_letter: 'E:', protection_status: 1, conversion_status: 1, encryption_method: 4, key_protector_types: [1] }
])
results = BitLockerAuditor.new(connector: fake).audit
check('returns 3 results in order C:,D:,E:') { results.map(&:drive_letter) == ['C:', 'D:', 'E:'] }
check('C: compliant, D: critical, E: warning') do
  results[0].severity == :ok && results[1].severity == :critical && results[2].severity == :warning
end

puts "\nTest 7: render_text and to_h produce sane, non-crashing output"
text = render_text(results)
check('text report mentions all three drive letters') { %w[C: D: E:].all? { |d| text.include?(d) } }
check('to_h round-trips through JSON without error') do
  require 'json'
  JSON.parse(JSON.generate(results.first.to_h))
  true
rescue StandardError
  false
end

puts "\n#{'=' * 60}"
puts "RESULTS: #{$passes} passed, #{$failures} failed"
puts '=' * 60
exit($failures.zero? ? 0 : 1)
