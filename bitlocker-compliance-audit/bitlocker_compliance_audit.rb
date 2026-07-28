#!/usr/bin/env ruby
# frozen_string_literal: true
#
# bitlocker_compliance_audit.rb
#
# Audits BitLocker drive-encryption status on Windows via WMI
# (Win32_EncryptableVolume) and reports which volumes are compliant with a
# simple, sane policy: fully encrypted, actively protected, and backed by a
# recovery-password key protector (so IT can actually unlock the drive if
# the TPM/PIN path fails). Read-only by design -- it reports drift, it
# doesn't flip encryption on for you, because enabling BitLocker involves
# choices (where the recovery key gets escrowed, whether to encrypt used
# space only or the whole drive) that shouldn't happen unattended.
#
# Why this exists: "is every laptop actually encrypted" is a routine
# compliance question (SOC 2, ISO 27001, a customer security questionnaire)
# that's easy to get wrong by trusting a policy setting instead of checking
# real device state. This script checks the real state, on every volume,
# and gives you a report you can hand to an auditor or wire into a fleet
# health check.
#
# IMPORTANT -- platform note:
# Win32_EncryptableVolume and WMI only exist on Windows (and require
# Administrator privileges to query). Exactly like this repo's other WMI
# tutorials, the *compliance decision logic* (BitLockerAuditor#evaluate) is
# fully platform-independent and unit-testable anywhere -- only the small
# WmiVolumeConnector class at the bottom touches WIN32OLE, and it's
# required lazily so this file can be required for tests on Linux/macOS
# without win32ole installed. See bitlocker_compliance_audit_test.rb for a
# fake-WMI test harness that exercises the real logic without Windows.
#
# Usage (on Windows, elevated):
#   ruby bitlocker_compliance_audit.rb
#   ruby bitlocker_compliance_audit.rb --json
#   ruby bitlocker_compliance_audit.rb --check   # exit 1 if any volume is non-compliant
#
# Requires: Ruby >= 2.7 built for Windows (e.g. via RubyInstaller) with the
# win32ole stdlib gem, and Administrator privileges (querying
# Win32_EncryptableVolume requires elevation even for read access).

require 'optparse'
require 'json'

# Friendly names for the WMI property codes on Win32_EncryptableVolume.
# See: https://learn.microsoft.com/en-us/windows/win32/secprov/win32-encryptablevolume
PROTECTION_STATUS = { 0 => 'Unprotected', 1 => 'Protected', 2 => 'Unknown' }.freeze
CONVERSION_STATUS = {
  0 => 'FullyDecrypted', 1 => 'FullyEncrypted', 2 => 'EncryptionInProgress',
  3 => 'DecryptionInProgress', 4 => 'EncryptionPaused', 5 => 'DecryptionPaused'
}.freeze
# Non-exhaustive; unrecognized codes are rendered as "Unknown(<code>)" rather
# than raising, since Microsoft has added new hardware/XTS variants over time.
ENCRYPTION_METHOD = {
  0 => 'None', 1 => 'AES_128_WITH_DIFFUSER', 2 => 'AES_256_WITH_DIFFUSER',
  3 => 'AES_128', 4 => 'AES_256', 6 => 'HW_AES_128', 7 => 'HW_AES_256'
}.freeze
KEY_PROTECTOR_TYPE = {
  0 => 'Unknown', 1 => 'TPM', 2 => 'ExternalKey', 3 => 'RecoveryPassword',
  4 => 'TPMAndPIN', 5 => 'TPMAndStartupKey', 6 => 'PublicKey', 7 => 'Password'
}.freeze
RECOVERY_PASSWORD_TYPE = 3

# One volume's audit outcome: whether it's compliant, how severe the gap is
# if not, and the specific reasons -- kept as a plain Struct so it
# serializes trivially to JSON for a compliance report or a monitoring feed.
VolumeAuditResult = Struct.new(
  :drive_letter, :compliant, :severity, :reasons,
  :protection_status, :conversion_status, :encryption_method, :has_recovery_password,
  keyword_init: true
) do
  def to_h
    {
      drive_letter: drive_letter,
      compliant: compliant,
      severity: severity,
      reasons: reasons,
      protection_status: protection_status,
      conversion_status: conversion_status,
      encryption_method: encryption_method,
      has_recovery_password: has_recovery_password
    }
  end
end

# BitLockerAuditor holds the actual compliance policy. It depends only on
# an injected `connector` responding to #volumes, which must return an
# array of plain hashes shaped like:
#   { drive_letter:, protection_status:, conversion_status:,
#     encryption_method:, key_protector_types: [...] }
# In production that's WmiVolumeConnector (real WIN32OLE calls); in tests
# it's a FakeVolumeConnector that hands back canned volume hashes directly,
# with no WMI or Windows involved at all.
class BitLockerAuditor
  def initialize(connector:)
    @connector = connector
  end

  # Audits every volume the connector reports and returns an array of
  # VolumeAuditResult, one per volume.
  def audit
    @connector.volumes.map { |vol| evaluate(vol) }
  end

  # Core compliance policy for a single volume. Pulled out as its own
  # method (rather than inlined in #audit) so tests can exercise it one
  # volume at a time with precise, hand-built fixtures.
  def evaluate(vol)
    reasons = []

    protection_name = PROTECTION_STATUS.fetch(vol[:protection_status], "Unknown(#{vol[:protection_status]})")
    conversion_name = CONVERSION_STATUS.fetch(vol[:conversion_status], "Unknown(#{vol[:conversion_status]})")
    method_name = ENCRYPTION_METHOD.fetch(vol[:encryption_method], "Unknown(#{vol[:encryption_method]})")
    has_recovery_password = Array(vol[:key_protector_types]).include?(RECOVERY_PASSWORD_TYPE)

    reasons << "protection is #{protection_name}, expected Protected" if vol[:protection_status] != 1
    reasons << "volume is #{conversion_name}, expected FullyEncrypted" if vol[:conversion_status] != 1
    reasons << 'no RecoveryPassword key protector configured' unless has_recovery_password

    severity =
      if reasons.empty?
        :ok
      elsif vol[:protection_status] != 1 || vol[:conversion_status] != 1
        :critical # the drive itself isn't encrypted/protected -- the real risk
      else
        :warning # encrypted and protected, but missing the recovery-password safety net
      end

    VolumeAuditResult.new(
      drive_letter: vol[:drive_letter],
      compliant: reasons.empty?,
      severity: severity,
      reasons: reasons,
      protection_status: protection_name,
      conversion_status: conversion_name,
      encryption_method: method_name,
      has_recovery_password: has_recovery_password
    )
  end
end

# --- Report rendering --------------------------------------------------------
def render_text(results)
  lines = []
  results.each do |r|
    tag = r.compliant ? 'PASS   ' : (r.severity == :critical ? 'CRIT   ' : 'WARN   ')
    lines << "#{tag} #{r.drive_letter}  method=#{r.encryption_method}  protection=#{r.protection_status}  conversion=#{r.conversion_status}  recovery_password=#{r.has_recovery_password}"
    r.reasons.each { |reason| lines << "         - #{reason}" }
  end
  lines.join("\n")
end

# --- Real WMI connector (Windows only) ---------------------------------------
class WmiVolumeConnector
  def initialize
    require 'win32ole' # raises LoadError on non-Windows -- expected and fine for tests
    @wmi = WIN32OLE.connect('winmgmts://./root/cimv2/security/MicrosoftVolumeEncryption')
  end

  def volumes
    result = []
    @wmi.ExecQuery('SELECT * FROM Win32_EncryptableVolume').each do |v|
      result << {
        drive_letter: v.DriveLetter,
        protection_status: v.ProtectionStatus,
        conversion_status: v.ConversionStatus,
        encryption_method: v.EncryptionMethod,
        key_protector_types: key_protector_types_for(v)
      }
    end
    result
  rescue StandardError => e
    warn "WMI query failed (are you running elevated?): #{e.message}"
    []
  end

  private

  # GetKeyProtectors(0) returns the IDs of all key protectors on the volume
  # (a filter value of 0 means "no type filter"); GetKeyProtectorType(id)
  # then resolves each ID to its numeric type code.
  def key_protector_types_for(volume)
    ids = volume.GetKeyProtectors(0)
    Array(ids).map { |id| volume.GetKeyProtectorType(id) }
  rescue StandardError
    []
  end
end

# --- CLI entry point ----------------------------------------------------------
if $PROGRAM_NAME == __FILE__
  options = { json: false, check: false }
  OptionParser.new do |opts|
    opts.banner = 'Usage: bitlocker_compliance_audit.rb [options]'
    opts.on('--json', 'Output the report as JSON instead of text') { options[:json] = true }
    opts.on('--check', 'Exit 1 if any volume is non-compliant (for cron/CI)') { options[:check] = true }
  end.parse!

  auditor = BitLockerAuditor.new(connector: WmiVolumeConnector.new)
  results = auditor.audit

  if options[:json]
    puts JSON.pretty_generate(results.map(&:to_h))
  else
    puts render_text(results)
  end

  exit(1) if options[:check] && results.any? { |r| !r.compliant }
end
