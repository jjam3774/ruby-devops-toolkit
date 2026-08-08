#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Unit tests for ntfs_acl_audit.rb's parsing and risk-scoring logic.
#
# This environment has no Windows host, so icacls.exe can't actually be
# invoked here. Instead, these tests feed realistic icacls.exe TEXT OUTPUT
# (captured from a real Windows box and reproduced as fixtures below)
# straight into parse_icacls_output / evaluate_ace / audit_path, and for
# audit_path, inject a fake "runner" lambda in place of Open3 so the whole
# pipeline is exercised without shelling out. Run with:
#
#   ruby ntfs_acl_audit_test.rb

require 'minitest/autorun'
require_relative 'ntfs_acl_audit'

# --- Fixtures --------------------------------------------------------------
# Captured (redacted/reproduced) icacls.exe output shapes.

FIXTURE_SAFE = <<~OUT
  C:\\Windows\\System32 BUILTIN\\Administrators:(OI)(CI)(F)
                        NT AUTHORITY\\SYSTEM:(OI)(CI)(F)
                        BUILTIN\\Users:(OI)(CI)(RX)
                        APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES:(OI)(CI)(RX)

  Successfully processed 1 files; Failed processing 0 files
OUT

FIXTURE_RISKY_EVERYONE_FULLCONTROL = <<~OUT
  C:\\inetpub\\wwwroot BUILTIN\\Administrators:(OI)(CI)(F)
                       NT AUTHORITY\\SYSTEM:(OI)(CI)(F)
                       BUILTIN\\Users:(OI)(CI)(RX)
                       Everyone:(OI)(CI)(F)

  Successfully processed 1 files; Failed processing 0 files
OUT

FIXTURE_RISKY_USERS_MODIFY = <<~OUT
  C:\\ProgramData\\LegacyApp BUILTIN\\Administrators:(OI)(CI)(F)
                             NT AUTHORITY\\SYSTEM:(OI)(CI)(F)
                             BUILTIN\\Users:(OI)(CI)(M)

  Successfully processed 1 files; Failed processing 0 files
OUT

FIXTURE_DENY_IS_NOT_A_FINDING = <<~OUT
  C:\\Secure\\Vault BUILTIN\\Administrators:(OI)(CI)(F)
                    Everyone:(DENY)(OI)(CI)(F)
                    NT AUTHORITY\\SYSTEM:(OI)(CI)(F)

  Successfully processed 1 files; Failed processing 0 files
OUT

FIXTURE_WRITE_ONLY_IS_WARN = <<~OUT
  C:\\Shares\\Drop BUILTIN\\Administrators:(OI)(CI)(F)
                   Authenticated Users:(OI)(CI)(W)

  Successfully processed 1 files; Failed processing 0 files
OUT

# --- Tests -------------------------------------------------------------

class NtfsAclAuditTest < Minitest::Test
  RISKY_IDENTITIES = ['Everyone', 'BUILTIN\\Users', 'Authenticated Users', 'NT AUTHORITY\\Authenticated Users'].freeze
  RISKY_PERMS = %w[F M W WD WDAC].freeze
  SAFE_IDENTITIES = ['NT AUTHORITY\\SYSTEM', 'BUILTIN\\Administrators', 'CREATOR OWNER'].freeze

  def test_parses_all_aces_for_a_path
    entries = parse_icacls_output(FIXTURE_SAFE)
    assert_equal 4, entries.size
    assert_equal 'C:\\Windows\\System32', entries.first[:path]
    assert entries.all? { |e| e[:path] == 'C:\\Windows\\System32' }, 'every ACE should inherit the path from the first line'
  end

  def test_extracts_permission_codes_separately_from_inheritance_flags
    entries = parse_icacls_output(FIXTURE_SAFE)
    admins = entries.find { |e| e[:identity] == 'BUILTIN\\Administrators' }
    assert_equal ['F'], admins[:perms]
    assert_equal %w[OI CI], admins[:inheritance_flags]
  end

  def test_safe_identity_is_never_flagged_even_with_fullcontrol
    entries = parse_icacls_output(FIXTURE_SAFE)
    admins = entries.find { |e| e[:identity] == 'BUILTIN\\Administrators' }
    result = evaluate_ace(admins, RISKY_IDENTITIES, RISKY_PERMS, SAFE_IDENTITIES)
    assert_equal :ok, result[:severity]
  end

  def test_everyone_fullcontrol_is_critical
    entries = parse_icacls_output(FIXTURE_RISKY_EVERYONE_FULLCONTROL)
    everyone = entries.find { |e| e[:identity] == 'Everyone' }
    result = evaluate_ace(everyone, RISKY_IDENTITIES, RISKY_PERMS, SAFE_IDENTITIES)
    assert_equal :crit, result[:severity]
    assert_match(/Everyone granted F on C:\\inetpub\\wwwroot/, result[:reasons].first)
  end

  def test_users_modify_is_critical
    entries = parse_icacls_output(FIXTURE_RISKY_USERS_MODIFY)
    users = entries.find { |e| e[:identity] == 'BUILTIN\\Users' }
    result = evaluate_ace(users, RISKY_IDENTITIES, RISKY_PERMS, SAFE_IDENTITIES)
    assert_equal :crit, result[:severity]
  end

  def test_users_read_execute_is_not_flagged
    entries = parse_icacls_output(FIXTURE_RISKY_EVERYONE_FULLCONTROL)
    users = entries.find { |e| e[:identity] == 'BUILTIN\\Users' }
    result = evaluate_ace(users, RISKY_IDENTITIES, RISKY_PERMS, SAFE_IDENTITIES)
    assert_equal :ok, result[:severity], 'Users:(RX) is read-only and should never be a finding'
  end

  def test_explicit_deny_ace_is_not_a_finding
    entries = parse_icacls_output(FIXTURE_DENY_IS_NOT_A_FINDING)
    everyone_deny = entries.find { |e| e[:identity] == 'Everyone' }
    assert everyone_deny[:deny], 'fixture ACE should have parsed as a DENY'
    result = evaluate_ace(everyone_deny, RISKY_IDENTITIES, RISKY_PERMS, SAFE_IDENTITIES)
    assert_equal :ok, result[:severity], 'an explicit DENY is protective, not risky'
  end

  def test_write_only_grant_is_warn_not_crit
    entries = parse_icacls_output(FIXTURE_WRITE_ONLY_IS_WARN)
    auth_users = entries.find { |e| e[:identity] == 'Authenticated Users' }
    result = evaluate_ace(auth_users, RISKY_IDENTITIES, RISKY_PERMS, SAFE_IDENTITIES)
    assert_equal :warn, result[:severity]
  end

  def test_audit_path_end_to_end_with_fake_runner
    fake_runner = ->(_path) { [FIXTURE_RISKY_EVERYONE_FULLCONTROL, '', Struct.new(:success?).new(true)] }
    result = audit_path('C:\\inetpub\\wwwroot', RISKY_IDENTITIES, RISKY_PERMS, SAFE_IDENTITIES, runner: fake_runner)
    assert_equal :crit, result[:status]
    flagged = result[:aces].select { |a| !a[:reasons].empty? }
    assert_equal 1, flagged.size
    assert_equal 'Everyone', flagged.first[:identity]
  end

  def test_audit_path_reports_error_when_icacls_fails
    fake_runner = ->(_path) { ['', 'ERROR: The system cannot find the file specified.', Struct.new(:success?).new(false)] }
    result = audit_path('C:\\Nonexistent', RISKY_IDENTITIES, RISKY_PERMS, SAFE_IDENTITIES, runner: fake_runner)
    assert_equal :error, result[:status]
    assert_match(/cannot find the file/, result[:error])
  end

  def test_clean_tree_has_no_findings
    entries = parse_icacls_output(FIXTURE_SAFE)
    findings = entries.map { |e| evaluate_ace(e, RISKY_IDENTITIES, RISKY_PERMS, SAFE_IDENTITIES) }
    assert findings.all? { |f| f[:severity] == :ok }
  end
end
