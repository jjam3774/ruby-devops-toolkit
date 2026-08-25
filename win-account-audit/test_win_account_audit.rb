#!/usr/bin/env ruby
# frozen_string_literal: true
#
# test_win_account_audit.rb -- exercises the audit logic of win_account_audit.rb
# on ANY platform by injecting a stub provider with realistic Win32_UserAccount /
# Win32_GroupUser / Win32_NetworkLoginProfile fixture data. This is how the
# audit rules were verified on Linux, since WMI itself needs a real Windows host.
#
require 'minitest/autorun'
require 'time'
require_relative 'win_account_audit'

class StubProvider
  def user_accounts
    [
      # healthy admin-ish account: enabled, password required + expires, recent logon
      { name: 'jsmith',        sid: 'S-1-5-21-111-1001', disabled: false, password_expires: true,  password_required: true,  lockout: false },
      # built-in Administrator, still enabled, password never expires
      { name: 'Administrator', sid: 'S-1-5-21-111-500',  disabled: false, password_expires: false, password_required: true,  lockout: false },
      # built-in Guest ENABLED -- classic finding
      { name: 'Guest',         sid: 'S-1-5-21-111-501',  disabled: false, password_expires: false, password_required: false, lockout: false },
      # service account: blank password allowed -- the worst finding
      { name: 'svc_legacy',    sid: 'S-1-5-21-111-1002', disabled: false, password_expires: false, password_required: false, lockout: false },
      # departed employee: enabled but hasn't logged on in ~7 months
      { name: 'tchen',         sid: 'S-1-5-21-111-1003', disabled: false, password_expires: true,  password_required: true,  lockout: false },
      # disabled account -- should produce NO findings at all
      { name: 'old_intern',    sid: 'S-1-5-21-111-1004', disabled: true,  password_expires: false, password_required: false, lockout: false }
    ]
  end

  def admin_group_members
    ['Administrator', 'jsmith', 'svc_legacy'] # svc_legacy is NOT on the allow list
  end

  def last_logons
    { 'jsmith'        => Time.now - 2 * 86_400,
      'Administrator' => Time.now - 10 * 86_400,
      'tchen'         => Time.parse('2026-01-14 09:30:00') }
  end
end

class AccountAuditorTest < Minitest::Test
  def setup
    @findings = AccountAuditor.new(
      StubProvider.new, stale_days: 90, allowed_admins: %w[Administrator jsmith]
    ).findings
  end

  def rules_for(account)
    @findings.select { |f| f[:account] == account }.map { |f| f[:rule] }.sort
  end

  def test_guest_enabled_is_crit
    f = @findings.find { |x| x[:rule] == 'GUEST-ENABLED' }
    assert f, 'expected GUEST-ENABLED finding'
    assert_equal 'CRIT', f[:severity]
    assert_equal 'Guest', f[:account]
  end

  def test_blank_password_service_account_flagged
    assert_includes rules_for('svc_legacy'), 'PW-NOT-REQUIRED'
    assert_includes rules_for('svc_legacy'), 'UNEXPECTED-ADMIN'
  end

  def test_builtin_admin_enabled_and_never_expires
    assert_includes rules_for('Administrator'), 'BUILTIN-ADMIN-ON'
    assert_includes rules_for('Administrator'), 'PW-NEVER-EXPIRES'
  end

  def test_stale_account_detected_with_date
    f = @findings.find { |x| x[:rule] == 'STALE-ACCOUNT' && x[:account] == 'tchen' }
    assert f, 'expected STALE-ACCOUNT finding for tchen'
    assert_match(/2026-01-14/, f[:detail])
  end

  def test_disabled_accounts_are_ignored
    assert_empty rules_for('old_intern')
  end

  def test_healthy_account_is_clean
    assert_empty rules_for('jsmith')
  end

  def test_crit_findings_sort_first
    severities = @findings.map { |f| f[:severity] }
    assert_equal severities.sort_by { |s| s == 'CRIT' ? 0 : 1 }, severities
  end
end

# When run directly, also print the findings table the way the real CLI would,
# so you can eyeball what the audit output looks like without a Windows box.
if $PROGRAM_NAME == __FILE__
  findings = AccountAuditor.new(StubProvider.new, stale_days: 90,
                                allowed_admins: %w[Administrator jsmith]).findings
  puts
  puts '--- simulated audit output (stub WMI fixtures) ---'
  findings.each do |f|
    puts format('[%s] %-17s %-16s %s', f[:severity], f[:rule], f[:account], f[:detail])
  end
  puts "#{findings.size} finding(s), #{findings.count { |f| f[:severity] == 'CRIT' }} critical"
end
