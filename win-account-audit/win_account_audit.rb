#!/usr/bin/env ruby
# frozen_string_literal: true
#
# win_account_audit.rb -- audit local Windows user accounts for the security
# problems auditors actually look for, using WMI via the win32ole standard
# library. No gems, no PowerShell dependency, no AD modules.
#
# Checks performed on every LOCAL account (Win32_UserAccount LocalAccount=true):
#
#   PW-NEVER-EXPIRES  enabled account whose password never expires
#   PW-NOT-REQUIRED   enabled account that does not require a password  (CRIT)
#   BUILTIN-ADMIN-ON  built-in Administrator (SID ending -500) is enabled
#   GUEST-ENABLED     built-in Guest (SID ending -501) is enabled       (CRIT)
#   STALE-ACCOUNT     enabled account with no interactive logon in N days
#   UNEXPECTED-ADMIN  member of local Administrators not on the allow list
#
# Run it elevated on Windows:
#   ruby win_account_audit.rb
#   ruby win_account_audit.rb --stale-days 90 --allow-admins "Administrator,svc_backup"
#   ruby win_account_audit.rb --json > audit.json
#
# Exit codes: 0 clean, 1 warnings only, 2 at least one CRIT finding.
#
# DESIGN NOTE -- the WMI access is isolated behind a tiny provider object with
# three methods (#user_accounts, #admin_group_members, #last_logons). That is
# the whole win32ole surface. It keeps the audit logic pure Ruby, which means
# the logic can be tested anywhere (including Linux CI) by injecting a stub
# provider with fixture data. See test_win_account_audit.rb in the repo.
#
require 'optparse'
require 'json'
require 'time'

# ---------------------------------------------------------------------------
# WMI provider: the only part of the script that touches win32ole.
# ---------------------------------------------------------------------------
class WmiProvider
  def initialize
    require 'win32ole' # raises LoadError on non-Windows -- caught in main
    @wmi = WIN32OLE.connect('winmgmts://./root/cimv2')
  end

  # Local accounts with the flags the audit needs.
  def user_accounts
    @wmi.ExecQuery(
      'SELECT Name, SID, Disabled, PasswordExpires, PasswordRequired, Lockout ' \
      'FROM Win32_UserAccount WHERE LocalAccount = TRUE'
    ).each.map do |u|
      { name: u.Name, sid: u.SID, disabled: u.Disabled,
        password_expires: u.PasswordExpires, password_required: u.PasswordRequired,
        lockout: u.Lockout }
    end
  end

  # Names of members of the local Administrators group (SID S-1-5-32-544),
  # resolved through Win32_GroupUser associations.
  def admin_group_members
    q = "SELECT * FROM Win32_GroupUser WHERE GroupComponent = " \
        "\"Win32_Group.Domain='#{computer_name}',Name='Administrators'\""
    @wmi.ExecQuery(q).each.map do |assoc|
      # PartComponent looks like: \\HOST\root\cimv2:Win32_UserAccount.Domain="HOST",Name="bob"
      assoc.PartComponent[/Name="([^"]+)"/, 1]
    end.compact
  end

  # Last interactive logon per user from Win32_NetworkLoginProfile.
  # WMI datetimes arrive as "20260801093000.000000-300" -- parse the stem.
  def last_logons
    @wmi.ExecQuery('SELECT Name, LastLogon FROM Win32_NetworkLoginProfile')
        .each.each_with_object({}) do |prof, h|
      next unless prof.LastLogon
      user = prof.Name.to_s.split('\\').last
      h[user] = Time.strptime(prof.LastLogon[0, 14], '%Y%m%d%H%M%S')
    rescue ArgumentError
      nil
    end
  end

  def computer_name
    @computer_name ||= @wmi.ExecQuery('SELECT Name FROM Win32_ComputerSystem')
                           .each.first.Name
  end
end

# ---------------------------------------------------------------------------
# Pure audit logic. Takes any provider that answers the three questions above.
# ---------------------------------------------------------------------------
class AccountAuditor
  SEVERITY = { 'PW-NOT-REQUIRED' => 'CRIT', 'GUEST-ENABLED' => 'CRIT',
               'UNEXPECTED-ADMIN' => 'CRIT', 'PW-NEVER-EXPIRES' => 'WARN',
               'BUILTIN-ADMIN-ON' => 'WARN', 'STALE-ACCOUNT' => 'WARN' }.freeze

  def initialize(provider, stale_days: 90, allowed_admins: ['Administrator'])
    @provider = provider
    @stale_days = stale_days
    @allowed_admins = allowed_admins.map(&:downcase)
  end

  def findings
    accounts = @provider.user_accounts
    admins   = @provider.admin_group_members
    logons   = @provider.last_logons
    out = []

    accounts.each do |a|
      builtin_admin = a[:sid].end_with?('-500')
      builtin_guest = a[:sid].end_with?('-501')

      if builtin_guest && !a[:disabled]
        out << finding('GUEST-ENABLED', a[:name], 'built-in Guest account is enabled')
      end
      next if a[:disabled] # everything below only matters for live accounts

      if builtin_admin
        out << finding('BUILTIN-ADMIN-ON', a[:name],
                       'built-in Administrator (RID 500) is enabled -- rename/disable per CIS 2.3.1')
      end
      unless a[:password_required]
        out << finding('PW-NOT-REQUIRED', a[:name], 'account can log on with a blank password')
      end
      unless a[:password_expires]
        out << finding('PW-NEVER-EXPIRES', a[:name], 'password is set to never expire')
      end

      last = logons[a[:name]]
      if last.nil? || last < Time.now - @stale_days * 86_400
        seen = last ? "last logon #{last.strftime('%Y-%m-%d')}" : 'no recorded logon'
        out << finding('STALE-ACCOUNT', a[:name],
                       "enabled but inactive > #{@stale_days} days (#{seen})")
      end
    end

    admins.each do |member|
      next if @allowed_admins.include?(member.downcase)
      out << finding('UNEXPECTED-ADMIN', member,
                     'member of local Administrators but not on the allow list')
    end

    out.sort_by { |f| [f[:severity] == 'CRIT' ? 0 : 1, f[:account]] }
  end

  private

  def finding(rule, account, detail)
    { rule: rule, severity: SEVERITY.fetch(rule), account: account, detail: detail }
  end
end

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if $PROGRAM_NAME == __FILE__
  opts = { stale_days: 90, allow: ['Administrator'], json: false }
  OptionParser.new do |o|
    o.banner = 'Usage: win_account_audit.rb [options]'
    o.on('--stale-days N', Integer, 'Days of inactivity before an account is stale (default 90)') { |v| opts[:stale_days] = v }
    o.on('--allow-admins LIST', 'Comma-separated allow list for Administrators membership') { |v| opts[:allow] = v.split(',').map(&:strip) }
    o.on('--json', 'Emit JSON instead of text') { opts[:json] = true }
  end.parse!

  begin
    provider = WmiProvider.new
  rescue LoadError
    abort 'win32ole is only available on Windows Ruby builds. ' \
          'On other platforms, run test_win_account_audit.rb to exercise the logic.'
  end

  findings = AccountAuditor.new(provider, stale_days: opts[:stale_days],
                                          allowed_admins: opts[:allow]).findings

  if opts[:json]
    puts JSON.pretty_generate(generated_at: Time.now.utc.iso8601,
                              host: provider.computer_name, findings: findings)
  else
    if findings.empty?
      puts '[ OK ] no findings -- local accounts look clean'
    else
      findings.each do |f|
        puts format('[%s] %-17s %-16s %s', f[:severity], f[:rule], f[:account], f[:detail])
      end
      crit = findings.count { |f| f[:severity] == 'CRIT' }
      puts "#{findings.size} finding(s), #{crit} critical"
    end
  end
  exit findings.empty? ? 0 : (findings.any? { |f| f[:severity] == 'CRIT' } ? 2 : 1)
end
