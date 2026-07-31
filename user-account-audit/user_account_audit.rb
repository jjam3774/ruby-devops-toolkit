#!/usr/bin/env ruby
# frozen_string_literal: true
#
# user_account_audit.rb
#
# Audits local Linux user accounts for common security misconfigurations by
# parsing /etc/passwd (and, when readable, /etc/shadow) without shelling out
# to external tools. Designed to run standalone on any box with a stock Ruby
# install -- no gems required.
#
# Checks performed:
#   1. Duplicate UID 0 accounts (any account besides "root" with UID 0 is a
#      classic backdoor / privilege-escalation red flag).
#   2. Duplicate UIDs across different usernames (breaks accountability --
#      two "different" users are actually the same account to the kernel).
#   3. Accounts with a login shell but a missing/non-existent home directory.
#   4. Accounts with no password hash set at all in /etc/shadow (empty field,
#      not "!" or "*") -- these can be logged into with an empty password if
#      PAM allows it.
#   5. Accounts whose password field shows "never expires" (empty max-age)
#      combined with a real login shell -- flagged as informational, since
#      it is common but worth knowing about on a hardened box.
#   6. System accounts (UID < 1000 by convention) that have been given an
#      interactive login shell instead of nologin/false.
#
# Usage:
#   ruby user_account_audit.rb                       # audit the live system
#   ruby user_account_audit.rb --passwd FILE          # audit a passwd fixture
#   ruby user_account_audit.rb --passwd FILE --shadow FILE
#   ruby user_account_audit.rb --json                 # machine-readable output
#   ruby user_account_audit.rb --min-uid 1000          # override system/human UID cutoff
#
# Exit codes (cron/CI friendly):
#   0 - no findings
#   1 - WARN-level findings only
#   2 - CRIT-level findings present

require 'optparse'
require 'json'
require 'etc'
require 'time'

# ---------------------------------------------------------------------------
# Data object for a single finding so text and JSON output stay in sync.
# ---------------------------------------------------------------------------
Finding = Struct.new(:severity, :user, :check, :detail) do
  def to_h
    { severity: severity.to_s, user: user, check: check, detail: detail }
  end
end

class UserAccountAuditor
  SEVERITY_RANK = { info: 0, warn: 1, crit: 2 }.freeze

  def initialize(passwd_path:, shadow_path:, min_uid:)
    @passwd_path = passwd_path
    @shadow_path = shadow_path
    @min_uid = min_uid
    @findings = []
  end

  def run
    users = parse_passwd(@passwd_path)
    shadow = @shadow_path && File.readable?(@shadow_path) ? parse_shadow(@shadow_path) : nil

    check_duplicate_root_uid(users)
    check_duplicate_uids(users)
    check_missing_home_dirs(users)
    check_system_accounts_with_shell(users)
    check_shadow_findings(users, shadow) if shadow

    @findings
  end

  private

  # /etc/passwd fields: username:x:uid:gid:gecos:home:shell
  def parse_passwd(path)
    users = []
    File.foreach(path) do |line|
      line = line.strip
      next if line.empty? || line.start_with?('#')

      fields = line.split(':', -1)
      next unless fields.size >= 7

      users << {
        name: fields[0],
        uid: fields[2].to_i,
        gid: fields[3].to_i,
        gecos: fields[4],
        home: fields[5],
        shell: fields[6]
      }
    end
    users
  end

  # /etc/shadow fields: username:password_hash:last_change:min:max:warn:inactive:expire:reserved
  def parse_shadow(path)
    shadow = {}
    File.foreach(path) do |line|
      line = line.strip
      next if line.empty? || line.start_with?('#')

      fields = line.split(':', -1)
      next unless fields.size >= 8

      shadow[fields[0]] = {
        hash: fields[1],
        max_age: fields[4]
      }
    end
    shadow
  end

  NOLOGIN_SHELLS = %w[/usr/sbin/nologin /sbin/nologin /bin/false /usr/bin/false].freeze

  def interactive_shell?(shell)
    return false if shell.nil? || shell.empty?
    return false if NOLOGIN_SHELLS.include?(shell)

    true
  end

  def check_duplicate_root_uid(users)
    zero_uid_users = users.select { |u| u[:uid].zero? }
    extras = zero_uid_users.reject { |u| u[:name] == 'root' }
    extras.each do |u|
      add(:crit, u[:name], 'duplicate-root-uid',
          "UID 0 shared with account '#{u[:name]}' -- this account has full root " \
          'privileges. Verify it is expected; if not, this is likely a backdoor.')
    end
  end

  def check_duplicate_uids(users)
    users.group_by { |u| u[:uid] }.each do |uid, group|
      next if group.size < 2
      next if uid.zero? # already covered by check_duplicate_root_uid with clearer messaging

      names = group.map { |u| u[:name] }.join(', ')
      group.each do |u|
        add(:warn, u[:name], 'duplicate-uid',
            "UID #{uid} is shared by multiple accounts (#{names}). These accounts " \
            'are indistinguishable at the filesystem/permission level.')
      end
    end
  end

  def check_missing_home_dirs(users)
    users.each do |u|
      next unless interactive_shell?(u[:shell])
      next if u[:home].nil? || u[:home].empty?

      unless Dir.exist?(u[:home])
        add(:warn, u[:name], 'missing-home-dir',
            "Home directory '#{u[:home]}' does not exist, but the account has " \
            "login shell '#{u[:shell]}'.")
      end
    end
  end

  def check_system_accounts_with_shell(users)
    users.each do |u|
      next unless u[:uid] < @min_uid
      next if u[:name] == 'root'
      next unless interactive_shell?(u[:shell])

      add(:warn, u[:name], 'system-account-interactive-shell',
          "System account (UID #{u[:uid]}) has an interactive shell " \
          "'#{u[:shell]}' instead of nologin/false.")
    end
  end

  def check_shadow_findings(users, shadow)
    users.each do |u|
      entry = shadow[u[:name]]
      next unless entry
      next unless interactive_shell?(u[:shell])

      hash = entry[:hash]
      if hash == ''
        add(:crit, u[:name], 'empty-password-hash',
            'Password hash field in /etc/shadow is empty -- account may be ' \
            'loggable-in with a blank password depending on PAM config.')
      elsif !hash.start_with?('!', '*')
        if entry[:max_age].nil? || entry[:max_age].empty?
          add(:info, u[:name], 'password-never-expires',
              'Account has a set password with no maximum password age configured.')
        end
      end
    end
  end

  def add(severity, user, check, detail)
    @findings << Finding.new(severity, user, check, detail)
  end
end

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_options(argv)
  opts = { passwd: '/etc/passwd', shadow: '/etc/shadow', json: false, min_uid: 1000 }
  parser = OptionParser.new do |o|
    o.banner = 'Usage: ruby user_account_audit.rb [options]'
    o.on('--passwd FILE', 'Path to passwd-format file (default: /etc/passwd)') { |v| opts[:passwd] = v }
    o.on('--shadow FILE', 'Path to shadow-format file (default: /etc/shadow, skipped if unreadable)') { |v| opts[:shadow] = v }
    o.on('--min-uid N', Integer, 'UID cutoff between system and human accounts (default: 1000)') { |v| opts[:min_uid] = v }
    o.on('--json', 'Emit machine-readable JSON instead of text') { opts[:json] = true }
    o.on('-h', '--help', 'Show this help') do
      puts o
      exit 0
    end
  end
  parser.parse!(argv)
  opts
end

def print_text_report(findings, users_scanned)
  puts "user_account_audit: scanned #{users_scanned} accounts, #{findings.size} finding(s)"
  puts '-' * 72

  if findings.empty?
    puts 'No issues found.'
    return
  end

  %i[crit warn info].each do |sev|
    group = findings.select { |f| f.severity == sev }
    next if group.empty?

    puts "\n[#{sev.to_s.upcase}] (#{group.size})"
    group.each do |f|
      puts "  - #{f.user}: #{f.check}"
      puts "      #{f.detail}"
    end
  end
end

if __FILE__ == $PROGRAM_NAME
  options = parse_options(ARGV)

  unless File.readable?(options[:passwd])
    warn "Cannot read passwd file: #{options[:passwd]}"
    exit 3
  end

  auditor = UserAccountAuditor.new(
    passwd_path: options[:passwd],
    shadow_path: options[:shadow],
    min_uid: options[:min_uid]
  )
  findings = auditor.run
  users_scanned = File.readlines(options[:passwd]).reject { |l| l.strip.empty? || l.start_with?('#') }.size

  if options[:json]
    puts JSON.pretty_generate(
      scanned_at: Time.now.utc.iso8601,
      users_scanned: users_scanned,
      finding_count: findings.size,
      findings: findings.map(&:to_h)
    )
  else
    print_text_report(findings, users_scanned)
  end

  worst = findings.map { |f| UserAccountAuditor::SEVERITY_RANK[f.severity] }.max || -1
  exit(worst >= UserAccountAuditor::SEVERITY_RANK[:crit] ? 2 : worst >= UserAccountAuditor::SEVERITY_RANK[:warn] ? 1 : 0)
end
