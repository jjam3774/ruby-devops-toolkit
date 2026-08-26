#!/usr/bin/env ruby
# frozen_string_literal: true
#
# user_account_audit.rb -- Linux local-account security audit.
#
# Reads /etc/passwd and (when readable) /etc/shadow and flags the classic
# local-account misconfigurations that auditors and attackers both look for:
#
#   CRIT  uid0-not-root        an account other than root with UID 0
#   CRIT  empty-password       shadow field is empty => login with no password
#   CRIT  passwd-has-hash      password hash stored in world-readable /etc/passwd
#   WARN  duplicate-uid        two accounts sharing a UID (indistinguishable in logs)
#   WARN  system-acct-shell    system account (uid < 1000) with a real login shell
#   WARN  stale-password       password older than --max-age days (default 365)
#   WARN  no-password-aging    human account whose password never expires
#   INFO  missing-home         home directory doesn't exist on disk
#   INFO  world-writable-home  home directory writable by everyone
#
#   sudo ruby user_account_audit.rb            # full audit incl. shadow checks
#   ruby user_account_audit.rb                 # passwd-only checks (no root)
#   ruby user_account_audit.rb --json          # machine-readable
#   ruby user_account_audit.rb --passwd F --shadow F   # audit copied files offline
#
# Stdlib only: json, optparse, date. No gems. Exit codes: 0 clean, 1 warnings,
# 2 criticals -- so it drops straight into cron or a CI compliance job.

require 'json'
require 'optparse'
require 'date'

options = { json: false, passwd: '/etc/passwd', shadow: '/etc/shadow', max_age: 365 }

OptionParser.new do |o|
  o.banner = 'Usage: [sudo] ruby user_account_audit.rb [options]'
  o.on('--json', 'JSON output') { options[:json] = true }
  o.on('--passwd FILE', 'passwd file to audit (default /etc/passwd)') { |v| options[:passwd] = v }
  o.on('--shadow FILE', 'shadow file to audit (default /etc/shadow)') { |v| options[:shadow] = v }
  o.on('--max-age DAYS', Integer, 'flag passwords older than DAYS (default 365)') { |v| options[:max_age] = v }
end.parse!

NOLOGIN_SHELLS = %w[/usr/sbin/nologin /sbin/nologin /bin/false /usr/bin/false].freeze
findings = []   # { severity:, code:, user:, detail: }

def note(findings, severity, code, user, detail)
  findings << { severity: severity, code: code, user: user, detail: detail }
end

# --- parse /etc/passwd -----------------------------------------------------
# name:pw:uid:gid:gecos:home:shell -- 7 colon-separated fields per line.

abort("error: cannot read #{options[:passwd]}") unless File.readable?(options[:passwd])

users = File.readlines(options[:passwd], chomp: true).filter_map do |line|
  next if line.empty? || line.start_with?('#')
  f = line.split(':', 7)
  { name: f[0], pw: f[1], uid: f[2].to_i, gid: f[3].to_i,
    home: f[5].to_s, shell: f[6].to_s }
end

# --- passwd-level checks ---------------------------------------------------

users.each do |u|
  # UID 0 grants root no matter what the account is called.
  if u[:uid].zero? && u[:name] != 'root'
    note(findings, 'CRIT', 'uid0-not-root', u[:name], 'account has UID 0 but is not root')
  end
  # Anything except "x" or "*" in the passwd pw field is a real hash sitting
  # in a world-readable file -- crackable offline by any local user.
  unless ['x', '*', '!', '!!', ''].include?(u[:pw])
    note(findings, 'CRIT', 'passwd-has-hash', u[:name], 'password hash stored in world-readable passwd file')
  end
  # System/daemon accounts should not have interactive shells.
  if u[:uid] < 1000 && u[:uid] != 0 && !NOLOGIN_SHELLS.include?(u[:shell]) && !u[:shell].empty?
    note(findings, 'WARN', 'system-acct-shell', u[:name], "system account with login shell #{u[:shell]}")
  end
  # Home-dir hygiene -- only meaningful for accounts that can log in.
  next if NOLOGIN_SHELLS.include?(u[:shell]) || u[:home].empty?
  if !File.directory?(u[:home])
    note(findings, 'INFO', 'missing-home', u[:name], "home #{u[:home]} does not exist")
  elsif File.world_writable?(u[:home])
    note(findings, 'INFO', 'world-writable-home', u[:name], "home #{u[:home]} is world-writable")
  end
end

# Duplicate UIDs: group by uid, flag any uid owned by 2+ names.
users.group_by { |u| u[:uid] }.each do |uid, group|
  next if group.size < 2
  names = group.map { |u| u[:name] }.join(', ')
  note(findings, 'WARN', 'duplicate-uid', names, "UID #{uid} shared by #{group.size} accounts")
end

# --- shadow-level checks (needs root, or an offline copy) ------------------
# name:hash:lastchg:min:max:warn:inactive:expire -- lastchg is in days since
# the Unix epoch; hash "" means NO password required; "!"/"*" mean locked.

shadow_read = false
if File.readable?(options[:shadow])
  shadow_read = true
  today = (Date.today - Date.new(1970, 1, 1)).to_i
  File.readlines(options[:shadow], chomp: true).each do |line|
    next if line.empty? || line.start_with?('#')
    f = line.split(':', 9)
    name, hash, lastchg, maxdays = f[0], f[1].to_s, f[2].to_s, f[4].to_s
    user = users.find { |u| u[:name] == name }
    locked = hash.start_with?('!', '*')
    if hash.empty?
      note(findings, 'CRIT', 'empty-password', name, 'no password set -- login succeeds with empty password')
    end
    # Aging checks only matter for unlocked, real-shell human accounts.
    next if locked || hash.empty? || user.nil? || NOLOGIN_SHELLS.include?(user[:shell])
    if !lastchg.empty? && lastchg.to_i.positive?
      age = today - lastchg.to_i
      if age > options[:max_age]
        note(findings, 'WARN', 'stale-password', name, "password last changed #{age} days ago")
      end
    end
    if user[:uid] >= 1000 && (maxdays.empty? || maxdays.to_i >= 99_999 || maxdays.to_i == -1)
      note(findings, 'WARN', 'no-password-aging', name, 'password never expires (max age unset)')
    end
  end
end

# --- output ----------------------------------------------------------------

sev_rank = { 'CRIT' => 0, 'WARN' => 1, 'INFO' => 2 }
findings.sort_by! { |f| sev_rank[f[:severity]] }
crit = findings.count { |f| f[:severity] == 'CRIT' }
warn = findings.count { |f| f[:severity] == 'WARN' }

if options[:json]
  puts JSON.pretty_generate(
    'audited'       => options[:passwd],
    'shadow_read'   => shadow_read,
    'accounts'      => users.size,
    'findings'      => findings.map { |f| f.transform_keys(&:to_s) },
    'summary'       => { 'crit' => crit, 'warn' => warn,
                         'info' => findings.size - crit - warn }
  )
else
  puts "user account audit -- #{options[:passwd]} (#{users.size} accounts)"
  puts "shadow checks: #{shadow_read ? 'enabled' : 'SKIPPED (not readable -- run as root)'}"
  puts
  if findings.empty?
    puts 'no findings -- clean.'
  else
    findings.each do |f|
      puts format('%-5s %-20s %-18s %s', f[:severity], f[:code], f[:user], f[:detail])
    end
    puts
    puts "#{crit} critical, #{warn} warning, #{findings.size - crit - warn} info"
  end
end

exit(crit.positive? ? 2 : warn.positive? ? 1 : 0)
