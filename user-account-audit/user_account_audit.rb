#!/usr/bin/env ruby
# frozen_string_literal: true
#
# user_account_audit.rb — audit Linux local accounts for the classic
# "how did THAT get there" problems: duplicate UID 0 entries, passwordless
# accounts, system accounts that can log in, stale passwords, and human
# accounts with missing or world-writable home directories.
#
# Reads /etc/passwd, /etc/shadow and /etc/group directly (no PAM, no LDAP —
# local files only), so it also works against COPIES of those files taken
# from another box or an image. That's what --etc is for.
#
# Stdlib only. Run as root for shadow checks; without root you still get
# every passwd/group finding, and the script tells you what it had to skip.
#
# Usage:
#   sudo ruby user_account_audit.rb                 # audit the live system
#   ruby user_account_audit.rb --etc ./fixtures     # audit copied files
#   sudo ruby user_account_audit.rb --json          # for pipelines
#   sudo ruby user_account_audit.rb --max-age 90    # password older than 90d = WARN
#
# Exit codes: 0 = clean, 1 = warnings only, 2 = at least one CRIT.

require "json"
require "optparse"
require "time"

options = { etc: "/etc", json: false, max_age: 365, sudo_groups: %w[sudo wheel admin] }

OptionParser.new do |o|
  o.banner = "Usage: ruby user_account_audit.rb [options]"
  o.on("--etc DIR", "Directory holding passwd/shadow/group (default /etc)") { |v| options[:etc] = v }
  o.on("--json", "Emit JSON instead of text") { options[:json] = true }
  o.on("--max-age DAYS", Integer, "Flag passwords older than DAYS (default 365)") { |v| options[:max_age] = v }
  o.on("--sudo-groups A,B", Array, "Groups that grant admin (default sudo,wheel,admin)") { |v| options[:sudo_groups] = v }
end.parse!

NOLOGIN_SHELLS = %w[/usr/sbin/nologin /sbin/nologin /bin/false /usr/bin/false /bin/sync].freeze

findings = []        # {severity:, code:, user:, detail:}
skipped  = []

def findings_add(findings, severity, code, user, detail)
  findings << { severity: severity, code: code, user: user, detail: detail }
end

# --- parse passwd -----------------------------------------------------------
passwd_path = File.join(options[:etc], "passwd")
abort "cannot read #{passwd_path}" unless File.readable?(passwd_path)

users = File.readlines(passwd_path).filter_map do |line|
  line = line.strip
  next if line.empty? || line.start_with?("#")
  f = line.split(":", -1)
  next unless f.size >= 7
  { name: f[0], pw: f[1], uid: f[2].to_i, gid: f[3].to_i, home: f[5], shell: f[6] }
end

# --- parse group ------------------------------------------------------------
group_path = File.join(options[:etc], "group")
admin_members = []
if File.readable?(group_path)
  File.readlines(group_path).each do |line|
    f = line.strip.split(":", -1)
    next unless f.size >= 4
    admin_members.concat(f[3].split(",")) if options[:sudo_groups].include?(f[0])
  end
else
  skipped << "group file unreadable — sudo-membership check skipped"
end
admin_members = admin_members.reject(&:empty?).uniq

# --- parse shadow (root only, usually) -------------------------------------
shadow_path = File.join(options[:etc], "shadow")
shadow = {}
if File.readable?(shadow_path)
  File.readlines(shadow_path).each do |line|
    f = line.strip.split(":", -1)
    next unless f.size >= 3
    shadow[f[0]] = { hash: f[1], last_change_days: f[2].to_i }
  end
else
  skipped << "shadow unreadable (need root) — empty-password and password-age checks skipped"
end

# --- checks ----------------------------------------------------------------
today_days = (Time.now.to_i / 86_400)

# 1. Any UID shared by two accounts; a second UID-0 account is the classic
#    backdoor left by an intruder (or a 2 a.m. "temporary" fix).
users.group_by { |u| u[:uid] }.each do |uid, dup|
  next if dup.size < 2
  names = dup.map { |u| u[:name] }.join(", ")
  sev = uid.zero? ? :crit : :warn
  findings_add(findings, sev, "duplicate-uid", names, "UID #{uid} shared by: #{names}")
end

# 2. passwd field not 'x' means the hash lives IN passwd (world-readable) —
#    or worse, is empty.
users.each do |u|
  if u[:pw].empty?
    findings_add(findings, :crit, "empty-passwd-field", u[:name], "empty password field in passwd — logs in with NO password")
  elsif !%w[x *].include?(u[:pw])
    findings_add(findings, :crit, "hash-in-passwd", u[:name], "password hash stored in world-readable passwd file")
  end
end

# 3. Shadow checks: empty hash = passwordless login; old hash = stale cred.
shadow.each do |name, s|
  if s[:hash].empty?
    findings_add(findings, :crit, "empty-shadow-hash", name, "empty hash in shadow — account has NO password")
  elsif !s[:hash].start_with?("!", "*") && s[:last_change_days].positive?
    age = today_days - s[:last_change_days]
    if age > options[:max_age]
      findings_add(findings, :warn, "stale-password", name, "password last changed #{age} days ago (max #{options[:max_age]})")
    end
  end
end

# 4. System accounts (UID < 1000, not root) that still have a login shell.
users.each do |u|
  next unless u[:uid] < 1000 && u[:uid] != 0
  unless NOLOGIN_SHELLS.include?(u[:shell]) || u[:shell].empty?
    findings_add(findings, :warn, "system-account-shell", u[:name], "system account (UID #{u[:uid]}) has login shell #{u[:shell]}")
  end
end

# 5. Human accounts: home missing, or world-writable (their dotfiles — and
#    therefore their next login — are editable by everyone).
users.each do |u|
  next unless u[:uid] >= 1000 && !NOLOGIN_SHELLS.include?(u[:shell])
  if !File.directory?(u[:home])
    findings_add(findings, :warn, "missing-home", u[:name], "home #{u[:home]} does not exist")
  else
    mode = File.stat(u[:home]).mode & 0o777
    if (mode & 0o002).positive?
      findings_add(findings, :crit, "world-writable-home", u[:name], format("home %s is world-writable (%o)", u[:home], mode))
    end
  end
rescue SystemCallError
  skipped << "could not stat home for #{u[:name]}"
end

# 6. Who actually holds admin? Not a finding — an inventory line reviewers
#    always want in the same report.
admin_report = admin_members.sort

# --- output ----------------------------------------------------------------
sev_rank = { crit: 2, warn: 1 }
findings.sort_by! { |f| [-sev_rank[f[:severity]], f[:code]] }
exit_code = if findings.any? { |f| f[:severity] == :crit } then 2
            elsif findings.any? then 1
            else 0
            end

if options[:json]
  puts JSON.pretty_generate(
    "generated_at" => Time.now.utc.iso8601,
    "source" => options[:etc],
    "accounts_total" => users.size,
    "admin_group_members" => admin_report,
    "findings" => findings.map { |f| f.transform_keys(&:to_s).tap { |h| h["severity"] = h["severity"].to_s } },
    "skipped_checks" => skipped,
    "exit_code" => exit_code
  )
else
  puts "user_account_audit: #{users.size} accounts in #{passwd_path}"
  puts "admin group members: #{admin_report.empty? ? '(none found)' : admin_report.join(', ')}"
  skipped.each { |s| puts "SKIP: #{s}" }
  puts
  if findings.empty?
    puts "no findings — clean."
  else
    findings.each do |f|
      puts format("%-4s %-22s %-14s %s", f[:severity].to_s.upcase, f[:code], f[:user], f[:detail])
    end
    puts
    puts "#{findings.count { |f| f[:severity] == :crit }} CRIT, #{findings.count { |f| f[:severity] == :warn }} WARN"
  end
end

exit exit_code
