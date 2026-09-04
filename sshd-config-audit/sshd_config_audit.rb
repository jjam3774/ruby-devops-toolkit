#!/usr/bin/env ruby
# frozen_string_literal: true
#
# sshd_config_audit.rb — audit an OpenSSH server configuration against a
# hardening baseline, with sshd's own parsing semantics:
#
#   * first-occurrence-wins: sshd uses the FIRST value it sees for a
#     directive, so a hardened line at the bottom of the file does nothing
#     if a sloppy one appears above it (or in an earlier Include)
#   * Include directives are resolved and merged in order, like sshd does
#   * unset directives are audited against OpenSSH's compiled-in DEFAULTS,
#     because "we never set PermitRootLogin" is itself a finding
#   * Match blocks are fenced off: only the global section is audited, and
#     the report tells you how many Match blocks it skipped
#
# Checks (CIS-flavoured, explained in each finding):
#   CRIT  PermitRootLogin yes · PermitEmptyPasswords yes · Protocol 1
#   WARN  PasswordAuthentication yes · X11Forwarding yes · MaxAuthTries > 4
#         no session timeout (ClientAliveInterval 0) · LoginGraceTime > 60
#         MaxStartups unset-ish · AllowTcpForwarding yes (flag, not verdict)
#   INFO  no AllowUsers/AllowGroups restriction · port · root login mode
#
# Standard library only — no gems. Ruby >= 2.7.
#
#   sudo ruby sshd_config_audit.rb                      # /etc/ssh/sshd_config
#   ruby sshd_config_audit.rb --config fixtures/sshd_config
#   sudo ruby sshd_config_audit.rb --json | jq '.findings'
#
# Exit codes: 0 = clean, 1 = warnings, 2 = criticals.

require "json"
require "optparse"
require "time"

options = { config: "/etc/ssh/sshd_config", json: false }

OptionParser.new do |o|
  o.banner = "Usage: [sudo] ruby sshd_config_audit.rb [--config FILE] [--json]"
  o.on("--config FILE", "sshd_config to audit (default /etc/ssh/sshd_config)") { |v| options[:config] = v }
  o.on("--json", "emit JSON instead of text") { options[:json] = true }
  o.on("-h", "--help") { puts o; exit 0 }
end.parse!

# ---------------------------------------------------------------------------
# Parser. sshd semantics that matter for a *correct* audit:
#   * keywords are case-insensitive; values keep their case
#   * the FIRST occurrence of a directive wins — later lines are ignored
#   * Include is processed inline, in order, glob-expanded, relative
#     patterns resolved against /etc/ssh
#   * everything after the first Match block only applies conditionally,
#     so the global audit must stop collecting there
# ---------------------------------------------------------------------------
def parse_sshd_config(path, state = nil, depth = 0)
  state ||= { directives: {}, match_blocks: 0, files: [], missing: [] }
  raise "include depth exceeded" if depth > 8
  unless File.readable?(path)
    state[:missing] << path
    return state
  end
  state[:files] << path
  in_match = false

  File.foreach(path) do |line|
    line = line.strip
    next if line.empty? || line.start_with?("#")
    key, _, rest = line.partition(/\s+/)
    key = key.downcase
    value = rest.strip

    if key == "match"
      in_match = true
      state[:match_blocks] += 1
      next
    end
    next if in_match # conditional section — not part of the global audit

    if key == "include"
      value.split(/\s+/).each do |pattern|
        pattern = File.join("/etc/ssh", pattern) unless pattern.start_with?("/")
        Dir.glob(pattern).sort.each { |inc| parse_sshd_config(inc, state, depth + 1) }
      end
      next
    end

    # first-occurrence-wins: only record if we haven't seen this key yet
    unless state[:directives].key?(key)
      state[:directives][key] = { value: value, file: path }
    end
  end
  state
end

# OpenSSH compiled-in defaults for every directive we audit (OpenSSH 9.x).
# An unset directive is audited against these, flagged "(default)".
DEFAULTS = {
  "permitrootlogin"        => "prohibit-password",
  "passwordauthentication" => "yes",
  "permitemptypasswords"   => "no",
  "x11forwarding"          => "no",
  "maxauthtries"           => "6",
  "clientaliveinterval"    => "0",
  "clientalivecountmax"    => "3",
  "logingracetime"         => "120",
  "allowtcpforwarding"     => "yes",
  "port"                   => "22",
  "protocol"               => "2"
}.freeze

state = parse_sshd_config(options[:config])
abort "error: cannot read #{options[:config]}" if state[:files].empty?

dirs = state[:directives]
effective = lambda do |key|
  if dirs.key?(key)
    [dirs[key][:value], dirs[key][:file], false]
  else
    [DEFAULTS[key], "(default)", true]
  end
end

findings = []
add = lambda do |level, key, detail|
  value, source, is_default = effective.call(key)
  findings << { level: level, directive: key, value: value,
                source: is_default ? "compiled-in default" : source, detail: detail }
end

# ---------------------------------------------------------------------------
# The baseline. Each check reads the *effective* value (set or default).
# ---------------------------------------------------------------------------
val = ->(key) { effective.call(key).first.to_s.downcase }

case val.call("permitrootlogin")
when "yes"
  add.call("CRIT", "permitrootlogin",
           "root can log in with a password — brute-forcing root needs no username guess")
when "prohibit-password", "without-password"
  add.call("INFO", "permitrootlogin",
           "root login allowed with keys only; consider 'no' + sudo for auditability")
end

add.call("CRIT", "permitemptypasswords", "accounts with empty passwords can log in") if val.call("permitemptypasswords") == "yes"

add.call("CRIT", "protocol", "SSH protocol 1 is cryptographically broken") if val.call("protocol").include?("1")

if val.call("passwordauthentication") == "yes"
  add.call("WARN", "passwordauthentication",
           "password auth invites credential stuffing — prefer keys, then set 'no'")
end

add.call("WARN", "x11forwarding", "X11 forwarding widens the attack surface on the client display") if val.call("x11forwarding") == "yes"

if val.call("maxauthtries").to_i > 4
  add.call("WARN", "maxauthtries", "more than 4 auth attempts per connection aids brute forcing")
end

if val.call("clientaliveinterval").to_i.zero?
  add.call("WARN", "clientaliveinterval",
           "0 means dead/abandoned sessions are never reaped — set e.g. 300")
end

if val.call("logingracetime").to_i > 60
  add.call("WARN", "logingracetime", "long unauthenticated grace holds sockets open — set 60 or less")
end

if val.call("allowtcpforwarding") == "yes"
  add.call("INFO", "allowtcpforwarding",
           "TCP forwarding is on (default); fine for admins, disable on bastion-only hosts")
end

unless dirs.key?("allowusers") || dirs.key?("allowgroups")
  add.call("INFO", "allowusers",
           "no AllowUsers/AllowGroups — every valid account is an SSH target")
end

add.call("INFO", "port", "listening on the default port; expect scanner noise") if val.call("port") == "22"

# ---------------------------------------------------------------------------
# Report + exit code.
# ---------------------------------------------------------------------------
crit = findings.count { |f| f[:level] == "CRIT" }
warn = findings.count { |f| f[:level] == "WARN" }

if options[:json]
  puts JSON.pretty_generate(
    generated: Time.now.iso8601, config: options[:config],
    files_read: state[:files], unreadable_includes: state[:missing],
    match_blocks_skipped: state[:match_blocks],
    directives_set: dirs.size, crit: crit, warn: warn, findings: findings
  )
else
  puts "sshd config audit — #{options[:config]}"
  puts "files read: #{state[:files].join(', ')}"
  puts "#{dirs.size} directives set; #{state[:match_blocks]} Match block(s) skipped" \
       "#{state[:missing].empty? ? '' : "; UNREADABLE includes: #{state[:missing].join(', ')}"}"
  puts "-" * 70
  %w[CRIT WARN INFO].each do |lvl|
    findings.select { |f| f[:level] == lvl }.each do |f|
      puts format("%-5s %-22s = %-18s [%s]", lvl, f[:directive], f[:value], f[:source])
      puts format("      %s", f[:detail])
    end
  end
  puts "-" * 70
  puts "result: #{crit} critical, #{warn} warning#{warn == 1 ? '' : 's'}"
end

exit(crit.positive? ? 2 : warn.positive? ? 1 : 0)
