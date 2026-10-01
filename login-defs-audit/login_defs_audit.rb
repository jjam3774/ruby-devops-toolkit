#!/usr/bin/env ruby
# frozen_string_literal: true
# login_defs_audit.rb - audit /etc/login.defs password-aging policy and check
# whether /etc/shadow accounts actually comply with it. Stdlib only.
#   ruby login_defs_audit.rb [--login-defs F] [--shadow F] [--json] [--today YYYY-MM-DD]
# Exit: 0 clean, 1 WARN, 2 FAIL
require 'optparse'
require 'json'
require 'date'

# Parse "KEY value" lines; comments/blank ignored; last value wins (like shadow-utils).
def parse_login_defs(text)
  text.each_line.with_object({}) do |l, h|
    l = l.sub(/#.*/, '').strip
    next if l.empty?
    k, v = l.split(/\s+/, 2)
    h[k] = v.to_s.strip
  end
end

def policy_findings(d)
  f = []
  max = d['PASS_MAX_DAYS']&.to_i
  f << ['FAIL', 'PASS_MAX_DAYS', "#{max.inspect} - passwords effectively never expire", 'PASS_MAX_DAYS 365 (CIS: <= 365)'] if max.nil? || max > 365 || max < 0
  f << ['WARN', 'PASS_MAX_DAYS', "#{max} days is long", 'use 90-365'] if max && max.between?(181, 365)
  min = d['PASS_MIN_DAYS']&.to_i
  f << ['WARN', 'PASS_MIN_DAYS', "#{min.inspect} - users can change passwords repeatedly to cycle history", 'PASS_MIN_DAYS 1'] if min.nil? || min < 1
  warn_age = d['PASS_WARN_AGE']&.to_i
  f << ['WARN', 'PASS_WARN_AGE', "#{warn_age.inspect} - too little notice", 'PASS_WARN_AGE 7'] if warn_age.nil? || warn_age < 7
  enc = d['ENCRYPT_METHOD'].to_s.upcase
  f << ['FAIL', 'ENCRYPT_METHOD', "#{enc.empty? ? 'unset' : enc} - weak or default hash", 'ENCRYPT_METHOD SHA512 (or YESCRYPT)'] unless %w[SHA512 YESCRYPT].include?(enc)
  umask = d['UMASK']
  f << ['WARN', 'UMASK', "#{umask || 'unset'} - new files group/world readable", 'UMASK 027'] if umask.nil? || (umask.to_i(8) & 0o027) != 0o027
  f
end

# shadow fields: name:hash:lastchg:min:max:warn:inactive:expire
def shadow_findings(text, defs, today)
  global_max = defs['PASS_MAX_DAYS'].to_i
  text.each_line.flat_map do |l|
    n, hash, lastchg, _min, max, = l.chomp.split(':', -1)
    next [] if n.nil? || n.empty?
    next [] if hash.start_with?('!', '*') # locked / no password
    out = []
    out << ['FAIL', n, 'empty password hash', 'passwd -l ' + n] if hash.empty?
    eff = max.to_s.empty? ? global_max : max.to_i
    out << ['FAIL', n, "account max=#{max} never expires (overrides login.defs)", "chage -M #{[global_max, 365].min} #{n}"] if max.to_i >= 99_999
    if !lastchg.to_s.empty? && lastchg.to_i.positive? && eff.positive? && eff < 99_999
      age = (today - Date.new(1970, 1, 1)).to_i - lastchg.to_i
      out << ['WARN', n, "password #{age} days old, policy max #{eff}", "chage -d 0 #{n}"] if age > eff
    end
    out
  end
end

if $PROGRAM_NAME == __FILE__
  o = { ld: '/etc/login.defs', sh: '/etc/shadow', today: Date.today }
  OptionParser.new do |op|
    op.on('--login-defs F') { |v| o[:ld] = v }
    op.on('--shadow F') { |v| o[:sh] = v }
    op.on('--today D') { |v| o[:today] = Date.parse(v) }
    op.on('--json') { o[:json] = true }
  end.parse!
  defs = parse_login_defs(File.read(o[:ld]))
  findings = policy_findings(defs).map { |s, w, m, fx| { sev: s, scope: 'policy', item: w, msg: m, fix: fx } }
  if File.readable?(o[:sh])
    findings += shadow_findings(File.read(o[:sh]), defs, o[:today]).map { |s, w, m, fx| { sev: s, scope: 'account', item: w, msg: m, fix: fx } }
  else
    warn "note: #{o[:sh]} not readable (run as root) - skipping per-account checks"
  end
  if o[:json]
    puts JSON.pretty_generate(findings)
  else
    findings.each { |x| puts format('%-4s %-8s %-15s %s  -> %s', x[:sev], x[:scope], x[:item], x[:msg], x[:fix]) }
    puts findings.empty? ? 'RESULT: clean' : "RESULT: #{findings.count { |x| x[:sev] == 'FAIL' }} FAIL, #{findings.count { |x| x[:sev] == 'WARN' }} WARN"
  end
  exit(findings.any? { |x| x[:sev] == 'FAIL' } ? 2 : (findings.empty? ? 0 : 1))
end
