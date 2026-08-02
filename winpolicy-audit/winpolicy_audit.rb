#!/usr/bin/env ruby
# frozen_string_literal: true
#
# winpolicy_audit.rb
#
# Runs the built-in `net accounts` command (no extra modules, no WMI,
# ships on every Windows box) and audits the local password/lockout
# policy it reports against a configurable baseline: minimum password
# length, maximum password age, and account lockout threshold/duration.
# A firewall that's locked down and a password policy that lets anyone
# set a 1-character password with unlimited login attempts protect
# nothing -- this is the other half of "the box is actually secure."
#
# No gems required -- `optparse`, `json`, and `open3` are stdlib.
#
# Usage (on Windows):
#   ruby winpolicy_audit.rb
#   ruby winpolicy_audit.rb --domain
#   ruby winpolicy_audit.rb --min-length 14 --max-age-days 90 --json
#
# Usage anywhere (Linux/macOS/CI), against captured `net accounts`
# output -- also what the test suite uses:
#   ruby winpolicy_audit.rb --test-fixtures fixtures/net_accounts_weak.txt
#
# Exit codes (cron/monitoring friendly):
#   0 = policy meets every threshold
#   1 = WARN-level findings
#   2 = CRIT-level findings, or `net accounts` couldn't be run

require 'optparse'
require 'json'
require 'open3'

# ---------------------------------------------------------------------------
# Parsing -- `net accounts` prints one "Label:    Value" line per
# setting. This maps the (English-locale) labels it uses to short keys;
# anything not recognized is ignored rather than raising, since output
# formatting has drifted slightly across Windows versions.
# ---------------------------------------------------------------------------
LABEL_MAP = {
  /force user logoff/i => :force_logoff,
  /minimum password age/i => :min_password_age_days,
  /maximum password age/i => :max_password_age_days,
  /minimum password length/i => :min_password_length,
  /length of password history/i => :password_history,
  /lockout threshold/i => :lockout_threshold,
  /lockout duration/i => :lockout_duration_minutes,
  /lockout observation window/i => :lockout_window_minutes,
  /computer role/i => :computer_role
}.freeze

# Converts a raw string value from `net accounts` into a normalized
# Ruby value: "Never"/"None" become nil (meaning "no limit set" --
# which is itself often the finding), pure integers become Integer,
# everything else stays a String.
def normalize_value(raw)
  v = raw.strip
  return nil if v.match?(/\A(never|none|unlimited)\z/i)
  return v.to_i if v.match?(/\A\d+\z/)

  v
end

def parse_net_accounts(text)
  policy = {}
  text.each_line do |line|
    next unless line.include?(':')

    label, value = line.split(':', 2)
    next unless value

    key = LABEL_MAP.find { |pattern, _| label.match?(pattern) }&.last
    next unless key

    policy[key] = normalize_value(value)
  end
  policy
end

def run_net_accounts(domain)
  cmd = domain ? %w[net accounts /domain] : %w[net accounts]
  out, status = Open3.capture2e(*cmd)
  raise "net accounts exited #{status.exitstatus}: #{out}" unless status.success?

  parse_net_accounts(out)
end

# ---------------------------------------------------------------------------
# Risk logic -- pure function over the normalized policy hash + a
# baseline hash, no Open3/subprocess involved.
# ---------------------------------------------------------------------------
DEFAULT_BASELINE = {
  min_password_length: 14,
  max_password_age_days: 90,
  min_password_history: 5,
  max_lockout_threshold: 10
}.freeze

def evaluate_policy(policy, baseline)
  findings = []

  len = policy[:min_password_length]
  if len.nil? || len.zero?
    findings << { severity: 'CRIT', reason: 'minimum password length is 0/unset -- any password, including empty, is accepted' }
  elsif len < baseline[:min_password_length]
    sev = len < 8 ? 'CRIT' : 'WARN'
    findings << { severity: sev, reason: "minimum password length is #{len}, below baseline of #{baseline[:min_password_length]}" }
  end

  max_age = policy[:max_password_age_days]
  if max_age.nil?
    findings << { severity: 'WARN', reason: 'maximum password age is "Never" -- passwords do not expire; confirm this is an intentional NIST-800-63B-style policy and not an oversight' }
  elsif max_age > baseline[:max_password_age_days]
    findings << { severity: 'WARN', reason: "maximum password age is #{max_age} days, above baseline of #{baseline[:max_password_age_days]}" }
  end

  hist = policy[:password_history]
  if hist.nil? || hist.zero?
    findings << { severity: 'WARN', reason: 'password history is "None" -- users can immediately reuse their previous password' }
  elsif hist < baseline[:min_password_history]
    findings << { severity: 'WARN', reason: "password history remembers only #{hist} password(s), below baseline of #{baseline[:min_password_history]}" }
  end

  threshold = policy[:lockout_threshold]
  if threshold.nil?
    findings << { severity: 'CRIT', reason: 'lockout threshold is "Never" -- unlimited password attempts, no brute-force protection' }
  elsif threshold > baseline[:max_lockout_threshold]
    findings << { severity: 'WARN', reason: "lockout threshold is #{threshold} attempts, above baseline of #{baseline[:max_lockout_threshold]}" }
  end

  findings
end

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  options = {
    domain: false,
    json: false,
    test_fixtures: nil,
    baseline: DEFAULT_BASELINE.dup
  }

  parser = OptionParser.new do |opts|
    opts.banner = 'Usage: winpolicy_audit.rb [options]'
    opts.on('--domain', 'Audit domain policy (net accounts /domain) instead of local') { options[:domain] = true }
    opts.on('--min-length N', Integer, "Baseline minimum password length (default: #{DEFAULT_BASELINE[:min_password_length]})") { |v| options[:baseline][:min_password_length] = v }
    opts.on('--max-age-days N', Integer, "Baseline maximum password age (default: #{DEFAULT_BASELINE[:max_password_age_days]})") { |v| options[:baseline][:max_password_age_days] = v }
    opts.on('--min-history N', Integer, "Baseline minimum password history (default: #{DEFAULT_BASELINE[:min_password_history]})") { |v| options[:baseline][:min_password_history] = v }
    opts.on('--max-lockout-threshold N', Integer, "Baseline max lockout threshold (default: #{DEFAULT_BASELINE[:max_lockout_threshold]})") { |v| options[:baseline][:max_lockout_threshold] = v }
    opts.on('--json', 'Emit machine-readable JSON instead of text') { options[:json] = true }
    opts.on('--test-fixtures PATH',
            'Read captured `net accounts` text output from a file instead of ' \
            'running it live (works on any OS -- see fixtures/ and the test suite)') { |v| options[:test_fixtures] = v }
    opts.on('-h', '--help', 'Show this help') { puts opts; exit 0 }
  end
  parser.parse!

  policy =
    begin
      if options[:test_fixtures]
        parse_net_accounts(File.read(options[:test_fixtures]))
      else
        run_net_accounts(options[:domain])
      end
    rescue Errno::ENOENT
      warn '`net` command not found -- this script audits live policy on Windows only. Use --test-fixtures PATH to audit captured output on any OS.'
      exit 2
    rescue StandardError => e
      warn "failed to read policy: #{e.class}: #{e.message}"
      exit 2
    end

  findings = evaluate_policy(policy, options[:baseline])

  if options[:json]
    puts JSON.pretty_generate(policy: policy, baseline: options[:baseline], findings: findings)
  else
    puts "winpolicy_audit: #{options[:domain] ? 'domain' : 'local'} account policy"
    policy.each { |k, v| puts "  #{k}: #{v.nil? ? '(never/none)' : v}" }
    puts ''
    if findings.empty?
      puts 'no findings -- policy meets every baseline threshold'
    else
      findings.sort_by { |f| f[:severity] == 'CRIT' ? 0 : 1 }.each { |f| puts "[#{f[:severity]}] #{f[:reason]}" }
      crit = findings.count { |f| f[:severity] == 'CRIT' }
      warn_n = findings.count { |f| f[:severity] == 'WARN' }
      puts "\n#{crit} CRIT, #{warn_n} WARN"
    end
  end

  exit_code =
    if findings.any? { |f| f[:severity] == 'CRIT' }
      2
    elsif findings.any? { |f| f[:severity] == 'WARN' }
      1
    else
      0
    end
  exit exit_code
end
