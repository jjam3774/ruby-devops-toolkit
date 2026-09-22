#!/usr/bin/env ruby
# frozen_string_literal: true
#
# pam_stack_audit.rb -- Audit Linux PAM stacks for policy gaps and ordering bugs.
#
# PAM (Pluggable Authentication Modules) decides who gets to log in and under
# what conditions. The rules live in /etc/pam.d/<service>, one file per service
# (sshd, login, sudo, su, ...). Each line is:
#
#     <type>  <control>  <module>  [args...]
#
# Two things go wrong on real fleets:
#
#   1. A required hardening module simply isn't there -- no pam_faillock, so
#      brute force attempts are never throttled; no pam_pwquality, so users
#      pick "Password1".
#   2. The modules ARE there, but in the wrong order. PAM evaluates a stack
#      top to bottom, and a "sufficient" result that succeeds short-circuits
#      every rule below it. A pam_unix marked "sufficient" placed above
#      pam_faillock means the lockout counter is never consulted.
#
# Neither problem shows up in a package inventory or a config-management diff,
# because the file exists and the package is installed. You have to parse the
# stack and reason about it.
#
# This script does that: it reads every service file, resolves @include and
# `substack` directives, evaluates a rule set of policy checks, and prints a
# findings report. It is READ-ONLY -- it never edits a PAM file, because a bad
# PAM edit locks you out of your own box.
#
# Usage:
#   ruby pam_stack_audit.rb                        # audit /etc/pam.d
#   ruby pam_stack_audit.rb --dir ./fixtures/pam.d # audit a captured copy
#   ruby pam_stack_audit.rb --service sshd --service sudo
#   ruby pam_stack_audit.rb --format json
#   ruby pam_stack_audit.rb --fail-on high         # exit 1 if any high finding
#
# Exit codes: 0 = clean (or below --fail-on threshold), 1 = findings at or above
# threshold, 2 = could not read the PAM directory.

require 'optparse'
require 'json'
require 'set'

# ---------------------------------------------------------------------------
# A single parsed PAM rule.
# ---------------------------------------------------------------------------
PamRule = Struct.new(
  :service,   # "sshd"
  :file,      # path the rule was read from (may differ from service via include)
  :lineno,    # 1-based line number in that file
  :type,      # auth | account | password | session (may carry a leading "-")
  :control,   # required | requisite | sufficient | optional | [success=1 ...]
  :module,    # pam_unix.so
  :args,      # ["try_first_pass", "nullok"]
  :raw,       # the original line, for quoting in findings
  keyword_init: true
)

# A finding: one policy problem in one service stack.
Finding = Struct.new(:severity, :service, :check, :message, :evidence, keyword_init: true)

SEVERITY_ORDER = { 'high' => 3, 'medium' => 2, 'low' => 1 }.freeze

# ---------------------------------------------------------------------------
# Parser: turns /etc/pam.d into a { service => [PamRule, ...] } map.
# ---------------------------------------------------------------------------
class PamParser
  VALID_TYPES = %w[auth account password session].freeze

  def initialize(dir)
    @dir = dir
    @cache = {}
  end

  # Returns the service names available in the directory.
  def services
    Dir.children(@dir)
       .reject { |f| f.start_with?('.') || f.end_with?('~', '.bak', '.rpmsave', '.dpkg-old') }
       .select { |f| File.file?(File.join(@dir, f)) }
       .sort
  end

  # Fully resolved rule list for a service, with @include / substack expanded.
  # `seen` guards against a config that includes itself (PAM would loop too).
  def rules_for(service, seen = Set.new)
    return @cache[service] if @cache.key?(service)

    path = File.join(@dir, service)
    return [] unless File.file?(path)
    return [] if seen.include?(service) # cycle -- stop descending

    seen = seen | [service]
    rules = []

    File.readlines(path, chomp: true).each_with_index do |line, idx|
      lineno = idx + 1
      stripped = line.sub(/#.*\z/, '').strip
      next if stripped.empty?

      # "@include common-auth" pulls in the whole of another file, all types.
      if stripped.start_with?('@include')
        target = stripped.split(/\s+/)[1]
        rules.concat(rules_for(target, seen)) if target
        next
      end

      tokens = tokenize(stripped)
      next if tokens.size < 3

      type = tokens.shift
      # A leading "-" means "skip silently if the module isn't installed".
      bare_type = type.sub(/\A-/, '')
      next unless VALID_TYPES.include?(bare_type)

      control = read_control(tokens)
      mod = tokens.shift
      next if mod.nil?

      # "session include common-session" / "auth substack password-auth" splice
      # in only the matching type from another file.
      if %w[include substack].include?(control)
        included = rules_for(mod, seen).select { |r| r.type.sub(/\A-/, '') == bare_type }
        rules.concat(included)
        next
      end

      rules << PamRule.new(
        service: service, file: path, lineno: lineno,
        type: type, control: control, module: mod, args: tokens,
        raw: line.strip
      )
    end

    @cache[service] = rules
  end

  private

  def tokenize(line)
    line.split(/\s+/)
  end

  # The control field is either a single word or a bracketed expression such as
  # [success=1 default=ignore]. Bracketed forms are joined back into one token.
  def read_control(tokens)
    first = tokens.shift
    return first unless first.start_with?('[')

    parts = [first]
    parts << tokens.shift until parts.last.nil? || parts.last.end_with?(']')
    parts.compact.join(' ')
  end
end

# ---------------------------------------------------------------------------
# Rule engine: each check inspects one service's resolved stack.
# ---------------------------------------------------------------------------
class PamAuditor
  # Services where an interactive human authenticates -- these are the ones
  # that need lockout and password quality. Auditing "cups" for faillock is
  # noise, so we scope the checks.
  INTERACTIVE = %w[sshd login system-auth common-auth password-auth sudo su gdm-password lightdm].freeze

  def initialize(parser)
    @parser = parser
  end

  def audit(service)
    rules = @parser.rules_for(service)
    return [] if rules.empty?

    findings = []
    findings.concat(check_short_circuit(service, rules))
    findings.concat(check_faillock(service, rules))
    findings.concat(check_pwquality(service, rules))
    findings.concat(check_nullok(service, rules))
    findings.concat(check_weak_hash(service, rules))
    findings.concat(check_pam_permit(service, rules))
    findings
  end

  private

  def auth_rules(rules)
    rules.select { |r| r.type.sub(/\A-/, '') == 'auth' }
  end

  def password_rules(rules)
    rules.select { |r| r.type.sub(/\A-/, '') == 'password' }
  end

  # ---- Check 1: a "sufficient" rule above a security module -----------------
  # If pam_unix is sufficient and succeeds, PAM returns success immediately and
  # every later auth rule -- including pam_faillock's counter -- is skipped.
  def check_short_circuit(service, rules)
    auth = auth_rules(rules)
    out = []

    auth.each_with_index do |rule, i|
      next unless rule.control == 'sufficient'

      later_guards = auth[(i + 1)..].to_a.select do |r|
        r.module =~ /pam_(faillock|tally2|succeed_if|access|time)\.so/
      end
      next if later_guards.empty?

      names = later_guards.map(&:module).uniq.join(', ')
      out << Finding.new(
        severity: 'high', service: service, check: 'auth.short_circuit',
        message: "#{rule.module} is 'sufficient' and sits above #{names}; " \
                 'a successful password skips those modules entirely.',
        evidence: "#{rule.file}:#{rule.lineno}: #{rule.raw}"
      )
    end
    out
  end

  # ---- Check 2: brute-force lockout present and complete --------------------
  # pam_faillock needs TWO auth entries to work: a "preauth" that checks the
  # counter before the password is tried, and an "authfail" that increments it
  # after a failure. One without the other is a half-built lock.
  def check_faillock(service, rules)
    return [] unless INTERACTIVE.include?(service)

    auth = auth_rules(rules)
    lock = auth.select { |r| r.module =~ /pam_(faillock|tally2)\.so/ }

    if lock.empty?
      return [Finding.new(
        severity: 'high', service: service, check: 'auth.no_lockout',
        message: 'No pam_faillock (or legacy pam_tally2) in the auth stack; ' \
                 'failed password attempts are never counted or throttled.',
        evidence: "#{auth.size} auth rule(s), none of them a lockout module"
      )]
    end

    out = []
    has_preauth  = lock.any? { |r| r.args.include?('preauth') }
    has_authfail = lock.any? { |r| r.args.include?('authfail') }

    if has_preauth ^ has_authfail
      missing = has_preauth ? 'authfail' : 'preauth'
      out << Finding.new(
        severity: 'high', service: service, check: 'auth.faillock_incomplete',
        message: "pam_faillock is present but the '#{missing}' entry is missing; " \
                 'the counter is only half-wired and lockout will not take effect.',
        evidence: lock.map { |r| "#{r.file}:#{r.lineno}: #{r.raw}" }.join(' | ')
      )
    end

    # deny=0 disables the lock while looking configured.
    lock.each do |r|
      deny = r.args.find { |a| a.start_with?('deny=') }
      next unless deny

      n = deny.split('=', 2).last.to_i
      if n.zero?
        out << Finding.new(
          severity: 'high', service: service, check: 'auth.faillock_deny_zero',
          message: 'pam_faillock has deny=0, which disables lockout entirely.',
          evidence: "#{r.file}:#{r.lineno}: #{r.raw}"
        )
      elsif n > 10
        out << Finding.new(
          severity: 'medium', service: service, check: 'auth.faillock_deny_high',
          message: "pam_faillock deny=#{n} is permissive; most baselines use 3-5.",
          evidence: "#{r.file}:#{r.lineno}: #{r.raw}"
        )
      end
    end
    out
  end

  # ---- Check 3: password quality enforcement -------------------------------
  def check_pwquality(service, rules)
    return [] unless %w[system-auth common-password password-auth passwd].include?(service)

    pw = password_rules(rules)
    quality = pw.select { |r| r.module =~ /pam_(pwquality|cracklib)\.so/ }

    if quality.empty?
      return [Finding.new(
        severity: 'medium', service: service, check: 'password.no_quality',
        message: 'No pam_pwquality/pam_cracklib in the password stack; ' \
                 'users can set trivially guessable passwords.',
        evidence: "#{pw.size} password rule(s), none enforcing quality"
      )]
    end

    out = []
    quality.each do |r|
      minlen = r.args.find { |a| a.start_with?('minlen=') }
      next unless minlen

      n = minlen.split('=', 2).last.to_i
      next if n >= 12

      out << Finding.new(
        severity: 'medium', service: service, check: 'password.minlen_low',
        message: "pam_pwquality minlen=#{n} is below the commonly required 12.",
        evidence: "#{r.file}:#{r.lineno}: #{r.raw}"
      )
    end
    out
  end

  # ---- Check 4: nullok lets empty passwords through ------------------------
  def check_nullok(service, rules)
    rules.select { |r| r.args.any? { |a| a == 'nullok' || a == 'nullok_secure' } }
         .map do |r|
      Finding.new(
        severity: 'high', service: service, check: 'auth.nullok',
        message: "#{r.module} accepts accounts with an empty password (#{r.args.grep(/nullok/).first}).",
        evidence: "#{r.file}:#{r.lineno}: #{r.raw}"
      )
    end
  end

  # ---- Check 5: password hashing algorithm ---------------------------------
  def check_weak_hash(service, rules)
    out = []
    password_rules(rules).select { |r| r.module =~ /pam_unix\.so/ }.each do |r|
      algos = r.args & %w[md5 des bigcrypt sha256 sha512 yescrypt gost_yescrypt blowfish]
      if algos.empty?
        out << Finding.new(
          severity: 'low', service: service, check: 'password.hash_unset',
          message: 'pam_unix specifies no hashing algorithm; the crypt default ' \
                   'applies and may be weaker than sha512/yescrypt.',
          evidence: "#{r.file}:#{r.lineno}: #{r.raw}"
        )
      elsif (algos & %w[md5 des bigcrypt]).any?
        out << Finding.new(
          severity: 'high', service: service, check: 'password.weak_hash',
          message: "pam_unix stores passwords with #{(algos & %w[md5 des bigcrypt]).join(', ')}, " \
                   'which is trivially crackable. Use sha512 or yescrypt.',
          evidence: "#{r.file}:#{r.lineno}: #{r.raw}"
        )
      end
    end
    out
  end

  # ---- Check 6: pam_permit in an auth stack --------------------------------
  # pam_permit always returns success. Required+pam_permit at the top of an
  # auth stack is an authentication bypass. It shows up in hand-hacked configs
  # and in debugging left behind after an outage.
  def check_pam_permit(service, rules)
    auth_rules(rules)
      .select { |r| r.module =~ /pam_permit\.so/ && %w[required sufficient].include?(r.control) }
      .map do |r|
      Finding.new(
        severity: 'high', service: service, check: 'auth.pam_permit',
        message: "pam_permit.so with control '#{r.control}' in the auth stack " \
                 'unconditionally succeeds -- this is an authentication bypass.',
        evidence: "#{r.file}:#{r.lineno}: #{r.raw}"
      )
    end
  end
end

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
class Reporter
  COLORS = { 'high' => "\e[31m", 'medium' => "\e[33m", 'low' => "\e[36m" }.freeze
  RESET = "\e[0m"

  def initialize(color: $stdout.tty?)
    @color = color
  end

  def text(findings, services_audited, dir)
    lines = []
    lines << "PAM stack audit -- #{dir}"
    lines << "services audited: #{services_audited}   findings: #{findings.size}"
    lines << '-' * 72

    if findings.empty?
      lines << 'OK  no policy gaps detected'
      return lines.join("\n")
    end

    findings.group_by(&:service).sort.each do |service, group|
      lines << ""
      lines << "[#{service}]"
      group.sort_by { |f| -SEVERITY_ORDER.fetch(f.severity, 0) }.each do |f|
        tag = paint(f.severity.upcase.ljust(6), f.severity)
        lines << "  #{tag} #{f.check}"
        lines << "         #{f.message}"
        lines << "         -> #{f.evidence}"
      end
    end

    lines << ""
    lines << '-' * 72
    counts = findings.group_by(&:severity)
                     .transform_values(&:size)
                     .sort_by { |sev, _| -SEVERITY_ORDER.fetch(sev, 0) }
                     .map { |sev, n| "#{sev}=#{n}" }
                     .join('  ')
    lines << "summary: #{counts}"
    lines.join("\n")
  end

  def json(findings, services_audited, dir)
    JSON.pretty_generate(
      generated_at: Time.now.utc.iso8601,
      pam_dir: dir,
      services_audited: services_audited,
      finding_count: findings.size,
      findings: findings.map(&:to_h)
    )
  end

  private

  def paint(text, severity)
    return text unless @color

    "#{COLORS.fetch(severity, '')}#{text}#{RESET}"
  end
end

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv)
  require 'time'

  opts = { dir: '/etc/pam.d', services: [], format: 'text', fail_on: nil }

  OptionParser.new do |o|
    o.banner = 'Usage: ruby pam_stack_audit.rb [options]'
    o.on('--dir DIR', 'PAM directory to audit (default /etc/pam.d)') { |v| opts[:dir] = v }
    o.on('--service NAME', 'Audit only this service (repeatable)') { |v| opts[:services] << v }
    o.on('--format FMT', %w[text json], 'text (default) or json') { |v| opts[:format] = v }
    o.on('--fail-on LEVEL', %w[high medium low], 'Exit 1 at/above this severity') { |v| opts[:fail_on] = v }
    o.on('-h', '--help') { puts o; exit 0 }
  end.parse!(argv)

  unless File.directory?(opts[:dir]) && File.readable?(opts[:dir])
    warn "error: cannot read PAM directory #{opts[:dir]} (try sudo)"
    return 2
  end

  parser = PamParser.new(opts[:dir])
  auditor = PamAuditor.new(parser)

  targets = opts[:services].empty? ? parser.services : opts[:services]
  findings = targets.flat_map { |s| auditor.audit(s) }

  reporter = Reporter.new
  puts(opts[:format] == 'json' ? reporter.json(findings, targets.size, opts[:dir])
                               : reporter.text(findings, targets.size, opts[:dir]))

  if opts[:fail_on]
    threshold = SEVERITY_ORDER.fetch(opts[:fail_on])
    return 1 if findings.any? { |f| SEVERITY_ORDER.fetch(f.severity, 0) >= threshold }
  end
  0
end

exit(main(ARGV)) if __FILE__ == $PROGRAM_NAME
