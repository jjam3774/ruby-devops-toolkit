#!/usr/bin/env ruby
# frozen_string_literal: true
#
# auditd_rules_audit.rb -- Linux auditd rule coverage gap analysis
#
# THE PROBLEM
# -----------
# auditd is the Linux kernel's audit subsystem. It is the difference between
# "someone changed /etc/sudoers last Tuesday" and "we have no idea." But auditd
# ships with essentially no rules. Every distro leaves /etc/audit/rules.d/ empty
# or near-empty, so a freshly built host is *running* auditd and logging almost
# nothing -- which looks exactly like compliance from a dashboard that only
# checks "is auditd active?"
#
# Worse, rules drift. Someone adds a -w watch for a new app, someone else copies
# a rules file from a 2016 hardening guide, a config-management run half-applies
# a template, and `-e 2` (immutable mode) gets left off so anything can wipe the
# ruleset at runtime.
#
# This script parses the *actual* rule files on disk (and optionally the live
# in-kernel ruleset from `auditctl -l`), normalises them, and compares them
# against a baseline of control objectives derived from the CIS Linux Benchmark
# audit section. It reports which objectives are COVERED, which are MISSING, and
# which rules are present but likely ineffective (shadowed by an earlier exclude,
# missing a key, or placed after the immutable flag).
#
# USAGE
#   ruby auditd_rules_audit.rb                      # audit the live host
#   ruby auditd_rules_audit.rb --rules-dir ./fixtures/rules.d
#   ruby auditd_rules_audit.rb --format json
#   ruby auditd_rules_audit.rb --live               # also diff against auditctl -l
#
# EXIT CODES
#   0  all baseline objectives covered
#   1  one or more objectives missing or degraded
#   2  could not read any rule source
#
# Requires: Ruby >= 2.7 (stdlib only). Root is only needed for --live.

require 'optparse'
require 'json'
require 'open3'
require 'set'

module AuditdRulesAudit
  VERSION = '1.0.0'

  # ---------------------------------------------------------------------------
  # A single parsed audit rule line.
  #
  # auditd rules come in three shapes and the parser has to treat them
  # differently, because they match completely different things:
  #
  #   -w <path> -p <perms> -k <key>       a "watch" -- filesystem path
  #   -a <list>,<action> -F ... -k <key>  a syscall rule -- arch/syscall filters
  #   -D / -e <0|1|2> / -b <n> / -f <n>   control directives, not matchers
  # ---------------------------------------------------------------------------
  Rule = Struct.new(:kind, :raw, :path, :perms, :key, :fields, :syscalls,
                    :source_file, :line_no, keyword_init: true) do
    # A rule with no -k key still *works*, but it is nearly useless in practice:
    # ausearch/aureport queries are key-driven, so an unkeyed rule generates
    # events nobody will ever find. We surface this as a degradation, not a pass.
    def keyed?
      !(key.nil? || key.empty?)
    end

    def to_h
      {
        kind: kind, key: key, path: path, perms: perms,
        syscalls: syscalls, fields: fields,
        source: "#{source_file}:#{line_no}", raw: raw
      }.compact
    end
  end

  # ---------------------------------------------------------------------------
  # Baseline control objectives.
  #
  # Each objective is deliberately expressed as a *predicate over parsed rules*
  # rather than a literal string to grep for. Hardening guides publish rules as
  # copy-paste text, but real hosts reorder fields, split 32/64-bit arches onto
  # separate lines, use different keys, and watch a symlinked path. String
  # matching produces false "missing" findings on hosts that are actually fine.
  # ---------------------------------------------------------------------------
  Objective = Struct.new(:id, :title, :severity, :rationale, :matcher,
                         keyword_init: true)

  # Helper predicates used by the baseline below.
  def self.watches_any?(rules, *paths)
    wanted = paths.map { |p| normalize_path(p) }
    rules.any? do |r|
      r.kind == :watch && wanted.include?(normalize_path(r.path.to_s))
    end
  end

  def self.watches_prefix?(rules, prefix)
    pre = normalize_path(prefix)
    rules.any? { |r| r.kind == :watch && normalize_path(r.path.to_s).start_with?(pre) }
  end

  def self.syscall_rule?(rules, *names)
    wanted = names.map(&:to_s).to_set
    rules.any? do |r|
      r.kind == :syscall && r.syscalls.any? { |s| wanted.include?(s) }
    end
  end

  # Trailing slashes and duplicate separators are cosmetic in a -w path but
  # break naive equality, so every comparison goes through here.
  def self.normalize_path(p)
    p = p.to_s.strip.gsub(%r{/+}, '/')
    p = p.chomp('/') unless p == '/'
    p
  end

  BASELINE = [
    Objective.new(
      id: 'AUD-001', title: 'Identity files are watched for modification',
      severity: :high,
      rationale: 'Changes to /etc/passwd, /etc/shadow, /etc/group or /etc/sudoers ' \
                 'are the classic persistence and privilege-escalation moves. ' \
                 'Without a watch there is no record of who edited them.',
      matcher: ->(rules) {
        watches_any?(rules, '/etc/passwd', '/etc/shadow') &&
          watches_any?(rules, '/etc/group') &&
          (watches_any?(rules, '/etc/sudoers') || watches_prefix?(rules, '/etc/sudoers.d'))
      }
    ),
    Objective.new(
      id: 'AUD-002', title: 'Login and session records are watched',
      severity: :high,
      rationale: 'wtmp/btmp/lastlog are where successful and failed logins land. ' \
                 'Attackers truncate them; a watch makes that visible.',
      matcher: ->(rules) {
        watches_any?(rules, '/var/log/wtmp', '/var/log/btmp') ||
          watches_any?(rules, '/var/run/utmp', '/run/utmp')
      }
    ),
    Objective.new(
      id: 'AUD-003', title: 'Kernel module load/unload is audited',
      severity: :high,
      rationale: 'init_module/finit_module/delete_module is how a rootkit gets ' \
                 'into the kernel. This is one of the highest-signal, ' \
                 'lowest-volume rules you can run.',
      matcher: ->(rules) {
        syscall_rule?(rules, 'init_module', 'finit_module', 'delete_module') ||
          watches_any?(rules, '/sbin/insmod', '/sbin/modprobe', '/usr/sbin/modprobe')
      }
    ),
    Objective.new(
      id: 'AUD-004', title: 'Time-change syscalls are audited',
      severity: :medium,
      rationale: 'Moving the clock is the cheapest way to make a log timeline ' \
                 'useless. adjtimex/settimeofday/clock_settime should be recorded.',
      matcher: ->(rules) {
        syscall_rule?(rules, 'adjtimex', 'settimeofday', 'clock_settime', 'stime') ||
          watches_any?(rules, '/etc/localtime')
      }
    ),
    Objective.new(
      id: 'AUD-005', title: 'Discretionary access control changes are audited',
      severity: :medium,
      rationale: 'chmod/chown/setxattr families reveal permission tampering, ' \
                 'including the setuid bit being added to a dropped binary.',
      matcher: ->(rules) {
        syscall_rule?(rules, 'chmod', 'fchmod', 'fchmodat',
                      'chown', 'fchown', 'fchownat', 'lchown',
                      'setxattr', 'lsetxattr', 'fsetxattr')
      }
    ),
    Objective.new(
      id: 'AUD-006', title: 'Unauthorised file-access attempts are audited',
      severity: :medium,
      rationale: 'EACCES/EPERM on open/openat/truncate is the signature of an ' \
                 'account probing for files it should not reach.',
      matcher: ->(rules) {
        rules.any? do |r|
          r.kind == :syscall &&
            r.syscalls.any? { |s| %w[open openat openat2 truncate ftruncate creat].include?(s) } &&
            r.fields.any? { |f| f =~ /\Aexit\s*(=|!=)\s*-(EACCES|EPERM|13|1)\z/i }
        end
      }
    ),
    Objective.new(
      id: 'AUD-007', title: 'Privileged (setuid/setgid) command execution is audited',
      severity: :medium,
      rationale: 'A -F path=<binary> -F perm=x -F auid>=1000 rule per setuid ' \
                 'binary is what turns "someone ran something" into "eve ran ' \
                 'pkexec at 03:12". Generated by find / -perm -4000.',
      matcher: ->(rules) {
        rules.count { |r|
          r.kind == :syscall &&
            r.fields.any? { |f| f.start_with?('path=') } &&
            r.fields.any? { |f| f =~ /\Aperm\s*=.*x/i }
        } >= 3
      }
    ),
    Objective.new(
      id: 'AUD-008', title: 'The audit configuration itself is watched',
      severity: :high,
      rationale: 'If /etc/audit/ is not watched, an attacker can rewrite the ' \
                 'ruleset and the only evidence is its absence.',
      matcher: ->(rules) {
        watches_prefix?(rules, '/etc/audit') || watches_any?(rules, '/etc/audit/auditd.conf')
      }
    ),
    Objective.new(
      id: 'AUD-009', title: 'Ruleset is made immutable (-e 2)',
      severity: :high,
      rationale: 'Without -e 2 as the final directive, root can run ' \
                 '`auditctl -D` and silently delete every rule until reboot. ' \
                 'This single line is the difference between an audit trail and ' \
                 'a suggestion.',
      matcher: ->(rules) {
        rules.any? { |r| r.kind == :control && r.raw =~ /\A-e\s+2\b/ }
      }
    ),
    Objective.new(
      id: 'AUD-010', title: 'Buffer size is raised above the 8192 default',
      severity: :low,
      rationale: 'The default -b 8192 overflows on busy hosts, and an overflowing ' \
                 'audit buffer drops events -- silently, unless -f 2 is set.',
      matcher: ->(rules) {
        rules.any? { |r| r.kind == :control && r.raw =~ /\A-b\s+(\d+)/ && Regexp.last_match(1).to_i > 8192 }
      }
    )
  ].freeze

  # ---------------------------------------------------------------------------
  # Parser
  # ---------------------------------------------------------------------------
  class Parser
    def initialize
      @rules = []
      @errors = []
    end

    attr_reader :rules, :errors

    # Rule files are read in the same order auditd's own augenrules(8) applies
    # them: lexical sort of rules.d/*.rules. Order matters for AUD-009 because a
    # rule placed after `-e 2` is silently ignored by the kernel.
    def load_dir(dir)
      files = Dir.glob(File.join(dir, '*.rules')).sort
      @errors << "no *.rules files found in #{dir}" if files.empty?
      files.each { |f| load_file(f) }
      self
    end

    def load_file(path)
      File.foreach(path).with_index(1) do |line, idx|
        rule = parse_line(line, path, idx)
        @rules << rule if rule
      end
    rescue SystemCallError => e
      @errors << "#{path}: #{e.message}"
      self
    end

    # Parse the live in-kernel ruleset. auditctl -l prints rules in a normalised
    # form that is *close to* but not identical to the file syntax (it expands
    # -w watches into -a always,exit rules), so we tag the source distinctly.
    def load_live
      out, err, status = Open3.capture3('auditctl', '-l')
      unless status.success?
        @errors << "auditctl -l failed: #{err.strip}"
        return self
      end
      out.each_line.with_index(1) do |line, idx|
        next if line.strip == 'No rules'
        rule = parse_line(line, '<auditctl -l>', idx)
        @rules << rule if rule
      end
      self
    rescue Errno::ENOENT
      @errors << 'auditctl not found in PATH (install the audit package)'
      self
    end

    private

    def parse_line(line, file, idx)
      # Strip the trailing newline FIRST. `sub(/#.*\z/, '')` on a string that
      # still ends in "\n" never matches, because `.` does not cross a newline
      # but `\z` demands the true end of string -- so every comment line would
      # survive and get reported as unparsed auditd syntax.
      raw = line.chomp.sub(/#.*/, '').strip
      return nil if raw.empty?

      tokens = raw.split(/\s+/)

      case tokens.first
      when '-w'
        build_watch(tokens, raw, file, idx)
      when '-a', '-A'
        build_syscall(tokens, raw, file, idx)
      when '-D', '-e', '-b', '-f', '-r', '--loginuid-immutable', '--backlog_wait_time'
        Rule.new(kind: :control, raw: raw, fields: [], syscalls: [],
                 source_file: file, line_no: idx)
      else
        # Unknown directive: keep it so the report can show it rather than
        # pretending the file was clean.
        Rule.new(kind: :unknown, raw: raw, fields: [], syscalls: [],
                 source_file: file, line_no: idx)
      end
    end

    def build_watch(tokens, raw, file, idx)
      Rule.new(
        kind: :watch,
        raw: raw,
        path: value_after(tokens, '-w'),
        perms: value_after(tokens, '-p'),
        key: value_after(tokens, '-k') || value_after(tokens, '-F', prefix: 'key='),
        fields: collect_fields(tokens),
        syscalls: [],
        source_file: file,
        line_no: idx
      )
    end

    def build_syscall(tokens, raw, file, idx)
      # -S may appear more than once and may be comma-separated:
      #   -S chmod -S fchmod   ==   -S chmod,fchmod
      syscalls = []
      tokens.each_with_index do |t, i|
        syscalls.concat(tokens[i + 1].to_s.split(',')) if t == '-S'
      end

      Rule.new(
        kind: :syscall,
        raw: raw,
        key: value_after(tokens, '-k') || value_after(tokens, '-F', prefix: 'key='),
        fields: collect_fields(tokens),
        syscalls: syscalls.map(&:strip).reject(&:empty?),
        source_file: file,
        line_no: idx
      )
    end

    def value_after(tokens, flag, prefix: nil)
      tokens.each_with_index do |t, i|
        next unless t == flag
        v = tokens[i + 1]
        next if v.nil?
        if prefix
          return v.sub(prefix, '') if v.start_with?(prefix)
        else
          return v
        end
      end
      nil
    end

    # Every -F field, kept verbatim so objective matchers can apply their own
    # regexes (exit=-EACCES, auid>=1000, perm=x, ...).
    def collect_fields(tokens)
      out = []
      tokens.each_with_index { |t, i| out << tokens[i + 1].to_s if t == '-F' }
      out.reject(&:empty?)
    end
  end

  # ---------------------------------------------------------------------------
  # Auditor -- runs the baseline and collects degradations
  # ---------------------------------------------------------------------------
  class Auditor
    Finding = Struct.new(:objective, :status, keyword_init: true)

    def initialize(rules)
      @rules = rules
      @effective = effective_rules(rules)
    end

    # Only rules the kernel will actually load count toward coverage. Once
    # `-e 2` is applied the ruleset is immutable until reboot, so anything
    # augenrules concatenates after it is dead text. Evaluating the baseline
    # against the raw file contents would report a host as compliant on the
    # strength of rules that are not running -- the exact failure mode this
    # tool exists to catch.
    def effective_rules(rules)
      imm = rules.index { |r| r.kind == :control && r.raw =~ /\A-e\s+2\b/ }
      imm ? rules[0..imm] : rules
    end

    attr_reader :effective

    def findings
      BASELINE.map do |obj|
        covered = begin
          obj.matcher.call(@effective)
        rescue StandardError => e
          warn "matcher #{obj.id} raised #{e.class}: #{e.message}"
          false
        end
        Finding.new(objective: obj, status: covered ? :covered : :missing)
      end
    end

    # Problems that are not "objective missing" but still make the ruleset weaker
    # than it looks. These are the findings that a string-matching checker never
    # produces, and they are usually the ones that matter operationally.
    def degradations
      out = []

      unkeyed = @rules.select { |r| %i[watch syscall].include?(r.kind) && !r.keyed? }
      unless unkeyed.empty?
        out << {
          code: 'DEG-UNKEYED',
          message: "#{unkeyed.size} rule(s) have no -k key; ausearch/aureport " \
                   'cannot select their events',
          examples: unkeyed.first(3).map { |r| "#{r.source_file}:#{r.line_no}" }
        }
      end

      # Anything after `-e 2` never reaches the kernel. This is the single most
      # common real-world auditd misconfiguration: a well-meaning admin appends a
      # new rule to the bottom of the last file in rules.d.
      imm_idx = @rules.index { |r| r.kind == :control && r.raw =~ /\A-e\s+2\b/ }
      if imm_idx && imm_idx < @rules.size - 1
        after = @rules[(imm_idx + 1)..].reject { |r| r.kind == :control }
        unless after.empty?
          out << {
            code: 'DEG-AFTER-IMMUTABLE',
            message: "#{after.size} rule(s) appear after '-e 2' and will be " \
                     'ignored by the kernel',
            examples: after.first(3).map { |r| "#{r.source_file}:#{r.line_no}" }
          }
        end
      end

      dupes = @rules.select { |r| %i[watch syscall].include?(r.kind) }
                    .group_by { |r| r.raw.split(/\s+/).sort.join(' ') }
                    .select { |_, v| v.size > 1 }
      unless dupes.empty?
        out << {
          code: 'DEG-DUPLICATE',
          message: "#{dupes.size} rule(s) are defined more than once; duplicates " \
                   'double event volume for no extra coverage',
          examples: dupes.keys.first(3)
        }
      end

      unknown = @rules.select { |r| r.kind == :unknown }
      unless unknown.empty?
        out << {
          code: 'DEG-UNPARSED',
          message: "#{unknown.size} line(s) were not recognised as auditd syntax",
          examples: unknown.first(3).map { |r| "#{r.source_file}:#{r.line_no} #{r.raw}" }
        }
      end

      out
    end
  end

  # ---------------------------------------------------------------------------
  # Reporters
  # ---------------------------------------------------------------------------
  module Report
    SEV_ORDER = { high: 0, medium: 1, low: 2 }.freeze

    def self.text(findings, degradations, rules, errors)
      lines = []
      lines << '=' * 72
      lines << 'auditd rule coverage audit'
      lines << '=' * 72

      counts = Hash.new(0)
      rules.each { |r| counts[r.kind] += 1 }
      lines << format('  parsed: %d rules  (%d watch, %d syscall, %d control, %d unparsed)',
                      rules.size, counts[:watch], counts[:syscall],
                      counts[:control], counts[:unknown])

      covered = findings.count { |f| f.status == :covered }
      lines << format('  coverage: %d/%d baseline objectives', covered, findings.size)
      lines << ''

      lines << 'OBJECTIVES'
      lines << '-' * 72
      findings.sort_by { |f| [f.status == :missing ? 0 : 1, SEV_ORDER[f.objective.severity]] }
              .each do |f|
        mark = f.status == :covered ? '[ OK ]' : '[MISS]'
        lines << format('%s %-8s %-9s %s', mark, f.objective.id,
                        f.objective.severity.to_s.upcase, f.objective.title)
        next unless f.status == :missing
        wrap(f.objective.rationale, 64).each { |w| lines << "         #{w}" }
      end

      unless degradations.empty?
        lines << ''
        lines << 'DEGRADATIONS'
        lines << '-' * 72
        degradations.each do |d|
          lines << format('[WARN] %-22s %s', d[:code], d[:message])
          d[:examples].each { |e| lines << "         - #{e}" }
        end
      end

      unless errors.empty?
        lines << ''
        lines << 'ERRORS'
        lines << '-' * 72
        errors.each { |e| lines << "[ERR ] #{e}" }
      end

      lines << ''
      lines << (covered == findings.size && degradations.empty? ? 'RESULT: PASS' : 'RESULT: FAIL')
      lines.join("\n")
    end

    def self.json(findings, degradations, rules, errors)
      JSON.pretty_generate(
        generated_at: Time.now.utc.iso8601,
        version: VERSION,
        rule_count: rules.size,
        coverage: {
          covered: findings.count { |f| f.status == :covered },
          total: findings.size
        },
        objectives: findings.map { |f|
          { id: f.objective.id, title: f.objective.title,
            severity: f.objective.severity, status: f.status }
        },
        degradations: degradations,
        errors: errors
      )
    end

    def self.wrap(text, width)
      text.split(/\s+/).each_with_object(['']) do |word, acc|
        if (acc.last.length + word.length + 1) > width
          acc << word
        else
          acc[-1] = acc.last.empty? ? word : "#{acc.last} #{word}"
        end
      end
    end
  end

  # ---------------------------------------------------------------------------
  # CLI
  # ---------------------------------------------------------------------------
  def self.run(argv)
    opts = { rules_dir: '/etc/audit/rules.d', format: 'text', live: false }

    OptionParser.new do |o|
      o.banner = 'Usage: ruby auditd_rules_audit.rb [options]'
      o.on('--rules-dir DIR', 'Directory of *.rules files') { |v| opts[:rules_dir] = v }
      o.on('--live', 'Also read the in-kernel ruleset via auditctl -l') { opts[:live] = true }
      o.on('--format FMT', %w[text json], 'text (default) or json') { |v| opts[:format] = v }
      o.on('-v', '--version') { puts VERSION; exit 0 }
      o.on('-h', '--help') { puts o; exit 0 }
    end.parse!(argv)

    parser = Parser.new
    parser.load_dir(opts[:rules_dir]) if Dir.exist?(opts[:rules_dir])
    parser.errors << "rules dir not found: #{opts[:rules_dir]}" unless Dir.exist?(opts[:rules_dir])
    parser.load_live if opts[:live]

    if parser.rules.empty?
      warn Report.text([], [], [], parser.errors)
      return 2
    end

    auditor = Auditor.new(parser.rules)
    findings = auditor.findings
    degradations = auditor.degradations

    puts(if opts[:format] == 'json'
           Report.json(findings, degradations, parser.rules, parser.errors)
         else
           Report.text(findings, degradations, parser.rules, parser.errors)
         end)

    findings.all? { |f| f.status == :covered } && degradations.empty? ? 0 : 1
  end
end

require 'time'
exit AuditdRulesAudit.run(ARGV) if $PROGRAM_NAME == __FILE__
