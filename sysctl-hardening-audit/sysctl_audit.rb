#!/usr/bin/env ruby
# frozen_string_literal: true
#
# sysctl_audit.rb -- Kernel parameter hardening auditor for Linux
#
# Every Linux hardening standard (CIS, STIG, your company's own wiki page)
# eventually boils down to a list of /proc/sys knobs that must hold particular
# values. The knobs are easy to set and even easier to lose: a kernel upgrade
# ships a new default, a container runtime rewrites ip_forward, someone reboots
# a host that only ever had the values applied by hand.
#
# This script reads a declarative YAML policy, reads the LIVE values straight
# out of /proc/sys (not `sysctl -a`, so it works without procps installed),
# compares them with a per-check operator, and reports what drifted. It can
# also emit a ready-to-drop /etc/sysctl.d/ file containing exactly the fixes
# needed -- so remediation is a file you can review, not a shell one-liner you
# have to trust.
#
# Exit codes for cron / CI use:
#   0  fully compliant
#   1  at least one check failed
#   2  the audit could not run
#
# Usage:
#   ruby sysctl_audit.rb --policy policy.yml
#   ruby sysctl_audit.rb --policy policy.yml --min-severity high
#   ruby sysctl_audit.rb --policy policy.yml --json
#   ruby sysctl_audit.rb --policy policy.yml --remediate 99-hardening.conf
#   ruby sysctl_audit.rb --policy policy.yml --root ./fixtures/proc  # offline test
#
# Ruby >= 2.7, stdlib only.

require 'yaml'
require 'json'
require 'optparse'
require 'fileutils'

module SysctlAudit
  VERSION = '1.0.0'
  SEVERITIES = %w[low medium high critical].freeze

  # ---------------------------------------------------------------------------
  # Reading the live kernel. `sysctl -a` is a thin wrapper over this directory,
  # so going straight to the filesystem removes a dependency and lets us point
  # --root at a fixture tree for testing.
  # ---------------------------------------------------------------------------
  class ProcSysReader
    class Missing < StandardError; end

    def initialize(root: '/proc/sys') = @root = root

    # net.ipv4.ip_forward -> <root>/net/ipv4/ip_forward
    def path_for(key) = File.join(@root, key.tr('.', '/'))

    def read(key)
      path = path_for(key)
      raise Missing, "#{key} not present (#{path})" unless File.file?(path)

      # Multi-value knobs (e.g. net.ipv4.tcp_rmem) are tab separated on one
      # line; squeeze all whitespace so comparisons are stable.
      File.read(path).strip.split(/\s+/).join(' ')
    rescue Errno::EACCES
      raise Missing, "#{key} is not readable by uid #{Process.uid}"
    rescue Errno::EIO, Errno::EINVAL
      # A few knobs exist but refuse to be read on some kernels.
      raise Missing, "#{key} exists but the kernel refused the read"
    end

    def available?(key) = File.file?(path_for(key))
  end

  # ---------------------------------------------------------------------------
  # Comparison operators. Keeping these in a lookup table (rather than a case
  # statement buried in the auditor) means adding a new one is a one-line change
  # and the policy file can name any of them.
  # ---------------------------------------------------------------------------
  module Operators
    HANDLERS = {
      # exact string/numeric match -- the common case
      'eq' => ->(actual, want) { numeric?(actual, want) ? f(actual) == f(want) : actual == want.to_s },
      'ne' => ->(actual, want) { actual != want.to_s },
      # "at least this hard" / "at most this loose"
      'gte' => ->(actual, want) { f(actual) >= f(want) },
      'lte' => ->(actual, want) { f(actual) <= f(want) },
      # any of a set of acceptable values
      'in' => ->(actual, want) { Array(want).map(&:to_s).include?(actual) },
      # free-form, for string knobs like kernel.core_pattern
      'match' => ->(actual, want) { Regexp.new(want.to_s) =~ actual ? true : false }
    }.freeze

    def self.f(v) = v.to_s.to_f
    def self.numeric?(*vals) = vals.all? { |v| v.to_s.match?(/\A-?\d+(\.\d+)?\z/) }

    def self.apply(op, actual, want)
      handler = HANDLERS[op]
      raise ArgumentError, "unknown operator '#{op}'" unless handler

      handler.call(actual, want)
    end

    def self.describe(op, want)
      case op
      when 'eq'    then "== #{want}"
      when 'ne'    then "!= #{want}"
      when 'gte'   then ">= #{want}"
      when 'lte'   then "<= #{want}"
      when 'in'    then "one of #{Array(want).join('|')}"
      when 'match' then "=~ /#{want}/"
      else "#{op} #{want}"
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Policy model
  # ---------------------------------------------------------------------------
  #   checks:
  #     - key: net.ipv4.ip_forward
  #       op: eq
  #       value: 0
  #       severity: high
  #       title: IP forwarding disabled
  #       rationale: a non-router host that forwards packets can be used to pivot
  #       skip_if_absent: true
  Check = Struct.new(:key, :op, :value, :severity, :title, :rationale,
                     :skip_if_absent, keyword_init: true) do
    def expectation = Operators.describe(op, value)

    # The literal line we would write into /etc/sysctl.d to satisfy this check.
    # Only meaningful for operators that imply one concrete correct value.
    def remediation_value
      case op
      when 'eq'  then value.to_s
      when 'gte', 'lte' then value.to_s
      when 'in'  then Array(value).first.to_s
      end
    end
  end

  class Policy
    attr_reader :checks, :name

    def initialize(data)
      @name = data['name'] || 'unnamed policy'
      @checks = Array(data['checks']).map do |c|
        sev = (c['severity'] || 'medium').downcase
        raise ArgumentError, "bad severity '#{sev}' on #{c['key']}" unless SEVERITIES.include?(sev)

        Check.new(
          key: c.fetch('key'),
          op: (c['op'] || 'eq').downcase,
          value: c['value'],
          severity: sev,
          title: c['title'] || c.fetch('key'),
          rationale: c['rationale'].to_s,
          skip_if_absent: c.fetch('skip_if_absent', false)
        )
      end
      raise ArgumentError, 'policy contains no checks' if @checks.empty?
    end

    def self.load(path)
      raise ArgumentError, "policy not found: #{path}" unless File.exist?(path)

      new(YAML.safe_load(File.read(path)) || {})
    end
  end

  # ---------------------------------------------------------------------------
  # The audit itself
  # ---------------------------------------------------------------------------
  Result = Struct.new(:status, :key, :title, :severity, :expected, :actual,
                      :rationale, :fix, keyword_init: true)

  class Auditor
    def initialize(policy, reader) = (@policy = policy; @reader = reader)

    def run
      @policy.checks.map { |check| evaluate(check) }
    end

    private

    def evaluate(check)
      actual = @reader.read(check.key)
      ok = Operators.apply(check.op, actual, check.value)

      Result.new(
        status: ok ? 'PASS' : 'FAIL',
        key: check.key, title: check.title, severity: check.severity,
        expected: check.expectation, actual: actual,
        rationale: check.rationale,
        fix: ok ? nil : fix_line(check)
      )
    rescue ProcSysReader::Missing => e
      # A knob can be legitimately absent: IPv6 compiled out, a module not
      # loaded, a container without the netfilter namespace. The policy author
      # decides whether that is acceptable via skip_if_absent.
      Result.new(
        status: check.skip_if_absent ? 'SKIP' : 'ERROR',
        key: check.key, title: check.title, severity: check.severity,
        expected: check.expectation, actual: 'n/a',
        rationale: e.message, fix: nil
      )
    rescue ArgumentError => e
      Result.new(status: 'ERROR', key: check.key, title: check.title,
                 severity: check.severity, expected: check.expectation,
                 actual: 'n/a', rationale: e.message, fix: nil)
    end

    def fix_line(check)
      v = check.remediation_value
      v ? "#{check.key} = #{v}" : nil
    end
  end

  # ---------------------------------------------------------------------------
  # Scoring + output
  # ---------------------------------------------------------------------------
  class Report
    WEIGHT = { 'critical' => 10, 'high' => 5, 'medium' => 2, 'low' => 1 }.freeze
    MARK   = { 'PASS' => '[PASS]', 'FAIL' => '[FAIL]', 'SKIP' => '[SKIP]',
               'ERROR' => '[ERR ]' }.freeze

    def initialize(results, policy_name) = (@results = results; @policy = policy_name)

    def failures = @results.select { |r| r.status == 'FAIL' }
    def counts   = @results.group_by(&:status).transform_values(&:size)

    # Weight the score by severity so ten low-risk misses do not look worse
    # than one critical one.
    def score
      scored = @results.reject { |r| r.status == 'SKIP' }
      return 100 if scored.empty?

      total = scored.sum { |r| WEIGHT.fetch(r.severity, 1) }
      earned = scored.select { |r| r.status == 'PASS' }
                     .sum { |r| WEIGHT.fetch(r.severity, 1) }
      ((earned.to_f / total) * 100).round
    end

    def text
      w = 78
      out = []
      out << '=' * w
      out << "  KERNEL HARDENING AUDIT -- #{@policy}"
      out << "  host=#{host} kernel=#{kernel} #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}"
      out << '=' * w
      out << format('  %-6s %-8s %-34s %-12s %s', 'STATE', 'SEV', 'PARAMETER', 'EXPECTED', 'ACTUAL')
      out << '-' * w

      ordered.each do |r|
        out << format('  %-6s %-8s %-34s %-12s %s', MARK[r.status], r.severity,
                      r.key[0, 34], r.expected.to_s[0, 12], r.actual.to_s[0, 14])
        out << "         reason: #{r.rationale}" if r.status == 'FAIL' && !r.rationale.empty?
        out << "         fix:    #{r.fix}"       if r.fix
      end

      out << '-' * w
      out << "  score: #{score}/100 (severity weighted)   " \
             "#{%w[PASS FAIL SKIP ERROR].map { |s| "#{s.downcase}=#{counts.fetch(s, 0)}" }.join('  ')}"
      out << '=' * w
      out.join("\n")
    end

    def json
      JSON.pretty_generate(
        policy: @policy, host: host, kernel: kernel,
        generated_at: Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ'),
        score: score, summary: counts,
        results: @results.map(&:to_h)
      )
    end

    # A drop-in file for /etc/sysctl.d/. Reviewable, version-controllable,
    # and applied with `sysctl --system` rather than a blind `sysctl -w` loop.
    def remediation_conf
      lines = ["# Generated by sysctl_audit #{VERSION} on #{Time.now.strftime('%Y-%m-%d')}",
               "# Policy: #{@policy}  Host: #{host}",
               '# Review before deploying. Apply with: sudo sysctl --system', '']
      failures.select(&:fix).sort_by { |r| [-Report::WEIGHT.fetch(r.severity, 1), r.key] }
              .each do |r|
        lines << "# [#{r.severity}] #{r.title}"
        lines << "#   #{r.rationale}" unless r.rationale.empty?
        lines << r.fix
        lines << ''
      end
      lines << '# no remediation required' if failures.empty?
      lines.join("\n")
    end

    private

    ORDER = { 'FAIL' => 0, 'ERROR' => 1, 'SKIP' => 2, 'PASS' => 3 }.freeze
    SEV_ORDER = { 'critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3 }.freeze

    def ordered
      @results.sort_by { |r| [ORDER.fetch(r.status, 9), SEV_ORDER.fetch(r.severity, 9), r.key] }
    end

    def host = @host ||= (ENV['HOSTNAME'] || `hostname 2>/dev/null`.strip)
    def kernel = @kernel ||= (File.read('/proc/sys/kernel/osrelease').strip rescue 'unknown')
  end
end

# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  opts = { policy: 'policy.yml', root: '/proc/sys', format: :text, min_severity: 'low' }

  OptionParser.new do |o|
    o.banner = 'Usage: sysctl_audit.rb [options]'
    o.on('-p', '--policy PATH', 'YAML hardening policy')   { |v| opts[:policy] = v }
    o.on('-j', '--json', 'emit JSON')                      { opts[:format] = :json }
    o.on('-r', '--remediate PATH', 'write a sysctl.d conf with the fixes') { |v| opts[:remediate] = v }
    o.on('--root PATH', 'alternate /proc/sys root (testing)') { |v| opts[:root] = v }
    o.on('--min-severity SEV', SysctlAudit::SEVERITIES,
         'only report at or above this severity') { |v| opts[:min_severity] = v }
    o.on('-v', '--version') { puts "sysctl_audit #{SysctlAudit::VERSION}"; exit 0 }
    o.on('-h', '--help')    { puts o; exit 0 }
  end.parse!

  begin
    policy = SysctlAudit::Policy.load(opts[:policy])
    reader = SysctlAudit::ProcSysReader.new(root: opts[:root])
    results = SysctlAudit::Auditor.new(policy, reader).run

    floor = SysctlAudit::SEVERITIES.index(opts[:min_severity])
    results = results.select { |r| SysctlAudit::SEVERITIES.index(r.severity) >= floor }

    report = SysctlAudit::Report.new(results, policy.name)

    if opts[:remediate]
      FileUtils.mkdir_p(File.dirname(opts[:remediate]))
      File.write(opts[:remediate], report.remediation_conf)
      warn "wrote #{report.failures.size} fix(es) to #{opts[:remediate]}"
    end

    puts opts[:format] == :json ? report.json : report.text
    exit(report.failures.empty? ? 0 : 1)
  rescue StandardError => e
    warn "sysctl_audit: #{e.class}: #{e.message}"
    exit 2
  end
end
