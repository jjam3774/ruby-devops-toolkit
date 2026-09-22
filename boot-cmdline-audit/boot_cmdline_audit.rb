#!/usr/bin/env ruby
# frozen_string_literal: true
#
# boot_cmdline_audit.rb -- Reconcile the RUNNING kernel command line against the
# CONFIGURED one, and check both against a hardening baseline.
#
# The problem this solves:
#
# Kernel boot parameters are where a lot of security and reliability settings
# actually live -- audit=1, slab_nomerge, init_on_alloc=1, iommu=force,
# panic_on_oops=1, and so on. They are set in /etc/default/grub (or a drop-in
# under /etc/default/grub.d/), compiled into the bootloader config by
# update-grub / grub2-mkconfig, and only take effect after a reboot.
#
# That creates a gap nothing else catches:
#
#   * Config management writes the parameter into /etc/default/grub and reports
#     "converged". The kernel running right now still doesn't have it.
#   * Someone edits the GRUB menu entry at boot for a one-off recovery and the
#     box keeps running that way for eight months.
#   * A vendor kernel update rewrites grub.cfg and silently drops a parameter.
#
# /proc/cmdline is ground truth for what the kernel booted with. /etc/default/grub
# is intent. This script diffs the two, and separately grades the running line
# against a hardening baseline, so you can tell "wrong config" apart from
# "right config, needs a reboot".
#
# It is read-only. It never touches grub.cfg -- a bad bootloader edit costs you
# a console trip.
#
# Usage:
#   ruby boot_cmdline_audit.rb
#   ruby boot_cmdline_audit.rb --cmdline ./fixtures/proc_cmdline \
#                              --grub-default ./fixtures/default_grub
#   ruby boot_cmdline_audit.rb --format json
#   ruby boot_cmdline_audit.rb --baseline ./my-baseline.json
#   ruby boot_cmdline_audit.rb --fail-on high
#
# Exit codes: 0 = clean, 1 = findings at/above --fail-on, 2 = cannot read inputs.

require 'optparse'
require 'json'
require 'time'

Finding = Struct.new(:severity, :category, :message, :evidence, keyword_init: true)
SEVERITY_ORDER = { 'high' => 3, 'medium' => 2, 'low' => 1 }.freeze

# ---------------------------------------------------------------------------
# Parsing a kernel command line.
#
# The format is space-separated tokens that are either bare flags ("quiet",
# "ro") or key=value ("root=UUID=...", "console=ttyS0,115200"). Values may be
# double-quoted and may themselves contain spaces, so a naive String#split is
# wrong. We scan character by character and track quote state.
# ---------------------------------------------------------------------------
module CmdlineParser
  module_function

  def tokenize(line)
    tokens = []
    buf = +''
    in_quote = false

    line.to_s.each_char do |ch|
      if ch == '"'
        in_quote = !in_quote
      elsif ch =~ /\s/ && !in_quote
        tokens << buf unless buf.empty?
        buf = +''
      else
        buf << ch
      end
    end
    tokens << buf unless buf.empty?
    tokens
  end

  # Returns { "audit" => "1", "quiet" => nil, ... }.
  # A parameter can legitimately appear twice (the last one usually wins in the
  # kernel), so we also hand back the duplicates for reporting.
  def parse(line)
    params = {}
    dupes = []

    tokenize(line).each do |tok|
      key, value = tok.split('=', 2)
      dupes << key if params.key?(key)
      params[key] = value
    end
    [params, dupes.uniq]
  end
end

# ---------------------------------------------------------------------------
# Reading the configured command line out of /etc/default/grub plus drop-ins.
#
# The file is shell syntax. We only care about two assignments:
#   GRUB_CMDLINE_LINUX="..."           -- applied to every entry
#   GRUB_CMDLINE_LINUX_DEFAULT="..."   -- applied to normal (non-recovery) entries
# A drop-in in /etc/default/grub.d/*.cfg that assigns the same variable wins,
# because those are sourced after the main file.
# ---------------------------------------------------------------------------
class GrubDefaults
  ASSIGN = /\A\s*(GRUB_CMDLINE_LINUX(?:_DEFAULT)?)\s*=\s*(.*)\z/.freeze

  attr_reader :values, :sources

  def initialize(path, dropin_dir = nil)
    @values = {}   # var name => value string
    @sources = {}  # var name => file it last came from

    load_file(path) if path && File.file?(path)

    return unless dropin_dir && File.directory?(dropin_dir)

    Dir.glob(File.join(dropin_dir, '*.cfg')).sort.each { |f| load_file(f) }
  end

  # The effective line for a normal boot is LINUX + LINUX_DEFAULT.
  def effective
    [@values['GRUB_CMDLINE_LINUX'], @values['GRUB_CMDLINE_LINUX_DEFAULT']]
      .compact.reject(&:empty?).join(' ')
  end

  def found?
    !@values.empty?
  end

  private

  def load_file(path)
    File.readlines(path, chomp: true).each do |line|
      next if line.strip.start_with?('#')

      m = ASSIGN.match(line)
      next unless m

      @values[m[1]] = unquote(m[2].sub(/\s+#.*\z/, '').strip)
      @sources[m[1]] = path
    end
  rescue SystemCallError => e
    warn "warn: cannot read #{path}: #{e.message}"
  end

  def unquote(str)
    if (str.start_with?('"') && str.end_with?('"')) ||
       (str.start_with?("'") && str.end_with?("'"))
      str[1..-2].to_s
    else
      str
    end
  end
end

# ---------------------------------------------------------------------------
# The hardening baseline.
#
# Each entry says: this parameter should be present, and (optionally) should
# equal this value. Severity reflects how much you lose without it.
# Ship your own with --baseline; this is a sane starting set drawn from the
# common Linux hardening guidance.
# ---------------------------------------------------------------------------
DEFAULT_BASELINE = [
  { 'param' => 'audit',          'value' => '1',    'severity' => 'high',
    'why'   => 'auditd cannot capture events that happen before it starts unless the kernel audit subsystem is enabled at boot.' },
  { 'param' => 'audit_backlog_limit', 'value' => nil, 'severity' => 'medium',
    'why'   => 'without a raised backlog the audit queue overflows during a burst and events are silently dropped.' },
  { 'param' => 'slab_nomerge',   'value' => nil,    'severity' => 'medium',
    'why'   => 'merging slab caches makes heap-overflow exploitation easier by letting an attacker groom an unrelated cache.' },
  { 'param' => 'init_on_alloc',  'value' => '1',    'severity' => 'medium',
    'why'   => 'zeroing pages on allocation removes a large class of uninitialised-memory information leaks.' },
  { 'param' => 'page_alloc.shuffle', 'value' => '1', 'severity' => 'low',
    'why'   => 'randomising the free list makes physical memory layout less predictable.' },
  { 'param' => 'panic_on_oops',  'value' => '1',    'severity' => 'low',
    'why'   => 'a machine that keeps running after an oops produces corrupt data instead of a clean, alertable reboot.' }
].freeze

# Parameters that are actively dangerous when present on a production host.
DANGEROUS = {
  'selinux'       => { 'bad' => '0', 'severity' => 'high',
                       'why' => 'SELinux disabled at the kernel level; no MAC policy is enforced.' },
  'enforcing'     => { 'bad' => '0', 'severity' => 'high',
                       'why' => 'SELinux booted permissive; policy violations are logged but allowed.' },
  'apparmor'      => { 'bad' => '0', 'severity' => 'high',
                       'why' => 'AppArmor disabled at the kernel level; profiles are not enforced.' },
  'mitigations'   => { 'bad' => 'off', 'severity' => 'high',
                       'why' => 'all CPU speculative-execution mitigations disabled (Spectre/Meltdown/MDS).' },
  'nokaslr'       => { 'bad' => nil,  'severity' => 'high',
                       'why' => 'kernel address space layout randomisation disabled; kernel symbol addresses are predictable.' },
  'init_on_free'  => { 'bad' => '0',  'severity' => 'low',
                       'why' => 'freed memory is not zeroed, leaving data recoverable from reused pages.' },
  'noexec'        => { 'bad' => 'off', 'severity' => 'medium',
                       'why' => 'NX/DEP disabled; data pages become executable.' },
  'debug'         => { 'bad' => nil,  'severity' => 'low',
                       'why' => 'verbose kernel debug output left enabled; noisy logs and slower boot.' },
  'systemd.unit'  => { 'bad' => 'rescue.target', 'severity' => 'high',
                       'why' => 'the host booted into rescue mode -- almost certainly a leftover from a recovery session.' }
}.freeze

# Parameters that are host-specific, or injected by the bootloader itself, and
# should never be diffed as "drift". `ro`/`rw` are in here because GRUB appends
# the root mount mode to every generated entry -- without this exclusion every
# single host reports a false "unmanaged" finding. (Found while testing this
# script against a real /proc/cmdline; see the Troubleshooting section.)
VOLATILE = %w[root rootflags rootfstype ro rw resume resume_offset BOOT_IMAGE
              initrd crashkernel console earlyprintk ip nfsroot cryptdevice
              rd.luks.uuid rd.lvm.lv rd.md.uuid].freeze

# ---------------------------------------------------------------------------
# The auditor.
# ---------------------------------------------------------------------------
class BootAuditor
  def initialize(running_line, configured_line, baseline)
    @running_line = running_line.to_s.strip
    @configured_line = configured_line.to_s.strip
    @baseline = baseline
    @running, @running_dupes = CmdlineParser.parse(@running_line)
    @configured, = CmdlineParser.parse(@configured_line)
  end

  attr_reader :running, :configured

  def findings
    out = []
    out.concat(drift_findings)
    out.concat(baseline_findings)
    out.concat(dangerous_findings)
    out.concat(hygiene_findings)
    out
  end

  private

  # ---- Drift: configured but not running, and running but not configured ----
  def drift_findings
    return [] if @configured_line.empty?

    out = []

    (@configured.keys - @running.keys - VOLATILE).sort.each do |key|
      out << Finding.new(
        severity: 'high', category: 'drift.pending_reboot',
        message: "'#{fmt(key, @configured[key])}' is configured in GRUB but is NOT on the running kernel. " \
                 'The setting takes effect only after update-grub + reboot.',
        evidence: "configured: #{fmt(key, @configured[key])} | running: (absent)"
      )
    end

    (@running.keys - @configured.keys - VOLATILE).sort.each do |key|
      out << Finding.new(
        severity: 'medium', category: 'drift.unmanaged',
        message: "'#{fmt(key, @running[key])}' is on the running kernel but is NOT in /etc/default/grub. " \
                 'It came from a manual GRUB edit or a package drop-in and will vanish on the next regeneration.',
        evidence: "running: #{fmt(key, @running[key])} | configured: (absent)"
      )
    end

    (@configured.keys & @running.keys).sort.each do |key|
      next if VOLATILE.include?(key)
      next if @configured[key] == @running[key]

      out << Finding.new(
        severity: 'high', category: 'drift.value_mismatch',
        message: "'#{key}' has a different value configured than the one the kernel booted with.",
        evidence: "configured: #{fmt(key, @configured[key])} | running: #{fmt(key, @running[key])}"
      )
    end

    out
  end

  # ---- Baseline: required hardening parameters ------------------------------
  def baseline_findings
    @baseline.filter_map do |rule|
      param = rule['param']
      want = rule['value']

      unless @running.key?(param)
        next Finding.new(
          severity: rule['severity'], category: 'baseline.missing',
          message: "#{param}#{want ? "=#{want}" : ''} is missing from the running kernel command line -- #{rule['why']}",
          evidence: 'running: (absent)'
        )
      end

      next if want.nil? || @running[param] == want

      Finding.new(
        severity: rule['severity'], category: 'baseline.wrong_value',
        message: "#{param} should be #{want} -- #{rule['why']}",
        evidence: "running: #{fmt(param, @running[param])}"
      )
    end
  end

  # ---- Dangerous parameters ------------------------------------------------
  def dangerous_findings
    DANGEROUS.filter_map do |param, rule|
      next unless @running.key?(param)

      # bad == nil means the bare presence of the flag is the problem.
      next if !rule['bad'].nil? && @running[param] != rule['bad']

      Finding.new(
        severity: rule['severity'], category: 'dangerous.parameter',
        message: "#{fmt(param, @running[param])} -- #{rule['why']}",
        evidence: "running: #{fmt(param, @running[param])}"
      )
    end
  end

  # ---- Hygiene -------------------------------------------------------------
  def hygiene_findings
    out = []

    @running_dupes.each do |key|
      out << Finding.new(
        severity: 'low', category: 'hygiene.duplicate',
        message: "'#{key}' appears more than once on the running command line; the last occurrence wins, " \
                 'which makes the effective value non-obvious.',
        evidence: "running line contains repeated '#{key}'"
      )
    end

    if @running_line.length > 512
      out << Finding.new(
        severity: 'low', category: 'hygiene.length',
        message: "The running command line is #{@running_line.length} characters. Some architectures " \
                 'truncate past COMMAND_LINE_SIZE (often 2048, 512 on a few), silently dropping trailing parameters.',
        evidence: "length=#{@running_line.length}"
      )
    end

    out
  end

  def fmt(key, value)
    value.nil? ? key : "#{key}=#{value}"
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

  def text(findings, auditor, sources)
    lines = []
    lines << 'Kernel boot command line audit'
    lines << "  running    (#{sources[:cmdline]}): #{wrap(auditor.instance_variable_get(:@running_line))}"
    lines << "  configured (#{sources[:grub] || 'not found'}): #{wrap(auditor.instance_variable_get(:@configured_line))}"
    lines << '-' * 76

    if findings.empty?
      lines << 'OK  running kernel matches configuration and satisfies the baseline'
      return lines.join("\n")
    end

    findings.group_by { |f| f.category.split('.').first }.each do |group, group_findings|
      lines << ''
      lines << "[#{group}]"
      group_findings.sort_by { |f| -SEVERITY_ORDER.fetch(f.severity, 0) }.each do |f|
        lines << "  #{paint(f.severity.upcase.ljust(6), f.severity)} #{f.category}"
        lines << "         #{f.message}"
        lines << "         -> #{f.evidence}"
      end
    end

    lines << ''
    lines << '-' * 76
    counts = findings.group_by(&:severity).transform_values(&:size)
                     .sort_by { |s, _| -SEVERITY_ORDER.fetch(s, 0) }
                     .map { |s, n| "#{s}=#{n}" }.join('  ')
    lines << "summary: #{findings.size} finding(s)  #{counts}"

    if findings.any? { |f| f.category == 'drift.pending_reboot' }
      lines << 'note: pending_reboot findings need `update-grub` (Debian) or ' \
               '`grub2-mkconfig -o /boot/grub2/grub.cfg` (RHEL) followed by a reboot.'
    end

    lines.join("\n")
  end

  def json(findings, auditor, sources)
    JSON.pretty_generate(
      generated_at: Time.now.utc.iso8601,
      hostname: (require('socket') && Socket.gethostname rescue 'unknown'),
      sources: sources,
      running_cmdline: auditor.instance_variable_get(:@running_line),
      configured_cmdline: auditor.instance_variable_get(:@configured_line),
      finding_count: findings.size,
      findings: findings.map(&:to_h)
    )
  end

  private

  def wrap(str, width = 96)
    s = str.to_s
    s.length > width ? "#{s[0, width]}..." : s
  end

  def paint(text, severity)
    return text unless @color

    "#{COLORS.fetch(severity, '')}#{text}#{RESET}"
  end
end

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv)
  opts = {
    cmdline: '/proc/cmdline',
    grub_default: '/etc/default/grub',
    grub_dropin: '/etc/default/grub.d',
    baseline: nil, format: 'text', fail_on: nil
  }

  OptionParser.new do |o|
    o.banner = 'Usage: ruby boot_cmdline_audit.rb [options]'
    o.on('--cmdline PATH', 'Running cmdline file (default /proc/cmdline)') { |v| opts[:cmdline] = v }
    o.on('--grub-default PATH', 'GRUB defaults file (default /etc/default/grub)') { |v| opts[:grub_default] = v }
    o.on('--grub-dropin DIR', 'GRUB drop-in dir (default /etc/default/grub.d)') { |v| opts[:grub_dropin] = v }
    o.on('--baseline PATH', 'JSON baseline file overriding the built-in set') { |v| opts[:baseline] = v }
    o.on('--format FMT', %w[text json], 'text (default) or json') { |v| opts[:format] = v }
    o.on('--fail-on LEVEL', %w[high medium low], 'Exit 1 at/above this severity') { |v| opts[:fail_on] = v }
    o.on('-h', '--help') { puts o; exit 0 }
  end.parse!(argv)

  unless File.readable?(opts[:cmdline])
    warn "error: cannot read #{opts[:cmdline]}"
    return 2
  end

  running = File.read(opts[:cmdline]).strip
  grub = GrubDefaults.new(opts[:grub_default], opts[:grub_dropin])

  baseline = DEFAULT_BASELINE
  if opts[:baseline]
    begin
      baseline = JSON.parse(File.read(opts[:baseline]))
    rescue StandardError => e
      warn "error: bad baseline file: #{e.message}"
      return 2
    end
  end

  auditor = BootAuditor.new(running, grub.effective, baseline)
  findings = auditor.findings
  sources = { cmdline: opts[:cmdline], grub: grub.found? ? opts[:grub_default] : nil }

  reporter = Reporter.new
  puts(opts[:format] == 'json' ? reporter.json(findings, auditor, sources)
                               : reporter.text(findings, auditor, sources))

  if opts[:fail_on]
    threshold = SEVERITY_ORDER.fetch(opts[:fail_on])
    return 1 if findings.any? { |f| SEVERITY_ORDER.fetch(f.severity, 0) >= threshold }
  end
  0
end

exit(main(ARGV)) if __FILE__ == $PROGRAM_NAME
