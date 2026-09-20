#!/usr/bin/env ruby
# frozen_string_literal: true
#
# win_auditpol_audit.rb - check what a Windows host is actually auditing.
#
# Every Windows incident response starts the same way: pull the Security log
# and find out what happened. Half the time the answer is "nothing was logged,"
# because the advanced audit policy was never configured, or because a legacy
# Group Policy setting quietly overwrote it, or because the Security log is
# 20 MB and rolled over before anyone looked.
#
# This script reads the EFFECTIVE audit policy from auditpol.exe, compares all
# 60-odd subcategories against a CIS-style baseline, and flags the two
# configuration traps that make a "configured" policy do nothing:
#
#   1. SCENoApplyLegacyAuditPolicy = 0, which lets the nine legacy audit
#      categories overwrite every advanced subcategory at policy refresh.
#   2. A Security log too small, or set to overwrite, to survive an incident.
#
# Ruby standard library only; win32ole/Win32::Registry ship with Ruby on
# Windows. No gems.
#
# Usage (on Windows, elevated):
#   ruby win_auditpol_audit.rb                    # audit this host
#   ruby win_auditpol_audit.rb --json
#   ruby win_auditpol_audit.rb --export pol.csv   # save the raw auditpol CSV
#
# Usage (anywhere - Linux, macOS, CI):
#   ruby win_auditpol_audit.rb --self-test        # run against built-in fixtures
#   ruby win_auditpol_audit.rb --csv pol.csv      # audit a CSV captured elsewhere
#
# Exit codes: 0 = baseline met, 1 = WARN findings, 2 = at least one CRIT.

require 'optparse'
require 'json'

module WinAuditpolAudit
  VERSION = '1.0.0'

  Subcategory = Struct.new(:category, :name, :guid, :setting, keyword_init: true)
  Finding = Struct.new(:severity, :code, :subject, :detail, :fix, keyword_init: true)

  SUCCESS = 'Success'
  FAILURE = 'Failure'
  BOTH = 'Success and Failure'
  NONE = 'No Auditing'

  # ---------------------------------------------------------------------------
  # Baseline. Each entry is [category, subcategory, required setting, severity,
  # why it matters]. "Required" means at minimum - auditing Success and Failure
  # where only Failure is required is a pass, not a finding.
  # ---------------------------------------------------------------------------
  BASELINE = [
    ['Account Logon', 'Credential Validation', BOTH, 'CRIT',
     'the only record of which account was tried against this machine, and from where'],
    ['Account Logon', 'Kerberos Authentication Service', FAILURE, 'WARN',
     'AS-REP roasting and password spraying against a DC show up here first'],
    ['Account Management', 'User Account Management', BOTH, 'CRIT',
     'account created, enabled, password reset - the standard persistence move'],
    ['Account Management', 'Security Group Management', BOTH, 'CRIT',
     'privilege escalation almost always ends with a group membership change'],
    ['Account Management', 'Computer Account Management', SUCCESS, 'WARN',
     'a rogue machine account is how several AD attacks get their foothold'],
    ['Detailed Tracking', 'Process Creation', SUCCESS, 'CRIT',
     '4688 is the single most useful event on the box; without it you cannot ' \
     'reconstruct what ran'],
    ['Detailed Tracking', 'PNP Activity', SUCCESS, 'WARN',
     'records USB and other removable devices being attached'],
    ['Logon/Logoff', 'Logon', BOTH, 'CRIT',
     '4624/4625 - who got in, who tried, from which address and logon type'],
    ['Logon/Logoff', 'Logoff', SUCCESS, 'WARN',
     'without logoff you cannot bound a session, only start it'],
    ['Logon/Logoff', 'Account Lockout', FAILURE, 'WARN',
     'the first visible symptom of a spray that hit the lockout threshold'],
    ['Logon/Logoff', 'Special Logon', SUCCESS, 'CRIT',
     '4672 marks a logon that carried administrator-equivalent privileges'],
    ['Logon/Logoff', 'Other Logon/Logoff Events', BOTH, 'WARN',
     'RDP session reconnect/disconnect lives here, not under Logon'],
    ['Object Access', 'Removable Storage', BOTH, 'WARN',
     'file access on removable media - the cheapest exfiltration channel'],
    ['Object Access', 'File Share', BOTH, 'WARN',
     '5140/5145 show lateral movement over SMB'],
    ['Object Access', 'Detailed File Share', FAILURE, 'WARN',
     'failed share access is noisy but is where enumeration shows up'],
    ['Policy Change', 'Audit Policy Change', SUCCESS, 'CRIT',
     'an attacker turning auditing off must itself be audited, or the trail ends silently'],
    ['Policy Change', 'Authentication Policy Change', SUCCESS, 'WARN',
     'trust and privilege-assignment changes'],
    ['Policy Change', 'MPSSVC Rule-Level Policy Change', BOTH, 'WARN',
     'Windows Firewall rule changes - a new inbound allow is worth knowing about'],
    ['Privilege Use', 'Sensitive Privilege Use', BOTH, 'WARN',
     'SeDebugPrivilege and friends being exercised - credential dumping signature'],
    ['System', 'Security State Change', SUCCESS, 'WARN',
     'audit subsystem start/stop'],
    ['System', 'Security System Extension', BOTH, 'CRIT',
     'a new service or driver registering with LSA - classic persistence'],
    ['System', 'System Integrity', BOTH, 'CRIT',
     'audit subsystem failures and dropped events; if this is off you cannot ' \
     'even tell that logging broke'],
    ['DS Access', 'Directory Service Access', FAILURE, 'WARN',
     'on a domain controller, failed directory reads are reconnaissance'],
    ['DS Access', 'Directory Service Changes', SUCCESS, 'WARN',
     'on a domain controller, the before/after of every AD object change']
  ].freeze

  # ---------------------------------------------------------------------------
  # Sources
  # ---------------------------------------------------------------------------

  # Runs the real auditpol.exe. The `runner` is injectable so the parsing and
  # scoring can be exercised without Windows.
  class AuditpolSource
    def initialize(runner: nil)
      @runner = runner || lambda do |cmd|
        out = `#{cmd} 2>&1`
        [out, $?.success?]
      end
    end

    def csv
      out, ok = @runner.call('auditpol.exe /get /category:* /r')
      unless ok
        raise "auditpol.exe failed: #{out.to_s.lines.first.to_s.strip}"
      end
      # auditpol on a non-elevated prompt prints an error to stdout and still
      # exits 0 on some builds, so check the shape of the output too.
      raise "auditpol.exe returned no policy rows (are you elevated?)" unless out.to_s.include?(',')

      out
    end
  end

  class FileSource
    def initialize(path)
      @path = path
    end

    def csv
      File.read(@path)
    end
  end

  # ---------------------------------------------------------------------------
  # Parser for `auditpol /r` CSV.
  #
  # Columns: Machine Name, Policy Target, Subcategory, Subcategory GUID,
  #          Inclusion Setting, Exclusion Setting
  # The category name is NOT a column - auditpol emits category rows with an
  # empty GUID interleaved with the subcategory rows, so the parser has to
  # carry the current category down the file.
  # ---------------------------------------------------------------------------
  class Parser
    def self.parse(text)
      rows = []
      machine = nil
      category = nil
      text.each_line do |raw|
        line = raw.strip
        next if line.empty?
        next if line.start_with?('Machine Name,')

        f = split_csv(line)
        next if f.size < 5

        machine ||= f[0]
        name = f[2].to_s.strip
        guid = f[3].to_s.strip
        setting = f[4].to_s.strip
        # A category header row has no GUID (or the all-zero GUID) and no
        # inclusion setting.
        if guid.empty? || guid =~ /\A\{0+-0+-0+-0+-0+\}\z/
          category = name
          next
        end
        rows << Subcategory.new(category: category, name: name, guid: guid,
                                setting: setting.empty? ? NONE : setting)
      end
      [machine, rows]
    end

    # auditpol quotes fields containing commas. Minimal RFC4180-ish splitter -
    # no embedded newlines to worry about in this format.
    def self.split_csv(line)
      out = []
      field = +''
      in_q = false
      i = 0
      while i < line.length
        c = line[i]
        if in_q
          if c == '"'
            if line[i + 1] == '"'
              field << '"'
              i += 1
            else
              in_q = false
            end
          else
            field << c
          end
        elsif c == '"'
          in_q = true
        elsif c == ','
          out << field
          field = +''
        else
          field << c
        end
        i += 1
      end
      out << field
      out
    end
  end

  # ---------------------------------------------------------------------------
  # Registry checks. Two settings decide whether the policy above is real.
  # ---------------------------------------------------------------------------
  class RegistrySource
    KEYS = {
      legacy_override: ['SYSTEM\\CurrentControlSet\\Control\\Lsa', 'SCENoApplyLegacyAuditPolicy'],
      crash_on_audit_fail: ['SYSTEM\\CurrentControlSet\\Control\\Lsa', 'CrashOnAuditFail'],
      security_log_max: ['SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security', 'MaxSize'],
      security_log_retention: ['SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security', 'Retention']
    }.freeze

    def self.read(overrides: nil)
      return overrides if overrides

      begin
        require 'win32/registry'
      rescue LoadError
        return nil
      end

      out = {}
      KEYS.each do |label, (path, value)|
        begin
          Win32::Registry::HKEY_LOCAL_MACHINE.open(path) do |reg|
            out[label] = reg[value]
          end
        rescue StandardError
          out[label] = nil
        end
      end
      out
    end
  end

  # ---------------------------------------------------------------------------
  # Auditor
  # ---------------------------------------------------------------------------
  class Auditor
    Result = Struct.new(:baseline_entry, :actual, :status, keyword_init: true)

    def initialize(subcategories, registry: nil)
      @subs = subcategories
      @by_name = subcategories.each_with_object({}) { |s, h| h[s.name.downcase] = s }
      @registry = registry
    end

    # Does `actual` satisfy `required`? "Success and Failure" satisfies
    # everything; "Success" satisfies a Success requirement only.
    def self.satisfies?(actual, required)
      a = actual.to_s.strip
      return false if a.empty? || a == NONE
      return true if a == BOTH
      return true if a == required

      false
    end

    def results
      BASELINE.map do |entry|
        cat, name, required, = entry
        found = @by_name[name.downcase]
        actual = found ? found.setting : nil
        status =
          if actual.nil? then :missing
          elsif Auditor.satisfies?(actual, required) then :pass
          elsif actual == NONE then :none
          else :partial
          end
        Result.new(baseline_entry: entry, actual: actual, status: status)
      end
    end

    def findings
      out = []
      results.each do |r|
        cat, name, required, sev, why = r.baseline_entry
        case r.status
        when :pass then next
        when :missing
          out << Finding.new(severity: 'INFO', code: 'SUBCATEGORY_ABSENT',
                             subject: "#{cat} / #{name}",
                             detail: 'not present in this auditpol output - expected on a ' \
                                     'non-domain-controller or an older Windows build',
                             fix: nil)
        when :none
          out << Finding.new(severity: sev, code: 'NO_AUDITING',
                             subject: "#{cat} / #{name}",
                             detail: "No Auditing (baseline requires #{required}) - #{why}",
                             fix: fix_line(name, required))
        when :partial
          out << Finding.new(severity: sev == 'CRIT' ? 'WARN' : 'INFO', code: 'PARTIAL_AUDITING',
                             subject: "#{cat} / #{name}",
                             detail: "#{r.actual} (baseline requires #{required}) - #{why}",
                             fix: fix_line(name, required))
        end
      end
      out.concat(registry_findings)
      out.sort_by { |f| [{ 'CRIT' => 0, 'WARN' => 1, 'INFO' => 2 }.fetch(f.severity, 3), f.code, f.subject] }
    end

    def score
      r = results.reject { |x| x.status == :missing }
      return 100 if r.empty?

      ((r.count { |x| x.status == :pass } * 100.0) / r.size).round
    end

    private

    def fix_line(name, required)
      flags = case required
              when BOTH then '/success:enable /failure:enable'
              when SUCCESS then '/success:enable'
              else '/failure:enable'
              end
      %(auditpol /set /subcategory:"#{name}" #{flags})
    end

    def registry_findings
      return [Finding.new(severity: 'INFO', code: 'REGISTRY_NOT_READ', subject: 'registry',
                          detail: 'Win32::Registry is unavailable (not Windows), so the legacy-policy ' \
                                  'override and Security log settings were not checked.',
                          fix: nil)] if @registry.nil?

      out = []
      legacy = @registry[:legacy_override]
      if legacy.to_i != 1
        out << Finding.new(
          severity: 'CRIT', code: 'LEGACY_POLICY_OVERRIDE',
          subject: 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\SCENoApplyLegacyAuditPolicy',
          detail: "value is #{legacy.inspect}. Unless this is 1, the nine legacy audit categories " \
                  'from Group Policy overwrite every advanced subcategory at the next policy ' \
                  'refresh. Everything auditpol reports above can silently revert.',
          fix: 'Enable "Audit: Force audit policy subcategory settings to override audit policy ' \
               'category settings" in Group Policy (sets this value to 1).'
        )
      end

      max = @registry[:security_log_max].to_i
      if max.positive? && max < 196_608 * 1024
        out << Finding.new(
          severity: max < 32_768 * 1024 ? 'CRIT' : 'WARN', code: 'SECURITY_LOG_SMALL',
          subject: 'Security event log size',
          detail: "MaxSize is #{(max / 1024.0 / 1024).round(1)} MB. With Process Creation auditing on, " \
                  'a busy server can churn that in hours - so by the time anyone investigates, the ' \
                  'evidence has already rolled over.',
          fix: 'Set the Security log to at least 192 MB, and forward events off the host.'
        )
      end

      retention = @registry[:security_log_retention]
      if retention.to_s == '0' || retention.to_i.zero?
        out << Finding.new(
          severity: 'INFO', code: 'SECURITY_LOG_OVERWRITE', subject: 'Security event log retention',
          detail: 'Retention is 0 (overwrite events as needed). That is the right setting only if ' \
                  'events are being forwarded somewhere durable first.',
          fix: nil
        )
      end

      if @registry[:crash_on_audit_fail].to_i == 1
        out << Finding.new(
          severity: 'WARN', code: 'CRASH_ON_AUDIT_FAIL', subject: 'CrashOnAuditFail',
          detail: 'the host is configured to halt if the Security log cannot be written. That is a ' \
                  'deliberate high-assurance setting, but it also means a full Security log is an ' \
                  'outage. Confirm it is intentional.',
          fix: nil
        )
      end
      out
    end
  end

  # ---------------------------------------------------------------------------
  # Fixtures for --self-test: a realistically half-configured member server.
  # ---------------------------------------------------------------------------
  module Fixtures
    module_function

    def csv
      rows = [
        'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting',
        'APPSRV02,System,System,,,',
        'APPSRV02,System,Security State Change,{0cce9210-69ae-11d9-bed3-505054503030},Success,',
        'APPSRV02,System,Security System Extension,{0cce9211-69ae-11d9-bed3-505054503030},No Auditing,',
        'APPSRV02,System,System Integrity,{0cce9212-69ae-11d9-bed3-505054503030},Success and Failure,',
        'APPSRV02,System,Logon/Logoff,,,',
        'APPSRV02,System,Logon,{0cce9215-69ae-11d9-bed3-505054503030},Success,',
        'APPSRV02,System,Logoff,{0cce9216-69ae-11d9-bed3-505054503030},Success,',
        'APPSRV02,System,Account Lockout,{0cce9217-69ae-11d9-bed3-505054503030},Failure,',
        'APPSRV02,System,Special Logon,{0cce921b-69ae-11d9-bed3-505054503030},No Auditing,',
        'APPSRV02,System,Other Logon/Logoff Events,{0cce921c-69ae-11d9-bed3-505054503030},No Auditing,',
        'APPSRV02,System,Object Access,,,',
        'APPSRV02,System,File Share,{0cce9224-69ae-11d9-bed3-505054503030},No Auditing,',
        'APPSRV02,System,Detailed File Share,{0cce9244-69ae-11d9-bed3-505054503030},No Auditing,',
        'APPSRV02,System,Removable Storage,{0cce9245-69ae-11d9-bed3-505054503030},No Auditing,',
        'APPSRV02,System,Detailed Tracking,,,',
        'APPSRV02,System,Process Creation,{0cce922b-69ae-11d9-bed3-505054503030},No Auditing,',
        'APPSRV02,System,PNP Activity,{0cce9248-69ae-11d9-bed3-505054503030},No Auditing,',
        'APPSRV02,System,Policy Change,,,',
        'APPSRV02,System,Audit Policy Change,{0cce922f-69ae-11d9-bed3-505054503030},Success,',
        'APPSRV02,System,Authentication Policy Change,{0cce9230-69ae-11d9-bed3-505054503030},Success,',
        'APPSRV02,System,MPSSVC Rule-Level Policy Change,{0cce9232-69ae-11d9-bed3-505054503030},No Auditing,',
        'APPSRV02,System,Privilege Use,,,',
        'APPSRV02,System,Sensitive Privilege Use,{0cce9228-69ae-11d9-bed3-505054503030},No Auditing,',
        'APPSRV02,System,Account Management,,,',
        'APPSRV02,System,User Account Management,{0cce9235-69ae-11d9-bed3-505054503030},Success,',
        'APPSRV02,System,Computer Account Management,{0cce9236-69ae-11d9-bed3-505054503030},Success,',
        'APPSRV02,System,Security Group Management,{0cce9237-69ae-11d9-bed3-505054503030},Success and Failure,',
        'APPSRV02,System,Account Logon,,,',
        'APPSRV02,System,Credential Validation,{0cce923f-69ae-11d9-bed3-505054503030},Success,',
        'APPSRV02,System,Kerberos Authentication Service,{0cce9242-69ae-11d9-bed3-505054503030},No Auditing,'
      ]
      "#{rows.join("\n")}\n"
    end

    # A member server that was hardened once and never re-checked: advanced
    # policy is half-on, but the legacy override was never enabled and the
    # Security log is still the 20 MB default.
    def registry
      { legacy_override: 0, crash_on_audit_fail: 0,
        security_log_max: 20_480 * 1024, security_log_retention: 0 }
    end
  end

  # ---------------------------------------------------------------------------
  # Reporters
  # ---------------------------------------------------------------------------
  class TextReporter
    COLORS = { 'CRIT' => "\e[31m", 'WARN' => "\e[33m", 'INFO' => "\e[36m" }.freeze
    RESET = "\e[0m"
    MARK = { pass: 'PASS', partial: 'PART', none: 'FAIL', missing: ' -- ' }.freeze

    def initialize(io, color:)
      @io = io
      @color = color
    end

    def report(machine:, results:, findings:, score:, source:)
      @io.puts "windows audit policy audit  -  #{machine || 'unknown host'}  (source: #{source})"
      @io.puts '=' * 78
      @io.puts
      @io.puts format('  %-4s %-22s %-34s %s', '', 'CATEGORY', 'SUBCATEGORY', 'EFFECTIVE')
      @io.puts "  #{'-' * 74}"
      results.each do |r|
        cat, name, = r.baseline_entry
        @io.puts format('  %-4s %-22s %-34s %s', MARK.fetch(r.status), truncate(cat, 22),
                        truncate(name, 34), r.actual || '(absent)')
      end

      @io.puts
      @io.puts format('  baseline coverage: %d%%  (%d of %d applicable subcategories)',
                      score, results.count { |r| r.status == :pass },
                      results.count { |r| r.status != :missing })

      findings.each do |f|
        @io.puts
        @io.puts "  #{paint(f.severity)}  #{f.code}  #{f.subject}"
        @io.puts "        #{f.detail}"
        @io.puts "        fix: #{f.fix}" if f.fix
      end

      counts = findings.group_by(&:severity).transform_values(&:size)
      @io.puts
      @io.puts '=' * 78
      @io.puts format('summary  CRIT=%d  WARN=%d  INFO=%d',
                      counts.fetch('CRIT', 0), counts.fetch('WARN', 0), counts.fetch('INFO', 0))
    end

    private

    def paint(sev)
      return sev.ljust(4) unless @color

      "#{COLORS.fetch(sev, '')}#{sev.ljust(4)}#{RESET}"
    end

    def truncate(s, n)
      s.to_s.length > n ? "#{s[0, n - 3]}..." : s.to_s
    end
  end

  class JsonReporter
    def initialize(io)
      @io = io
    end

    def report(machine:, results:, findings:, score:, source:)
      @io.puts JSON.pretty_generate(
        machine: machine, source: source, baseline_coverage_percent: score,
        subcategories: results.map do |r|
          cat, name, required, = r.baseline_entry
          { category: cat, subcategory: name, required: required,
            effective: r.actual, status: r.status.to_s }
        end,
        findings: findings.map do |f|
          { severity: f.severity, code: f.code, subject: f.subject, detail: f.detail, fix: f.fix }
        end
      )
    end
  end

  # ---------------------------------------------------------------------------
  # CLI
  # ---------------------------------------------------------------------------
  class CLI
    def self.run(argv, io = $stdout)
      opts = { json: false, color: io.tty?, self_test: false, csv: nil, export: nil }
      OptionParser.new do |o|
        o.banner = 'Usage: win_auditpol_audit.rb [options]'
        o.on('--self-test', 'Audit built-in fixtures (runs on any OS)') { opts[:self_test] = true }
        o.on('--csv FILE', 'Audit an auditpol /r CSV captured elsewhere') { |v| opts[:csv] = v }
        o.on('--export FILE', 'Write the raw auditpol CSV to FILE as well') { |v| opts[:export] = v }
        o.on('--json', 'Emit JSON') { opts[:json] = true }
        o.on('--[no-]color', 'Force colour on/off') { |v| opts[:color] = v }
        o.on('-v', '--version') { io.puts VERSION; exit 0 }
        o.on('-h', '--help') { io.puts o; exit 0 }
      end.parse!(argv)

      source_label, csv, registry =
        if opts[:self_test]
          ['self-test fixtures', Fixtures.csv, Fixtures.registry]
        elsif opts[:csv]
          [opts[:csv], FileSource.new(opts[:csv]).csv, RegistrySource.read]
        else
          begin
            ['auditpol.exe', AuditpolSource.new.csv, RegistrySource.read]
          rescue StandardError => e
            warn "win_auditpol_audit: #{e.message}"
            warn '                    Try --self-test, or capture a CSV on the server with:'
            warn '                    auditpol /get /category:* /r > pol.csv'
            return 2
          end
        end

      File.write(opts[:export], csv) if opts[:export]

      machine, subs = Parser.parse(csv)
      if subs.empty?
        warn 'win_auditpol_audit: no subcategory rows parsed - is this auditpol /r output?'
        return 2
      end

      auditor = Auditor.new(subs, registry: registry)
      findings = auditor.findings

      reporter = opts[:json] ? JsonReporter.new(io) : TextReporter.new(io, color: opts[:color])
      reporter.report(machine: machine, results: auditor.results, findings: findings,
                      score: auditor.score, source: source_label)

      return 2 if findings.any? { |f| f.severity == 'CRIT' }
      return 1 if findings.any? { |f| f.severity == 'WARN' }

      0
    end
  end
end

exit WinAuditpolAudit::CLI.run(ARGV) if $PROGRAM_NAME == __FILE__
