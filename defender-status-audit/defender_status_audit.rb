#!/usr/bin/env ruby
# frozen_string_literal: true
#
# defender_status_audit.rb — audit Microsoft Defender Antivirus health on
# Windows in pure Ruby stdlib. Shells out to PowerShell's Get-MpComputerStatus
# (backed by the WMI/CIM class MSFT_MpComputerStatus), parses the JSON, and
# flags every way Defender can be silently degraded. No gems.
#
# "We have antivirus" is not the same as "antivirus is working." Real-time
# protection gets toggled off during a botched troubleshooting session and
# never turned back on; signature updates quietly stall behind a broken proxy;
# tamper protection is disabled by a misapplied GPO. Each of those is a hole an
# attacker walks straight through, and none of them shows up unless you look.
# This script looks, and reports:
#
#   CRIT  real-time protection OFF, or the AV engine not running, or
#         signatures more than --crit-age days old
#   WARN  tamper protection off, behavior monitoring off, or signatures more
#         than --warn-age days old
#   INFO  a full scan hasn't run in --scan-age days
#   OK    everything healthy
#
# Exit codes: 0 clean, 1 WARN/INFO only, 2 any CRIT.
#
# Usage (on Windows):
#   ruby defender_status_audit.rb
#   ruby defender_status_audit.rb --json > defender.json
#   # Offline: audit a captured Get-MpComputerStatus JSON from another host
#   powershell -Command "Get-MpComputerStatus | ConvertTo-Json" > host.json
#   ruby defender_status_audit.rb --status-json host.json
#
# Pure stdlib: json, optparse, open3, time. The status source is injectable,
# so the rule logic is unit-testable on any OS (see test harness).

require 'json'
require 'optparse'
require 'open3'
require 'time'

module DefenderStatusAudit
  module_function

  Finding = Struct.new(:severity, :rule, :detail, keyword_init: true)

  # Ask PowerShell for Defender status as JSON. Windows-only at runtime.
  def live_source
    lambda do
      cmd = ['powershell', '-NoProfile', '-Command', 'Get-MpComputerStatus | ConvertTo-Json']
      out, status = Open3.capture2(*cmd)
      abort 'error: Get-MpComputerStatus failed — run on Windows with Defender present' \
        unless status.success? && !out.strip.empty?
      out
    end
  end

  # Normalize the parsed JSON: PowerShell may emit booleans, or dates as
  # "/Date(1699999999999)/", or ISO strings. Return a plain hash we can reason
  # about regardless of the source's date formatting.
  def normalize(raw_json, now: Time.now)
    data = raw_json.is_a?(String) ? JSON.parse(raw_json) : raw_json
    {
      real_time:        truthy(data['RealTimeProtectionEnabled']),
      antivirus_enabled: truthy(data['AntivirusEnabled']),
      am_service:       truthy(data['AMServiceEnabled']),
      behavior_monitor: truthy(data['BehaviorMonitorEnabled']),
      tamper_protection: truthy(data['IsTamperProtected']),
      sig_age_days:     age_in_days(data['AntivirusSignatureLastUpdated'], now),
      last_full_scan_days: age_in_days(data['FullScanEndTime'], now),
      sig_version:      data['AntivirusSignatureVersion']
    }
  end

  def truthy(v)
    return v if [true, false].include?(v)
    return false if v.nil?
    %w[true 1 yes enabled].include?(v.to_s.strip.downcase)
  end

  # Accept ISO-8601, "/Date(ms)/" (WCF), or nil. Return whole days since, or nil.
  def age_in_days(value, now)
    t = parse_time(value)
    return nil unless t
    ((now - t) / 86_400).floor
  end

  def parse_time(value)
    return nil if value.nil? || value.to_s.empty?
    if (m = value.to_s.match(%r{/Date\((\d+)\)/}))
      return Time.at(m[1].to_i / 1000.0)
    end
    Time.parse(value.to_s)
  rescue ArgumentError
    nil
  end

  def audit(status, warn_age:, crit_age:, scan_age:)
    f = []
    f << Finding.new(severity: 'CRIT', rule: 'realtime-protection-off',
                     detail: 'RealTimeProtectionEnabled is false') unless status[:real_time]
    f << Finding.new(severity: 'CRIT', rule: 'antivirus-disabled',
                     detail: 'AntivirusEnabled is false') unless status[:antivirus_enabled]
    f << Finding.new(severity: 'CRIT', rule: 'am-service-down',
                     detail: 'AMServiceEnabled is false — the AV engine is not running') unless status[:am_service]

    if (age = status[:sig_age_days])
      if age >= crit_age
        f << Finding.new(severity: 'CRIT', rule: 'signatures-critically-stale',
                         detail: "definitions #{age} days old (>= #{crit_age})")
      elsif age >= warn_age
        f << Finding.new(severity: 'WARN', rule: 'signatures-stale',
                         detail: "definitions #{age} days old (>= #{warn_age})")
      end
    else
      f << Finding.new(severity: 'WARN', rule: 'signature-age-unknown',
                       detail: 'could not determine signature age')
    end

    f << Finding.new(severity: 'WARN', rule: 'tamper-protection-off',
                     detail: 'IsTamperProtected is false') unless status[:tamper_protection]
    f << Finding.new(severity: 'WARN', rule: 'behavior-monitoring-off',
                     detail: 'BehaviorMonitorEnabled is false') unless status[:behavior_monitor]

    if (scan = status[:last_full_scan_days]) && scan >= scan_age
      f << Finding.new(severity: 'INFO', rule: 'full-scan-overdue',
                       detail: "last full scan #{scan} days ago (>= #{scan_age})")
    end
    f
  end

  def exit_code(findings)
    return 2 if findings.any? { |x| x.severity == 'CRIT' }
    return 1 if findings.any? { |x| %w[WARN INFO].include?(x.severity) }
    0
  end
end

if __FILE__ == $PROGRAM_NAME
  options = { json: false, status_json: nil, warn_age: 3, crit_age: 7, scan_age: 14 }
  OptionParser.new do |o|
    o.banner = 'Usage: ruby defender_status_audit.rb [options]'
    o.on('--status-json FILE', 'Audit a captured Get-MpComputerStatus JSON') { |v| options[:status_json] = v }
    o.on('--warn-age N', Integer, 'WARN if signatures >= N days old (default 3)') { |v| options[:warn_age] = v }
    o.on('--crit-age N', Integer, 'CRIT if signatures >= N days old (default 7)') { |v| options[:crit_age] = v }
    o.on('--scan-age N', Integer, 'INFO if no full scan in N days (default 14)') { |v| options[:scan_age] = v }
    o.on('--json', 'Emit JSON') { options[:json] = true }
  end.parse!

  raw =
    if options[:status_json]
      File.read(options[:status_json])
    else
      DefenderStatusAudit.live_source.call
    end

  status = DefenderStatusAudit.normalize(raw)
  findings = DefenderStatusAudit.audit(status, warn_age: options[:warn_age],
                                       crit_age: options[:crit_age], scan_age: options[:scan_age])
  order = { 'CRIT' => 0, 'WARN' => 1, 'INFO' => 2 }
  findings.sort_by! { |x| order[x.severity] }
  code = DefenderStatusAudit.exit_code(findings)

  if options[:json]
    puts JSON.pretty_generate(status: status, exit_code: code,
                              findings: findings.map(&:to_h))
  else
    puts 'defender_status_audit'
    puts "  signatures: v#{status[:sig_version] || '?'}, " \
         "#{status[:sig_age_days] ? "#{status[:sig_age_days]}d old" : 'age unknown'}"
    puts "  real-time: #{status[:real_time] ? 'on' : 'OFF'}  " \
         "tamper: #{status[:tamper_protection] ? 'on' : 'OFF'}  " \
         "behavior: #{status[:behavior_monitor] ? 'on' : 'OFF'}"
    puts
    if findings.empty?
      puts '  OK — Defender looks healthy'
    else
      findings.each do |x|
        puts format('  %-4s %-30s %s', x.severity, x.rule, x.detail)
      end
    end
    puts
    counts = findings.group_by(&:severity).transform_values(&:size)
    puts "summary: #{counts.map { |k, v| "#{k}=#{v}" }.join(' ')}" unless findings.empty?
  end
  exit code
end
