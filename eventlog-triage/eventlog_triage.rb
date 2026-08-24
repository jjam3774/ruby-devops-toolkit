#!/usr/bin/env ruby
# frozen_string_literal: true
#
# eventlog_triage.rb — triage Windows Event Logs via WMI (win32ole).
#
# Instead of scrolling Event Viewer after something breaks, this script
# pulls the last N hours of System + Security events through WMI
# (Win32_NTLogEvent), buckets the ones that actually matter, and prints
# a severity-ranked triage report:
#
#   CRIT  6008  unexpected shutdown (crash/power loss)
#   CRIT  4740  account locked out
#   CRIT  4625  failed logons >= threshold for one account (spray/brute force)
#   WARN  7034  service terminated unexpectedly
#   WARN  7045  new service installed (persistence technique — verify it!)
#   WARN  4625  failed logons below threshold
#   INFO  1074  planned shutdown/restart (who requested it)
#
# Requires Windows + Ruby with the win32ole stdlib (ships with RubyInstaller).
# Run elevated to read the Security log. Text and --json output; exits 2 if
# anything CRIT was found, 1 for WARN, 0 clean — schedulable via Task Scheduler.
#
# Usage (Windows, elevated):
#   ruby eventlog_triage.rb --hours 24
#   ruby eventlog_triage.rb --hours 6 --logon-threshold 10 --json
#
# The triage logic is separated from WMI access (EventSource vs Triage)
# so it can be unit-tested on any OS with a stub source — see
# eventlog_triage_test.rb in this folder.

require 'json'
require 'optparse'
require 'time'

# --------------------------------------------------------------------------
# WMI access layer. The ONLY thing that touches win32ole. Everything below
# it works on plain hashes, which is what makes the logic testable off-Windows.
# --------------------------------------------------------------------------
class EventSource
  def initialize
    require 'win32ole'
    @wmi = WIN32OLE.connect('winmgmts:\\\\.\\root\\cimv2')
  end

  # WMI wants dates in DMTF format: 20260824093000.000000+000
  def dmtf(time)
    time.utc.strftime('%Y%m%d%H%M%S.000000+000')
  end

  # Returns an array of plain hashes — one per event.
  def events_since(cutoff)
    query = "SELECT LogFile, EventCode, TimeGenerated, SourceName, Message, InsertionStrings " \
            "FROM Win32_NTLogEvent WHERE (LogFile='System' OR LogFile='Security') " \
            "AND TimeGenerated >= '#{dmtf(cutoff)}'"
    @wmi.ExecQuery(query).each.map do |e|
      {
        'log'     => e.LogFile,
        'code'    => e.EventCode.to_i,
        'time'    => e.TimeGenerated.to_s,
        'source'  => e.SourceName.to_s,
        'message' => e.Message.to_s,
        'strings' => (e.InsertionStrings || []).to_a.map(&:to_s)
      }
    end
  end
end

# --------------------------------------------------------------------------
# Triage logic — pure Ruby, no WMI. Feed it hashes, get findings back.
# --------------------------------------------------------------------------
class Triage
  SEV = { 'CRIT' => 2, 'WARN' => 1, 'INFO' => 0 }.freeze

  def initialize(logon_threshold: 5)
    @logon_threshold = logon_threshold
  end

  # For 4625 the target account name is insertion string index 5 in the
  # standard Security template; fall back to scraping the message text.
  def failed_logon_account(ev)
    acct = ev['strings'][5] if ev['strings'] && ev['strings'].size > 5
    acct = ev['message'][/Account Name:\s+(\S+)/, 1] if acct.nil? || acct.empty?
    acct || 'unknown'
  end

  def run(events)
    findings = []
    failed_by_account = Hash.new(0)

    events.each do |ev|
      case ev['code']
      when 6008
        findings << ['CRIT', "unexpected shutdown at #{ev['time']} — crash or power loss (System/6008)"]
      when 4740
        findings << ['CRIT', "account lockout: #{ev['strings']&.first || 'unknown'} (Security/4740)"]
      when 7034
        findings << ['WARN', "service terminated unexpectedly: #{ev['strings']&.first || ev['source']} (System/7034)"]
      when 7045
        svc = ev['strings']&.first || 'unknown'
        findings << ['WARN', "NEW service installed: #{svc} — verify this was intentional (System/7045)"]
      when 4625
        failed_by_account[failed_logon_account(ev)] += 1
      when 1074
        who = ev['strings'] ? ev['strings'][6] || ev['strings'][0] : 'unknown'
        findings << ['INFO', "planned shutdown/restart requested by #{who} (System/1074)"]
      end
    end

    failed_by_account.each do |acct, count|
      if count >= @logon_threshold
        findings << ['CRIT', "#{count} failed logons for account '#{acct}' — possible brute force (Security/4625)"]
      else
        findings << ['WARN', "#{count} failed logon(s) for account '#{acct}' (Security/4625)"]
      end
    end

    findings.sort_by { |sev, _| -SEV[sev] }
  end
end

# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
if $PROGRAM_NAME == __FILE__
  options = { hours: 24, logon_threshold: 5, json: false }
  OptionParser.new do |o|
    o.banner = 'Usage: eventlog_triage.rb [options]   (Windows, run elevated)'
    o.on('--hours N', Integer, 'Look back N hours (default 24)') { |v| options[:hours] = v }
    o.on('--logon-threshold N', Integer, 'CRIT when failed logons/account >= N (default 5)') { |v| options[:logon_threshold] = v }
    o.on('--json', 'Emit JSON instead of text') { options[:json] = true }
  end.parse!

  unless RUBY_PLATFORM =~ /mingw|mswin|cygwin/
    abort 'eventlog_triage: this script queries WMI and must run on Windows. ' \
          'On other platforms, run eventlog_triage_test.rb to exercise the triage logic.'
  end

  cutoff = Time.now - options[:hours] * 3600
  events = EventSource.new.events_since(cutoff)
  findings = Triage.new(logon_threshold: options[:logon_threshold]).run(events)
  worst = findings.map { |sev, _| Triage::SEV[sev] }.max || 0

  if options[:json]
    puts JSON.pretty_generate(
      'generated_at' => Time.now.iso8601,
      'window_hours' => options[:hours],
      'events_scanned' => events.size,
      'status' => %w[OK WARN CRIT][worst],
      'findings' => findings.map { |sev, msg| { 'severity' => sev, 'message' => msg } }
    )
  else
    puts "event log triage — last #{options[:hours]}h — #{events.size} events scanned  [#{%w[OK WARN CRIT][worst]}]"
    findings.each { |sev, msg| puts format('  [%-4s] %s', sev, msg) }
    puts '  nothing noteworthy — quiet logs are happy logs' if findings.empty?
  end

  exit(worst == 2 ? 2 : worst == 1 ? 1 : 0)
end
