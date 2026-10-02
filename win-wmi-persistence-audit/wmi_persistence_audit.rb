#!/usr/bin/env ruby
# frozen_string_literal: true
#
# wmi_persistence_audit.rb - list WMI permanent event subscriptions (a classic stealth persistence
# mechanism) and flag the ones that execute commands or scripts.
# Ruby 3.0+ on Windows (win32ole ships with Ruby). Run from an elevated prompt.
# Usage: ruby wmi_persistence_audit.rb [--json] [--input FIXTURE.json]
#   --input  read a saved snapshot instead of querying WMI (lets the logic be tested on any OS)
require 'json'
require 'optparse'

Finding = Struct.new(:severity, :consumer, :rule, :message, keyword_init: true)

# Consumer classes that run code. Others (LogFile, NTEventLog, SMTP) are noisy but passive.
EXEC_CLASSES = %w[CommandLineEventConsumer ActiveScriptEventConsumer].freeze
SUSPICIOUS = /powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|-enc|frombase64|downloadstring|\\appdata\\|\\temp\\|\\users\\public/i.freeze
# Microsoft's own subscription that ships with the SCM event log provider.
KNOWN_GOOD = ['SCM Event Log Consumer'].freeze

# Query root\subscription with the three classes that make up one persistence "triple".
def snapshot_from_wmi
  require 'win32ole'
  wmi = WIN32OLE.connect('winmgmts:\\\\.\\root\\subscription')
  props = lambda do |cls, names|
    wmi.ExecQuery("SELECT * FROM #{cls}").each.map do |o|
      names.to_h { |n| [n, (o.send(n) rescue nil)&.to_s] }.merge('__CLASS' => o.Path_.Class)
    end
  end
  {
    'filters'   => props.call('__EventFilter', %w[Name Query EventNamespace]),
    'consumers' => wmi.ExecQuery('SELECT * FROM __EventConsumer').each.map do |o|
      %w[Name CommandLineTemplate ExecutablePath ScriptText ScriptingEngine].to_h { |n| [n, (o.send(n) rescue nil)&.to_s] }
                        .merge('__CLASS' => o.Path_.Class)
    end,
    'bindings'  => props.call('__FilterToConsumerBinding', %w[Filter Consumer])
  }
end

def audit(snap)
  findings = []
  bindings = snap['bindings']
  snap['consumers'].each do |c|
    name = c['Name'].to_s
    next if KNOWN_GOOD.include?(name)
    add = ->(sev, rule, msg) { findings << Finding.new(severity: sev, consumer: name, rule: rule, message: msg) }
    bound = bindings.any? { |b| b['Consumer'].to_s.include?("\"#{name}\"") }
    if EXEC_CLASSES.include?(c['__CLASS'])
      payload = [c['CommandLineTemplate'], c['ExecutablePath'], c['ScriptText']].compact.join(' ')
      add.(:error, 'exec-consumer', "#{c['__CLASS']} runs: #{payload[0, 120]}")
      add.(:error, 'suspicious-payload', 'payload matches shell/LOLBin/encoded/temp-path pattern') if payload =~ SUSPICIOUS
      add.(:warn, 'script-consumer', "inline #{c['ScriptingEngine']} script stored in WMI repository") if c['__CLASS'] == 'ActiveScriptEventConsumer'
    else
      add.(:info, 'passive-consumer', "#{c['__CLASS']} (does not execute code)")
    end
    add.(:warn, 'orphan-consumer', 'consumer has no binding to a filter (dormant or half-removed)') unless bound
  end
  snap['filters'].each do |f|
    add = ->(sev, rule, msg) { findings << Finding.new(severity: sev, consumer: f['Name'].to_s, rule: rule, message: msg) }
    q = f['Query'].to_s
    add.(:warn, 'boot-timer-filter', 'filter fires on timer/startup/logon events') if q =~ /__IntervalTimerInstruction|Win32_LocalTime|Win32_ComputerSystem|Win32_LogonSession|SystemUpTime/i
  end
  findings
end

opts = { json: false }
OptionParser.new do |o|
  o.on('--json') { opts[:json] = true }
  o.on('--input FILE') { |v| opts[:input] = v }
end.parse!

snap = opts[:input] ? JSON.parse(File.read(opts[:input])) : snapshot_from_wmi
findings = audit(snap)
if opts[:json]
  puts JSON.pretty_generate(findings.map(&:to_h))
else
  puts "Subscriptions: #{snap['filters'].size} filter(s), #{snap['consumers'].size} consumer(s), #{snap['bindings'].size} binding(s)"
  findings.sort_by { |f| { error: 0, warn: 1, info: 2 }[f.severity] }.each do |f|
    puts format('%-5s %-20s %-24s %s', f.severity.upcase, f.rule, f.consumer, f.message)
  end
  puts 'No findings: no WMI persistence subscriptions of concern.' if findings.empty?
end
exit(findings.any? { |f| f.severity == :error } ? 2 : 0)
