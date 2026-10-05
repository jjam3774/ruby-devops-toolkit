#!/usr/bin/env ruby
# frozen_string_literal: true
#
# schtasks_audit.rb - Audit Windows Scheduled Tasks for privilege-escalation risks.
#
# Runs `schtasks /query /fo CSV /v` (or reads a saved CSV with --input) and flags:
#   HIGH   task runs as SYSTEM/Administrator but its executable lives in a
#          user-writable location (C:\Users, \Temp, \AppData, C:\ProgramData)
#   HIGH   unquoted executable path containing spaces (classic path-hijack)
#   MEDIUM task runs as SYSTEM and its last run failed
#   LOW    enabled task whose author is not Microsoft and runs as SYSTEM
# The parser and rules are pure Ruby and run on any OS; only the live query needs Windows.

require 'csv'
require 'optparse'
require 'json'

PRIVILEGED = /\A(NT AUTHORITY\\SYSTEM|SYSTEM|.*\\Administrator|Administrator|NT AUTHORITY\\LOCAL SERVICE|NT AUTHORITY\\NETWORK SERVICE)\z/i
WRITABLE   = %r{(\\users\\|\\temp\\|\\tmp\\|\\appdata\\|\\programdata\\|\\downloads\\|\\public\\)}i

Finding = Struct.new(:severity, :task, :run_as, :command, :reason)

# Split `"C:\Program Files\x\a.exe" -arg` or `C:\tools\a.exe -arg` into [exe, args].
def split_command(cmd)
  cmd = cmd.to_s.strip
  return [cmd[1..cmd.index('"', 1) - 1], cmd[(cmd.index('"', 1) + 1)..].to_s.strip] if cmd.start_with?('"') && cmd.index('"', 1)

  m = cmd.match(/\A(.+?\.(?:exe|bat|cmd|ps1|vbs|com))(?:\s+(.*))?\z/i)
  m ? [m[1], m[2].to_s] : [cmd, '']
end

# `schtasks /v` repeats the header row before each task and emits several rows per
# multi-trigger task; drop repeated headers and de-duplicate by task name.
def load_tasks(io)
  rows = CSV.parse(io, headers: true, skip_blanks: true)
  seen = {}
  rows.each do |r|
    next if r['TaskName'] == 'TaskName' # repeated header
    seen[r['TaskName']] ||= r.to_h
  end
  seen.values
end

def audit_task(t)
  name   = t['TaskName']
  run_as = t['Run As User'].to_s
  cmd    = t['Task To Run'].to_s
  state  = t['Scheduled Task State'].to_s
  return [] if state =~ /disabled/i || cmd.empty? || cmd =~ /COM handler/i # COM actions have no path to audit

  exe, = split_command(cmd)
  privileged = run_as =~ PRIVILEGED
  out = []
  quoted = cmd.start_with?('"')
  out << Finding.new(:high, name, run_as, cmd, 'unquoted path with spaces: Windows tries shorter paths first (C:\\Program.exe)') if !quoted && exe.include?(' ') && privileged
  out << Finding.new(:high, name, run_as, cmd, "privileged task runs binary from user-writable location") if privileged && exe =~ WRITABLE
  out << Finding.new(:medium, name, run_as, cmd, "privileged task last result #{t['Last Result']} (non-zero)") if privileged && t['Last Result'].to_s !~ /\A(0|267009|267011|267014)?\z/ # 0x41301 running, 0x41303 not yet run
  if privileged && t['Author'].to_s !~ /microsoft/i && name !~ %r{\\Microsoft\\}i && out.empty?
    out << Finding.new(:low, name, run_as, cmd, "third-party task (author: #{t['Author']}) runs with high privilege - confirm it is expected")
  end
  out
end

if $PROGRAM_NAME == __FILE__
  opts = { input: nil, json: false }
  OptionParser.new do |op|
    op.on('--input FILE', 'read a saved `schtasks /query /fo CSV /v` dump') { |v| opts[:input] = v }
    op.on('--json') { opts[:json] = true }
  end.parse!(ARGV)

  raw = opts[:input] ? File.read(opts[:input], encoding: 'bom|utf-8') : `schtasks /query /fo CSV /v`
  abort 'schtasks query failed (are you on Windows?)' if raw.to_s.strip.empty?

  tasks    = load_tasks(raw)
  findings = tasks.flat_map { |t| audit_task(t) }
  order    = { high: 0, medium: 1, low: 2 }
  findings.sort_by! { |f| [order[f.severity], f.task] }

  if opts[:json]
    puts JSON.pretty_generate(findings.map(&:to_h))
  else
    puts "Scanned #{tasks.size} scheduled tasks, #{findings.size} findings\n\n"
    findings.each do |f|
      puts "[#{f.severity.to_s.upcase.ljust(6)}] #{f.task}"
      puts "         run as : #{f.run_as}"
      puts "         command: #{f.command}"
      puts "         why    : #{f.reason}"
    end
  end
  exit(findings.any? { |f| f.severity == :high } ? 2 : 0)
end
