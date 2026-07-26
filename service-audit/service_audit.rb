#!/usr/bin/env ruby
# frozen_string_literal: true
#
# service_audit.rb -- Windows Service Inventory & Insecure-Configuration
#                      Audit via WMI (Win32_Service)
#
# Enumerates every Windows service through WMI and flags the specific
# misconfigurations that show up over and over again in privilege-
# escalation checklists (PrivescCheck, WinPEAS, PowerUp) and CIS
# benchmarks:
#
#   1. UNQUOTED SERVICE PATH containing a space -- e.g.
#        C:\Program Files\My App\service.exe
#      Windows will try C:\Program.exe, then C:\Program Files\My.exe,
#      before ever trying the real binary. If an attacker can drop a
#      file at any of those earlier stops, their code runs as
#      whatever account the service runs as.
#   2. Auto-start services running as LocalSystem/NT AUTHORITY\SYSTEM
#      whose binary lives in a directory a non-admin can write to
#      (BINARY_PATH_WRITABLE-style finding -- checked via a
#      best-effort ACL probe, see check_writable_by_everyone).
#   3. Services with no description / unexpected start account, which
#      are worth a human's attention even if not exploitable.
#
# Prerequisites: Windows + the win32ole stdlib (ships with every
# Windows Ruby install -- RubyInstaller included). Must run elevated
# to read every service's full configuration; a non-admin token will
# still enumerate services but some fields may come back blank.
#
# Usage (from an elevated PowerShell or cmd.exe):
#   ruby service_audit.rb
#   ruby service_audit.rb --json
#   ruby service_audit.rb --state Running
#
require 'optparse'
require 'json'

# win32ole is Windows-only. We require it lazily so this file can
# still be loaded (e.g. by `ruby -c` or a test harness) on any OS for
# syntax checking, and so the error message on the wrong platform is
# our own clear message instead of a raw LoadError.
def load_win32ole!
  require 'win32ole'
rescue LoadError
  warn 'win32ole is not available -- this script must run on Windows with a stock Ruby/RubyInstaller.'
  exit 1
end

# A path is "unquoted and dangerous" only if it (a) has no surrounding
# quotes, (b) contains at least one space, and (c) that space appears
# before the .exe -- i.e. there's a real ambiguous break point.
def unquoted_path_vulnerable?(path_name)
  return false if path_name.nil? || path_name.empty?
  return false if path_name.start_with?('"')

  exe_index = path_name =~ /\.exe/i
  return false unless exe_index

  space_index = path_name.index(' ')
  !space_index.nil? && space_index < exe_index
end

# List every "C:\...exe" stop Windows will attempt before reaching the
# real binary, in the order it tries them -- this is what makes the
# unquoted-path bug exploitable and is worth showing in the report so
# a reviewer doesn't have to work it out by hand.
def unquoted_path_candidates(path_name)
  exe_part = path_name.split(/\.exe/i).first + '.exe'
  segments = exe_part.split(' ')
  candidates = []
  running = +''
  segments.each_with_index do |seg, i|
    running = running.empty? ? seg : "#{running} #{seg}"
    next if i == segments.length - 1 # the real, final target -- not a vulnerable stop
    candidates << "#{running}.exe" unless running.end_with?('.exe')
  end
  candidates
end

# Best-effort check for "Everyone"/"Users" write access on the folder
# that holds the service binary, using icacls via WIN32OLE's shell-out
# free alternative isn't available in stdlib, so we do the minimal,
# well-understood thing: shell out to icacls and look for the classic
# dangerous ACE strings. This intentionally fails closed (returns
# false / "unknown") if icacls isn't available or output can't be
# parsed, so we never falsely accuse an ACL we don't understand.
def writable_by_everyone?(dir)
  return nil unless dir && Dir.exist?(dir)

  output = `icacls "#{dir}" 2>NUL`
  return nil if output.nil? || output.strip.empty?

  dangerous = /(Everyone|BUILTIN\\Users|NT AUTHORITY\\Authenticated Users):.*\((?:[A-Z]*,)*[MWF]\)/
  !!(output =~ dangerous)
rescue StandardError
  nil
end

ServiceFinding = Struct.new(:severity, :name, :display_name, :state, :start_mode,
                             :start_name, :path_name, :issues, keyword_init: false) do
  def to_h
    { severity: severity, name: name, display_name: display_name, state: state,
      start_mode: start_mode, start_name: start_name, path_name: path_name, issues: issues }
  end
end

def audit_services(state_filter: nil)
  load_win32ole!
  wmi = WIN32OLE.connect('winmgmts://./root/cimv2')
  query = 'SELECT Name, DisplayName, State, StartMode, StartName, PathName FROM Win32_Service'
  query += " WHERE State = '#{state_filter}'" if state_filter

  findings = []
  scanned = 0

  wmi.ExecQuery(query).each do |svc|
    scanned += 1
    issues = []
    severity = 'INFO'

    path_name = (svc.PathName || '').strip
    # PathName often includes trailing arguments; isolate the binary
    # path itself (everything up to the first .exe) before extracting
    # a directory for the ACL probe.
    binary_path = path_name.start_with?('"') ? path_name[1..].split('"').first : path_name.split(/\.exe/i).first&.+('.exe')

    if unquoted_path_vulnerable?(path_name)
      candidates = unquoted_path_candidates(path_name)
      issues << "UNQUOTED_PATH: #{candidates.join(', ')} would be tried before the real binary"
      severity = 'CRIT'
    end

    running_as_system = %w[LocalSystem NT\ AUTHORITY\\LocalService NT\ AUTHORITY\\NetworkService].include?(svc.StartName) ||
                         svc.StartName.to_s.strip.empty?

    if svc.StartMode == 'Auto' && running_as_system && binary_path
      dir = File.dirname(binary_path.tr('\\', '/'))
      writable = writable_by_everyone?(dir)
      if writable
        issues << "BINARY_DIR_WRITABLE: #{dir} appears writable by Everyone/Users while service runs as #{svc.StartName}"
        severity = 'CRIT'
      end
    end

    if svc.DisplayName.to_s.strip.empty?
      issues << 'NO_DISPLAY_NAME: service metadata looks incomplete'
      severity = 'WARN' if severity == 'INFO'
    end

    next if issues.empty?

    findings << ServiceFinding.new(severity, svc.Name, svc.DisplayName, svc.State,
                                    svc.StartMode, svc.StartName, path_name, issues)
  end

  rank = { 'CRIT' => 3, 'WARN' => 2, 'INFO' => 1 }
  findings.sort_by! { |f| -rank.fetch(f.severity, 0) }
  [findings, scanned]
end

def print_report(findings, scanned)
  puts '=' * 78
  puts 'WINDOWS SERVICE SECURITY AUDIT (Win32_Service via WMI)'
  puts '=' * 78
  puts "Services scanned: #{scanned}  |  Findings: #{findings.size}"
  puts '-' * 78

  if findings.empty?
    puts 'No unquoted-path or writable-binary-directory issues found.'
  else
    findings.each do |f|
      puts "[#{f.severity.ljust(4)}] #{f.name}  (#{f.display_name})"
      puts "         state=#{f.state}  start_mode=#{f.start_mode}  start_name=#{f.start_name}"
      puts "         path=#{f.path_name}"
      f.issues.each { |i| puts "         -> #{i}" }
    end
  end
  puts '=' * 78
  findings.count { |f| f.severity == 'CRIT' }
end

if $PROGRAM_NAME == __FILE__
  options = { json: false, state: nil }
  parser = OptionParser.new do |o|
    o.banner = 'Usage: service_audit.rb [options]'
    o.on('--json', 'Emit JSON instead of a text report') { options[:json] = true }
    o.on('--state STATE', 'Filter by service state, e.g. Running or Stopped') { |v| options[:state] = v }
  end
  parser.parse!

  findings, scanned = audit_services(state_filter: options[:state])

  if options[:json]
    puts JSON.pretty_generate(scanned: scanned, findings: findings.map(&:to_h))
  else
    crit = print_report(findings, scanned)
    exit(crit.positive? ? 2 : 0)
  end
end
