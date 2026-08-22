#!/usr/bin/env ruby
# frozen_string_literal: true
#
# scheduled_task_audit.rb -- security audit of Windows Scheduled Tasks.
#
# Scheduled Tasks are one of the most popular persistence mechanisms on
# Windows (MITRE ATT&CK T1053.005), and also one of the least-reviewed parts
# of a fleet. This script enumerates every task via the Task Scheduler COM
# API (Schedule.Service, through WIN32OLE) and flags:
#
#   CRIT  exec-from-writable  -> task runs as SYSTEM/an admin but its action
#                                binary lives in a user-writable directory
#                                (%TEMP%, Downloads, C:\Users\...): anyone who
#                                can replace that file owns the machine.
#   CRIT  missing-binary      -> the action's executable no longer exists;
#                                either debris, or a hijackable path.
#   WARN  hidden-task         -> task is flagged hidden; legitimate hidden
#                                tasks exist, but so does malware.
#   WARN  stale-disabled      -> disabled and hasn't run in > 180 days;
#                                audit debris that should be removed.
#   INFO  everything else
#
# Usage (on Windows, in an elevated prompt):
#   ruby scheduled_task_audit.rb
#   ruby scheduled_task_audit.rb --json
#   ruby scheduled_task_audit.rb --root "\\Microsoft\\Windows" --stale-days 90
#
# Exit codes: 0 = clean, 1 = WARN findings only, 2 = any CRIT finding.
# Requires Ruby with the win32ole stdlib (any RubyInstaller build). No gems.

require "json"
require "optparse"
require "time"

options = { json: false, root: "\\", stale_days: 180 }
OptionParser.new do |o|
  o.banner = "Usage: ruby scheduled_task_audit.rb [options]"
  o.on("--json", "Emit JSON instead of the text report") { options[:json] = true }
  o.on("--root PATH", 'Task folder to start from (default "\\")') { |v| options[:root] = v }
  o.on("--stale-days N", Integer, "Days without a run before a disabled task is stale (default 180)") { |v| options[:stale_days] = v }
end.parse!

# ---------------------------------------------------------------------------
# Collection layer -- the only part that touches COM/WMI.
#
# Kept deliberately thin and separate from the analysis logic below, so the
# analysis can be unit-tested on any OS with fixture data (see
# test_scheduled_task_audit.rb in this folder, which stubs this class).
# ---------------------------------------------------------------------------
class TaskCollector
  # Task Scheduler COM constants we care about
  TASK_ACTION_EXEC = 0

  def collect(root)
    require "win32ole"   # required HERE so non-Windows platforms can still load the analysis
    service = WIN32OLE.new("Schedule.Service")
    service.Connect
    tasks = []
    walk(service.GetFolder(root), tasks)
    tasks
  end

  private

  # Recursively walk task folders; flags=1 includes hidden tasks.
  def walk(folder, acc)
    folder.GetTasks(1).each do |t|
      d = t.Definition
      exec_actions = []
      d.Actions.each do |a|
        next unless a.Type == TASK_ACTION_EXEC
        exec_actions << { path: a.Path.to_s, args: a.Arguments.to_s }
      end
      acc << {
        name:          t.Name,
        folder:        folder.Path,
        enabled:       t.Enabled,
        hidden:        d.Settings.Hidden,
        run_as:        d.Principal.UserId.to_s,
        run_level:     d.Principal.RunLevel,      # 1 = highest privileges
        last_run:      (t.LastRunTime rescue nil),
        actions:       exec_actions
      }
    end
    folder.GetFolders(0).each { |f| walk(f, acc) }
  end
end

# ---------------------------------------------------------------------------
# Analysis layer -- pure Ruby, no COM. This is what the tests exercise.
# ---------------------------------------------------------------------------
module TaskAnalyzer
  PRIVILEGED = /\A(NT AUTHORITY\\SYSTEM|SYSTEM|LOCAL SERVICE|NT AUTHORITY\\LOCAL SERVICE|.*\\Administrators?)\z/i

  # Directories a normal user can typically write to. Anything privileged
  # executing from here is a privilege-escalation risk.
  WRITABLE_PATTERNS = [
    /\A%?TE?MP%?\\/i,
    /\\AppData\\Local\\Temp\\/i,
    /\AC:\\Users\\[^\\]+\\(Downloads|Desktop|Documents|AppData)\\/i,
    /\AC:\\Temp\\/i,
    /\AC:\\Windows\\Temp\\/i,
    /\AC:\\ProgramData\\(?!Microsoft\\)/i    # ProgramData subdirs are writable by default unless ACL'd
  ].freeze

  module_function

  # strip quotes and expand the two most common env vars so pattern
  # matching sees a real path
  def normalize(path)
    p = path.strip.delete_prefix('"')
    p = p[0...(p.index('"') || p.length)]
    p.sub(/%SystemRoot%/i, 'C:\Windows').sub(/%windir%/i, 'C:\Windows')
  end

  def privileged?(task)
    task[:run_as].match?(PRIVILEGED) || task[:run_level].to_i == 1
  end

  def writable_path?(path)
    WRITABLE_PATTERNS.any? { |re| normalize(path).match?(re) }
  end

  def analyze(task, stale_days:, file_exists: ->(p) { File.exist?(p) })
    findings = []
    task[:actions].each do |a|
      exe = normalize(a[:path])
      if privileged?(task) && writable_path?(a[:path])
        findings << { sev: "CRIT", rule: "exec-from-writable",
                      msg: "runs as '#{task[:run_as]}' but executes #{exe} from a user-writable directory" }
      end
      # Only meaningful for absolute local paths; skip system32-relative and UNC.
      if exe.match?(/\A[A-Za-z]:\\/) && !file_exists.call(exe)
        findings << { sev: "CRIT", rule: "missing-binary",
                      msg: "action binary #{exe} does not exist on disk" }
      end
    end
    if task[:hidden]
      findings << { sev: "WARN", rule: "hidden-task", msg: "task is flagged hidden" }
    end
    if !task[:enabled]
      last = task[:last_run]
      days = last ? ((Time.now - last) / 86_400).floor : nil
      if days.nil? || days > stale_days
        findings << { sev: "WARN", rule: "stale-disabled",
                      msg: "disabled and last ran #{days ? "#{days} days ago" : 'never'}" }
      end
    end
    findings
  end
end

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if $PROGRAM_NAME == __FILE__
  tasks = TaskCollector.new.collect(options[:root])

  report = tasks.map do |t|
    { task: "#{t[:folder]}\\#{t[:name]}".gsub("\\\\", "\\"),
      run_as: t[:run_as],
      findings: TaskAnalyzer.analyze(t, stale_days: options[:stale_days]) }
  end

  flagged  = report.reject { |r| r[:findings].empty? }
  severities = flagged.flat_map { |r| r[:findings].map { |f| f[:sev] } }
  exit_code  = severities.include?("CRIT") ? 2 : (severities.empty? ? 0 : 1)

  if options[:json]
    puts JSON.pretty_generate(
      generated_at: Time.now.utc.iso8601,
      scanned: tasks.size,
      summary: { crit: severities.count("CRIT"), warn: severities.count("WARN") },
      findings: flagged
    )
  else
    puts "Scanned #{tasks.size} scheduled tasks under '#{options[:root]}'"
    puts "=" * 78
    if flagged.empty?
      puts "No findings. Fleet is clean by the rules in this audit."
    else
      flagged.each do |r|
        puts "#{r[:task]}  (runs as: #{r[:run_as]})"
        r[:findings].each { |f| puts format("  [%-4s] %-20s %s", f[:sev], f[:rule], f[:msg]) }
      end
    end
    puts "=" * 78
    puts "crit=#{severities.count('CRIT')} warn=#{severities.count('WARN')}"
  end

  exit exit_code
end
