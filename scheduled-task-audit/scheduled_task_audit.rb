#!/usr/bin/env ruby
# frozen_string_literal: true
#
# scheduled_task_audit.rb — audit Windows Scheduled Tasks for the quiet
# persistence tricks and misconfigurations that accumulate in every fleet:
# tasks running as SYSTEM out of user-writable directories, tasks whose
# executable no longer exists, hidden tasks, and tasks that have been
# failing forever without anyone noticing.
#
# Uses the Task Scheduler 2.0 COM API (Schedule.Service) via win32ole —
# Ruby's stdlib COM bridge, so there is nothing to install beyond Ruby.
#
# Design note: collection (COM) and analysis (pure Ruby) are deliberately
# separated. `TaskInfo` is a plain Struct, and every audit rule takes an
# array of TaskInfo — which is what makes the logic testable on a machine
# with no Task Scheduler at all (see test_scheduled_task_audit.rb).
#
# Usage (on Windows, elevated prompt recommended so you see all tasks):
#   ruby scheduled_task_audit.rb
#   ruby scheduled_task_audit.rb --json
#   ruby scheduled_task_audit.rb --all       # include Microsoft\* tasks too
#
# Exit codes: 0 = clean, 1 = warnings, 2 = criticals.

require "json"
require "optparse"
require "time"

TaskInfo = Struct.new(
  :path,          # "\MyCorp\nightly-sync"
  :enabled,       # true/false
  :hidden,        # true/false
  :run_as,        # "SYSTEM", "MyCorp\\svc-backup", ...
  :run_level,     # :highest or :limited
  :action_exe,    # "C:\Users\bob\AppData\sync.exe" (first Exec action)
  :action_args,   # its arguments
  :last_result,   # 0 = success; anything else = last-run error code
  :last_run,      # Time or nil
  :missed_runs,   # integer
  :exe_missing,   # true if collection checked File.exist? and it was gone
  keyword_init: true
)

# --- audit rules (pure functions — no COM, no Windows required) ------------

ELEVATED_PRINCIPALS = ["SYSTEM", "NT AUTHORITY\\SYSTEM", "LOCALSYSTEM"].freeze

# Directories any local user can typically write to. An elevated task whose
# binary sits under one of these can be swapped for a payload by ANY user —
# instant privilege escalation.
WRITABLE_ROOTS = [
  %r{\A[A-Z]:\\Users\\[^\\]+\\}i,
  %r{\A[A-Z]:\\Temp\\}i,
  %r{\A[A-Z]:\\Windows\\Temp\\}i,
  %r{\A[A-Z]:\\ProgramData\\}i
].freeze

def elevated?(t)
  ELEVATED_PRINCIPALS.include?(t.run_as.to_s.upcase) || t.run_level == :highest
end

def audit(tasks, stale_days: 30)
  findings = []
  now = Time.now

  tasks.each do |t|
    exe = t.action_exe.to_s

    if elevated?(t) && WRITABLE_ROOTS.any? { |rx| exe.match?(rx) }
      findings << { severity: :crit, code: "elevated-writable-path", task: t.path,
                    detail: "runs as #{t.run_as} (#{t.run_level}) from user-writable path #{exe}" }
    end

    if t.hidden && !t.path.start_with?('\\Microsoft\\')
      findings << { severity: :warn, code: "hidden-task", task: t.path,
                    detail: "task is hidden from the UI — legitimate software rarely needs this" }
    end

    if t.enabled && t.exe_missing
      findings << { severity: :warn, code: "missing-executable", task: t.path,
                    detail: "enabled task points at #{exe}, which no longer exists" }
    end

    if t.enabled && t.last_result && t.last_result != 0 && t.last_result != 0x41303 # never yet run
      findings << { severity: :warn, code: "failing-task", task: t.path,
                    detail: format("last run returned 0x%08X", t.last_result) }
    end

    if t.enabled && t.last_run && (now - t.last_run) > stale_days * 86_400
      findings << { severity: :warn, code: "stale-task", task: t.path,
                    detail: "enabled but has not run in #{((now - t.last_run) / 86_400).to_i} days" }
    end

    if t.missed_runs.to_i > 3
      findings << { severity: :warn, code: "missed-runs", task: t.path,
                    detail: "#{t.missed_runs} missed runs — check its trigger conditions" }
    end
  end

  findings
end

# --- collection (Windows only) ---------------------------------------------

def collect_tasks(include_microsoft: false)
  require "win32ole"
  svc = WIN32OLE.new("Schedule.Service")
  svc.Connect
  out = []
  walk = lambda do |folder|
    folder.GetTasks(1).each do |task| # 1 = TASK_ENUM_HIDDEN
      d = task.Definition
      next if !include_microsoft && task.Path.start_with?('\\Microsoft\\')
      exec_action = nil
      d.Actions.each do |a|
        if a.Type == 0 # TASK_ACTION_EXEC
          exec_action = a
          break
        end
      end
      exe_path = exec_action ? exec_action.Path.to_s.gsub('"', "") : ""
      # Expand %ENVVAR% references the way Task Scheduler will before checking existence.
      expanded = exe_path.gsub(/%([^%]+)%/) { ENV[Regexp.last_match(1)] || Regexp.last_match(0) }
      out << TaskInfo.new(
        path: task.Path,
        enabled: task.Enabled,
        hidden: d.Settings.Hidden,
        run_as: d.Principal.UserId.to_s,
        run_level: d.Principal.RunLevel == 1 ? :highest : :limited,
        action_exe: exe_path,
        action_args: exec_action ? exec_action.Arguments.to_s : "",
        last_result: task.LastTaskResult,
        last_run: (task.LastRunTime rescue nil),
        missed_runs: (task.NumberOfMissedRuns rescue 0),
        exe_missing: !exe_path.empty? && !File.exist?(expanded)
      )
    end
    folder.GetFolders(0).each { |f| walk.call(f) }
  end
  walk.call(svc.GetFolder('\\'))
  out
end

# --- CLI -------------------------------------------------------------------

if $PROGRAM_NAME == __FILE__
  options = { json: false, all: false, stale_days: 30 }
  OptionParser.new do |o|
    o.banner = "Usage: ruby scheduled_task_audit.rb [options]  (Windows)"
    o.on("--json", "Emit JSON") { options[:json] = true }
    o.on("--all", "Include \\Microsoft\\* tasks (noisy)") { options[:all] = true }
    o.on("--stale-days N", Integer, "Enabled-but-not-running threshold (default 30)") { |v| options[:stale_days] = v }
  end.parse!

  begin
    tasks = collect_tasks(include_microsoft: options[:all])
  rescue LoadError
    abort "win32ole not available — this collector only runs on Windows. " \
          "The audit rules themselves are testable anywhere: see test_scheduled_task_audit.rb"
  end

  findings = audit(tasks, stale_days: options[:stale_days])
  sev_rank = { crit: 2, warn: 1 }
  findings.sort_by! { |f| -sev_rank[f[:severity]] }
  exit_code = findings.any? { |f| f[:severity] == :crit } ? 2 : (findings.empty? ? 0 : 1)

  if options[:json]
    puts JSON.pretty_generate(
      "generated_at" => Time.now.utc.iso8601,
      "tasks_scanned" => tasks.size,
      "findings" => findings.map { |f| f.transform_keys(&:to_s).tap { |h| h["severity"] = h["severity"].to_s } },
      "exit_code" => exit_code
    )
  else
    puts "scheduled_task_audit: #{tasks.size} tasks scanned"
    if findings.empty?
      puts "no findings — clean."
    else
      findings.each { |f| puts format("%-4s %-24s %-40s %s", f[:severity].to_s.upcase, f[:code], f[:task], f[:detail]) }
      puts "#{findings.count { |f| f[:severity] == :crit }} CRIT, #{findings.count { |f| f[:severity] == :warn }} WARN"
    end
  end
  exit exit_code
end
