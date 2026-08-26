#!/usr/bin/env ruby
# frozen_string_literal: true
#
# scheduled_task_audit.rb -- Windows Scheduled Task security audit via COM.
#
# Walks the whole Task Scheduler tree (Schedule.Service COM API -- the same
# thing schtasks.exe and taskschd.msc use) and flags the patterns that show
# up in real privilege-escalation and persistence findings:
#
#   CRIT  writable-binary-dir   task runs as SYSTEM/admin but its executable
#                               lives in a directory normal users can write to
#                               (drop a same-named EXE => code runs as SYSTEM)
#   CRIT  temp-path-binary      action executable lives under \Temp\ or
#                               \AppData\ -- classic malware persistence spot
#   WARN  hidden-task           task is flagged hidden in the UI
#   WARN  stored-credentials    task logs on with a stored password (logon
#                               type 1) -- credential material at rest
#   WARN  unquoted-spacey-path  action path has spaces but no quotes
#   INFO  stale-task            enabled task that hasn't run in --stale days
#
#   ruby scheduled_task_audit.rb                 # audit local machine (elevated)
#   ruby scheduled_task_audit.rb --json          # machine-readable
#   ruby scheduled_task_audit.rb --stale 180     # stale threshold (default 90)
#
# Requires: Windows, Ruby with the win32ole stdlib (ships with RubyInstaller).
# Run from an elevated prompt so the COM API will enumerate all task folders.
# Exit codes: 0 clean, 1 warnings, 2 criticals.

require 'json'
require 'optparse'
require 'time'

# Directories that are user-writable on a stock Windows box. An executable
# for a privileged task living under any of these = CRIT.
USER_WRITABLE_PREFIXES = [
  'C:\\Users\\',
  'C:\\ProgramData\\',           # ACLs vary; often creatable by users
  'C:\\Windows\\Temp\\',
  'C:\\Temp\\'
].freeze

PRIVILEGED_PRINCIPALS = ['SYSTEM', 'NT AUTHORITY\\SYSTEM', 'LOCALSYSTEM',
                         'ADMINISTRATORS', 'BUILTIN\\ADMINISTRATORS'].freeze

TASK_LOGON_PASSWORD = 1     # TASK_LOGON_TYPE: stored username+password
TASK_ACTION_EXEC    = 0     # TASK_ACTION_TYPE: launches an executable

# --- pure classification logic (no COM -- this is what the test stub hits) --

module TaskAudit
  module_function

  # task: { name:, path:, enabled:, hidden:, principal:, logon_type:,
  #         actions: [ { type:, exe:, args: } ], last_run: Time|nil }
  def classify(task, stale_days: 90, now: Time.now)
    findings = []
    privileged = PRIVILEGED_PRINCIPALS.include?(task[:principal].to_s.upcase)

    task[:actions].each do |a|
      next unless a[:type] == TASK_ACTION_EXEC
      exe = a[:exe].to_s.strip
      next if exe.empty?
      bare = exe.delete('"')                     # path with quotes stripped
      if privileged && USER_WRITABLE_PREFIXES.any? { |p| bare.upcase.start_with?(p.upcase) }
        findings << ['CRIT', 'writable-binary-dir',
                     "#{task[:principal]} task runs #{bare} from a user-writable directory"]
      end
      if bare =~ /\\(Temp|AppData)\\/i
        findings << ['CRIT', 'temp-path-binary', "executable under #{$1} directory: #{bare}"]
      end
      # Unquoted path containing spaces: Windows tries "C:\Program.exe" first.
      if !exe.start_with?('"') && bare.include?(' ') && bare.downcase.end_with?('.exe')
        findings << ['WARN', 'unquoted-spacey-path', "unquoted path with spaces: #{exe}"]
      end
    end

    findings << ['WARN', 'hidden-task', 'task is hidden from the Task Scheduler UI'] if task[:hidden]
    if task[:logon_type] == TASK_LOGON_PASSWORD
      findings << ['WARN', 'stored-credentials', 'task stores a password for its run-as account']
    end
    if task[:enabled] && task[:last_run] && (now - task[:last_run]) > stale_days * 86_400
      days = ((now - task[:last_run]) / 86_400).to_i
      findings << ['INFO', 'stale-task', "enabled but last ran #{days} days ago"]
    end

    findings.map { |sev, code, detail| { severity: sev, code: code, task: task[:path], detail: detail } }
  end
end

# --- COM collection (Windows only) -----------------------------------------

def collect_tasks
  require 'win32ole'
  svc = WIN32OLE.new('Schedule.Service')
  svc.Connect
  tasks = []
  walk = lambda do |folder|
    folder.GetTasks(1).each do |t|            # 1 = TASK_ENUM_HIDDEN: include hidden
      dfn = t.Definition
      actions = []
      dfn.Actions.each do |a|
        actions << if a.Type == TASK_ACTION_EXEC
                     { type: TASK_ACTION_EXEC, exe: a.Path.to_s, args: (a.Arguments.to_s rescue '') }
                   else
                     { type: a.Type }
                   end
      end
      last_run = begin
        lr = t.LastRunTime
        lr.respond_to?(:year) && lr.year > 1999 ? Time.parse(lr.to_s) : nil
      rescue StandardError
        nil
      end
      tasks << { name: t.Name, path: t.Path, enabled: t.Enabled,
                 hidden: dfn.Settings.Hidden,
                 principal: dfn.Principal.UserId.to_s,
                 logon_type: dfn.Principal.LogonType,
                 actions: actions, last_run: last_run }
    end
    folder.GetFolders(0).each { |sub| walk.call(sub) }
  end
  walk.call(svc.GetFolder('\\'))
  tasks
end

# --- main ------------------------------------------------------------------

if __FILE__ == $PROGRAM_NAME
  options = { json: false, stale: 90 }
  OptionParser.new do |o|
    o.banner = 'Usage: ruby scheduled_task_audit.rb [options]   (run elevated, on Windows)'
    o.on('--json', 'JSON output') { options[:json] = true }
    o.on('--stale DAYS', Integer, 'stale-task threshold (default 90)') { |v| options[:stale] = v }
  end.parse!

  begin
    tasks = collect_tasks
  rescue LoadError
    abort 'error: win32ole not available -- this script must run on Windows. ' \
          'On other platforms, run scheduled_task_audit_test.rb to exercise the logic.'
  end

  findings = tasks.flat_map { |t| TaskAudit.classify(t, stale_days: options[:stale]) }
  sev_rank = { 'CRIT' => 0, 'WARN' => 1, 'INFO' => 2 }
  findings.sort_by! { |f| sev_rank[f[:severity]] }
  crit = findings.count { |f| f[:severity] == 'CRIT' }
  warn = findings.count { |f| f[:severity] == 'WARN' }

  if options[:json]
    puts JSON.pretty_generate('tasks_scanned' => tasks.size,
                              'findings' => findings.map { |f| f.transform_keys(&:to_s) },
                              'summary' => { 'crit' => crit, 'warn' => warn,
                                             'info' => findings.size - crit - warn })
  else
    puts "scheduled task audit -- #{tasks.size} tasks scanned"
    puts
    if findings.empty?
      puts 'no findings -- clean.'
    else
      findings.each do |f|
        puts format('%-5s %-22s %-40s %s', f[:severity], f[:code], f[:task], f[:detail])
      end
      puts
      puts "#{crit} critical, #{warn} warning, #{findings.size - crit - warn} info"
    end
  end
  exit(crit.positive? ? 2 : warn.positive? ? 1 : 0)
end
