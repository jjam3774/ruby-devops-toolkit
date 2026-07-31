#!/usr/bin/env ruby
# frozen_string_literal: true
#
# scheduled_task_audit.rb
#
# Audits Windows Task Scheduler tasks for privilege-escalation risks by
# walking the Task Scheduler COM API (Schedule.Service) via WIN32OLE. Task
# Scheduler is a favorite persistence/privilege-escalation mechanism for
# attackers because a task that runs as SYSTEM but launches a binary from a
# directory a low-privileged user can write to is a straight line from
# "local user" to "SYSTEM" -- and because unquoted paths with spaces let an
# attacker plant an evil executable earlier in the path.
#
# Checks performed on every task:
#   1. Unquoted action path containing spaces (classic unquoted-path hijack:
#      "C:\Program Files\Vendor App\run.exe" launched unquoted lets an
#      attacker place C:\Program.exe or C:\Program Files\Vendor.exe).
#   2. Action executable located under a directory that is commonly
#      user-writable (Temp, Users profile paths, ProgramData root, Public).
#   3. Task runs as SYSTEM (or with "Highest" run level) while its action
#      executable lives outside the trusted C:\Windows or
#      C:\Program Files trees.
#   4. Task is both hidden and elevated -- a common stealth-persistence
#      pattern worth a second look even when nothing else is wrong.
#
# Because Schedule.Service is a Windows-only COM object, this script cannot
# run on Linux/macOS at all. The repository's test suite instead exercises
# `evaluate_task`, the pure risk-scoring function, against realistic fixture
# hashes shaped exactly like what `TaskFetcher#fetch_tasks` builds from the
# live COM objects -- see scheduled_task_audit_test.rb. That test harness
# runs anywhere Ruby runs, including this Linux sandbox; the WIN32OLE
# integration itself was verified by code review against the documented
# Schedule.Service object model (Microsoft's ITaskService/IRegisteredTask/
# IPrincipal/IExecAction interfaces -- see the References section of the
# README) since a live Windows host was not available in this environment.
#
# Usage (on Windows, ideally an elevated prompt so hidden/system tasks are
# visible):
#   ruby scheduled_task_audit.rb
#   ruby scheduled_task_audit.rb --folder "\\Microsoft\\Windows\\UpdateOrchestrator"
#   ruby scheduled_task_audit.rb --json
#
# Exit codes (cron/CI/Task Scheduler friendly):
#   0 - no findings
#   1 - WARN-level findings only
#   2 - CRIT-level findings present

require 'optparse'
require 'json'
require 'time'

Finding = Struct.new(:severity, :task, :check, :detail) do
  def to_h
    { severity: severity.to_s, task: task, check: check, detail: detail }
  end
end

SEVERITY_RANK = { info: 0, warn: 1, crit: 2 }.freeze

# Directories that are commonly writable by non-administrator users on a
# default Windows install. Not exhaustive -- a real hardened audit should
# also check the actual ACL via icacls/Get-Acl, but this catches the
# overwhelming majority of real-world misconfigurations cheaply.
USER_WRITABLE_HINTS = [
  %r{\\Users\\[^\\]+\\}i,
  %r{\\Temp\\}i,
  %r{\\AppData\\}i,
  %r{^[A-Z]:\\ProgramData\\}i,
  %r{\\Public\\}i,
  %r{\\Downloads\\}i
].freeze

TRUSTED_ROOTS = [
  %r{^[A-Z]:\\Windows\\}i,
  %r{^[A-Z]:\\Program Files\\}i,
  %r{^[A-Z]:\\Program Files \(x86\)\\}i
].freeze

# ---------------------------------------------------------------------------
# Pure risk-scoring logic -- no WIN32OLE dependency, fully unit-testable.
#
# task is a Hash shaped like:
#   {
#     name: String, path: String, enabled: Boolean, hidden: Boolean,
#     run_as: String, run_level: "Highest" | "LUA",
#     actions: [{ execute: String, arguments: String }]
#   }
# ---------------------------------------------------------------------------
def evaluate_task(task)
  findings = []
  name = task[:path] || task[:name]

  task[:actions].each do |action|
    exe = action[:execute].to_s
    next if exe.empty?

    if unquoted_with_space?(exe)
      findings << Finding.new(:crit, name, 'unquoted-action-path',
                               "Action executable '#{exe}' contains a space and is not " \
                               'quoted. An attacker able to write to an earlier path ' \
                               'segment can hijack execution.')
    end

    if USER_WRITABLE_HINTS.any? { |re| exe =~ re }
      findings << Finding.new(:crit, name, 'writable-action-directory',
                               "Action executable '#{exe}' lives under a directory that " \
                               'is commonly writable by non-admin users.')
    end

    runs_privileged = task[:run_as].to_s.casecmp('SYSTEM').zero? || task[:run_level].to_s == 'Highest'
    if runs_privileged && !TRUSTED_ROOTS.any? { |re| exe =~ re }
      findings << Finding.new(:warn, name, 'privileged-task-untrusted-path',
                               "Task runs as #{task[:run_as]} (run level: #{task[:run_level]}) " \
                               "but its action executable '#{exe}' is outside the trusted " \
                               'Windows/Program Files trees.')
    end
  end

  if task[:hidden] && task[:run_level].to_s == 'Highest'
    findings << Finding.new(:warn, name, 'hidden-and-elevated',
                             'Task is marked hidden and requests the highest available run ' \
                             'level -- a common stealth-persistence combination worth a ' \
                             'manual look even if nothing else fires.')
  end

  findings
end

def unquoted_with_space?(exe)
  return false unless exe.include?(' ')
  return false if exe.start_with?('"') && exe.rstrip.end_with?('"')
  # A bare executable path with no arguments and no spaces before the .exe
  # extension is fine; flag only when the space appears before we've hit the
  # executable extension, i.e. the path itself (not just its arguments) has
  # unquoted whitespace.
  path_part = exe[/\A[^"]*?\.(exe|bat|cmd|ps1|vbs)\b/i]
  return false unless path_part

  path_part.include?(' ')
end

# ---------------------------------------------------------------------------
# WIN32OLE integration -- only loaded/used on Windows.
# ---------------------------------------------------------------------------
class TaskFetcher
  RUN_LEVEL_MAP = { 0 => 'LUA', 1 => 'Highest' }.freeze

  def initialize(root_folder: '\\')
    require 'win32ole'
    @service = WIN32OLE.new('Schedule.Service')
    @service.Connect
    @root_folder = root_folder
  end

  def fetch_tasks
    tasks = []
    walk_folder(@service.GetFolder(@root_folder), tasks)
    tasks
  end

  private

  def walk_folder(folder, tasks)
    folder.GetTasks(1).each do |task|
      tasks << build_task_hash(folder, task)
    end
    folder.GetFolders(0).each { |sub| walk_folder(sub, tasks) }
  end

  def build_task_hash(folder, task)
    definition = task.Definition
    principal = definition.Principal
    actions = definition.Actions.each.map do |a|
      { execute: a.Path.to_s, arguments: a.Arguments.to_s }
    end

    {
      name: task.Name,
      path: task.Path,
      enabled: task.Enabled,
      hidden: definition.Settings.Hidden,
      run_as: principal.UserId.to_s,
      run_level: RUN_LEVEL_MAP.fetch(principal.RunLevel, 'Unknown'),
      actions: actions
    }
  end
end

def parse_options(argv)
  opts = { folder: '\\', json: false }
  parser = OptionParser.new do |o|
    o.banner = 'Usage: ruby scheduled_task_audit.rb [options]'
    o.on('--folder PATH', 'Task Scheduler folder to start from (default: \\ = root, recurses)') { |v| opts[:folder] = v }
    o.on('--json', 'Emit machine-readable JSON instead of text') { opts[:json] = true }
    o.on('-h', '--help', 'Show this help') do
      puts o
      exit 0
    end
  end
  parser.parse!(argv)
  opts
end

def print_text_report(findings, task_count)
  puts "scheduled_task_audit: scanned #{task_count} task(s), #{findings.size} finding(s)"
  puts '-' * 72

  if findings.empty?
    puts 'No issues found.'
    return
  end

  %i[crit warn info].each do |sev|
    group = findings.select { |f| f.severity == sev }
    next if group.empty?

    puts "\n[#{sev.to_s.upcase}] (#{group.size})"
    group.each do |f|
      puts "  - #{f.task}: #{f.check}"
      puts "      #{f.detail}"
    end
  end
end

if __FILE__ == $PROGRAM_NAME
  options = parse_options(ARGV)

  unless RUBY_PLATFORM =~ /mingw|mswin|windows/i
    warn 'scheduled_task_audit.rb requires Windows (Schedule.Service via WIN32OLE is ' \
         'not available on this platform). See scheduled_task_audit_test.rb for the ' \
         'platform-independent logic test.'
    exit 3
  end

  tasks = TaskFetcher.new(root_folder: options[:folder]).fetch_tasks
  findings = tasks.flat_map { |t| evaluate_task(t) }

  if options[:json]
    puts JSON.pretty_generate(
      scanned_at: Time.now.utc.iso8601,
      task_count: tasks.size,
      finding_count: findings.size,
      findings: findings.map(&:to_h)
    )
  else
    print_text_report(findings, tasks.size)
  end

  worst = findings.map { |f| SEVERITY_RANK[f.severity] }.max || -1
  exit(worst >= SEVERITY_RANK[:crit] ? 2 : worst >= SEVERITY_RANK[:warn] ? 1 : 0)
end
