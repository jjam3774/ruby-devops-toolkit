#!/usr/bin/env ruby
# frozen_string_literal: true
#
# scheduled_task_manager.rb -- Declarative Windows Scheduled Task management
# via the Task Scheduler 2.0 COM API (WIN32OLE), instead of shelling out to
# schtasks.exe.
#
# schtasks.exe works, but its /create /tr /sc /st flag soup is easy to get
# subtly wrong (quoting, trigger syntax, run-level flags), and it gives you
# no clean way to inspect an existing task's settings before deciding
# whether to touch it. This script talks to the same Task Scheduler service
# schtasks.exe talks to, but through its COM object model, so it can create,
# update-in-place (idempotently), list, and remove tasks from a small Ruby
# API and a one-line CLI.
#
# Usage (run elevated on Windows; Ruby installed via RubyInstaller):
#   ruby scheduled_task_manager.rb list
#   ruby scheduled_task_manager.rb apply --name "NightlyBackup" \
#       --command "C:\Ruby33\bin\ruby.exe" --args "C:\ops\backup.rb" \
#       --schedule daily --at 02:30 --run-as SYSTEM
#   ruby scheduled_task_manager.rb remove --name "NightlyBackup"
#
# This file is organized so the Task Scheduler logic lives in a class
# (TaskSchedulerClient) that takes an injectable "engine" object -- in
# production that's WIN32OLE talking to the real "Schedule.Service", but the
# test suite (scheduled_task_manager_test.rb) swaps in a plain Ruby fake that
# mimics the handful of COM calls this script makes. That's what lets the
# core create/update/diff logic be verified on a machine with no Task
# Scheduler at all.

require 'optparse'
require 'time'

# ---------------------------------------------------------------------------
# Real WIN32OLE-backed engine. Only require'd (and only instantiated) on an
# actual Windows host -- see main() at the bottom.
# ---------------------------------------------------------------------------
class RealTaskEngine
  FOLDER = '\\'
  TASK_CREATE_OR_UPDATE = 6
  TASK_LOGON_SERVICE_ACCOUNT = 5
  TASK_LOGON_PASSWORD = 1
  TASK_ACTION_EXEC = 0
  TASK_TRIGGER_DAILY = 2
  TASK_TRIGGER_WEEKLY = 3

  def initialize
    require 'win32ole'
    @service = WIN32OLE.new('Schedule.Service')
    @service.Connect
    @root_folder = @service.GetFolder(FOLDER)
  end

  def list
    tasks = []
    @root_folder.GetTasks(0).each do |t|
      tasks << { name: t.Name, state: t.State, next_run: safe_next_run(t), enabled: t.Enabled }
    end
    tasks
  end

  def find(name)
    @root_folder.GetTask(name)
  rescue WIN32OLERuntimeError
    nil
  end

  def create_or_update(spec)
    task_def = @service.NewTask(0)
    task_def.RegistrationInfo.Description = spec[:description] || "Managed by scheduled_task_manager.rb"
    task_def.Settings.Enabled = true
    task_def.Settings.StartWhenAvailable = true

    trigger = build_trigger(task_def, spec)
    trigger.StartBoundary = spec[:start_boundary]
    trigger.Enabled = true

    action = task_def.Actions.Create(TASK_ACTION_EXEC)
    action.Path = spec[:command]
    action.Arguments = spec[:args].to_s

    logon_type = spec[:run_as] == 'SYSTEM' ? TASK_LOGON_SERVICE_ACCOUNT : TASK_LOGON_PASSWORD
    user_id = spec[:run_as] == 'SYSTEM' ? 'SYSTEM' : spec[:run_as]

    @root_folder.RegisterTaskDefinition(
      spec[:name], task_def, TASK_CREATE_OR_UPDATE, user_id, spec[:password], logon_type
    )
  end

  def remove(name)
    @root_folder.DeleteTask(name, 0)
  end

  private

  def build_trigger(task_def, spec)
    kind = spec[:schedule] == 'weekly' ? TASK_TRIGGER_WEEKLY : TASK_TRIGGER_DAILY
    task_def.Triggers.Create(kind)
  end

  def safe_next_run(t)
    t.NextRunTime
  rescue StandardError
    nil
  end
end

# ---------------------------------------------------------------------------
# Task spec builder + idempotent diff logic. This part is pure Ruby with no
# COM calls at all, which is exactly why it's the part that's unit-tested
# directly (see the test file) rather than only exercised through the fake
# engine.
# ---------------------------------------------------------------------------
class TaskSchedulerClient
  def initialize(engine)
    @engine = engine
  end

  def list
    @engine.list
  end

  # Returns :created, :updated, or :unchanged
  def apply(spec)
    validate!(spec)
    existing = @engine.find(spec[:name])

    if existing.nil?
      @engine.create_or_update(spec)
      return :created
    end

    if same?(existing, spec)
      :unchanged
    else
      @engine.create_or_update(spec)
      :updated
    end
  end

  def remove(name)
    @engine.remove(name)
  end

  private

  def validate!(spec)
    raise ArgumentError, 'name is required' if spec[:name].to_s.empty?
    raise ArgumentError, 'command is required' if spec[:command].to_s.empty?
    raise ArgumentError, 'schedule must be daily or weekly' unless %w[daily weekly].include?(spec[:schedule])

    hh, mm = spec[:at].to_s.split(':')
    raise ArgumentError, 'at must be HH:MM (24h)' unless hh && mm && hh.to_i.between?(0, 23) && mm.to_i.between?(0, 59)

    spec[:start_boundary] ||= build_start_boundary(spec[:at])
  end

  def build_start_boundary(at)
    hh, mm = at.split(':').map(&:to_i)
    today = Time.now
    start = Time.new(today.year, today.month, today.day, hh, mm, 0)
    start.strftime('%Y-%m-%dT%H:%M:%S')
  end

  # A task is considered "the same" (no COM write needed) when the fields we
  # manage all already match. Real Task Scheduler objects expose these as
  # nested COM properties (Definition.Actions/.Triggers); the fake test
  # engine mirrors just enough of that shape to exercise this comparison.
  def same?(existing, spec)
    action = existing.Definition.Actions.Item(1)
    trigger = existing.Definition.Triggers.Item(1)
    # Compare only the HH:MM time-of-day, not the date: StartBoundary on the
    # existing task carries whatever date it was originally created on,
    # while a freshly-built spec always carries today's date, so comparing
    # full timestamps would report "updated" every single day even when the
    # schedule itself never changed.
    action.Path == spec[:command] &&
      action.Arguments.to_s == spec[:args].to_s &&
      time_of_day(trigger.StartBoundary) == time_of_day(spec[:start_boundary])
  rescue StandardError
    false
  end

  def time_of_day(iso_timestamp)
    iso_timestamp.to_s[11, 5] # "YYYY-MM-DDTHH:MM:SS" -> "HH:MM"
  end
end

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args(argv)
  command = argv.shift
  options = { schedule: 'daily', run_as: 'SYSTEM', password: nil }

  OptionParser.new do |o|
    o.banner = 'Usage: scheduled_task_manager.rb <list|apply|remove> [options]'
    o.on('--name NAME', 'Task name') { |v| options[:name] = v }
    o.on('--command PATH', 'Executable to run') { |v| options[:command] = v }
    o.on('--args ARGS', 'Arguments passed to the executable') { |v| options[:args] = v }
    o.on('--schedule TYPE', %w[daily weekly], 'daily or weekly (default daily)') { |v| options[:schedule] = v }
    o.on('--at HH:MM', 'Time of day to run, 24h') { |v| options[:at] = v }
    o.on('--run-as USER', 'SYSTEM or DOMAIN\\user (default SYSTEM)') { |v| options[:run_as] = v }
    o.on('--password PASS', 'Password for --run-as user (not needed for SYSTEM)') { |v| options[:password] = v }
    o.on('-h', '--help', 'Show this help') { puts o; exit 0 }
  end.parse!(argv)

  [command, options]
end

def main
  command, options = parse_args(ARGV)

  unless %w[list apply remove].include?(command)
    warn 'Usage: scheduled_task_manager.rb <list|apply|remove> [options]'
    exit 1
  end

  unless RUBY_PLATFORM.match?(/mingw|mswin/)
    warn "This command talks to Windows Task Scheduler via WIN32OLE and only runs on Windows."
    warn "(Ruby detected platform: #{RUBY_PLATFORM}). See scheduled_task_manager_test.rb for the" \
         " fixture-driven test suite that exercises this script's logic on any OS."
    exit 1
  end

  client = TaskSchedulerClient.new(RealTaskEngine.new)

  case command
  when 'list'
    client.list.each do |t|
      puts format('%-30s state=%-10s enabled=%-5s next_run=%s', t[:name], t[:state], t[:enabled], t[:next_run])
    end
  when 'apply'
    result = client.apply(options)
    puts "Task '#{options[:name]}': #{result}"
  when 'remove'
    client.remove(options[:name])
    puts "Task '#{options[:name]}': removed"
  end
rescue ArgumentError => e
  warn "Error: #{e.message}"
  exit 1
end

main if $PROGRAM_NAME == __FILE__
