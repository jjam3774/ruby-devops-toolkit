#!/usr/bin/env ruby
# frozen_string_literal: true
#
# test_scheduled_task_audit.rb — exercises every audit rule in
# scheduled_task_audit.rb with realistic TaskInfo fixtures, no Windows and
# no COM required. This is how the detection logic was verified before
# publishing, since the collector itself needs a real Task Scheduler.
#
#   ruby test_scheduled_task_audit.rb

require "minitest/autorun"
require_relative "scheduled_task_audit"

def make_task(over = {})
  TaskInfo.new(**{
    path: '\\MyCorp\\healthy-task',
    enabled: true,
    hidden: false,
    run_as: 'MyCorp\\svc-runner',
    run_level: :limited,
    action_exe: 'C:\\Program Files\\MyCorp\\runner.exe',
    action_args: "",
    last_result: 0,
    last_run: Time.now - 3600,
    missed_runs: 0,
    exe_missing: false
  }.merge(over))
end

class AuditRulesTest < Minitest::Test
  def codes(tasks)
    audit(tasks).map { |f| [f[:code], f[:severity]] }
  end

  def test_clean_task_produces_no_findings
    assert_empty audit([make_task])
  end

  def test_system_task_in_user_profile_is_critical
    t = make_task(path: '\\updater', run_as: "SYSTEM",
                  action_exe: 'C:\\Users\\bob\\AppData\\Local\\updater.exe')
    assert_includes codes([t]), ["elevated-writable-path", :crit]
  end

  def test_highest_runlevel_in_programdata_is_critical
    t = make_task(run_as: 'MyCorp\\bob', run_level: :highest,
                  action_exe: 'C:\\ProgramData\\sync\\sync.exe')
    assert_includes codes([t]), ["elevated-writable-path", :crit]
  end

  def test_limited_task_in_user_profile_is_fine
    t = make_task(run_as: 'MyCorp\\bob', run_level: :limited,
                  action_exe: 'C:\\Users\\bob\\tool.exe')
    refute_includes codes([t]).map(&:first), "elevated-writable-path"
  end

  def test_hidden_non_microsoft_task_warns
    assert_includes codes([make_task(hidden: true)]), ["hidden-task", :warn]
  end

  def test_hidden_microsoft_task_is_ignored
    t = make_task(hidden: true, path: '\\Microsoft\\Windows\\Defrag\\ScheduledDefrag')
    refute_includes codes([t]).map(&:first), "hidden-task"
  end

  def test_missing_executable_warns
    assert_includes codes([make_task(exe_missing: true)]), ["missing-executable", :warn]
  end

  def test_failing_task_warns
    assert_includes codes([make_task(last_result: 0x80070002)]), ["failing-task", :warn]
  end

  def test_never_ran_code_is_not_a_failure
    refute_includes codes([make_task(last_result: 0x41303, last_run: nil)]).map(&:first), "failing-task"
  end

  def test_stale_enabled_task_warns
    t = make_task(last_run: Time.now - 90 * 86_400)
    assert_includes codes([t]), ["stale-task", :warn]
  end

  def test_disabled_stale_task_does_not_warn
    t = make_task(enabled: false, last_run: Time.now - 90 * 86_400)
    refute_includes codes([t]).map(&:first), "stale-task"
  end

  def test_missed_runs_warns
    assert_includes codes([make_task(missed_runs: 12)]), ["missed-runs", :warn]
  end
end
