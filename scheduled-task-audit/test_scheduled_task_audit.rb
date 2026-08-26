#!/usr/bin/env ruby
# frozen_string_literal: true
#
# test_scheduled_task_audit.rb -- cross-platform test harness for the
# analysis layer of scheduled_task_audit.rb.
#
# The collection layer needs the Task Scheduler COM API and therefore a real
# Windows host. The analysis layer (TaskAnalyzer) is pure Ruby, so this
# harness feeds it realistic fixture tasks and asserts every detection rule
# fires (and does not fire) where expected. Run it anywhere:
#
#   ruby test_scheduled_task_audit.rb

require "minitest/autorun"
require "time"
require_relative "scheduled_task_audit"

class TestTaskAnalyzer < Minitest::Test
  # file_exists stub: pretend only these binaries are on disk
  EXISTING = [
    'C:\Windows\System32\svchost.exe',
    'C:\Program Files\Vendor\updater.exe',
    'C:\Users\bob\AppData\Local\Temp\sync.exe',
    'C:\ProgramData\Acme\agent.exe'
  ].freeze
  FILE_EXISTS = ->(p) { EXISTING.include?(p) }

  def analyze(task)
    TaskAnalyzer.analyze(task, stale_days: 180, file_exists: FILE_EXISTS)
  end

  def base_task(over = {})
    { name: "T", folder: "\\", enabled: true, hidden: false,
      run_as: 'NT AUTHORITY\SYSTEM', run_level: 1,
      last_run: Time.now - 3600,
      actions: [{ path: 'C:\Windows\System32\svchost.exe', args: "" }] }.merge(over)
  end

  def test_clean_system_task_has_no_findings
    assert_empty analyze(base_task)
  end

  def test_system_task_in_temp_is_crit
    t = base_task(actions: [{ path: 'C:\Users\bob\AppData\Local\Temp\sync.exe', args: "" }])
    rules = analyze(t).map { |f| f[:rule] }
    assert_includes rules, "exec-from-writable"
  end

  def test_unprivileged_task_in_temp_is_not_flagged_writable
    t = base_task(run_as: 'DESKTOP\bob', run_level: 0,
                  actions: [{ path: 'C:\Users\bob\AppData\Local\Temp\sync.exe', args: "" }])
    rules = analyze(t).map { |f| f[:rule] }
    refute_includes rules, "exec-from-writable"
  end

  def test_missing_binary_is_crit
    t = base_task(actions: [{ path: 'C:\Program Files\Gone\uninstalled.exe', args: "" }])
    f = analyze(t)
    assert_equal ["missing-binary"], f.map { |x| x[:rule] }
    assert_equal ["CRIT"], f.map { |x| x[:sev] }
  end

  def test_programdata_non_microsoft_is_writable_risk
    t = base_task(actions: [{ path: 'C:\ProgramData\Acme\agent.exe', args: "" }])
    assert_includes analyze(t).map { |f| f[:rule] }, "exec-from-writable"
  end

  def test_programdata_microsoft_is_not_flagged
    t = base_task(actions: [{ path: 'C:\ProgramData\Microsoft\Windows Defender\platform.exe', args: "" }])
    refute_includes analyze(t).map { |f| f[:rule] }, "exec-from-writable"
  end

  def test_hidden_task_is_warn
    f = analyze(base_task(hidden: true))
    assert_equal [%w[WARN hidden-task]], f.map { |x| [x[:sev], x[:rule]] }
  end

  def test_stale_disabled_task_is_warn
    t = base_task(enabled: false, last_run: Time.now - (400 * 86_400))
    assert_includes analyze(t).map { |f| f[:rule] }, "stale-disabled"
  end

  def test_recently_disabled_task_is_not_stale
    t = base_task(enabled: false, last_run: Time.now - (10 * 86_400))
    refute_includes analyze(t).map { |f| f[:rule] }, "stale-disabled"
  end

  def test_disabled_never_ran_is_stale
    t = base_task(enabled: false, last_run: nil)
    assert_includes analyze(t).map { |f| f[:rule] }, "stale-disabled"
  end

  def test_quoted_path_with_args_normalizes
    assert_equal 'C:\Program Files\Vendor\updater.exe',
                 TaskAnalyzer.normalize('"C:\Program Files\Vendor\updater.exe" /silent')
  end

  def test_systemroot_env_var_expands
    assert_equal 'C:\Windows\System32\svchost.exe',
                 TaskAnalyzer.normalize('%SystemRoot%\System32\svchost.exe')
  end
end
