#!/usr/bin/env ruby
# frozen_string_literal: true
#
# scheduled_task_manager_test.rb -- fixture-driven test suite for
# scheduled_task_manager.rb's TaskSchedulerClient, using a fake in-memory
# engine that mimics the handful of WIN32OLE/Task Scheduler COM calls the
# real RealTaskEngine makes. This lets the create/update/diff logic be
# verified on any OS, with no real Windows host or Task Scheduler service
# involved -- see the README for exactly what this does and does not prove.
#
# Run with: ruby scheduled_task_manager_test.rb

require_relative 'scheduled_task_manager'
require 'minitest/autorun'

# ---------------------------------------------------------------------------
# Fake COM object shapes, just deep enough to satisfy TaskSchedulerClient's
# #same? comparison (existing.Definition.Actions.Item(1).Path, etc.) and
# RealTaskEngine's #create_or_update / #remove call shape.
# ---------------------------------------------------------------------------
FakeAction = Struct.new(:Path, :Arguments)
FakeTrigger = Struct.new(:StartBoundary)
FakeActions = Struct.new(:list) do
  def Item(i) = list[i - 1]
end
FakeTriggers = Struct.new(:list) do
  def Item(i) = list[i - 1]
end
FakeDefinition = Struct.new(:Actions, :Triggers)
FakeTask = Struct.new(:Name, :Definition, :State, :Enabled)

class FakeTaskEngine
  attr_reader :registered # spec hashes passed to create_or_update, in order
  attr_reader :removed    # task names passed to remove, in order

  def initialize(seed_tasks = {})
    @tasks = seed_tasks # name => FakeTask
    @registered = []
    @removed = []
  end

  def list
    @tasks.values.map { |t| { name: t.Name, state: t.State, next_run: nil, enabled: t.Enabled } }
  end

  def find(name)
    @tasks[name]
  end

  def create_or_update(spec)
    @registered << spec
    @tasks[spec[:name]] = FakeTask.new(
      spec[:name],
      FakeDefinition.new(
        FakeActions.new([FakeAction.new(spec[:command], spec[:args].to_s)]),
        FakeTriggers.new([FakeTrigger.new(spec[:start_boundary])])
      ),
      'Ready',
      true
    )
  end

  def remove(name)
    @removed << name
    @tasks.delete(name)
  end
end

class TaskSchedulerClientTest < Minitest::Test
  def valid_spec(overrides = {})
    {
      name: 'NightlyBackup',
      command: 'C:\\Ruby33\\bin\\ruby.exe',
      args: 'C:\\ops\\backup.rb',
      schedule: 'daily',
      at: '02:30',
      run_as: 'SYSTEM'
    }.merge(overrides)
  end

  def test_apply_creates_new_task
    engine = FakeTaskEngine.new
    client = TaskSchedulerClient.new(engine)

    result = client.apply(valid_spec)

    assert_equal :created, result
    assert_equal 1, engine.registered.length
    assert_equal 'NightlyBackup', engine.registered.first[:name]
  end

  def test_apply_is_idempotent_when_nothing_changed
    engine = FakeTaskEngine.new
    client = TaskSchedulerClient.new(engine)

    first = client.apply(valid_spec)
    second = client.apply(valid_spec)

    assert_equal :created, first
    assert_equal :unchanged, second
    assert_equal 1, engine.registered.length, 'a second identical apply should not re-register the task'
  end

  def test_apply_updates_when_command_changes
    engine = FakeTaskEngine.new
    client = TaskSchedulerClient.new(engine)

    client.apply(valid_spec)
    result = client.apply(valid_spec(command: 'C:\\Ruby33\\bin\\ruby.exe', args: 'C:\\ops\\backup_v2.rb'))

    assert_equal :updated, result
    assert_equal 2, engine.registered.length
  end

  def test_apply_updates_when_schedule_time_changes
    engine = FakeTaskEngine.new
    client = TaskSchedulerClient.new(engine)

    client.apply(valid_spec(at: '02:30'))
    result = client.apply(valid_spec(at: '04:00'))

    assert_equal :updated, result
  end

  def test_apply_rejects_missing_name
    client = TaskSchedulerClient.new(FakeTaskEngine.new)
    assert_raises(ArgumentError) { client.apply(valid_spec(name: '')) }
  end

  def test_apply_rejects_bad_time_format
    client = TaskSchedulerClient.new(FakeTaskEngine.new)
    assert_raises(ArgumentError) { client.apply(valid_spec(at: '25:99')) }
  end

  def test_apply_rejects_invalid_schedule
    client = TaskSchedulerClient.new(FakeTaskEngine.new)
    assert_raises(ArgumentError) { client.apply(valid_spec(schedule: 'monthly')) }
  end

  def test_remove_delegates_to_engine
    engine = FakeTaskEngine.new
    client = TaskSchedulerClient.new(engine)
    client.apply(valid_spec)

    client.remove('NightlyBackup')

    assert_equal ['NightlyBackup'], engine.removed
    assert_nil engine.find('NightlyBackup')
  end

  def test_list_reflects_engine_state
    seed = { 'Existing' => FakeTask.new('Existing', nil, 'Ready', true) }
    engine = FakeTaskEngine.new(seed)
    client = TaskSchedulerClient.new(engine)

    tasks = client.list

    assert_equal 1, tasks.length
    assert_equal 'Existing', tasks.first[:name]
  end
end
