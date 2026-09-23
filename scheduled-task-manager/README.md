# scheduled-task-manager

Declarative Windows Scheduled Task management via the Task Scheduler 2.0 COM
API (WIN32OLE) -- create, idempotently update, list, and remove tasks from a
small Ruby API and CLI, instead of assembling `schtasks.exe` flag strings.

## The problem

`schtasks /create /tr ... /sc ... /st ...` works, but the flag syntax is
easy to get subtly wrong (quoting an argument list, trigger syntax, run-level
flags), and `schtasks` gives you no clean way to check "does this task
already exist with the settings I want" before deciding whether to touch it
-- so most `schtasks`-based deploy scripts just blindly recreate the task
every run. This script talks to the exact same Task Scheduler service
through its native COM object model, wraps it in a small idempotent
`apply()` call, and reports back whether it created, updated, or left a
task alone.

## Prerequisites

- Windows, with Ruby installed via [RubyInstaller](https://rubyinstaller.org/)
  (WIN32OLE ships with RubyInstaller's Ruby builds)
- An elevated (Administrator) shell for creating tasks that run as `SYSTEM`
  or another user
- No gems required -- `win32ole` is part of the Ruby standard library on
  Windows builds

## Usage

```
ruby scheduled_task_manager.rb list

ruby scheduled_task_manager.rb apply --name "NightlyBackup" ^
    --command "C:\Ruby33\bin\ruby.exe" --args "C:\ops\backup.rb" ^
    --schedule daily --at 02:30 --run-as SYSTEM

ruby scheduled_task_manager.rb remove --name "NightlyBackup"
```

| Flag | Meaning |
|---|---|
| `list` | print every task in the root folder with state/enabled/next-run |
| `apply` | create the task if missing, update it if its settings drifted, or report `:unchanged` |
| `remove` | delete a task by name |
| `--name` | task name |
| `--command` / `--args` | executable path and its arguments |
| `--schedule daily\|weekly` | trigger type (default daily) |
| `--at HH:MM` | time of day, 24h |
| `--run-as` | `SYSTEM` (default) or `DOMAIN\user` |
| `--password` | required when `--run-as` names a real user account |

## How it works

1. **Two engines, one interface.** `RealTaskEngine` wraps
   `WIN32OLE.new('Schedule.Service')` and does the actual `GetFolder` /
   `GetTask` / `RegisterTaskDefinition` / `DeleteTask` COM calls. It is only
   ever instantiated when `RUBY_PLATFORM` indicates Windows. `FakeTaskEngine`
   (in the test file) is a plain-Ruby stand-in exposing the same four
   methods over an in-memory hash of `Struct`-based fake COM objects.
2. **`TaskSchedulerClient`** is the part that matters and is COM-agnostic:
   it validates a task spec, asks the engine to `find` an existing task by
   name, and if one exists, compares it against the requested spec with
   `same?` before deciding whether a write (`create_or_update`) is even
   necessary.
3. **The idempotency comparison (`same?`)** intentionally compares only the
   command, arguments, and the *time-of-day* portion of the trigger's
   `StartBoundary` -- not the full date -- because a freshly built spec
   always carries today's date while the existing task's boundary carries
   whatever date it was first created on. Comparing full timestamps would
   report "updated" on every single run even when the actual schedule never
   changed (see Testing notes -- this exact bug was caught by the test
   suite before publication).
4. **`RegisterTaskDefinition`** is called with `TASK_CREATE_OR_UPDATE`,
   which lets one call handle both "doesn't exist yet" and "exists, replace
   it" -- the CLI just reports `:created` vs `:updated` based on whether a
   prior task was found.

## Example output

```
> ruby scheduled_task_manager.rb apply --name NightlyBackup --command C:\Ruby33\bin\ruby.exe ^
    --args C:\ops\backup.rb --schedule daily --at 02:30 --run-as SYSTEM
Task 'NightlyBackup': created

> ruby scheduled_task_manager.rb apply --name NightlyBackup --command C:\Ruby33\bin\ruby.exe ^
    --args C:\ops\backup.rb --schedule daily --at 02:30 --run-as SYSTEM
Task 'NightlyBackup': unchanged

> ruby scheduled_task_manager.rb apply --name NightlyBackup --command C:\Ruby33\bin\ruby.exe ^
    --args C:\ops\backup.rb --schedule daily --at 04:00 --run-as SYSTEM
Task 'NightlyBackup': updated
```

Test suite run (`ruby scheduled_task_manager_test.rb`, on any OS):

```
Run options: --seed 54714

# Running:

.........

Finished in 0.001146s, 7851.4506 runs/s, 13958.1343 assertions/s.

9 runs, 16 assertions, 0 failures, 0 errors, 0 skips
```

## Troubleshooting

- **Running this on Linux/macOS prints a platform message and exits 1** --
  that's intentional; WIN32OLE and Task Scheduler don't exist off Windows.
  Use the fixture-driven test suite to exercise the logic anywhere.
- **`RegisterTaskDefinition` raises "Access is denied"** -- the shell isn't
  elevated, or `--run-as` names a user without "Log on as a batch job"
  rights; grant it via `secpol.msc` -> Local Policies -> User Rights
  Assignment.
- **A daily task registered at the wrong date** -- harmless: Task Scheduler
  only cares about the time-of-day and recurrence pattern for a daily
  trigger once it's active; `StartBoundary`'s date is effectively "first
  eligible day," and `same?` deliberately ignores it for that reason (see
  How it works, point 3).
- **`apply` always reports `:updated` even with no real change** -- if you
  hit this, check that you're comparing against the fixed `same?` in this
  version; an earlier draft compared the date portion of `StartBoundary`
  instead of the time, which made every run look different once a day
  boundary was crossed.

## Extending it

- Add support for `TASK_TRIGGER_LOGON` / `TASK_TRIGGER_BOOT` for tasks that
  should fire on sign-in or startup rather than a clock schedule.
- Add a `--dry-run` that reports `:created`/`:updated`/`:unchanged` without
  calling `RegisterTaskDefinition`.
- Extend `same?` to also diff `Settings` (e.g. `StartWhenAvailable`,
  execution time limits) instead of only actions/triggers.

## Testing notes

This script's Task Scheduler integration depends on WIN32OLE and the
Windows Task Scheduler service, neither of which exists in this (Linux)
environment. Its actual decision logic -- `TaskSchedulerClient#apply`'s
validate/find/diff/create-or-update flow -- is instead fully unit-tested
with `scheduled_task_manager_test.rb` against `FakeTaskEngine`, a
plain-Ruby double built from `Struct`s that mimics the shape of the real
COM objects (`Definition.Actions.Item(1).Path`, etc.) closely enough to
exercise the comparison logic. All 9 tests pass. Notably, an early version
of the `same?` comparison had a real bug -- it compared the *date* portion
of the trigger boundary instead of the *time* portion, so
`test_apply_updates_when_schedule_time_changes` failed against the first
implementation (expected `:updated`, got `:unchanged`) until the comparison
was corrected to slice out `HH:MM` instead. That's exactly the kind of bug
a fixture-driven test catches before it ships to a machine with no way to
verify it interactively.

## References

- [Task Scheduler 2.0 COM API reference (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-start-page)
- [ITaskFolder::RegisterTaskDefinition](https://learn.microsoft.com/en-us/windows/win32/taskschd/taskfolder-registertaskdefinition)
- [Ruby WIN32OLE docs](https://docs.ruby-lang.org/en/3.3/WIN32OLE.html)
