# scheduled-task-audit

Audits Windows Task Scheduler tasks for privilege-escalation risk via the
`Schedule.Service` COM API (WIN32OLE). Task Scheduler is a favorite
persistence/privilege-escalation mechanism for attackers: a task that runs as
SYSTEM but launches a binary from a directory a low-privileged user can write
to is a straight line from "local user" to "SYSTEM."

## What it catches

1. **Unquoted action paths containing spaces** — the classic unquoted-path
   hijack. `C:\Program Files\Vendor App\run.exe` launched unquoted lets an
   attacker who can write to `C:\` plant `C:\Program.exe`, which Windows will
   execute instead.
2. **Action executables in commonly user-writable directories** — `Temp`,
   `AppData`, user profile directories, `ProgramData`, `Public`, `Downloads`.
3. **Privileged tasks (SYSTEM or "Highest" run level) whose action lives
   outside the trusted `C:\Windows` / `C:\Program Files` trees.**
4. **Hidden + elevated tasks** — a common stealth-persistence combination
   worth a manual look even when nothing else fires.

## Prerequisites

- **Windows only.** `Schedule.Service` is a Windows COM object; this script
  cannot run on Linux or macOS at all — attempting to will print a clear
  error and exit 3.
- Ruby with the `win32ole` standard library gem (bundled with the standard
  Windows Ruby installers, e.g. RubyInstaller)
- Run from an elevated (Administrator) prompt to see hidden and
  SYSTEM-owned tasks; a non-elevated run will only see tasks visible to the
  current user.

## Usage

```powershell
# Audit every task under the Task Scheduler root, recursively
ruby scheduled_task_audit.rb

# Start from a specific folder instead of the root
ruby scheduled_task_audit.rb --folder "\Microsoft\Windows\UpdateOrchestrator"

# Machine-readable output
ruby scheduled_task_audit.rb --json
```

Exit codes: `0` clean, `1` WARN-level findings only, `2` at least one CRIT
finding. Drops straight into a scheduled maintenance task, CI runner, or a
Nagios-style check.

## How it works — and how it was tested without a Windows box

The script is split deliberately into two halves:

- **`TaskFetcher`** (WIN32OLE-dependent): connects to `Schedule.Service`,
  recursively walks folders with `GetFolders(0)`/`GetTasks(1)`, and pulls each
  task's `Definition.Principal` (run-as user, run level) and
  `Definition.Actions` (executable path + arguments) into a plain Ruby hash
  via `build_task_hash`.
- **`evaluate_task(hash)`** (pure Ruby, zero WIN32OLE dependency): takes that
  hash and runs the four risk checks above, returning `Finding` structs.

Because this sandbox is Linux, `TaskFetcher` cannot be exercised here —
`Schedule.Service` simply doesn't exist outside Windows. Instead,
**`scheduled_task_audit_test.rb`** feeds `evaluate_task` a set of fixture
hashes shaped exactly like what `build_task_hash` produces from a live COM
object tree (verified by code review against Microsoft's documented
`ITaskService`/`IRegisteredTask`/`IPrincipal`/`IExecAction` interfaces — see
References below), covering: a clean SYSTEM task, an unquoted path with a
space, the same path properly quoted (should NOT flag), a SYSTEM task in a
writable Temp directory, a non-privileged user task in an untrusted path
(should NOT trigger the privileged-only check), a hidden+elevated task, a
hidden-but-LUA task (should NOT flag), and a task with two actions where only
one is risky (each action evaluated independently). Run it with:

```bash
ruby scheduled_task_audit_test.rb
```

This is the same approach this repository's `service-audit/` and
`registry-drift/` scripts use for their own WIN32OLE-backed logic — the COM
integration is reviewed against Microsoft's object model, and the
decision logic is unit-tested with realistic fixtures on any platform.

## Example output

From `ruby scheduled_task_audit_test.rb` in this sandbox:

```
scheduled_task_audit_test.rb -- exercising evaluate_task() against WIN32OLE-shaped fixtures
==============================================================================

[1] Healthy task: trusted path, quoted, not hidden
  PASS  no findings for a clean SYSTEM task in C:\Windows\System32

[2] Unquoted path with a space -- classic hijack vector
  PASS  flags unquoted-action-path
  PASS  severity is crit
...
==============================================================================
11 assertions, 0 failures
```

And the guard message when running the real script (not the test) on Linux:

```
$ ruby scheduled_task_audit.rb
scheduled_task_audit.rb requires Windows (Schedule.Service via WIN32OLE is
not available on this platform). See scheduled_task_audit_test.rb for the
platform-independent logic test.
```

On a real Windows host, `ruby scheduled_task_audit.rb` would instead print a
grouped CRIT/WARN/INFO report exactly like the other auditors in this repo
(`user-account-audit`, `perm-audit`), built from the live task list.

## Troubleshooting

- **"Access is denied" connecting to Schedule.Service** — run from an
  elevated prompt; some folders/tasks (especially under
  `\Microsoft\Windows\`) are only enumerable as Administrator.
- **Hidden tasks don't show up** — `GetTasks(1)` passes the
  `TASK_ENUM_HIDDEN` flag so hidden tasks ARE included; if you still don't
  see them, confirm you're elevated, since Task Scheduler additionally
  hides some tasks from non-admin enumeration regardless of the API flag.
- **False positive on `writable-action-directory`** — the directory hint
  list is intentionally broad (anything under `Users`, `Temp`, `AppData`,
  `ProgramData`, `Public`, `Downloads`). A real hardened environment might
  lock down `ProgramData` ACLs such that it isn't actually user-writable;
  treat a hit as "verify the ACL," not an automatic confirmed finding — the
  script trades some false positives for not missing real ones.
- **`LoadError: cannot load such file -- win32ole`** — you're not running on
  Windows, or you're on a minimal Ruby build without the `win32ole` gem.
  It ships by default with RubyInstaller for Windows.

## Extending it

- Add a real ACL check via `icacls` (shelled out with `Open3.capture2`) to
  replace the directory-name heuristic in `USER_WRITABLE_HINTS` with an
  actual "is this writable by non-admins" answer.
- Cross-reference `Actions` arguments (not just the executable path) for
  additional unquoted-path risk when a script interpreter (`cmd.exe`,
  `powershell.exe`) is the action and the real payload is in `arguments`.
- Add a check for tasks with network-facing triggers (`TASK_TRIGGER_REGISTRATION`,
  event-log triggers) combined with elevated run level — a broader remote
  attack surface than time-based triggers alone.
- Feed `evaluate_task` findings into `registry-drift/`'s or this repo's other
  Windows scripts' JSON baseline pattern, so a "known good" task inventory
  can be diffed over time instead of re-evaluated from static rules alone.

## References

- [`ITaskService` interface (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/taskschd/itaskservice)
- [`IRegisteredTask` interface (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/taskschd/iregisteredtask)
- [`IPrincipal` interface (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/taskschd/iprincipal2)
- [Ruby `WIN32OLE`](https://docs.ruby-lang.org/en/3.0/WIN32OLE.html)
