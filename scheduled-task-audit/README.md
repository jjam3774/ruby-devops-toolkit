# scheduled-task-audit

Windows Scheduled Task security audit in Ruby, via the `Schedule.Service` COM API
(the same interface `schtasks.exe` and `taskschd.msc` use). Walks the entire task
tree and flags the patterns that show up in real privilege-escalation and
persistence findings.

![architecture](img/task_audit_arch.png)

## Prerequisites

- **Windows** with Ruby that includes the `win32ole` standard library
  (RubyInstaller builds do). No gems required.
- Run from an **elevated** prompt so the COM API enumerates every task folder.
- The pure classification logic is cross-platform and is exercised by the included
  stub test harness, which runs on Linux/macOS.

## Usage

```powershell
# audit the local machine (run elevated)
ruby scheduled_task_audit.rb

# machine-readable
ruby scheduled_task_audit.rb --json

# treat tasks idle for 180+ days as stale (default 90)
ruby scheduled_task_audit.rb --stale 180
```

Run the logic tests on any platform:

```bash
ruby scheduled_task_audit_test.rb
```

## What it flags

| Severity | Code | Meaning |
|----------|------|---------|
| CRIT | `writable-binary-dir` | Privileged (SYSTEM/admin) task whose executable lives in a user-writable directory — drop a same-named EXE and it runs as SYSTEM |
| CRIT | `temp-path-binary` | Action executable under `\Temp\` or `\AppData\` — classic malware persistence spot |
| WARN | `unquoted-spacey-path` | Executable path has spaces but no quotes (unquoted-service-path style ambiguity) |
| WARN | `hidden-task` | Task is flagged hidden in the Task Scheduler UI |
| WARN | `stored-credentials` | Task logs on with a stored password (logon type 1) |
| INFO | `stale-task` | Enabled task that hasn't run in `--stale` days |

## How it works

The script is deliberately split into two layers:

1. **COM collection (`collect_tasks`, Windows-only).** Connects to
   `Schedule.Service`, walks from the root folder recursively, calls `GetTasks(1)`
   to include hidden tasks, and normalizes each task into a plain Ruby hash:
   principal, logon type, hidden/enabled flags, action executables, and last run time.
2. **Pure classification (`TaskAudit.classify`).** Takes that hash and returns the
   findings — no COM, no I/O. Because it's pure, it can be unit-tested anywhere.

`collect_tasks` requires `win32ole` lazily, so on a non-Windows box the main script
exits with a clear message instead of a stack trace, and points you at the test harness.

## Example output (stub harness)

```
PASS  clean system task
PASS  SYSTEM task with exe in user-writable dir
PASS  exe under AppData flags temp-path-binary
PASS  SYSTEM + Windows\Temp flags both CRITs
PASS  unquoted path with spaces
PASS  hidden task
PASS  stored credentials (logon type 1)
PASS  stale enabled task
...
all tests passed
```

On a real Windows host, `scheduled_task_audit.rb` prints a severity-ranked table of
findings across all task folders and exits `2`/`1`/`0` for CRIT/WARN/clean.

## Troubleshooting

- **`win32ole not available`** — you're not on Windows (or on a Ruby build without it).
  The detection logic is still fully testable via `scheduled_task_audit_test.rb`.
- **Fewer tasks than `taskschd.msc` shows** — you're not elevated; some folders
  (e.g. `\Microsoft\Windows\...`) won't enumerate without admin rights.
- **`writable-binary-dir` false positives on ProgramData** — ACLs on `C:\ProgramData`
  vary; confirm the actual directory ACL with `icacls` before treating it as exploitable.
- **No `last_run` / stale never fires** — tasks that have never run report a placeholder
  1899/1999 timestamp, which the script treats as "never ran" rather than stale.

> **Note on testing honesty:** the COM enumeration path depends on WMI/Task Scheduler and
> can only run on a real Windows host, so it is *not* executed in CI here. What **is**
> verified — on Linux, via the stub harness — is every CRIT/WARN/INFO decision, using
> realistic task fixtures fed straight into `TaskAudit.classify`.

## Extending

- Resolve and check the real NTFS ACL of each binary directory instead of matching
  path prefixes, for a definitive writable-dir verdict.
- Parse action `Arguments` for suspicious `-enc`/`DownloadString` PowerShell patterns.
- Emit findings as JSON to a SIEM, or wire into a scheduled compliance job that mails on CRIT.
- Add allowlisting for known-good vendor tasks that legitimately live under AppData.

## References

- [Task Scheduler Scripting Objects (`Schedule.Service`)](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-scripting-objects)
- [`TASK_LOGON_TYPE` enumeration](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type)
- [Ruby `WIN32OLE`](https://docs.ruby-lang.org/en/3.4/WIN32OLE.html)
