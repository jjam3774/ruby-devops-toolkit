# scheduled-task-audit

A security audit of Windows Scheduled Tasks in one Ruby file. Scheduled tasks
are a favorite persistence mechanism ([MITRE ATT&CK T1053.005](https://attack.mitre.org/techniques/T1053/005/))
and one of the least-reviewed corners of a Windows fleet. This script
enumerates every task — including hidden ones — via the Task Scheduler COM API
(`Schedule.Service` through `win32ole`) and flags privilege-escalation and
hygiene risks.

![Architecture](img/task_audit_arch.png)

## Findings

| Severity | Rule | Meaning |
|---|---|---|
| CRIT | `exec-from-writable` | Task runs privileged (SYSTEM/admin/highest run level) but its action binary lives in a user-writable directory (`%TEMP%`, `Downloads`, non-Microsoft `ProgramData`, ...). Anyone who can replace that file owns the machine. |
| CRIT | `missing-binary` | The action's executable no longer exists on disk — either debris or a hijackable path. |
| WARN | `hidden-task` | Task is flagged hidden. Legitimate hidden tasks exist; so does malware. |
| WARN | `stale-disabled` | Disabled and hasn't run in > `--stale-days` (default 180) — audit debris. |

## Prerequisites

- Windows with Ruby (any [RubyInstaller](https://rubyinstaller.org/) build —
  `win32ole` ships in the stdlib). No gems.
- An **elevated** prompt, or you will only see tasks your user can read.
- The test harness (`test_scheduled_task_audit.rb`) runs on **any** OS.

## Usage

```
ruby scheduled_task_audit.rb
ruby scheduled_task_audit.rb --json
ruby scheduled_task_audit.rb --root "\Microsoft\Windows" --stale-days 90
```

Exit codes: `0` clean, `1` WARN findings only, `2` any CRIT — so it slots into
a scheduled compliance job that fails loudly.

## How it works

The script is split into two layers, and that split is the point:

1. **Collector (thin, COM-touching)** — `WIN32OLE.new("Schedule.Service")`,
   `Connect`, then a recursive walk of task folders with `GetTasks(1)` (the
   `1` includes hidden tasks). For each task it extracts name, folder,
   enabled, hidden, `run_as` principal, run level, last run time, and every
   exec-type action's path — into plain Ruby hashes.
2. **Analyzer (pure Ruby)** — path normalization (strips quotes, expands
   `%SystemRoot%`/`%windir%`), a privileged-principal regex, a list of
   user-writable directory patterns, and the four rules above. It takes a
   `file_exists:` lambda instead of calling `File.exist?` directly, so tests
   can stub the filesystem.

Because the analyzer never touches COM, every detection rule is unit-testable
on Linux/macOS — which is exactly how this was verified (below).

## Example output (from the stub harness fixtures)

```
Scanned 8 scheduled tasks under '\'
==============================================================================
\Updater\SyncTask  (runs as: NT AUTHORITY\SYSTEM)
  [CRIT] exec-from-writable   runs as 'NT AUTHORITY\SYSTEM' but executes C:\Users\bob\AppData\Local\Temp\sync.exe from a user-writable directory
\Vendor\OldCleanup  (runs as: NT AUTHORITY\SYSTEM)
  [CRIT] missing-binary       action binary C:\Program Files\Gone\uninstalled.exe does not exist on disk
  [WARN] stale-disabled       disabled and last ran 400 days ago
==============================================================================
crit=2 warn=1
```

## Testing notes — read this honestly

`Schedule.Service` requires a real Windows host, and this repo's CI is Linux.
So what's verified where:

- **Analyzer: fully tested.** `test_scheduled_task_audit.rb` (minitest, 12
  tests / 21 assertions, all passing) feeds realistic task fixtures through
  `TaskAnalyzer.analyze` on Linux — every rule's fire and no-fire cases,
  quote/env-var path normalization, the Microsoft-vs-non-Microsoft
  `ProgramData` distinction, and the privileged-vs-unprivileged writable-path
  logic.
- **Collector: not machine-verified here.** It follows the documented
  Task Scheduler scripting objects (`GetFolder`, `GetTasks`, `Definition`,
  `Principal`, `Actions`) and mirrors working patterns from this repo's other
  WMI/COM scripts, but run it on a disposable Windows box before you trust it
  in production. If a property bombs on your Windows version, see
  Troubleshooting.

## Troubleshooting

- **`WIN32OLERuntimeError` on `LastRunTime`** — tasks that never ran can
  return an error or a sentinel date (1899-12-30); the collector already
  rescues per-property, but treat sentinel dates as "never ran".
- **Empty results** — run elevated; without admin you only enumerate a subset.
- **`ProgramData` false positives** — if a vendor correctly ACLs its
  `ProgramData` folder, add it to the exclusion in `WRITABLE_PATTERNS`.
- **32/64-bit Ruby** — use 64-bit Ruby on 64-bit Windows or COM may show you
  a redirected view of the filesystem for `File.exist?` checks.
- **Localized group names** — the privileged-principal regex matches English
  (`SYSTEM`, `Administrators`); extend `PRIVILEGED` for non-English installs.

## Extending

- **Trigger analysis**: flag tasks with logon/boot triggers pointing at
  scripts (`.ps1`, `.vbs`, `.js`) — a common persistence shape.
- **Baseline diffing**: snapshot task lists to JSON and alert on *new* tasks,
  like this repo's [registry-drift](../registry-drift) does for the registry.
- **Signature checks**: shell out to `Get-AuthenticodeSignature` for each
  action binary and flag unsigned executables in privileged tasks.
- **schtasks fallback**: parse `schtasks /query /fo CSV /v` for hosts where
  COM is blocked.

## References

- Task Scheduler scripting objects: https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-objects
- Ruby win32ole stdlib docs: https://docs.ruby-lang.org/en/master/WIN32OLE.html
- MITRE ATT&CK T1053.005 (Scheduled Task): https://attack.mitre.org/techniques/T1053/005/
