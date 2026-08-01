# eventlog-monitor

Polls the Windows Event Log (System/Application, or any log you name) via
WMI for new Error/Warning/Audit-Failure events since the last run,
classifies them, and reports — cron/Task-Scheduler friendly, with state
persisted between runs so you only ever see genuinely new events.

![eventlog-monitor architecture](img/eventlog_monitor_architecture.png)

## Why

`Get-WinEvent` is the modern interactive way to read the event log, but a
lot of shops run scheduled Ruby tooling alongside PowerShell. Re-scanning
the whole log every cron run either misses events between wide windows or
floods you with the same events repeatedly. This script polls
`Win32_NTLogEvent` via WMI and persists a "last seen" watermark so a
5-minute Task Scheduler job only ever reports new events.

## Prerequisites

- **Windows**, with a stock Ruby install (RubyInstaller) — `win32ole` ships
  in the standard library, no gem install needed.
- Permission to *read* the event logs you name.
- Ruby 2.7+ — the rest is stdlib: `optparse`, `json`, `time`, `fileutils`.

## Usage

```powershell
ruby eventlog_monitor.rb --logs System,Application
ruby eventlog_monitor.rb --logs System --since-minutes 120 --json
ruby eventlog_monitor.rb --logs System,Application --exclude-source "Print Spooler"
```

Exit codes: `0` = no new Error/Warning/Audit-Failure events, `1` = new
Warning events only, `2` = new Error or Audit-Failure events.

## How it works

1. **`WmiDateTime`** converts between Ruby `Time` and WMI's `CIM_DATETIME`
   string format (`yyyymmddHHMMSS.mmmmmm±UUU`, where the offset is in
   *minutes*, not hours) — both directions, since the query needs to send a
   WMI-formatted timestamp and results come back the same way.
2. **`EventClassifier`** is pure logic with **zero WIN32OLE dependency** —
   it only calls a handful of methods (`EventType`, `SourceName`, etc.) on
   whatever it's given, so any object that duck-types those properties
   satisfies it. `EventType` 1 (Error) and 5 (Audit Failure) become
   `:crit`; 2 (Warning) becomes `:warn`; everything else is dropped
   entirely rather than reported at `:info`.
3. **`EventLogMonitor`** connects to WMI lazily (`require 'win32ole'` only
   happens inside the method that actually needs it, so the rest of the
   file loads fine on any platform), runs the WQL query bounded by the
   persisted `last_seen` timestamp, classifies the results, and writes the
   newest timestamp back to a small JSON state file for next run.

## Example output

```
$ ruby eventlog_monitor.rb --logs System
CRIT [System] 2026-08-01 14:30:22 Microsoft-Windows-Kernel-Power (#41): The system has rebooted without cleanly shutting down first.

1 new event(s): 1 crit, 0 warn
$ echo $?
2
```

## Testing notes

`Win32_NTLogEvent` and `WIN32OLE` only exist on Windows, so the WMI query
itself couldn't run in this Linux sandbox — the same constraint this repo's
other WMI-based scripts (`service-audit`, `registry-drift`,
`scheduled-task-audit`) already document. What *is* tested live, on any
platform: `WmiDateTime`'s format/parse round-trip (pure string/Time logic)
and `EventClassifier`'s severity rules (pure logic over duck-typed
fixtures). The "since" state handling and full `run()` pipeline are tested
by injecting a fake `wmi_connector` that responds to `ExecQuery` exactly
like a real WIN32OLE WMI connection, returning `OpenStruct` fixtures shaped
like real `Win32_NTLogEvent` rows:

```
$ ruby eventlog_monitor_test.rb
PASS  WmiDateTime.to_wmi produces a valid CIM_DATETIME string
PASS  WmiDateTime.parse round-trips a real Win32_NTLogEvent TimeGenerated value
PASS  WmiDateTime.parse returns nil for garbage input
PASS  EventType 1 (Error) classifies as :crit
PASS  EventType 2 (Warning) classifies as :warn
PASS  EventType 5 (Audit Failure) classifies as :crit
PASS  EventType 3 (Information) is filtered out entirely (nil)
PASS  excluded source names are filtered out
PASS  classify() only keeps the first line of a multi-line Message
PASS  run() returns events sorted by record number with correct levels
PASS  state file is written with the latest generated_at after a run
PASS  a second run queries TimeGenerated using the persisted state, not the default lookback

ALL TESTS PASSED
```

## Troubleshooting

- **`win32ole is not available`** — you're running this on macOS/Linux by
  design; the connector is built lazily so the rest of the file loads
  anywhere, and only errors when something actually tries to talk to WMI.
- **No events ever show up** — check the state file's `last_seen` value; if
  it somehow got written in the future (clock skew, a bad parse), every
  query will ask for events "since" a time that hasn't happened yet.
  Delete the state file to reset to `--since-minutes`.
- **Query is slow on a busy System log** — `Win32_NTLogEvent` queries scale
  with total log size on some Windows versions; shrinking the log's max
  size or running more frequently (smaller time windows) usually helps
  more than optimizing the WQL further.
- **A footgun we hit writing this one**: an early draft named a module
  method `WmiDateTime.format`. Since `self` inside a module method *is*
  the module, a later bare `format(...)` call elsewhere in the same module
  resolved to that method instead of `Kernel#format` — it silently
  swallowed an `ArgumentError` and returned `nil` for every parsed
  timestamp until the test suite caught it. Renamed to `to_wmi` and
  switched the internal call to `sprintf`.

## Extending

- Add an `--event-ids` allow/deny list by `EventCode` for finer filtering
  than a whole-source exclude.
- Ship matched CRIT events to a webhook or this repo's
  [`prometheus-exporter`](../prometheus-exporter) as a gauge.
- Add a `--computer` flag to query a remote host's event log via WMI
  (`winmgmts://user:pass@host/root/cimv2`).

## References

- [Win32_NTLogEvent class (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-ntlogevent)
- [Ruby stdlib: WIN32OLE](https://ruby-doc.org/stdlib/libdoc/win32ole/rdoc/WIN32OLE.html)
