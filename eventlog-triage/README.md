# eventlog-triage

Triage Windows Event Logs via WMI (`win32ole`) — severity-ranked findings instead of
Event Viewer scrolling.

After a Windows box misbehaves, the answers are almost always in the System and
Security event logs — buried under thousands of routine entries. `eventlog_triage.rb`
pulls the last N hours of both channels through WMI (`Win32_NTLogEvent`), buckets the
events that actually matter, and prints a ranked triage report:

| Event | Meaning | Severity |
|---|---|---|
| System/6008 | unexpected shutdown (crash / power loss) | CRIT |
| Security/4740 | account locked out | CRIT |
| Security/4625 | failed logons >= threshold per account (spray / brute force) | CRIT |
| System/7034 | service terminated unexpectedly | WARN |
| System/7045 | **new service installed** (classic persistence technique) | WARN |
| Security/4625 | failed logons below threshold | WARN |
| System/1074 | planned shutdown/restart, and who asked for it | INFO |

![architecture](img/eventlog_triage_arch.png)

## Prerequisites

- Windows with Ruby (RubyInstaller builds ship the `win32ole` stdlib)
- An **elevated** prompt — reading the Security log requires admin rights
- Failed-logon auditing enabled if you want 4625s (`secpol.msc` -> Audit Policy ->
  Audit logon events -> Failure)

## Usage

```powershell
# last 24h, human report
ruby eventlog_triage.rb --hours 24

# tighter window, stricter brute-force threshold, JSON for pipelines
ruby eventlog_triage.rb --hours 6 --logon-threshold 10 --json
```

Exit codes: `0` clean, `1` WARN, `2` CRIT — schedule it in Task Scheduler and act on
the exit code, or ship the JSON to your monitoring stack.

## How it works

- **`EventSource` is the only class that touches `win32ole`.** It connects to
  `winmgmts:\\.\root\cimv2`, runs one `ExecQuery` over `Win32_NTLogEvent` with a
  DMTF-formatted (`yyyymmddHHMMSS.000000+000`) time cutoff, and immediately converts
  each COM object into a plain Ruby hash.
- **`Triage` is pure Ruby.** It never sees WMI — just hashes. 4625 events aggregate
  per target account (insertion string index 5 in the standard Security template,
  with a message-scrape fallback), then per-account counts convert to CRIT/WARN
  against the threshold. Findings sort CRIT-first.
- **That split is the testability story.** The stub harness feeds `Triage` fixture
  events shaped exactly like `EventSource` output, so the classification logic runs
  and is asserted on any OS.

## Testing (honest note)

WMI does not exist off Windows, so this script **cannot be end-to-end tested on
Linux**. What is tested — and what ran before publishing — is
`eventlog_triage_test.rb`: a stub harness that drives the `Triage` class with 13
realistic fixture events (crash, lockout, brute-force burst, service crash x2, new
service install, planned restart) and makes 8 assertions about the classifications.
The WMI query itself follows Microsoft's documented `Win32_NTLogEvent` schema; treat
the `EventSource` layer as "verified by documentation + stub", not by execution.

```
stub harness: 13 fixture events -> 8 findings
  [CRIT] unexpected shutdown at 20260824T031502 — crash or power loss (System/6008)
  [CRIT] account lockout: svc_backup (Security/4740)
  [CRIT] 6 failed logons for account 'Administrator' — possible brute force (Security/4625)
  ...
ALL 8 ASSERTIONS PASSED
```

## Troubleshooting

- **`WIN32OLERuntimeError: Access is denied`** — not elevated; run the prompt as
  Administrator. Non-admin can usually read System but not Security.
- **Empty Security results** — auditing may be disabled (see prerequisites), or the
  log rolled over; check Event Viewer -> Windows Logs -> Security.
- **Query is slow on big logs** — WMI filters `TimeGenerated` server-side, but a
  multi-GB Security log still takes a while; shrink `--hours` first.
- **4625 account shows `unknown`** — some logon types populate insertion strings
  differently; extend `failed_logon_account` with the patterns you see.

## Extending

- Add more event IDs: 4720 (user created), 4732 (added to admin group), 1102
  (audit log cleared — huge red flag).
- Correlate 7045 new-service installs with 4625 bursts in the same window.
- Emit JSON to a scheduled task + webhook for a poor-man's SIEM.
- Swap `EventSource` for a `Get-WinEvent` JSON bridge to read modern channels
  (Sysmon, PowerShell Operational) that `Win32_NTLogEvent` can't see.

## References

- Win32_NTLogEvent class: https://learn.microsoft.com/en-us/previous-versions/windows/desktop/eventlogprov/win32-ntlogevent
- Ruby win32ole stdlib: https://docs.ruby-lang.org/en/3.3/WIN32OLE.html
- Event 4625 reference: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
- Tutorial with full walkthrough: https://tha-shed.com/ruby-for-devops-triage-windows-event-logs-with-wmi/
