# Ruby DevOps Toolkit

Small, self-contained Ruby scripts for Linux and Windows sysadmin/DevOps tasks — most use
only the Ruby standard library, no gems required. Each one was written to be read end-to-end
in a few minutes and dropped straight onto a box.

| Script | Platform | What it does |
| --- | --- | --- |
| [`perm-audit/perm_audit.rb`](perm-audit/) | Linux | Scans directory trees for world-writable paths missing the sticky bit and unexpected SUID/SGID binaries. |
| [`ntp-drift/ntp_drift.rb`](ntp-drift/) | Linux / macOS / Windows | Pure-Ruby SNTP client that checks clock drift against a fleet of NTP sources concurrently. |
| [`service-audit/service_audit.rb`](service-audit/) | Windows | Audits Windows services via WMI for the unquoted-service-path privilege-escalation bug and writable-binary-directory risk. |
| [`log-analyzer/log_analyzer.rb`](log-analyzer/) | Linux / macOS / Windows | Buckets a log file into time windows and flags spikes in error rate, with text/JSON output and cron-friendly exit codes. |
| [`registry-drift/registry_drift.rb`](registry-drift/) | Windows | Compares live or snapshotted Windows Registry values against a JSON security baseline and reports pass/drift/missing per key. |
| [`backup-rotate/backup_rotate.rb`](backup-rotate/) | Linux / macOS | Creates checksummed, gzip-compressed backups and enforces a retention policy so old archives get rotated out automatically. |
| [`prometheus-exporter/prometheus_exporter.rb`](prometheus-exporter/) | Linux (portable HTTP/registry layer) | Pure-Ruby Prometheus `/metrics` HTTP exporter built on TCPServer — no prometheus-client gem, no framework. |
| [`config-state-engine/config_state_engine.rb`](config-state-engine/) | Linux / macOS / Windows | A ~180-line idempotent, Chef/Puppet-style configuration engine: declare file/directory/line state, only touches disk on drift. |
| [`bitlocker-compliance-audit/bitlocker_compliance_audit.rb`](bitlocker-compliance-audit/) | Windows | Audits BitLocker drive-encryption compliance via WMI (`Win32_EncryptableVolume`), classifying gaps by severity. |
| [`user-account-audit/user_account_audit.rb`](user-account-audit/) | Linux | Audits local user accounts via /etc/passwd and /etc/shadow for duplicate root UIDs, empty password hashes, and other account-hygiene risks. |
| [`api-health-check/api_health_check.rb`](api-health-check/) | Linux / macOS / Windows | Concurrent Net::HTTP endpoint health checker with retry/backoff and healthy/degraded/down reporting, no gems. |
| [`scheduled-task-audit/scheduled_task_audit.rb`](scheduled-task-audit/) | Windows | Audits Task Scheduler via WIN32OLE/Schedule.Service for unquoted action paths, writable-directory hijacks, and privileged tasks in untrusted locations. |
| [`proc-monitor/proc_monitor.rb`](proc-monitor/) | Linux | Lightweight process & resource monitor built on `/proc` — RSS, CPU%, state, and liveness checks with WARN/CRIT thresholds and cron-friendly exit codes. |
| [`disk-usage-report/disk_usage_report.rb`](disk-usage-report/) | Linux / macOS | Walks a directory tree to find the biggest space consumers, flags stale cleanup candidates by age/pattern, and threshold-checks `df` output for paging. |
| [`powershell-bridge/powershell_bridge.rb`](powershell-bridge/) | Windows | Drives `powershell.exe` from Ruby via `Open3` + `ConvertTo-Json`, adding retry/timeout/error handling for service, disk, and event-log admin tasks. |
| [`systemd-watchdog/systemd_watchdog.rb`](systemd-watchdog/) | Linux | Watches systemd units and classifies OK/WARN/CRIT, with optional rate-limited auto-restart for failed units. |
| [`ssh-fleet-runner/ssh_fleet_runner.rb`](ssh-fleet-runner/) | Linux (control host) | Runs one command across a fleet of hosts over a bounded thread pool via the system `ssh` binary, with per-host timeout and retry. |
| [`eventlog-monitor/eventlog_monitor.rb`](eventlog-monitor/) | Windows | Polls the Windows Event Log via WMI for new Error/Warning/Audit-Failure events since the last run, with persisted state between runs. |
| [`dns-resolver-checker/dns_resolver_checker.rb`](dns-resolver-checker/) | Linux / macOS / Windows | Cross-checks DNS records across multiple resolvers concurrently and flags drift, missing records, and resolver failures. |
| [`sudoers-audit/sudoers_audit.rb`](sudoers-audit/) | Linux | Parses /etc/sudoers (including #include/#includedir) and flags privilege-escalation risks like NOPASSWD wildcards and ALL=(ALL) grants. |
| [`winpolicy-audit/winpolicy_audit.rb`](winpolicy-audit/) | Windows | Audits Windows password and account lockout policy via `net accounts` against a configurable security baseline. |

Each subdirectory has its own README with prerequisites, usage, a walkthrough of how the
script works, example output, troubleshooting notes, and ideas for extending it.

## Quick start

```
git clone <this-repo-url>
cd ruby-devops-toolkit

# Linux permission audit
ruby perm-audit/perm_audit.rb /etc /home

# NTP drift check
ruby ntp-drift/ntp_drift.rb pool.ntp.org time.cloudflare.com

# Windows service audit (run on Windows, elevated)
ruby service-audit\service_audit.rb
```

## Design notes

- **No gems by default.** Everything here runs on a stock Ruby install — `find`, `etc`,
`socket`, `win32ole`, `optparse`, `json` from the standard library. Nothing to `bundle install` on a box you're trying to audit quickly.
- **Text and `--json` output** on every script, so each one works equally well read by a
human on a terminal or piped into a monitoring/alerting pipeline.
- **Exit codes matter.** Every script exits non-zero when it finds something CRIT, so they
drop straight into cron, CI, or a Nagios-style check without extra wrapping.

## Testing notes

The permission auditor and NTP drift checker were tested against live/simulated environments
before being published — the Linux script was run against real system directories, and the
NTP client's protocol math was validated against a loopback mock SNTP server with a known,
simulated clock offset. The Windows service auditor's detection logic was verified with a
WIN32OLE stub test harness feeding realistic `Win32_Service` fixtures, since it depends on
WMI, which requires a real Windows host. See each script's README for the specifics.

The user account auditor and API health checker were both tested live in a Linux sandbox
(against real `/etc/passwd`/`/etc/shadow` fixtures and a local WEBrick mock server,
respectively). The scheduled task auditor's WIN32OLE integration could not be run against a
real Windows host in this environment; its risk-scoring logic (`evaluate_task`) is instead
fully unit-tested with realistic WIN32OLE-shaped fixtures — see
`scheduled-task-audit/scheduled_task_audit_test.rb`.

The process monitor and disk usage reporter were both tested live in a Linux sandbox — the
process monitor against real backgrounded processes (including a CPU-bound loop to trigger
CRIT thresholds), and the disk usage reporter against a scratch directory tree with
backdated/oversized files plus a real `df`-based threshold check. The PowerShell bridge's
`Open3`/JSON-parsing/retry/timeout logic is fully unit-tested with a stub shell-runner
feeding realistic `ConvertTo-Json`-shaped fixtures, since `powershell.exe` itself isn't
available in this environment — see `powershell-bridge/powershell_bridge_test.rb`.

## License

MIT — see [LICENSE](LICENSE). Use it, fork it, ship it.

## Contributing

Issues and PRs welcome — especially more test coverage, additional platforms, or edge cases
these scripts don't yet handle.
