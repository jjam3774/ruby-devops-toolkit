# winservice_manager.rb

Declarative Windows service management via WMI. Full write-up: [Ruby for DevOps: Declarative Windows Service Reconciliation with winservice_manager.rb](https://tha-shed.com/ruby-for-devops-declarative-windows-service-reconciliation-with-winservice_manager-rb/)

## The problem it solves

"Make sure the Spooler service is running and set to Automatic startup on all 40 print servers" is a one-line requirement that sysadmins end up re-solving by hand with `services.msc`, or with a pile of ad-hoc PowerShell one-liners that don't record *what* they changed.

`winservice_manager.rb` takes a small YAML file describing the desired state of a set of services (running/stopped, startup type) and reconciles reality to match it — Chef/Puppet-style, but a couple hundred lines of stdlib Ruby talking straight to WMI's `Win32_Service` class. It only touches a service when it's actually out of the desired state, and it tells you exactly what it changed (or would change, with `--dry-run`).

## Prerequisites

- Ruby with `win32ole` (ships with any Windows Ruby install, e.g. RubyInstaller)
- Administrator privileges (starting/stopping services and changing startup type requires elevation)
- Run locally, or against a remote host with WMI/DCOM reachable and appropriate credentials (see `--host`)

## Usage

```
ruby winservice_manager.rb --config services.yml
ruby winservice_manager.rb --config services.yml --dry-run
ruby winservice_manager.rb --config services.yml --json
```

Example `services.yml`:

```yaml
Spooler:
  state: running
  start_mode: automatic
Fax:
  state: stopped
  start_mode: disabled
wuauserv:
  state: running
```

### CLI options

| Flag | Description |
| --- | --- |
| `--config PATH` | YAML file describing desired service state (required) |
| `--host HOST` | Target host for WMI (default: `.` = local machine) |
| `--dry-run` | Report drift without changing anything |
| `--json` | Emit machine-readable JSON instead of text |
| `-h`, `--help` | Show help |

## How it works

- Connects to WMI via `WIN32OLE.connect("winmgmts:{impersonationLevel=impersonate}!//<host>/root/cimv2")` and queries `Win32_Service` for each named service.
- For each service, compares the actual `StartMode` and `State` against the desired spec. It only calls `ChangeStartMode`, `StartService`, or `StopService` when there's a real difference — no unnecessary WMI writes.
- WMI method return codes are translated into readable labels (`Access Denied`, `Service Already Running`, etc.) via a lookup table built from the `Win32_Service` MSDN documentation, instead of surfacing bare integers.
- Exit codes are cron/monitoring-friendly: `0` = already in desired state, `1` = drift found and reconciled, `2` = a service was missing or a WMI call failed.

## Example output

```
OK      wuauserv: already in desired state
CHANGED Spooler:
          - set_start_mode -> Automatic: Success (code 0)
          - start -> Running: Success (code 0)
MISSING LegacyPrintSvc: no such service
```

## Testing

The WMI layer is injected (`wmi:` in `WinServiceManager.new`), so the reconciliation logic is fully unit-testable on any platform without a real Windows host or WIN32OLE — see `winservice_manager_test.rb` for a fake WMI adapter and test cases covering matched state, drift, missing services, and dry-run mode.

## Troubleshooting

- **`Access Denied` (code 2) on every action** — run the terminal or scheduled task as Administrator; service control requires elevation.
- **`WIN32OLE` not found** — you're not on a Windows Ruby install; `win32ole` only ships with Windows builds (e.g. RubyInstaller), not on Linux/macOS Ruby.
- **Remote host times out** — check that WMI/DCOM (TCP 135 plus the dynamic RPC range, or a fixed port if configured) is reachable through any firewall between the two hosts.
- **Service name mismatches** — `winservice_manager.rb` matches on the WMI service `Name` (the short internal name), not the display name shown in `services.msc`.

## Extending

- Add a `--host-list FILE` option to reconcile the same `services.yml` across many machines in one run.
- Emit Nagios/Prometheus-friendly exit codes or metrics alongside the existing JSON output.
- Support dependency-aware ordering (e.g. don't stop a service other running services depend on) by querying `Win32_DependentService`.

## References

- [Win32_Service class (WMI)](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service)
- [Ruby WIN32OLE documentation](https://docs.ruby-lang.org/en/master/WIN32OLE.html)
- [Full tutorial on tha-shed.com](https://tha-shed.com/ruby-for-devops-declarative-windows-service-reconciliation-with-winservice_manager-rb/)
