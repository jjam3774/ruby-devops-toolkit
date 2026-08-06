# Local Administrators Group Audit (WMI)

A Ruby + WMI script that audits local `Administrators` group membership across a fleet of Windows hosts and
flags anyone who shouldn't be there, using a per-host YAML allow-list. Ships with a stub-based test harness
so the comparison/reporting logic is fully unit-tested without needing a live Windows host.

## The problem

"Who has local admin on our servers?" is a question every SOC 2 audit, ISO 27001 review, and incident
response asks -- and the honest answer at most shops is "someone got added for a one-off task and never got
removed." This script queries the Administrators group on every host in an inventory file via WMI, compares
membership against a YAML allow-list, and reports two distinct kinds of drift: **unauthorized** members
(present, not allow-listed -- privilege creep) and **missing** required members (allow-listed but absent --
e.g. a break-glass or EDR service account that vanished).

## Prerequisites

- Ruby with the `win32ole` stdlib -- bundled with every Windows Ruby build (e.g. RubyInstaller); nothing to
  `gem install`.
- Run from a domain-joined Windows host ("jump box") with network access to WMI/DCOM (TCP 135 + dynamic RPC
  ports) on each target host.
- An account with permission to query WMI on the targets -- local admin, or a delegated read-only WMI
  namespace ACL if you don't want the auditor itself to need admin rights.
- `yaml` and `json` stdlibs (bundled with Ruby) for the allow-list and report.

## Usage

```powershell
# Audit every host listed in hosts.txt (one hostname per line)
ruby local_admin_audit.rb --inventory hosts.txt --allowlist allowlist.yml --out report.json

# Audit a single host
ruby local_admin_audit.rb --host WEB01 --allowlist allowlist.yml
```

`allowlist.yml` format:

```yaml
default:                 # applies to any host without a specific entry
  - CORP\Domain Admins
  - CORP\svc-edr
overrides:
  WEB01:
    - CORP\Domain Admins
    - CORP\svc-edr
    - CORP\jsmith        # temporary, ticket #4821
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Every host's Administrators membership matches the allow-list |
| `1`  | At least one host has unauthorized or missing members (or a query error) |
| `2`  | Usage error (missing required flags) |

## How it works

### 1. WMI collection (`WmiAdminGroupSource`)

Uses `WbemScripting.SWbemLocator` to connect to each host's `root\cimv2` namespace, then runs an
`ASSOCIATORS OF` WQL query scoped to `Win32_Group.Name='Administrators'` joined through `Win32_GroupUser` --
the standard WMI pattern for "every account associated with this group." Results are formatted as
`DOMAIN\username`.

### 2. Pure comparison logic (`AdminAudit.evaluate`)

Takes two plain arrays -- current members, allowed members -- and returns unauthorized/missing/ok sets using
case-insensitive matching (Windows account names aren't case-sensitive: `CORP\JSmith` and `corp\jsmith` are
the same account). This method has zero knowledge of WMI, YAML, or the filesystem, which is what makes it
trivially unit-testable.

### 3. Allow-list resolution (`load_allowlist`)

Returns the per-host `overrides` entry if one exists, otherwise falls back to `default` -- a plain Hash
lookup, no WMI, no network.

### 4. The run loop (`run`)

Iterates hosts (from `--inventory` or a single `--host`), wraps each host's collection + comparison in
`begin/rescue` so one unreachable host doesn't abort the whole fleet scan, and accumulates a
JSON-serializable report. Any host with unauthorized/missing members or a connection error flips the exit
code to 1.

### 5. Testing without Windows

WMI/`win32ole` only exist on Windows, so the collection step can't execute in a Linux CI sandbox. The
included `test_local_admin_audit.rb` swaps `StubAdminGroupSource` (a fixture-backed `Hash` lookup, zero WMI
calls) in place of the real WMI source and drives the exact same `run()`/`AdminAudit.evaluate` code the CLI
uses. This proves the comparison/reporting logic correct end-to-end; it does not (and cannot, outside
Windows) validate the WQL `ASSOCIATORS OF` query syntax against a live host -- that part was verified by
manual read-through against Microsoft's `Win32_Group`/`Win32_GroupUser` documentation instead. Said plainly
in the script's own header comment and repeated here for anyone extending it.

## Example output

Test suite (pure logic + stubbed end-to-end run -- executes on any platform, including this Linux sandbox):

```
$ ruby test_local_admin_audit.rb
== AdminAudit.evaluate (pure logic) ==
  PASS  clean host -> no unauthorized
  PASS  clean host -> no missing
  PASS  extra member flagged unauthorized
  PASS  no false missing
  PASS  absent required member flagged missing
  PASS  no false unauthorized
  PASS  case-insensitive match treated as OK

== End-to-end run() with StubAdminGroupSource ==
Auditing WEB01... OK
Auditing WEB02... FINDINGS
Auditing DB01... OK

--- Summary ---
WEB02: FINDINGS
    UNAUTHORIZED: CORP\bcompromised
    MISSING REQUIRED: CORP\svc-edr

Full report written to /tmp/report.json
  PASS  run() returns 1 when findings exist
  PASS  WEB01 status OK
  PASS  DB01 status OK
  PASS  WEB02 status FINDINGS
  PASS  WEB02 unauthorized includes bcompromised
  PASS  WEB02 missing includes svc-edr

ALL TESTS PASSED
exit: 0
```

Real CLI invoked on a non-Windows dev box, demonstrating the graceful (non-crashing) failure path when
`win32ole` is unavailable -- the actual bug this project found and fixed during testing, since `LoadError` is
not a `StandardError` subclass in Ruby and needs an explicit rescue clause:

```
$ ruby local_admin_audit.rb --host WEB01 --allowlist allowlist.yml
Auditing WEB01... ERROR (win32ole is not available on this platform (this script's WMI collection step only
runs on Windows). Use --host with a stub source for local testing, or run this on a Windows host.)

--- Summary ---
WEB01: ERROR
    ERROR: win32ole is not available on this platform...
exit: 1
```

## Troubleshooting

- **"win32ole is not available on this platform"** -- expected and intentional off Windows; the WMI
  collection step only runs on Windows. Use `StubAdminGroupSource` for local development/testing on macOS or
  Linux, exactly as the included test harness does.
- **"WMI query failed for host X" with an RPC/access-denied error** -- almost always firewall (TCP 135 +
  dynamic RPC ports blocked between jump box and target) or the running account lacking WMI query rights on
  that host; verify with `Get-WmiObject -ComputerName X -Class Win32_ComputerSystem` from PowerShell on the
  jump box before assuming this script is at fault.
- **A known-good account keeps showing as unauthorized** -- check the allow-list entry's domain prefix
  matches exactly what WMI returns (e.g. `CORP\svc-edr` vs. just `svc-edr`); comparison is case-insensitive
  but not prefix-tolerant by design, to avoid accidentally allow-listing an identically-named account in the
  wrong domain.
- **Script hangs on one host** -- WMI/DCOM calls can block a long time against an unreachable host; wrap
  `source.members_for(host)` in `Timeout.timeout` if your inventory includes hosts that may be powered off or
  network-isolated.

## Extending this

- **Remote credentials** -- pass explicit credentials to `ConnectServer` instead of relying on the jump box's
  current security context, for environments without a trust relationship.
- **Scheduled + alerting** -- run nightly via Task Scheduler and pipe a non-zero exit into an email/Teams
  webhook so findings reach someone the same day.
- **Audit other sensitive groups** -- the WQL query only needs a different `Name=` value to audit
  `Remote Desktop Users`, `Backup Operators`, or any other local group the same way.
- **Historical trend tracking** -- append each run's JSON report (with a timestamp) to a running log or
  time-series store, so privilege creep shows up as a trend, not just a point-in-time snapshot.

## References

- Ruby `WIN32OLE` stdlib docs: https://docs.ruby-lang.org/en/3.0/WIN32OLE.html
- Microsoft: `Win32_Group` class (WMI): https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-group
- Microsoft: `Win32_GroupUser` class (WMI): https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-groupuser
- Ruby `YAML` stdlib docs: https://docs.ruby-lang.org/en/3.0/YAML.html
