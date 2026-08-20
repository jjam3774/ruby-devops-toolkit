# defender-status-audit

Audit Microsoft Defender Antivirus health on Windows — pure Ruby standard
library over `Get-MpComputerStatus`, with an OS-agnostic stub test harness. No gems.

![Architecture](img/defender_status_audit_flow.png)

## The problem

"We have antivirus" is not the same as "antivirus is working." Real-time
protection gets toggled off during a botched troubleshooting session and never
turned back on. Signature updates quietly stall behind a broken proxy. Tamper
protection is disabled by a misapplied GPO. Each of those is a hole an attacker
walks straight through, and none of them shows up unless someone actually
checks. This script checks — it reads Defender's live status and flags every
way the endpoint can be silently degraded.

## Prerequisites

- Ruby 2.7+ (tested on 3.0) — stdlib only: `json`, `optparse`, `open3`, `time`
- Windows with Microsoft Defender for a live audit (PowerShell `Get-MpComputerStatus`,
  backed by the CIM class `MSFT_MpComputerStatus`)
- Any OS for offline `--status-json` audits and the test harness

## Usage

```powershell
# Live audit on the host
ruby defender_status_audit.rb
ruby defender_status_audit.rb --json > defender.json

# Offline: audit a captured status from another machine
powershell -NoProfile -Command "Get-MpComputerStatus | ConvertTo-Json" > host.json
ruby defender_status_audit.rb --status-json host.json
```

Exit codes: `0` clean · `1` WARN/INFO only · `2` any CRIT.

## What it flags

| Severity | Rule | Meaning |
|---|---|---|
| CRIT | `realtime-protection-off` | `RealTimeProtectionEnabled` is false |
| CRIT | `antivirus-disabled` / `am-service-down` | AV or the AM service is not running |
| CRIT | `signatures-critically-stale` | definitions older than `--crit-age` days (default 7) |
| WARN | `signatures-stale` | definitions older than `--warn-age` days (default 3) |
| WARN | `tamper-protection-off` / `behavior-monitoring-off` | protection layers disabled |
| INFO | `full-scan-overdue` | no full scan in `--scan-age` days (default 14) |

## How it works

1. **PowerShell is the source.** `Get-MpComputerStatus | ConvertTo-Json`
   returns Defender's full state. The source is injectable, so `--status-json`
   (and the tests) feed a captured file instead of shelling out.
2. **Normalization handles PowerShell's quirks.** Booleans may arrive as
   `true`/`false` or as strings; timestamps arrive either as ISO-8601 or in
   WCF's `/Date(1699999999999)/` millisecond format. `normalize` converts all
   of it into plain booleans and *ages in days*, so the rules reason about one
   clean shape regardless of the source's formatting.
3. **A flat rule engine** turns that normalized status into severity-tagged
   findings, sorted CRIT → WARN → INFO.
4. **Exit codes** make it CI/monitoring-ready: any CRIT is exit 2.

## Example output

```
defender_status_audit
  signatures: v1.415.88.0, 9d old
  real-time: OFF  tamper: OFF  behavior: OFF

  CRIT realtime-protection-off        RealTimeProtectionEnabled is false
  CRIT signatures-critically-stale    definitions 9 days old (>= 7)
  WARN tamper-protection-off          IsTamperProtected is false
  WARN behavior-monitoring-off        BehaviorMonitorEnabled is false
  INFO full-scan-overdue              last full scan 28 days ago (>= 14)

summary: CRIT=2 WARN=2 INFO=1
```

## Testing

`Get-MpComputerStatus` only exists on Windows, so the rule logic is verified
with a stub harness that feeds the normalizer + rule engine realistic
`Get-MpComputerStatus` JSON fixtures — including the WCF `/Date(ms)/` timestamp
format PowerShell actually emits — for both a healthy and a degraded host, and
asserts each rule and exit code. It runs green on any OS:

```
ruby test_defender_status_audit.rb
  parses /Date(ms)/ signature age to 1 day                       PASS
  healthy host has zero findings                                 PASS
  CRIT realtime-protection-off                                   PASS
  CRIT signatures-critically-stale (10>=7)                       PASS
  INFO full-scan-overdue (30>=14)                                PASS
  4-day sigs -> WARN not CRIT                                    PASS
all assertions passed
```

The live `Get-MpComputerStatus` invocation has **not** been exercised in CI
(it needs a real Windows host with Defender). The parsing and rule logic are
fully covered against fixtures; validate on a lab box before trusting it in
production.

## Troubleshooting

- **`Get-MpComputerStatus failed`** — you're not on Windows, Defender is
  replaced by a third-party AV, or PowerShell is locked down. Capture the JSON
  elsewhere and use `--status-json`.
- **Signature age is `unknown`** — the JSON lacked `AntivirusSignatureLastUpdated`,
  or it was in an unrecognized format; the script emits a WARN rather than
  silently passing.
- **Third-party AV installed** — Defender reports itself disabled by design
  when another AV is active. That's a true `antivirus-disabled` from Defender's
  perspective; audit the third-party product separately.
- **Times look off by hours** — Defender reports local time; the age math uses
  `Time.now`. Run the audit on the same host, or feed UTC via `--status-json`.

## Extending

- Add cloud-protection (`MAPS`) and PUA-protection checks from the same status object.
- Pull `Get-MpThreatDetection` for a recent-threats section.
- Push `--json` into your SIEM keyed on `rule` for fleet-wide Defender-health rollups.
- Add a baseline-diff mode to alert when a previously-healthy host regresses.

## References

- Microsoft `Get-MpComputerStatus`: https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus
- WMI/CIM class `MSFT_MpComputerStatus`: https://learn.microsoft.com/en-us/previous-versions/windows/desktop/defender/msft-mpcomputerstatus
- Ruby `Open3` / `Time.parse`: https://docs.ruby-lang.org/en/3.3/Open3.html
