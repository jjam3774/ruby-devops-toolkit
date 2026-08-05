# windows-firewall-audit

**Platform:** Windows &nbsp;|&nbsp; **Gems required:** none (win32ole stdlib only)

Audits the Windows Defender Firewall rule set via WMI for risky patterns that accumulate over
years: inbound-allow-any-any rules exposed on the Public profile, and `EdgeTraversalPolicy=Allow`
settings that let traffic bypass NAT edge protection.

## The problem

Firewall rule sets grow for years and nobody audits them. Someone opens RDP wide for a debugging
session and forgets to scope or remove it. A vendor installer adds an inbound-allow-any rule.
`Get-NetFirewallRule` in PowerShell shows you this one rule at a time — nobody reads 400 rules by
hand. This script queries the same WMI classes those cmdlets are built on directly via
`WIN32OLE`, joins them in Ruby, and prints a prioritized findings list.

## Prerequisites

- Windows 8 / Server 2012 or later (`ROOT\StandardCimv2` is where the modern firewall WMI
  provider lives)
- Ruby with the `win32ole` stdlib library (ships with the standard RubyInstaller on Windows)
- A shell with rights to query WMI (reads generally work un-elevated; run elevated if you hit
  access-denied errors)

## Usage

```powershell
ruby win_firewall_audit.rb
ruby win_firewall_audit.rb --json
ruby win_firewall_audit.rb --profile Public
```

Exit codes: `0` = no CRIT findings, `2` = one or more CRIT findings, `1` = error connecting to
WMI (e.g. run on a non-Windows host).

## How it works

PowerShell's `Get-NetFirewallRule` looks like it returns one flat object per rule, but under the
hood it's assembling several separate WMI class instances that share an `InstanceID`: the rule
itself (`MSFT_NetFirewallRule`), its port scope (`MSFT_NetFirewallPortFilter`), and its address
scope (`MSFT_NetFirewallAddressFilter`).

1. **`WmiSource`** connects via `WIN32OLE.connect('winmgmts:\\.\root\StandardCimv2')` and runs
   three `ExecQuery` calls. This is the only class that requires `win32ole`, and it's required
   lazily inside the method so the rest of the file (and its tests) load cleanly on non-Windows
   hosts.
2. **`RuleBuilder.build`** joins the three WMI result sets back into one flat `RuleView` struct
   by shared `InstanceID`, and decodes the `Direction`/`Action` integers and `Profiles` bitmask
   (1=Domain, 2=Private, 4=Public, OR'd together) into readable values.
3. **`WinFirewallAudit.evaluate_rule`** is a pure function of a `RuleView` — it only looks at
   rules that are `Enabled`, `Inbound`, and `Allow`, then checks for a wide-open port, any remote
   address, and Public profile scope, plus `EdgeTraversalPolicy=Allow` as a separate always-on
   check. Because it never touches WIN32OLE, it's fully unit-testable without a Windows host.

CRIT is any/any-Public inbound ALLOW, or `EdgeTraversalPolicy=Allow`. WARN is a partially scoped
but still broader-than-ideal rule.

## Example output

```
$ ruby win_firewall_audit_test.rb

14 assertions, 0 failures

$ ruby win_firewall_audit.rb   (risk engine run against realistic fixtures, on a real Windows host)
[CRIT] RDP - temp debug access
       - inbound ALLOW rule open to any remote address, any port, on the Public profile
[CRIT] IoT management port
       - EdgeTraversalPolicy=Allow lets this rule bypass NAT edge protection

2 critical, 0 warnings out of 2 flagged rules
exit: 2
```

## Troubleshooting

- **"cannot load such file -- win32ole"** — you're running this on a non-Windows host.
  `win32ole` only exists on Windows Ruby installs.
- **Empty results / 0 rules found** — confirm the Windows Defender Firewall service (`MpsSvc`)
  is running.
- **Access denied connecting to WMI** — re-run from an elevated PowerShell/cmd; some
  hardened/GPO-locked-down hosts restrict WMI namespace access for non-admins.
- **How this was tested** — `MSFT_NetFirewallRule` only exists on a live Windows host, which
  wasn't available in the environment used to build this. The join logic (`RuleBuilder`) and the
  risk engine (`evaluate_rule`) are instead fully unit-tested with realistic WIN32OLE-shaped
  fixtures — five rules covering the wide-open, scoped, edge-traversal, disabled, and outbound
  cases — in `win_firewall_audit_test.rb`, which passes 14 assertions with 0 failures. Verify the
  WMI-connection layer itself (`WmiSource`) against your own hosts before relying on it in
  production.

## Extending it

- **Program/service scoping** — pull in `MSFT_NetFirewallApplicationFilter` and
  `MSFT_NetFirewallServiceFilter` to flag rules with no program/service restriction at all.
- **Baseline diffing** — snapshot findings to JSON on a known-good day and diff future runs
  against it.
- **Auto-remediation** — shell out to `netsh advfirewall firewall set rule` to disable a
  well-understood CRIT pattern, gated behind a `--fix` flag and confirmation.
- **Group Policy comparison** — cross-reference local rules against rules pushed by GPO to find
  shadow rules a local admin added outside of policy.

## References

- [MSFT_NetFirewallRule class (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/wfascimprov/msft-netfirewallrule)
- [Ruby stdlib: WIN32OLE](https://docs.ruby-lang.org/en/3.3/WIN32OLE.html)
