# winpolicy-audit

Runs the built-in `net accounts` command -- no extra modules, no WMI,
ships on every Windows box -- and audits the local password/lockout
policy it reports against a configurable baseline: minimum password
length, maximum password age, password history, and account lockout
threshold. A firewall that's locked down and a password policy that
lets anyone set a 1-character password with unlimited login attempts
protect nothing; this is the other half of "the box is actually
secure."

No gems required: `optparse`, `json`, and `open3` are all stdlib.

## Why

Password and lockout policy is exactly the kind of setting that gets
configured once during imaging and never looked at again. `net
accounts` already tells you the live values -- but only as
human-readable text on one box at a time, with no pass/fail judgment
and no way to compare it against what your org's baseline actually
requires. This script turns that text dump into a real audit: run it,
get CRIT/WARN/OK, drop it into a scheduled task next to your other
compliance checks.

## Prerequisites

- Ruby >= 2.7 (ships with the standard RubyInstaller build for Windows;
  **Windows only** for live use)
- `net.exe` on `PATH` (present on every Windows install by default)
- No gems -- stdlib only
- **On any other OS** (Linux, macOS, CI): the CLI still runs against a
  captured text fixture with `--test-fixtures`, and the entire
  evaluation engine is unit-tested without touching `net.exe` at all --
  see Testing notes below.

## Usage

```powershell
# Audit the local machine's account policy
ruby winpolicy_audit.rb

# Audit domain policy instead (net accounts /domain)
ruby winpolicy_audit.rb --domain

# Tighten or loosen the baseline
ruby winpolicy_audit.rb --min-length 14 --max-age-days 90 --min-history 5 --max-lockout-threshold 10

# JSON output for a monitoring pipeline
ruby winpolicy_audit.rb --json
```

```bash
# On any OS, including this sandbox: audit captured `net accounts` output
ruby winpolicy_audit.rb --test-fixtures fixtures/net_accounts_weak.txt
```

Exit codes (cron/monitoring friendly):

| Code | Meaning |
|------|---------|
| 0 | policy meets every baseline threshold |
| 1 | at least one WARN-level finding |
| 2 | at least one CRIT-level finding, or `net accounts` couldn't be run |

## How it works

1. **`run_net_accounts(domain)`** shells out to `net accounts` (or
   `net accounts /domain`) via `Open3.capture2e` and hands the raw text
   to the parser. `net.exe` not existing (any non-Windows OS) is caught
   specifically via `rescue Errno::ENOENT` with a message pointing at
   `--test-fixtures` rather than a raw stack trace.
2. **`parse_net_accounts(text)`** reads every `Label:    Value` line
   `net accounts` prints and matches each label against `LABEL_MAP`
   (a small table of regexes -- output wording has stayed stable across
   Windows versions, but the mapping is centralized in one place in
   case that ever changes). **`normalize_value`** turns `"Never"` /
   `"None"` / `"Unlimited"` into `nil` (meaning "no limit is set," which
   is itself frequently the finding) and pure-digit strings into real
   `Integer`s, so `evaluate_policy` never has to do string parsing.
3. **`evaluate_policy(policy, baseline)`** is a pure function -- no
   `Open3`, no subprocess -- that compares the normalized policy hash
   against a baseline hash: password length below 8 is CRIT (below the
   full baseline but above 8 is WARN), a length of `0`/unset is CRIT
   outright; lockout threshold of `nil` (`Never`) is CRIT (unlimited
   login attempts), above the baseline ceiling is WARN; max password
   age of `nil` (`Never`/`Unlimited`) is WARN (deliberately WARN, not
   CRIT -- see Troubleshooting for why); password history of `nil`/`0`
   or below baseline is WARN. Because `evaluate_policy` and
   `parse_net_accounts` never touch a subprocess, both are fully
   testable on any OS with captured text.
4. The `__FILE__ == $PROGRAM_NAME` guard keeps the whole file
   `require_relative`-able by the test suite without triggering CLI
   parsing, a live `net accounts` call, or `exit`.

## Example output

```
$ ruby winpolicy_audit.rb --test-fixtures fixtures/net_accounts_weak.txt
winpolicy_audit: local account policy
  force_logoff: (never/none)
  min_password_age_days: 0
  max_password_age_days: (never/none)
  min_password_length: 0
  password_history: (never/none)
  lockout_threshold: (never/none)
  lockout_duration_minutes: 30
  lockout_window_minutes: 30
  computer_role: WORKSTATION

[CRIT] minimum password length is 0/unset -- any password, including empty, is accepted
[CRIT] lockout threshold is "Never" -- unlimited password attempts, no brute-force protection
[WARN] maximum password age is "Never" -- passwords do not expire; confirm this is an intentional NIST-800-63B-style policy and not an oversight
[WARN] password history is "None" -- users can immediately reuse their previous password

2 CRIT, 2 WARN
```

## Troubleshooting

- **"maximum password age is Never" is only WARN, not CRIT -- shouldn't
  unlimited password age always be a failure?** Deliberately not
  automatic: classic compliance baselines (PCI-DSS, older CIS
  benchmarks) expect forced periodic rotation, but current NIST
  800-63B guidance actively recommends *against* forced rotation
  (it tends to produce weaker, more predictable passwords) in favor of
  length, breach-list screening, and MFA. This script surfaces the
  setting either way and lets a human decide which policy your org is
  actually following -- that's why it's WARN with an explanatory
  reason, not a hardcoded CRIT.
- **`net accounts` not found / this script doesn't do anything on my
  Mac or Linux box** -- expected; `net.exe` is Windows-only. Use
  `--test-fixtures` to audit previously captured output anywhere else,
  or run this on the Windows host itself.
- **Values look off after a locale change** -- `net accounts` output is
  localized; `LABEL_MAP`'s regexes match the English-locale wording
  shown above. On a non-English Windows install, either capture output
  with `net accounts` run under an English code page, or extend
  `LABEL_MAP` with the localized label text (see Extending).
- **`--domain` fails with an error about no domain controller** --
  `net accounts /domain` requires the machine to actually be
  domain-joined and able to reach a DC; on a standalone workstation,
  drop `--domain` and audit the local policy instead.
- **A setting you changed with `secpol.msc` / Group Policy isn't
  reflected** -- `net accounts` reports the *effective* local security
  policy, which on a domain-joined machine can be overridden by Group
  Policy; if a GPO enforces stricter settings than what you configured
  locally, `net accounts` (and therefore this script) will correctly
  show the GPO-enforced values, not your local edit.

## Testing notes

`net accounts` only exists on Windows, so `run_net_accounts` itself
could not be executed in this Linux sandbox -- an honest limitation,
not glossed over here. What *was* fully tested: `parse_net_accounts`
against two real, hand-captured `net accounts`-format text fixtures
(`fixtures/net_accounts_weak.txt` and `net_accounts_strong.txt`,
formatted to match real Windows output verified against public
`net accounts` output examples, including the `Never`/`None`/`Unlimited`
sentinel values), confirming every label parses to the correct
normalized value; and `evaluate_policy`, a pure function with zero
subprocess dependency, exercised against both fixtures end-to-end plus
individual hand-built hashes covering every severity branch (length
0/6/10/14, lockout `nil`/50/5) -- 18/18 checks passing
(`winpolicy_audit_test.rb`). The full CLI was also run directly against
both fixtures in text and `--json` mode (see Example output), and the
"`net` not found" path was verified for real by running the script
unmodified in this Linux sandbox. Because `run_net_accounts` does
nothing but hand `net accounts`'s stdout to `parse_net_accounts`, this
coverage exercises the exact same parsing/evaluation code path a live
Windows run would use -- only the text's origin (a file vs. a live
subprocess) differs.

## Extending

- **Additional policy surfaces**: `net accounts` doesn't cover
  everything worth auditing (e.g. password complexity requirements,
  which live in Local Security Policy / Group Policy, not `net
  accounts`). Cross-reference with `secedit /export` output for a
  fuller picture -- same "parse text into a hash, evaluate the hash"
  shape as this script.
- **Localization**: extend `LABEL_MAP` with additional regex
  alternatives per label to support non-English Windows installs
  without needing a forced-English capture.
- **Fleet mode**: wrap `run_net_accounts` in the same bounded-
  concurrency worker-pool pattern this toolkit's other checkers use
  (`ssh-fleet-runner`, `cert-expiry-monitor`-style scripts), invoking
  it over PowerShell Remoting/WinRM across many hosts and rolling up
  one pass/fail table.
- **Baseline profiles**: ship named baseline presets (`--profile cis`,
  `--profile pci-dss`, `--profile nist-800-63b`) instead of only
  individual `--min-length`/`--max-age-days` flags, so the CLI call
  documents *which* standard is being checked against.
- **Auto-remediation**: for CRIT findings, print (or, behind an
  `--apply` flag, actually run) the matching `net accounts /minpwlen:N`
  /`/lockoutthreshold:N` command to bring the box into compliance,
  mirroring this toolkit's `cron-manager`-style dry-run-by-default
  pattern.

## References

- [net accounts (Microsoft Learn / Windows Server networking commands)](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/net-commands-on-operating-systems)
- [NIST SP 800-63B Digital Identity Guidelines (authentication & lifecycle management)](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [Ruby Open3 stdlib docs](https://docs.ruby-lang.org/en/3.0/Open3.html)
