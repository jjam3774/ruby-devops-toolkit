# package-drift-audit

Audit installed OS packages against an approved manifest and report drift —
Debian/Ubuntu (dpkg) and RHEL/Fedora (rpm), pure Ruby standard library, no gems.

![Architecture](img/package_drift_audit_flow.png)

## The problem

Configuration drift on long-lived servers is silent and dangerous. Someone
`apt install`s a debugging tool during a 2 a.m. incident and never removes it.
A base image ships fifty packages nobody audited. A compromised box quietly
grows one extra binary. None of it shows up until an auditor asks "what's
installed here, and why?" — and nobody can answer. This script snapshots what
is installed and diffs it against a manifest of what is *supposed* to be there.

## Prerequisites

- Ruby 2.7+ (tested on 3.0) — stdlib only: `optparse`, `json`, `open3`
- Debian/Ubuntu with `dpkg-query`, or RHEL/Fedora with `rpm`
- Any OS for the offline `--installed` mode and the test harness

## Usage

```bash
# 1. Snapshot the current box into a manifest, review it, commit it to git
ruby package_drift_audit.rb --snapshot > baseline.txt

# 2. Later (or on a sibling host), audit against that baseline
ruby package_drift_audit.rb --manifest baseline.txt
ruby package_drift_audit.rb --manifest baseline.txt --json

# Presence-only audit (ignore version pins)
ruby package_drift_audit.rb --manifest baseline.txt --no-versions
```

Manifest format: one `name version` per line (version optional), `#` comments allowed.

Statuses: `MISSING` (in manifest, not installed) · `UNEXPECTED` (installed, not in
manifest) · `VERSION` (installed, wrong pinned version) · `OK`.

Exit codes: `0` no drift · `1` only MISSING/VERSION drift · `2` any UNEXPECTED package.

## How it works

1. **Injectable package source.** On Debian it runs `dpkg-query -W`, on RHEL
   `rpm -qa`; both parse into a `{ name => version }` hash. The source is a
   lambda, so `--installed FILE` (and the tests) swap in a captured list —
   the diff logic never needs a live package DB.
2. **Set diff + version match.** Manifest-minus-installed gives MISSING;
   installed-minus-manifest gives UNEXPECTED; the intersection is compared by
   version (when a pin is present) to find VERSION drift.
3. **`--snapshot` bootstraps the baseline.** You don't hand-write the manifest;
   you snapshot a known-good box, eyeball it, and commit it. Drift is then
   anything that diverges from that committed file.
4. **Exit codes rank severity.** UNEXPECTED packages (the scary ones) force
   exit 2; presence/version drift is exit 1; a clean box is 0 — so it drops
   into CI or cron without extra wrapping.

## Example output

```
package_drift_audit — 1115 installed vs 1114 in manifest
summary: OK=1112  MISSING=1  VERSION=1  UNEXPECTED=2

  UNEXPECTED ftp                          installed 20210827-4build1 — not in manifest
  UNEXPECTED libdns-export1110            installed 1:9.11.19+dfsg-2.1ubuntu3 — not in manifest
  MISSING    acme-monitoring-agent        expected 2.1.0
  VERSION    dbus-user-session            want 0.0.1-pinned, have 1.12.20-2ubuntu4.1
```

## Testing

The diff logic is covered by `test_package_drift_audit.rb`, which builds
`installed`/`manifest` fixtures in memory and asserts every status and exit
code — no real package database required, so it runs on any OS:

```
ruby test_package_drift_audit.rb
  OK: nginx + openssl match                                        PASS
  VERSION: curl pinned-mismatch                                    PASS
  MISSING: fail2ban absent                                         PASS
  UNEXPECTED: netcat-openbsd not in manifest                       PASS
  UNEXPECTED present -> exit 2                                     PASS
  ...
all assertions passed
```

The live `dpkg`/`rpm` snapshot path was exercised against this repo's build
environment (Ubuntu 22.04, 1115 packages) before publishing.

## Troubleshooting

- **Everything shows UNEXPECTED** — your manifest is smaller than the box.
  That's expected on the first run; `--snapshot` a known-good host to seed a
  realistic baseline.
- **`no supported package manager found`** — you're not on dpkg/rpm; use
  `--installed FILE` with an exported list (`dpkg-query -W -f='${Package} ${Version}\n'`).
- **rpm multi-arch noise** — `rpm -qa` can list the same name for i686 and
  x86_64; the parser keeps the last-seen version. Add `%{ARCH}` to the format
  string if you need per-arch granularity.
- **Version strings never match** — distros embed epochs (`1:`) and build
  suffixes; snapshot and audit on the same distro release, or use `--no-versions`.

## Extending

- Add `--held` handling to flag `apt-mark hold` / `dnf versionlock` packages
  separately from ordinary drift.
- Emit `--json` into your config-management pipeline and alert on any
  UNEXPECTED across the fleet.
- Diff two snapshots directly (`--manifest a.txt --installed b.txt`) to compare
  two hosts rather than a host against a baseline.
- Layer in a per-package allowlist so approved ad-hoc tools don't page you.

## References

- Debian `dpkg-query` manual: https://manpages.debian.org/bookworm/dpkg/dpkg-query.1.html
- RPM `rpm(8)` query format: https://man7.org/linux/man-pages/man8/rpm.8.html
- Ruby `Open3`: https://docs.ruby-lang.org/en/3.3/Open3.html
