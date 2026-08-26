# user-account-audit

Linux local-account security audit in a single stdlib-only Ruby script. Reads
`/etc/passwd` and (when readable) `/etc/shadow` and flags the classic
account misconfigurations that both auditors and attackers look for.

![architecture](img/user_audit_arch.png)

## Prerequisites

- Ruby 2.7+ (tested on 3.0) — standard library only (`json`, `optparse`, `date`), no gems
- Linux (any distro with `/etc/passwd` + `/etc/shadow` format accounts)
- Run with `sudo` to include the shadow-file checks; without root it still runs
  every `passwd`-based check and clearly reports that shadow checks were skipped

## Usage

```bash
# full audit including shadow (empty password + aging) checks
sudo ruby user_account_audit.rb

# passwd-only checks, no root
ruby user_account_audit.rb

# audit copied files offline (e.g. pulled from another host)
ruby user_account_audit.rb --passwd ./passwd.bak --shadow ./shadow.bak

# flag passwords older than 180 days instead of the 365 default
sudo ruby user_account_audit.rb --max-age 180

# machine-readable
sudo ruby user_account_audit.rb --json
```

## What it flags

| Severity | Code | Meaning |
|----------|------|---------|
| CRIT | `uid0-not-root` | An account other than `root` with UID 0 (full root by another name) |
| CRIT | `empty-password` | Shadow hash field empty — login succeeds with no password |
| CRIT | `passwd-has-hash` | A real hash stored in world-readable `/etc/passwd` |
| WARN | `duplicate-uid` | Two accounts sharing a UID (indistinguishable in logs/ownership) |
| WARN | `system-acct-shell` | System account (UID < 1000) with a real login shell |
| WARN | `stale-password` | Password older than `--max-age` days |
| WARN | `no-password-aging` | Human account whose password never expires |
| INFO | `missing-home` | Home directory doesn't exist on disk |
| INFO | `world-writable-home` | Home directory writable by everyone |

## How it works

1. **Parse `/etc/passwd`** — seven colon-separated fields per line
   (`name:pw:uid:gid:gecos:home:shell`), comments and blanks skipped.
2. **Passwd-level checks** run per account (UID 0, hash-in-passwd, system shells,
   home-dir hygiene), plus a group-by-UID pass to catch duplicates.
3. **Shadow-level checks** run only if the shadow file is readable. The `lastchg`
   field is days since the Unix epoch, so password age is `today_in_days - lastchg`.
   Locked accounts (`!`/`*` hashes) are excluded from aging noise.
4. **Severity-ranked output.** Findings sort CRIT → WARN → INFO. The process exits
   `2` if any CRIT, `1` if any WARN, else `0` — ready for cron or a CI compliance gate.

## Example output

```
user account audit -- /etc/passwd (7 accounts)
shadow checks: enabled

CRIT  uid0-not-root        toor               account has UID 0 but is not root
CRIT  passwd-has-hash      legacy             password hash stored in world-readable passwd file
CRIT  empty-password       badsvc             no password set -- login succeeds with empty password
WARN  duplicate-uid        alice, bob         UID 1002 shared by 2 accounts
WARN  stale-password       legacy             password last changed 3688 days ago

3 critical, 9 warning, 4 info
```

## Troubleshooting

- **"shadow checks: SKIPPED"** — you're not root. Rerun with `sudo`, or point
  `--shadow` at a readable copy.
- **`stale-password` on service accounts** — locked accounts are already excluded;
  if a daemon account legitimately has a static password, whitelist it downstream.
- **`no-password-aging` everywhere** — many distros ship without a default max-age;
  that's exactly the finding. Set aging with `chage -M`.
- **Reading a copied shadow file with different epoch semantics** — the age math
  assumes standard `lastchg` (days since 1970-01-01); vendor-modified formats may
  need adjustment.

## Extending

- Add group-membership checks (`/etc/group`) — e.g. flag unexpected members of `sudo`/`wheel`.
- Cross-check `authorized_keys` presence for accounts with a login shell.
- Emit findings as SARIF or push to a SIEM webhook.
- Add an allowlist file so known-good exceptions don't re-alert every night.

## Testing

Verified on Linux (Ruby 3.0.2) against the live `/etc/passwd` and against crafted
fixtures seeding every finding type (UID-0 backdoor, empty password, hash-in-passwd,
duplicate UIDs, stale passwords, missing homes); `--json` summary confirmed.

## References

- [Ruby `Etc` / passwd format docs](https://docs.ruby-lang.org/en/3.4/Etc.html)
- [`shadow(5)` man page](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [`passwd(5)` man page](https://man7.org/linux/man-pages/man5/passwd.5.html)
