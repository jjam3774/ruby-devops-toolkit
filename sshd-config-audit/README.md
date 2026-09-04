# sshd-config-audit

Audit an OpenSSH server configuration against a hardening baseline — using
sshd's own parsing semantics, because that's the part most audits get wrong:

- **first-occurrence-wins:** sshd uses the *first* value it sees for a
  directive. A hardened `PermitRootLogin no` at the bottom of the file does
  nothing if a `yes` appears above it (or in an earlier `Include`).
- **Includes merge in order**, glob-expanded, relative patterns resolved
  against `/etc/ssh` — cloud-init drop-ins in `conf.d/` are where surprises
  live.
- **Unset means default:** every unset directive is audited against OpenSSH's
  compiled-in default and marked `(default)`, because "we never set it" is
  itself a finding.
- **Match blocks are fenced off:** only the global section is audited, and the
  report says how many conditional blocks it skipped.

![architecture](img/sshd_audit_flow.png)

## Prerequisites

- Ruby >= 2.7 (tested on 3.0) — standard library only, no gems
- Read access to the config (root for the real `/etc/ssh/sshd_config` on most
  distros; any fixture file works unprivileged)

## Usage

```bash
sudo ruby sshd_config_audit.rb                       # audit /etc/ssh/sshd_config
ruby sshd_config_audit.rb --config fixtures/sshd_config
sudo ruby sshd_config_audit.rb --json | jq '.findings[] | select(.level=="CRIT")'
```

Exit codes: `0` clean, `1` warnings, `2` criticals — cron/CI friendly.

## The checks

| Level | Directive | Why |
| --- | --- | --- |
| CRIT | `PermitRootLogin yes` | brute-forcing root needs no username guess |
| CRIT | `PermitEmptyPasswords yes` | empty-password logins |
| CRIT | `Protocol 1` | cryptographically broken |
| WARN | `PasswordAuthentication yes` | credential stuffing; prefer keys |
| WARN | `X11Forwarding yes` | widens client-side attack surface |
| WARN | `MaxAuthTries > 4` | aids brute forcing |
| WARN | `ClientAliveInterval 0` | dead sessions never reaped |
| WARN | `LoginGraceTime > 60` | unauthenticated sockets held open |
| INFO | no `AllowUsers`/`AllowGroups` | every valid account is an SSH target |
| INFO | `AllowTcpForwarding yes` | fine for admins; disable on bastions |
| INFO | `Port 22`, root key-only mode | worth knowing, not verdicts |

Every finding names the **file that set the value** (or "compiled-in
default"), which matters exactly when an Include is the culprit.

## Example output

```
sshd config audit — /tmp/sshfix/sshd_config
files read: /tmp/sshfix/sshd_config, /tmp/sshfix/conf.d/00-cloudinit.conf
8 directives set; 1 Match block(s) skipped
----------------------------------------------------------------------
CRIT  permitrootlogin        = yes                [/tmp/sshfix/sshd_config]
      root can log in with a password — brute-forcing root needs no username guess
CRIT  permitemptypasswords   = yes                [/tmp/sshfix/conf.d/00-cloudinit.conf]
      accounts with empty passwords can log in
WARN  maxauthtries           = 8                  [/tmp/sshfix/sshd_config]
      more than 4 auth attempts per connection aids brute forcing
...
result: 2 critical, 5 warnings
```

The fixture demonstrates both traps: the "hardened" lines at the bottom of the
main file are ignored (first occurrence wins), and the empty-password hole
comes from a cloud-init drop-in via `Include`.

## Troubleshooting

- **`sshd -T` disagrees with the script:** `sshd -T` prints the *effective*
  config after Match evaluation for a given connection. This script audits the
  global section statically (and works on files `sshd -T` can't load, e.g.
  from images). Use both: this to find file-level mistakes, `sshd -T` to
  confirm runtime state.
- **Defaults drift between OpenSSH versions.** The `DEFAULTS` table is for
  OpenSSH 9.x; older servers differ (e.g. `PermitRootLogin` was `yes` before
  7.0 — stricter, not looser, today). Adjust the table for your fleet floor.
- **Unreadable Includes** are reported, not silently skipped — an audit that
  can't see a drop-in shouldn't claim a verdict on it.
- **Match-block hardening** (per-user overrides) isn't audited by design;
  the count in the header tells you it exists.

## Extending it

- Add `Ciphers`/`MACs`/`KexAlgorithms` allowlist checks against your policy.
- Compare two audits (`--json` + `diff`/`jq`) as a pre/post for config PRs.
- Wire into CI so every change to a golden image re-audits the config.
- Fleet mode: pair with this repo's [ssh-fleet-runner](../ssh-fleet-runner)
  to pull configs from many hosts and audit centrally.

## References

- OpenSSH sshd_config(5): https://man.openbsd.org/sshd_config
- CIS-style SSH hardening guidance: https://www.ssh.com/academy/ssh/sshd_config
- Ruby stdlib `Dir.glob`: https://docs.ruby-lang.org/en/3.3/Dir.html#method-c-glob
- Tutorial on tha-shed.com: https://tha-shed.com/ (Ruby for DevOps series)
