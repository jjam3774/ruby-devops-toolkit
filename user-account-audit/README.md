# user-account-audit

Audits local Linux user accounts for common security misconfigurations by parsing
`/etc/passwd` (and, when readable, `/etc/shadow`) with nothing but Ruby's standard
library. No gems, no `bundle install` — drop it on a box and run it.

## What it catches

1. **Duplicate UID 0** — any account besides `root` with UID 0 has full root
   privileges. This is one of the classic signs of a backdoor account.
2. **Duplicate UIDs** across different usernames — the kernel can't tell two
   "different" accounts apart if they share a UID, which breaks auditability.
3. **Missing home directories** for accounts with an interactive login shell.
4. **System accounts with an interactive shell** instead of `nologin`/`false`
   (UID below the configurable cutoff, default 1000).
5. **Empty password hashes** in `/etc/shadow` — depending on PAM configuration,
   this can mean the account is loggable-in with a blank password.
6. **Passwords with no maximum age** configured — informational, but worth
   knowing on a hardened box.

## Prerequisites

- Ruby >= 2.7 (tested on 3.0.2; uses only `optparse`, `json`, `etc`, `time` from
  the standard library)
- Read access to `/etc/passwd`; read access to `/etc/shadow` requires root (the
  script gracefully skips shadow-based checks if it can't read the file)

## Usage

```bash
# Audit the live system (shadow checks only run if you can read /etc/shadow)
ruby user_account_audit.rb

# As root, to include the shadow-based checks
sudo ruby user_account_audit.rb

# Audit fixture files instead of the live system (useful for testing/CI)
ruby user_account_audit.rb --passwd fixtures/passwd.fixture --shadow fixtures/shadow.fixture

# JSON output for piping into a monitoring system
ruby user_account_audit.rb --json

# Change the system/human UID cutoff (default: 1000)
ruby user_account_audit.rb --min-uid 500
```

Exit codes: `0` clean, `1` WARN-level findings only, `2` at least one CRIT finding.
This makes it drop straight into cron, CI, or a Nagios-style check.

## How it works

- `parse_passwd` and `parse_shadow` split each line on `:` (with `-1` as the
  limit so trailing empty fields, like an empty shadow password hash, are not
  silently dropped) and build plain hashes — no `Etc.passwd` iteration, because
  `Etc` doesn't expose the shadow file at all and we want passwd and shadow
  entries to line up by username explicitly.
- `UserAccountAuditor` runs six independent check methods over the parsed
  users, each appending `Finding` structs (`severity`, `user`, `check`,
  `detail`) to a shared list.
- The CLI prints either a grouped text report (CRIT, then WARN, then INFO) or
  `JSON.pretty_generate` output, and exits with a severity-derived code.

## Example output

```
user_account_audit: scanned 7 accounts, 12 finding(s)
------------------------------------------------------------------------

[CRIT] (2)
  - backdoor: duplicate-root-uid
      UID 0 shared with account 'backdoor' -- this account has full root privileges. Verify it is expected; if not, this is likely a backdoor.
  - ghost: empty-password-hash
      Password hash field in /etc/shadow is empty -- account may be loggable-in with a blank password depending on PAM config.

[WARN] (9)
  - alice: duplicate-uid
      UID 1001 is shared by multiple accounts (alice, bob). These accounts are indistinguishable at the filesystem/permission level.
  ...

[INFO] (1)
  - alice: password-never-expires
      Account has a set password with no maximum password age configured.
```

This was captured by running the script against `fixtures/passwd.fixture` and
`fixtures/shadow.fixture` in this directory, which intentionally contain a
duplicate root UID, a duplicate non-root UID, a missing home directory, an
empty password hash, and a system account with an interactive shell.

## Troubleshooting

- **"Cannot read passwd file"** — the `--passwd` path is wrong or unreadable;
  double check the path and permissions.
- **Shadow checks never fire** — you're not running as root. `/etc/shadow` is
  `0600 root:shadow` on virtually every distro; the script detects this via
  `File.readable?` and simply skips those checks rather than erroring out, so
  a non-root run against a live system will only show passwd-based findings.
- **False positive on `system-account-interactive-shell`** — some
  distributions intentionally give certain service accounts a real shell
  (e.g. for `su - serviceaccount` workflows). Treat this check as a prompt to
  verify, not an automatic finding of wrongdoing.
- **Different distros, different shadow layout** — this script assumes the
  standard glibc `/etc/shadow` field order (`user:hash:lastchange:min:max:warn:
  inactive:expire`). That's true for every mainstream Linux distribution.

## Extending it

- Add a check for accounts with `PASS_MAX_DAYS` set unreasonably high (weak
  rotation policy) by parsing the `max_age` field numerically.
- Cross-reference `/etc/group` to flag accounts unexpectedly in `wheel`/`sudo`.
- Add a `--lastlog` flag that shells out to `lastlog -b <n>` to flag accounts
  that haven't logged in within N days as "stale."
- Emit Prometheus-style metrics instead of/alongside JSON (this repo's
  `prometheus-exporter/` script shows a pure-Ruby `/metrics` HTTP server you
  could bolt this onto for continuous auditing).

## References

- [Ruby `Etc` module](https://docs.ruby-lang.org/en/3.0/Etc.html)
- [Ruby `OptionParser`](https://docs.ruby-lang.org/en/3.0/OptionParser.html)
- [`shadow(5)` man page](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [`passwd(5)` man page](https://man7.org/linux/man-pages/man5/passwd.5.html)
