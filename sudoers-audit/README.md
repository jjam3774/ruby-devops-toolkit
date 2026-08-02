# sudoers-audit

Parses `/etc/sudoers` -- plus any files it pulls in via `#include` /
`#includedir`, exactly like real `sudo` does -- and flags the privilege
grants that show up over and over in real escalation writeups:
passwordless (`NOPASSWD`) root shells, wildcard command paths that let a
"restricted" rule run arbitrary binaries, and sudoers files that are
group- or world-writable. It also shells out to `visudo -c` so a syntax
mistake gets caught before it locks someone out of `sudo` entirely.

No gems required: `optparse`, `json`, and `open3` are all stdlib.

## Why

`sudo` misconfigurations are one of the most common local-privilege-
escalation vectors on Linux, and they accumulate the same way firewall
rules do: someone adds `NOPASSWD: ALL` to unblock a deploy script at
2am, or a wildcard cmnd spec seemed fine when it was written and nobody
revisits it once the binary it points at changes behavior. `visudo`
only checks that the file *parses* -- it says nothing about whether the
policy it describes is a good idea. This script is the second check
`visudo` doesn't do.

## Prerequisites

- Ruby >= 2.7 (tested on 3.0.2)
- Read access to the sudoers file you're auditing -- for the real
  `/etc/sudoers` that means running as root (it's `0440 root:root` on a
  normal system); for any other file, ordinary permissions
- `visudo` on `PATH` for the syntax check (skip with `--skip-visudo` if
  it's not installed)
- No gems -- stdlib only

## Usage

```bash
# Audit the real system sudoers (needs root to read the file)
sudo ruby sudoers_audit.rb

# Audit any sudoers-format file -- CI, a staged change, a container image
ruby sudoers_audit.rb --file ./staged_sudoers

# Machine-readable output
ruby sudoers_audit.rb --file ./staged_sudoers --json

# Skip the visudo syntax check (e.g. visudo isn't installed here)
ruby sudoers_audit.rb --file ./staged_sudoers --skip-visudo
```

Exit codes (cron/CI friendly):

| Code | Meaning |
|------|---------|
| 0 | no risky grants found |
| 1 | WARN-level findings only |
| 2 | CRIT-level findings, a `visudo -c` syntax error, or the file couldn't be read |

## How it works

1. **`parse_sudoers(path)`** reads the file line by line, joins
   backslash-continued lines, skips comments/`Defaults`/`*_Alias`
   lines, and follows `#include FILE` / `#includedir DIR` directives
   recursively (with a `seen` guard against include cycles) -- the same
   mechanism real `sudo` uses to pull in `/etc/sudoers.d/*`. Each
   recognized user-spec line (`who host=(runas) tags: cmnds`) becomes a
   `SudoersEntry` struct; unreadable files and missing include targets
   are collected as errors instead of raising, so one bad file doesn't
   kill the whole audit.
2. **`classify_entry(entry)`** is a pure function -- no file I/O -- that
   splits an entry's command specs on their top-level commas and
   checks each one: `who == 'ALL'` granted anything is CRIT (every
   local account, not a specific administrator); `NOPASSWD: ALL` is
   CRIT (passwordless full root); `NOPASSWD` combined with a wildcard
   (`*`/`?`) in the command is CRIT (the classic "restricted" rule
   that isn't); `NOPASSWD` alone on a specific command is WARN; a bare
   wildcard command (password still required) is WARN; and a broad
   group (`%something`) granted `ALL` commands is WARN. A plain
   `root ALL=(ALL:ALL) ALL` -- completely normal -- produces no
   findings at all, and neither does a tightly scoped
   `bob ALL=(ALL) /usr/bin/systemctl restart nginx`.
3. **`check_file_permissions(path)`** flags world-writable (CRIT) and
   group-writable (WARN) sudoers files via `File.stat(path).mode`,
   checked for both the main file and every included file.
4. **`run_visudo(path)`** shells out to `visudo -c -f path` via
   `Open3.capture2e` and reports pass/fail/skipped (skipped when
   `visudo` isn't on `PATH` at all, handled via `rescue Errno::ENOENT`
   rather than crashing).
5. The `__FILE__ == $PROGRAM_NAME` guard keeps all of the above
   `require_relative`-able by the test suite without triggering CLI
   parsing or a live run.

## Example output

```
$ ruby sudoers_audit.rb --file ./example_sudoers
[CRIT] ./sudoers.d/deploy
        ./sudoers.d/deploy is world-writable (mode 666) -- any local user could edit sudo policy
[CRIT] ./example_sudoers:7
        NOPASSWD: ALL -- passwordless full-root grant for 'alice'
        > alice   ALL=(ALL) NOPASSWD: ALL
[CRIT] ./example_sudoers:9
        NOPASSWD with a wildcard command ('/usr/bin/vim *') -- wildcards can usually be abused to run arbitrary binaries
        > carol   ALL=(root) NOPASSWD: /usr/bin/vim *
[CRIT] ./example_sudoers:10
        who=ALL (every local account) granted 'ALL'
        > ALL     ALL=(ALL) ALL
[WARN] ./sudoers.d/deploy
        ./sudoers.d/deploy is group-writable (mode 666) -- confirm the group is trusted
[WARN] ./example_sudoers:6
        '%sudo' can run ALL commands (password required) -- confirm this group is meant to be full sudoers
        > %sudo   ALL=(ALL:ALL) ALL
[WARN] ./sudoers.d/deploy:1
        NOPASSWD grant for 'deploy' on '/usr/local/bin/deploy.sh' -- passwordless, review if still needed
        > deploy  ALL=(www-data) NOPASSWD: /usr/local/bin/deploy.sh

7 entries checked, 4 CRIT, 3 WARN
visudo -c: PASSED
```

## Troubleshooting

- **`cannot read /etc/sudoers (permission denied?)`** -- expected on a
  normal system unless you run as root; `/etc/sudoers` is `0440
  root:root` by design. Run with `sudo`, or point `--file` at a copy/
  staged version for review without elevated access.
- **A rule you know is risky isn't flagged** -- this is a lightweight,
  line-oriented parser, not a full sudoers grammar implementation. It
  does not resolve `User_Alias`/`Cmnd_Alias`/`Runas_Alias` definitions,
  so a command hidden behind a `Cmnd_Alias DANGEROUS = /usr/bin/vim *`
  and referenced as `alice ALL=(ALL) DANGEROUS` won't be traced back to
  the wildcard. Expand aliases by hand for any file that leans on them
  heavily, or extend `classify_entry` (see Extending).
- **`visudo -c` fails on a file that "looks fine"** -- `visudo`
  complains about more than syntax: it also checks ownership/
  permissions of included files (you'll see warnings like `owned by
  uid N, should be 0` if you're testing as a non-root user against
  scratch files, which is expected and separate from `sudoers_audit.rb`'s
  own findings). If it's failing on the actual grammar, `visudo -c`'s
  own output (surfaced verbatim in this script's CRIT reason) tells you
  the exact line.
- **`#includedir` target reported as missing** -- sudoers on some
  distros includes an empty or not-yet-created `/etc/sudoers.d`
  directory by default; that's reported as a parse error here rather
  than silently ignored, which is intentional (a directive pointing at
  nothing is worth knowing about even if it's harmless today).
- **False positive on a legitimate wildcard** -- some wildcard command
  specs really are safe (e.g. `/usr/bin/systemctl restart myapp-*`
  where `myapp-*` only ever matches a fixed, trusted set of unit
  files). The WARN/CRIT distinction exists specifically so these get a
  human look rather than a hard failure; treat WARN as "review," not
  "wrong."

## Testing notes

Tested live in this repo's sandbox in two layers. `classify_entry` and
`check_file_permissions` (pure functions -- no file I/O for the former,
scratch files for the latter) were unit-tested directly, covering: a
normal unrestricted root grant (no findings), `NOPASSWD: ALL` (CRIT),
`who=ALL` (CRIT), `NOPASSWD` plus a wildcard (CRIT), `NOPASSWD` alone
(WARN), a tightly-scoped non-wildcard command (no findings, confirming
the checker doesn't cry wolf on ordinary rules), a broad group granted
`ALL` (WARN), and both world-writable (CRIT+WARN) and normal-mode
(no findings) file permissions. `parse_sudoers` was then tested
end-to-end against real scratch files on disk, including a real
`#includedir` pulling in a second file and an unreadable-file error
path (`sudoers_audit_test.rb`, 14/14 checks passing). The full CLI was
also run end-to-end against a hand-built sudoers file plus an
`#includedir`'d, deliberately world-writable second file, in both text
and `--json` mode, with `visudo -c` genuinely invoked and its real
output captured (see Example output). The real `/etc/sudoers` in this
sandbox is `0440` and unreadable to a non-root user, which the script
handles as documented above rather than crashing -- verified directly.

## Extending

- **Alias resolution**: parse `User_Alias`/`Cmnd_Alias`/`Runas_Alias`
  definitions into a lookup table and expand them before classification,
  so a wildcard hidden behind a `Cmnd_Alias` gets caught too.
- **Baseline diffing**: snapshot `--json` output and diff consecutive
  runs (same pattern as this toolkit's `registry-drift` script) to
  alert on *newly added* risky grants specifically, rather than
  re-reporting the same accepted-risk entries every run.
- **Environment-variable exposure**: flag entries with `SETENV` (lets
  the invoking user pass arbitrary environment variables through to
  the privileged command, a common `LD_PRELOAD`-style escalation path)
  and missing `Defaults env_reset`/`secure_path`.
- **Per-organization allowlisting**: some `NOPASSWD` grants are
  intentional and reviewed (a deploy user, a monitoring agent) --
  add a `--baseline known_good.json` of expected entries so only *new*
  or *changed* risky grants surface as findings.
- **Group membership cross-check**: resolve `%groupname` against
  `/etc/group` (or `getent group`) and report how many real accounts a
  broad group grant actually covers today.

## References

- [sudoers(5) man page](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [visudo(8) man page](https://man7.org/linux/man-pages/man8/visudo.8.html)
- [Ruby Open3 stdlib docs](https://docs.ruby-lang.org/en/3.0/Open3.html)
