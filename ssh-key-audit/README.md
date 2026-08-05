# ssh-key-audit

**Platform:** Linux / macOS &nbsp;|&nbsp; **Gems required:** none (stdlib only)

Walks a fleet of home directories, parses every `authorized_keys` entry against the real sshd
wire format, and flags weak/DSA keys, unrestricted service-account access, bad permissions, and
keys shared across multiple accounts.

## The problem

`authorized_keys` files accrete for years and nobody audits them. Someone leaves the company and
their key never gets removed. A deploy key gets pasted into five accounts because it was
convenient. A 1024-bit RSA key from 2011 is still accepted alongside brand-new ed25519 keys. A
`svc-backup` automation account has an unrestricted key that can log in interactively from
anywhere, when it should only run one backup command from one host.

## Prerequisites

- Ruby 2.7+ (tested on 3.0.2)
- Uses only `optparse`, `json`, `base64`, and `stringio` from the standard library
- Read access to the home directories you want to audit (typically run as root, since `.ssh`
  directories are usually `700`)
- Optionally, a JSON array of departed-employee usernames/comment fragments for `--denylist`

## Usage

```bash
ruby ssh_key_audit.rb /home /root
ruby ssh_key_audit.rb /home --denylist departed_users.json
ruby ssh_key_audit.rb /home --json
```

Exit codes: `0` = no CRIT findings, `2` = one or more CRIT findings, `1` = usage error.

## The authorized_keys format, briefly

Per `sshd(8)`, each line is: an optional comma-separated `options` field, the key type
(`ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-*`, or the legacy weak `ssh-dss`), the base64-encoded key
blob, and an optional trailing comment:

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIxxxx... alice@laptop
command="/opt/backup/run.sh",no-pty,no-X11-forwarding ssh-ed25519 AAAAC3Nza... backup-automation
```

## How it works

1. **`Parser.parse_line` / `tokenize`** — tokenizes the line character-by-character, tracking
   quote state so options like `command="rsync --server . dest"` don't get split on their
   internal spaces.
2. **`KeyBlob.bit_strength`** — base64-decodes the key blob and walks it as SSH wire-format
   fields (4-byte big-endian length + payload, repeated). For `ssh-rsa` it reads the bit-length
   of the modulus directly, without shelling out to `ssh-keygen -l`.
3. **Per-key checks** — `check_weak_type` (DSA / short RSA), `check_service_account_restrictions`
   (accounts matching `svc-*`, `deploy*`, `backup*`, `ci-*`, `automation*` must have `from=` or
   `command=` on every key), `check_denylisted_comment` (departed-identity matching).
4. **`check_duplicates`** — runs once after every file has been scanned, against a
   `key_blob => [locations]` map, flagging any key authorized for 2+ different accounts.

## Example output

```
$ ruby ssh_key_audit.rb /home --denylist departed_users.json
[CRIT] bob /home/bob/.ssh/authorized_keys:1 -- ssh-rsa key is only 1024-bit (< 2048); replace with ed25519 or a >= 2048-bit RSA key
[CRIT] frank /home/frank/.ssh/authorized_keys:1 -- key comment/user matches denylisted (departed) identity 'jsmith'
[CRIT] svc-backup /home/svc-backup/.ssh/authorized_keys:1 -- service account 'svc-backup' has a key with no from= or command= restriction -- anyone holding the private key can log in interactively from anywhere
[WARN] bob /home/bob/.ssh/authorized_keys -- authorized_keys mode is 644, expected 600 (group/world access should be denied)
[WARN] bob /home/bob/.ssh -- .ssh directory mode is 755, expected 700

3 critical, 2 warnings
exit: 2
```

## Troubleshooting

- **"permission denied reading authorized_keys"** — the auditor ran as a user without read
  access into someone's `700` home directory. Run as root for a complete fleet scan; this is
  logged as a WARN per-file rather than a crash.
- **Service account false positives** — the `SERVICE_ACCOUNT_PATTERNS` regex list
  (`svc-`, `deploy`, `backup`, `ci-`, `automation`) is a starting point. Edit it to match your
  fleet's naming convention.
- **Legitimate shared key flagged as duplicate** — some teams intentionally share a
  break-glass key across an on-call group. Treat the WARN as documentation, not necessarily a
  bug.

## Testing notes

Tested live in a Linux sandbox against real `ssh-keygen`-generated fixtures covering every
check: a healthy ed25519 key, a weak 1024-bit RSA key, a healthy 3072-bit RSA key, a DSA key, a
correctly-restricted service account, an incorrectly-unrestricted service account, a duplicated
key across two accounts, and a denylist-matched departed-employee comment. All eight scenarios
produced the expected findings, and a clean fleet correctly produced zero findings.

## Extending it

- **Key age** — cross-reference each line's file mtime against a maximum key age policy.
- **Certificate-based auth awareness** — recognize `@cert-authority` entries separately instead
  of treating them as regular keys.
- **Fleet-wide execution over SSH** — pair with this series' `ssh-fleet-runner` script to audit
  remote hosts' home directories.
- **CI gate** — run against a golden/staging image in CI and fail the build on any CRIT finding.

## References

- [sshd(8) man page — AUTHORIZED_KEYS FILE FORMAT](http://man.openbsd.org/sshd.8)
- [Ruby stdlib: Base64](https://docs.ruby-lang.org/en/3.3/Base64.html)
