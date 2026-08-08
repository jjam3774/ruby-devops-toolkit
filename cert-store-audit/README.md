# cert-store-audit

**Platform:** Linux / macOS / Windows (pure Ruby stdlib, no gems)

Audits every certificate and private key file sitting on disk under one or more directories -- not just the one certificate a server happens to be presenting live over TLS. Flags expired and soon-to-expire certificates, weak RSA keys, self-signed certificates, world-readable private key files, and cert/key pairs whose public keys don't actually match.

## The problem

A live TLS checker (`openssl s_client`, a script that connects to `host:443`) tells you about exactly one certificate: the one currently in use. It says nothing about the forgotten renewal sitting in `/etc/ssl/old/`, the private key some deploy script left world-readable, or the cert/key pair where someone copied the wrong `.key` file during a rushed deploy. Those all live on disk, not on the wire, and a filesystem-level audit is the only way to catch them before they cause an incident.

## Prerequisites

- Ruby >= 2.7 (tested on 3.0.2)
- No gems -- `openssl`, `find`, `optparse`, `json`, and `time` are all Ruby standard library
- Read access to the certificate/key directories you're auditing

## Usage

```bash
ruby cert_store_audit.rb <dir> [<dir> ...] [options]
```

| Option | Default | Description |
|---|---|---|
| `--min-days N` | 30 | Days-to-expiry WARN threshold |
| `--min-key-bits N` | 2048 | Minimum acceptable RSA key size |
| `--ext LIST` | `.pem,.crt,.cer,.key` | Comma-separated extensions to scan |
| `--json` | off | Emit machine-readable JSON |
| `-q`, `--quiet` | off | Text mode: only print WARN/CRIT findings |

```bash
# Audit everything under /etc/ssl and /opt/app/certs
ruby cert_store_audit.rb /etc/ssl /opt/app/certs

# Tighter expiry window, JSON for a monitoring pipeline
ruby cert_store_audit.rb /etc/ssl --min-days 45 --json

# Require modern key sizes
ruby cert_store_audit.rb /etc/ssl --min-key-bits 3072
```

## How it works

1. **Discovery** -- `Find.find` walks each directory, keeping files whose extension matches `--ext` and whose size is under 1&nbsp;MB (certs and keys are always small; this skips accidentally-pointed-at-a-data-directory mistakes).
2. **PEM splitting** -- a single `.pem`/`.crt` file can hold a full chain (leaf + intermediates), so each file is split into individual `-----BEGIN ... -----END ...-----` blocks with a regex scan rather than assumed to hold exactly one object.
3. **Certificate analysis** -- each certificate block is parsed with `OpenSSL::X509::Certificate`. The script computes days until `not_after`, classifies OK/WARN/CRIT against `--min-days`, checks whether `issuer == subject` (self-signed), and reads the RSA key size off the public key.
4. **Key analysis** -- each private-key block is parsed with `OpenSSL::PKey.read`. Password-protected keys raise `OpenSSL::PKey::PKeyError`, which the script catches and reports as "skipped" rather than crashing (an unattended audit script can't prompt for a passphrase). File mode is checked with `File.stat(path).mode & 0o777`; anything with group or world bits set (`mode & 0o077 != 0`) is CRIT.
5. **Cert/key matching** -- files are grouped by basename stem (`deploy.pem` and `deploy.key` share the stem `deploy`). For each cert/key pair with the same RSA bit length, `cert.check_private_key(key)` confirms the key actually belongs to that certificate. A mismatch is always CRIT.
6. **Reporting** -- text or `--json`, with a summary line and a process exit code so this drops straight into cron or a monitoring pipeline.

## Example output

```
$ ruby cert_store_audit.rb testfixtures
cert-store-audit: scanned 11 file(s) under testfixtures

[   OK] testfixtures/badperm/exposed.pem
        subject: /CN=exposed.internal
        expires: 2027-06-04T17:04:02Z (299 days) | key: RSA 2048
        - self-signed
[ CRIT] testfixtures/expired/old.pem
        subject: /CN=old.internal
        expires: 2026-08-03T17:04:02Z (-6 days) | key: RSA 2048
        - EXPIRED 6 day(s) ago
        - self-signed
[ WARN] testfixtures/warn/soon.pem
        subject: /CN=soon.internal
        expires: 2026-08-18T17:04:02Z (9 days) | key: RSA 2048
        - expires in 9 day(s) (threshold: 30)
[   OK] testfixtures/weak/legacy.pem
        subject: /CN=legacy.internal
        expires: 2027-02-24T17:04:02Z (199 days) | key: RSA 1024
        - self-signed
        - weak RSA key (<2048 bits)
[ CRIT] testfixtures/badperm/exposed.key
        key: RSA 2048 bits, mode 644
        - world/group-readable private key (mode 644)

KEY/CERT MISMATCHES:
  [CRIT] testfixtures/mismatch/deploy.pem  <->  testfixtures/mismatch/deploy.key  (public keys do not match)

Summary: 4 OK certs, 1 expiring soon, 1 expired, 1 key issue(s), 1 mismatch(es)
```

Exit code: `0` clean, `1` warnings only, `2` critical findings (expired, mismatch, weak/exposed key).

## Troubleshooting

- **"unreadable (...); likely password-protected"** -- expected and safe. The script deliberately does not prompt for private-key passphrases in an unattended run; it reports the file as skipped instead of hanging or crashing. If you need those audited too, decrypt to a scratch copy first (and make sure that scratch copy gets deleted).
- **World-readable check doesn't fire on the file you expect** -- some overlay/network filesystems (sshfs, certain container bind mounts, FUSE mounts) silently normalize permissions on write and don't honor `chmod` the way a native filesystem does. Test against a native path (e.g. `/tmp`) if permission findings look wrong; this was actually hit during development of this script -- see the Testing notes in the top-level repo README.
- **A directory with thousands of certs is slow** -- the `check_private_key` matching step is O(certs × keys) *within a basename stem*, not across the whole tree, so it stays fast in practice; if you have a genuinely enormous flat directory, narrow with `--ext .pem` first to skip `.crt`/`.cer` duplicates.
- **False positive on a legitimate self-signed internal CA root** -- `self-signed` is a note, not a failure by itself (it doesn't affect exit code). It's informational so you can eyeball whether it's expected (an internal root) or not (a leaf cert that should have been signed by something).

## Extending it

- Add OCSP/CRL revocation checking for certs that are still time-valid but have been revoked.
- Add EC key support to the weak-key check (currently only flags weak RSA; add curve-name checks for `OpenSSL::PKey::EC`).
- Wire the JSON output into `alert-notifier/alert_notifier.rb` (elsewhere in this repo) for Slack/webhook paging on CRIT.
- Add a `--fix-perms` flag that `chmod 600`s any world-readable key it finds, gated behind an explicit confirmation flag.

## Testing notes

Tested live in a Linux sandbox against `openssl`-library-generated fixtures covering all six code paths: a healthy long-lived cert, a cert expiring inside the warning window, an already-expired cert, a 1024-bit weak-key cert, a cert paired with the wrong key (mismatch), and a valid pair where the key file is world-readable. All six were verified to produce the correct OK/WARN/CRIT classification and the correct process exit code. One real gotcha hit during testing: this repo's sandboxed output directory is mounted over a filesystem that doesn't honor `chmod`, which silently broke the world-readable-key test until the fixtures were regenerated under `/tmp` on a native filesystem -- worth knowing if your own CI runs on a similar mount.

## References

- [Ruby `OpenSSL::X509::Certificate`](https://docs.ruby-lang.org/en/3.0/OpenSSL/X509/Certificate.html)
- [Ruby `OpenSSL::PKey`](https://docs.ruby-lang.org/en/3.0/OpenSSL/PKey.html)
- [Ruby `Find` module](https://docs.ruby-lang.org/en/3.0/Find.html)
