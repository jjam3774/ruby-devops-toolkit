# Backup + Restore-Test Verification Tool

A pure Ruby stdlib script that creates a `tar.gz` backup of a directory and, in the same run, proves the
backup actually restores by extracting it into a scratch directory and diffing every file's SHA-256 hash
against the original. Includes retention (keep newest N) and a JSON manifest for monitoring/alerting.

## The problem

Most backup scripts stop the moment `tar` exits 0. Nobody finds out a backup is corrupt, truncated, or
missing files until the day someone actually needs to restore it -- the worst possible day to learn that.
This script closes the gap: every backup run also runs a restore-test in the same pass, so a bad backup
fails loudly (non-zero exit code, a log line) instead of failing silently for months.

## Prerequisites

- Ruby 3.0 or newer (developed and tested against Ruby 3.0.2). Standard library only (`digest`, `find`,
  `fileutils`, `optparse`, `json`, `tmpdir`, `open3`) -- nothing to `gem install`.
- A POSIX `tar` and `gzip` on `PATH` (present on essentially every Linux distro and macOS by default).
- Read access to the source directory; write access to the backup directory; enough free space for the
  scratch restore-test extraction (roughly the uncompressed size of the source tree).

## Usage

```bash
# Back up /etc/myapp into /var/backups/myapp, keep the newest 7 verified backups
ruby backup_verify.rb /etc/myapp /var/backups/myapp

# Custom retention count
ruby backup_verify.rb /etc/myapp /var/backups/myapp --keep 14

# Custom manifest location (defaults to BACKUP_DIR/manifest.json)
ruby backup_verify.rb /etc/myapp /var/backups/myapp --manifest /var/log/myapp-backups.json
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Backup created and restore-verified successfully |
| `1`  | Verification failed (checksum mismatch or restore diff found missing/extra/mismatched files) |
| `2`  | Usage or IO error (bad arguments, source directory missing, etc.) |

## How it works

### 1. Fingerprint the source tree

`fingerprint_tree` walks the source with `Find.find` and computes a streaming SHA-256 (64KB chunks, so
large files never get fully loaded into memory) for every regular file, keyed by path relative to the
source root.

### 2. Create the archive

A single `tar -C parent -czf archive.tar.gz entry` call, run via `Open3.capture3` (not backticks/`system`)
so a path with spaces or shell metacharacters can't cause command injection. The archive filename embeds a
UTC timestamp (`name-YYYYMMDD-HHMMSS.tar.gz`) so repeated runs never collide and sort chronologically by
filename.

### 3. Restore-test

The archive is extracted into a `Dir.mktmpdir` scratch directory (auto-deleted after the block), then
re-fingerprinted. The two fingerprint maps are diffed for three failure modes: files **missing** after
restore, **extra** files that shouldn't be there, and files whose hash **changed** (silent corruption).
Only if all three sets are empty does the run count as verified.

### 4. Retention

After a verified run, existing backups for that source are globbed, sorted by filename (which sorts
chronologically), and anything past `--keep` is deleted. Retention runs *after* verification on purpose --
a failed backup shouldn't cause pruning of a still-good older backup.

### 5. Manifest

Every run appends a JSON record (timestamp, archive name + hash + size, files verified, restore result,
diff detail, pruned files) to `manifest.json`, giving a queryable audit trail without parsing log text.

## Example output

```
$ ruby backup_verify.rb /etc/webapp /var/backups/webapp --keep 5
[2026-08-06T18:54:34Z] Fingerprinting source: /etc/webapp
[2026-08-06T18:54:34Z]   3 file(s) hashed
[2026-08-06T18:54:34Z] Creating archive: /var/backups/webapp/webapp-20260806-185434.tar.gz
[2026-08-06T18:54:34Z]   archive size: 20432 bytes, sha256: 4c9bbc43c1735168...
[2026-08-06T18:54:34Z] Running restore-test into scratch directory...
[2026-08-06T18:54:34Z] Restore-test PASSED: all 3 file(s) verified byte-for-byte
[2026-08-06T18:54:34Z] Manifest updated: /var/backups/webapp/manifest.json
[2026-08-06T18:54:34Z] RESULT: OK
```

Verified in a Linux sandbox: 5 sequential runs against a growing source tree with `--keep 3` correctly
retained exactly the newest 3 archives after the 4th and 5th runs; a truncated/corrupted archive reliably
fails `tar -tzf` (the same extraction step this script performs), demonstrating the restore-test path
catches it rather than silently reporting success.

## Troubleshooting

- **"tar failed" with a permission error** -- the user running the script needs read access to every file
  under the source directory. Unreadable files make `tar` exit non-zero, which this script treats as a hard
  failure rather than silently skipping them.
- **Restore-test fails only on very large trees** -- check free space where your system temp directory lives
  (`$TMPDIR`, usually `/tmp`); the scratch extraction needs roughly as much free space as the uncompressed
  source tree.
- **Manifest grows unbounded over months of daily runs** -- intentional (it's your audit trail); rotate it
  externally or post-process into a database/metrics system rather than trimming the script's history array.
- **Timestamps collide when testing in a tight loop** -- timestamp granularity is one second; running twice
  within the same second overwrites the first archive filename. Real cron usage (at most once a minute)
  won't hit this.

## Extending this

- **Encrypt the archive** -- pipe `tar` output through `gpg --symmetric` or shell out to `age` before writing
  to disk, and checksum the encrypted blob instead.
- **Ship to remote/object storage** -- after a verified pass, upload via the AWS SDK for Ruby, `rclone`, or a
  simple `scp` call, and only prune local copies after the remote copy is confirmed present.
- **Alert on failure** -- wrap the script's exit code in your scheduler and pipe a non-zero exit into
  email/Slack/PagerDuty.
- **Parallelize across many source directories** -- wrap the core logic in a small runner iterating a list of
  `[source, backup_dir]` pairs, optionally with a thread pool for I/O-bound archives.

## References

- Ruby `Digest` stdlib docs: https://docs.ruby-lang.org/en/3.0/Digest.html
- Ruby `Find` stdlib docs: https://docs.ruby-lang.org/en/3.0/Find.html
- Ruby `Open3` stdlib docs: https://docs.ruby-lang.org/en/3.0/Open3.html
- GNU tar manual: https://www.gnu.org/software/tar/manual/tar.html
