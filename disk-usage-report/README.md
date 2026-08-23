# disk-usage-report

Disk usage reporting and growth tracking for Linux in a single stdlib-only Ruby script.
`df` tells you a filesystem is at 92% — this tells you **which directories got you there,
and which ones grew since the last run**.

![workflow](img/disk_usage_flow.png)

## Prerequisites

- Ruby 2.7+ (tested on 3.0) — standard library only (`find`, `json`, `optparse`), no gems
- Linux or macOS (works anywhere `Find.find` and `File.lstat` do)
- Read access to the trees you scan (run with `sudo` for system paths like `/var`)

## Usage

```bash
# one-off report: biggest directories and files under /var
ruby disk_usage_report.rb /var

# more rows, ignore files under 10 MB
ruby disk_usage_report.rb /var --top 15 --min-mb 10

# growth tracking: first run saves a baseline, every later run diffs against it
ruby disk_usage_report.rb /var --snapshot /var/tmp/var-usage.json

# alerting for cron: exit 2 if any first-level dir under /var exceeds 20 GiB
ruby disk_usage_report.rb /var --snapshot /var/tmp/var-usage.json --alert-gb 20

# machine-readable
ruby disk_usage_report.rb /var --json
```

## How it works

1. **One `Find.find` pass per root.** Every regular file's size is charged to *every
   ancestor directory* up to the scan root, which yields `du`-style cumulative totals
   without shelling out to `du`. `File.lstat` is used so symlinks are never followed —
   no loops, no double counting.
2. **Big-file table.** Files at or above `--min-mb` are collected and the top N kept.
3. **Snapshot diff.** With `--snapshot`, the per-directory totals hash is written to a
   JSON file at the end of each run. If the file already existed, current totals are
   diffed against it first and the biggest movers (positive or negative) are reported.
4. **Alerts and exit codes.** `--alert-gb` checks each root's first-level children;
   any dir over the limit prints an `ALERT` line and the script exits `2` (otherwise `0`),
   so it drops straight into cron/Nagios/CI without wrapping.
5. Unreadable paths (`EACCES`, files deleted mid-scan, symlink loops) are counted and
   skipped, never fatal.

## Example output

```
disk usage report -- /tmp/dutest
files scanned: 3  (0 unreadable paths skipped)

SIZE         LARGEST DIRECTORIES (cumulative)
58.0 MiB     /tmp/dutest
33.0 MiB     /tmp/dutest/logs
25.0 MiB     /tmp/dutest/cache/deep

SIZE         LARGEST FILES (>= 1 MB)
30.0 MiB     /tmp/dutest/logs/app.log
25.0 MiB     /tmp/dutest/cache/deep/blob.bin

GROWTH       BIGGEST MOVERS SINCE LAST SNAPSHOT
+18.0 MiB    /tmp/dutest
+18.0 MiB    /tmp/dutest/logs

ALERT: /tmp/dutest/logs is 33.0 MiB (over 0.02 GiB limit)
```

## Troubleshooting

- **Totals differ slightly from `du`** — `du` reports allocated blocks, this script
  reports apparent file sizes (`lstat.size`). Sparse files and filesystem overhead
  account for the difference.
- **`0 files scanned` under `/proc` or `/sys`** — don't scan virtual filesystems;
  their "files" have no meaningful sizes.
- **Lots of skipped paths** — you're scanning as an unprivileged user; rerun with
  `sudo` for system directories.
- **Snapshot growth looks wrong after moving directories** — renames appear as a big
  negative delta at the old path and a big positive one at the new path; that's the
  diff being honest, not a bug.

## Extending

- Charge `stat.blocks * 512` instead of `stat.size` for allocated-space accounting.
- Add `--exclude PATTERN` to skip cache/venv/node_modules noise.
- Emit the JSON to a Prometheus textfile-collector or push it at a monitoring API.
- Track per-UID usage (`stat.uid`) for a quick "who owns the bloat" report.

## Testing

Verified on Linux (Ruby 3.0.2): fixture tree scan, snapshot save + growth diff after
appending data, `--alert-gb` exit code 2, and `--json` output shape.

## References

- [Ruby `Find` module](https://docs.ruby-lang.org/en/3.4/Find.html)
- [Ruby `File::Stat`](https://docs.ruby-lang.org/en/3.4/File/Stat.html)
- Blog walkthrough: <https://tha-shed.com/> (Ruby for DevOps series)
