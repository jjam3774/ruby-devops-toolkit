# disk-usage-report

Answers "**what is eating this disk?**" in one pass of standard-library Ruby.
Combines the three views a sysadmin usually assembles by hand from `df`, `du`
and `find`: filesystem fill levels with warn/crit thresholds, the heaviest
directories under a scan root, and the largest / stalest files.

![one walk, three views](img/disk_usage_flow.png)

## Prerequisites

- Ruby 2.7+ (tested on 3.0) — standard library only (`find`, `optparse`, `json`)
- Linux/macOS with a POSIX `df` in `PATH`
- Read access to the trees you scan (unreadable entries are counted and skipped,
  not fatal)

## Usage

```bash
# what's eating /var/log?
ruby disk_usage_report.rb /var/log

# top 10 offenders, stale = untouched 90+ days, alert thresholds 80/90%
ruby disk_usage_report.rb --top 10 --stale-days 90 --warn 80 --crit 90 /srv

# monitoring pipeline
ruby disk_usage_report.rb --json /var/log | jq '.scans[0].stale_total_bytes'
```

Exit codes: `0` all filesystems under `--warn`, `1` over warn, `2` over crit —
so the same script doubles as a Nagios-style disk check.

## How it works

- **`df -P -k`**, not plain `df`: the POSIX flag guarantees one line per
  filesystem with stable columns, which makes parsing safe. Bind mounts are
  deduplicated by device name (first mount wins).
- **One `Find.find` walk** per scan root. For every regular file, its size is
  *billed upward* to every ancestor directory up to the scan root. That yields
  cumulative directory totals — what `du -s` would report — while the same
  pass also collects the largest-files and stale-files lists. No shelling out
  to `du`, no second walk.
- **`File.lstat`**, not `stat`, so symlinks are never followed — no loops, no
  double-billing files that live elsewhere.
- **Stale = mtime older than `--stale-days`**. Old + big = archive candidate;
  the report totals the reclaimable bytes for you.

## Example output

```
$ ruby disk_usage_report.rb --top 5 --stale-days 60 --warn 80 --crit 90 /tmp/srv-data
== Filesystems ==
[ OK ] /dev/sda1                    /                   5.7 GB used of 9.5 GB    (60%)
[ OK ] /dev/sdc                     /sessions           3.4 GB used of 9.7 GB    (37%)

== /tmp/srv-data -- 46.3 MB in 6 files ==
-- heaviest directories (cumulative) --
     46.3 MB  /tmp/srv-data
     25.7 MB  /tmp/srv-data/db
     25.7 MB  /tmp/srv-data/db/backups
     20.5 MB  /tmp/srv-data/app
     12.4 MB  /tmp/srv-data/app/logs
-- largest files --
     14.3 MB  /tmp/srv-data/db/backups/db_2026-05-01.sql.gz  (modified 2026-05-01)
     11.4 MB  /tmp/srv-data/db/backups/db_2026-08-24.sql.gz  (modified 2026-08-25)
      8.6 MB  /tmp/srv-data/app/logs/app.log  (modified 2026-08-25)
-- stale files (untouched > 60 days, top 5 by size) --
     14.3 MB  /tmp/srv-data/db/backups/db_2026-05-01.sql.gz  (modified 2026-05-01)
      5.7 MB  /tmp/srv-data/app/cache/assets.bin  (modified 2026-04-10)
  reclaimable if archived: 20.0 MB across 2 stale files
```

## Troubleshooting

- **Numbers differ slightly from `du`** — `du` reports *allocated blocks*
  (sparse files, block rounding); this script reports *apparent size*
  (`stat.size`). Both are "right"; know which one you want.
- **Scan is slow on huge trees** — it's one full walk; on multi-million-file
  trees run it against subtrees, or via `nice`/`ionice` from cron.
- **Permission noise** — unreadable files/dirs are skipped and counted in the
  `unreadable` figure rather than aborting the scan.
- **`df` shows a filesystem you don't care about** — dedupe keeps the first
  mount per device; squashfs/loop devices can be filtered by extending
  `filesystems`.

## Extending it

- `--min-size` floor so tiny files never clutter the lists
- Trend mode: write each run's JSON to disk and diff growth run-over-run
- An `--exclude PATTERN` list for cache/venv directories
- Wire exit codes into Nagios/Icinga or a systemd timer + OnFailure alert

## References

- [Ruby Find module docs](https://docs.ruby-lang.org/en/3.0/Find.html)
- [POSIX df specification](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/df.html)
- Blog post: https://tha-shed.com/ (Ruby for DevOps series)
