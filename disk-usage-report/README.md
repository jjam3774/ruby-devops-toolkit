# disk-usage-report

Disk usage reporting that remembers what grew. `du` can tell you `/var/log` is 40 GB —
it can't tell you it was 33 GB yesterday. This script walks directory trees, ranks the
largest directories and files, checks filesystem fullness against warn/crit thresholds,
and persists a JSON snapshot each run so the next run can flag exactly what grew.

![pipeline diagram](img/disk_usage_pipeline.png)

## Prerequisites

- Ruby 2.7+ (tested on 3.0.2) — stdlib only (`find`, `json`, `optparse`), no gems
- Linux or macOS (filesystem fullness uses POSIX `df -kP`; the walker itself is portable)
- Read access to the trees you scan — unreadable entries are counted, not fatal

## Usage

```
ruby disk_usage_report.rb [options] DIR [DIR ...]

-n, --top N            top N entries per section (default 10)
-d, --depth N          aggregate directory sizes at depth N below each root (default 1)
-s, --snapshot FILE    diff against previous snapshot, then overwrite it with this run
-w, --warn PCT         WARN when a filesystem is >= PCT% full (default 80)
-c, --crit PCT         CRIT when a filesystem is >= PCT% full (default 90)
-g, --growth-warn MB   WARN when a directory grew >= MB since snapshot (default 512)
-j, --json             JSON output
-x, --one-file-system  don't cross filesystem boundaries
```

Exit codes: `0` OK, `1` WARN, `2` CRIT — cron/Nagios friendly.

Typical cron entry:

```
15 6 * * * ruby /opt/tools/disk_usage_report.rb -s /var/lib/du_snap.json -g 512 /var /home || notify-team
```

## How it works

1. **Walk** — `Find.find` + `File.lstat` (symlinks never followed). With
   `--one-file-system`, any directory whose `st.dev` differs from the root's device is
   pruned — same trick as `du -x`, and what keeps the walker out of `/proc` and NFS mounts.
2. **Aggregate** — every file's size is credited to its depth-N ancestor
   ("bucket"), so millions of files collapse into a dozen directories you can reason
   about. A rolling `max_by` prune keeps the top-files candidate list small, so memory
   stays flat on huge trees.
3. **Fullness** — `df -kP` per scanned root, compared against `--warn`/`--crit`.
4. **Snapshot diff** — bucket sizes are written to the `--snapshot` JSON at the end of
   every run; buckets present in both runs get a delta, and positive deltas above
   `--growth-warn` MB become WARN findings. First run with a fresh snapshot is quiet by
   design.

## Example output

```
disk_usage_report — 2026-08-21 13:54:37
scanned /tmp/dutest (5 files, 0 unreadable)

filesystem /                     66% full

top 5 directories (depth 2):
   709.0 MiB  /tmp/dutest/var/log
     5.0 MiB  /tmp/dutest/var/cache
     2.0 MiB  /tmp/dutest/home/app

top 5 files:
   700.0 MiB  /tmp/dutest/var/log/app.log
     9.0 MiB  /tmp/dutest/var/log/syslog.1

growth since last snapshot:
  +697.0 MiB  /tmp/dutest/var/log [WARN]

verdict: WARN
```

## Troubleshooting

- **Numbers differ from `du`** — this sums *apparent* sizes (`st.size`); `du` reports
  allocated blocks. Sparse files and reflinks make them diverge; both are correct answers
  to different questions.
- **Slow on huge trees** — the cost is `lstat` syscalls. Scope roots tighter and use
  `--one-file-system`.
- **Empty growth section** — growth needs a bucket present in *both* snapshots; the first
  run is always quiet. Changing `--depth` between runs changes bucket keys and resets the
  comparison.
- **Concurrent runs** — last writer wins on the snapshot file; `flock` the script or use
  per-target snapshot paths.

## Extending

- Track `mtime` per bucket and flag directories that are huge *and* untouched for 90+ days
- Write dated snapshots instead of overwriting, and chart growth over weeks
- Pipe `--json` into an alerting webhook — the `alerts` array is built for machines
- Per-filesystem warn/crit thresholds from a small config file

## Testing notes

Tested in a Linux sandbox against a generated directory tree: two consecutive snapshot
runs with a 700 MB file inflation between them correctly produced a `+697.0 MiB` growth
WARN and exit code 1; threshold and JSON paths exercised as well.

## References

- [Ruby stdlib: Find](https://docs.ruby-lang.org/en/3.3/Find.html)
- [Ruby stdlib: File::Stat](https://docs.ruby-lang.org/en/3.3/File/Stat.html)
- [POSIX df specification](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/df.html)
