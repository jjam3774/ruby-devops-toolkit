# disk-usage-report

Answer "where did the disk go?" with one Ruby script: a `du`-style rollup of the
largest subdirectories, the largest individual files, stale heavyweights nobody
has touched in months, filesystem capacity with warn/crit thresholds for cron,
and JSON snapshots so a later run can tell you exactly which directories grew.

One `Find.find` pass fills three accumulators; `df -kP` adds capacity; snapshots
make growth diffable:

![architecture](img/disk_usage_flow.png)

## Prerequisites

- Ruby >= 2.7 (tested on 3.0) — standard library only, no gems
- Linux or macOS for the `df -kP` capacity check (the tree walker itself is pure
  Ruby and runs anywhere; without a POSIX `df` you just lose the use% gate)

## Usage

```bash
# Top offenders under /var and /home, stale files older than 180 days
ruby disk_usage_report.rb /var /home --top 10 --stale-days 180

# Nightly cron: page when the filesystem crosses 90%
ruby disk_usage_report.rb /data --warn-pct 80 --crit-pct 90

# Take a snapshot today...
ruby disk_usage_report.rb /data --snapshot /var/tmp/du_snap.json

# ...and diff against it tomorrow: "what grew overnight?"
ruby disk_usage_report.rb /data --compare /var/tmp/du_snap.json

# Machine-readable everything
ruby disk_usage_report.rb /data --json | jq '.roots[].dirs'
```

| Option | Meaning |
| --- | --- |
| `--top N` | largest files to list (default 15) |
| `--dirs N` | top-level subdirectories to list (default 12) |
| `--stale-days N` | age before a file counts as stale (default 90) |
| `--stale-min-size BYTES` | minimum size for stale reporting (default 50 MiB) |
| `--warn-pct N` / `--crit-pct N` | filesystem use% gates -> exit 1 / exit 2 |
| `--snapshot FILE` / `--compare FILE` | write / diff per-directory totals as JSON |
| `--json` | full report as JSON |

Exit codes: `0` ok, `1` warn threshold breached, `2` crit threshold breached —
drop it straight into cron or a Nagios-style check.

## How it works

- **One pass, three answers.** A single `Find.find` walk fills a `Hash.new(0)`
  rollup keyed by top-level subdirectory, a bounded top-N list of largest files,
  and a stale list (`mtime` older than the cutoff and size above the floor).
  No second walk, no sorting millions of entries.
- **`lstat`, not `stat`.** Symlinks count as themselves (a link to a 40 GB image
  is a few bytes, not 40 GB) and symlink loops can't trap the walker.
- **Errors are data.** Unreadable entries are counted and skipped; a disk report
  that dies on the first `EACCES` is useless on a real box.
- **Bounded top-N.** The candidate list is trimmed at 512 entries (sort, keep
  64) so memory stays flat no matter how many files you scan.
- **Capacity via `df -kP`.** POSIX-portable output, parsed from the last line;
  `--warn-pct` / `--crit-pct` turn use% into exit codes.
- **Snapshots are just JSON.** `{root -> {dir -> bytes}}` plus a timestamp.
  `--compare` aligns old and new keys and prints the delta per directory —
  usually the fastest possible answer to "what grew overnight?".

## Example output

```
== /tmp/dutest  [WARN]
   total 17.0 MiB in 5 files
   filesystem /dev/sda1 on /: 5.6 GiB used of 9.5 GiB (60%), 3.9 GiB free
   -- largest subdirectories --
      8.0 MiB  cache/
      5.0 MiB  logs/
      4.0 MiB  projects/
      2.0 KiB  ./
   -- largest files --
      8.0 MiB  /tmp/dutest/cache/tmp/giant.iso
      5.0 MiB  /tmp/dutest/logs/app.log
      3.0 MiB  /tmp/dutest/projects/appA/build.tar.gz
   -- stale (>= 1.0 MiB, untouched 90+ days) --
      8.0 MiB  /tmp/dutest/cache/tmp/giant.iso  (mtime 2025-01-15)

== growth since 2026-09-04T13:50:04-05:00
   /tmp/dutest:
   +  4.0 MiB  logs/  (5.0 MiB -> 9.0 MiB)
   +  2.0 MiB  projects/  (4.0 MiB -> 6.0 MiB)
```

## Troubleshooting

- **Numbers differ from `du`.** `du` reports *allocated blocks* (and follows
  hardlinks differently); this script sums apparent file sizes via `lstat`.
  Sparse files and heavy hardlinking are the usual causes of a gap.
- **`df` column missing / weird on BSD.** The script uses `df -kP` (POSIX mode)
  precisely to stabilise columns; if your platform lacks `-P`, the capacity
  block is skipped and everything else still works.
- **Scan is slow on NFS.** Millions of `lstat` calls over the wire hurt; run it
  on the fileserver itself, or point it at specific subtrees.
- **Permission noise.** Run with `sudo` for a complete picture; the unreadable
  count in the summary tells you how much you're missing.
- **Root of `/`.** Scanning `/` works (prefix handling is `delete_prefix`-safe)
  but consider per-mount invocations so one filesystem's totals don't mix with
  another's.

## Extending it

- Group by *owner* (`st.uid` -> `Etc.getpwuid`) for "who owns the disk" reports.
- Add `--one-file-system` by comparing `st.dev` against the root's device.
- Emit Prometheus metrics instead of text (see this repo's
  [prometheus-exporter](../prometheus-exporter)).
- Auto-prune: wire the stale list to `File.delete` behind an explicit
  `--delete-stale-older-than` flag with a dry-run default.
- Keep dated snapshots and plot growth over weeks with your favourite grapher.

## References

- Ruby stdlib `Find`: https://docs.ruby-lang.org/en/3.3/Find.html
- Ruby `File::Stat`: https://docs.ruby-lang.org/en/3.3/File/Stat.html
- POSIX `df`: https://pubs.opengroup.org/onlinepubs/9699919799/utilities/df.html
- Tutorial on tha-shed.com: https://tha-shed.com/ (Ruby for DevOps series)
