# disk-usage-report

Disk usage reporting with growth tracking, in one stdlib-only Ruby script.

When a "filesystem almost full" alert fires, `df` tells you *which* filesystem is in
trouble but not *what inside it* is eating the space — and neither tells you what
**grew** since yesterday, which is usually the real question. `disk_usage_report.rb`
answers all three in one pass:

1. **Filesystem view** — parses `df -Pk` for every target path (POSIX-stable output).
2. **Top-N offenders** — a single `Find.find` walk aggregates bytes per top-level
   child directory and collects the largest individual files.
3. **Growth deltas** — a JSON snapshot (`dir => bytes`) is persisted between runs, so
   the next run shows `+2.1 GB /var/log` style deltas. A 2 GB log dir is fine; a log
   dir that grew 2 GB overnight isn't.

![architecture](img/disk_usage_flow.png)

## Prerequisites

- Ruby >= 2.7 (stdlib only: `find`, `json`, `optparse`, `time` — no gems)
- Linux or macOS (anything with a POSIX `df`)
- Read access to the trees you scan (run via `sudo` for full coverage; unreadable
  entries are counted and skipped, never fatal)

## Usage

```sh
# human report, top 10, with growth tracking between runs
ruby disk_usage_report.rb /var /home --top 10 --state /var/tmp/du_state.json

# alerting mode for cron: WARN at 80% fs use, CRIT at 92%, JSON for pipelines
ruby disk_usage_report.rb /var --warn-pct 80 --crit-pct 92 --json
```

Options: `--top N`, `--warn-pct N`, `--crit-pct N`, `--min-mb N` (ignore small files
in the file list), `--state FILE`, `--json`.

Exit codes: `0` OK, `1` WARN threshold crossed, `2` CRIT — drop it into cron or a
Nagios-style check with no extra wrapping.

## How it works

- **One walk, not many.** `Find.find` visits each entry once; `File.lstat` (not
  `stat`) so symlinks aren't followed into loops or other trees.
- **Filesystem boundaries respected.** The walker records the device of the root and
  `Find.prune`s any directory whose `st.dev` differs — a bind-mounted
  `/var/lib/docker` doesn't get double-counted against the wrong mount.
- **Attribution to top-level children.** `/var/log/nginx/access.log` counts toward
  `/var/log`, which is the granularity a human wants first.
- **Flat memory.** The big-file candidate list is trimmed with `max_by(200)` whenever
  it exceeds 4000 entries, so multi-million-file trees don't balloon RSS.
- **Snapshot deltas.** The whole dir map (not just top-N) is persisted, so a
  directory that newly enters the top-N still has a real delta on its first
  appearance there.

## Example output

```
disk usage report — 2026-08-24 14:50  [OK]

FILESYSTEMS
  /                          5.9 GB used /   9.5 GB  ( 62%)  /dev/sda1

TOP 5 DIRECTORIES
      102 MB     +32 MB  /tmp/dutest/logs
       95 MB       +0 B  /tmp/dutest/db
       30 MB       +0 B  /tmp/dutest/uploads
       12 MB       +0 B  /tmp/dutest/cache
         6 B       +0 B  /tmp/dutest

TOP 5 FILES (>= 1 MB)
       95 MB  /tmp/dutest/db/data.sqlite
       80 MB  /tmp/dutest/logs/app.log
       30 MB  /tmp/dutest/uploads/video.mp4
```

## Troubleshooting

- **Numbers differ from `du -sh`** — `du` reports *allocated blocks*, this script
  reports *file sizes* (`lstat.size`). Sparse files make the script read higher;
  hard links (counted once per path here) can push it either way. Both are "right".
- **`unreadable entries skipped: N`** — you're not root; rerun with `sudo` if you
  need those trees counted.
- **Slow on NFS** — every `lstat` is a round trip. Scan the server locally instead.
- **Deltas all show `(new)`** — the `--state` file path changed or was deleted;
  deltas need two runs against the same state file.

## Extending

- Emit the JSON straight into Prometheus's textfile collector or an ELK pipeline.
- Track per-file deltas for a "fastest-growing files" view.
- Add `--exclude GLOB` for cache directories you never care about.
- Alert on *growth rate* rather than absolute fullness (predictive "full in ~3 days").

## References

- Ruby stdlib Find: https://docs.ruby-lang.org/en/3.3/Find.html
- Ruby File::Stat: https://docs.ruby-lang.org/en/3.3/File/Stat.html
- POSIX df spec (-P portable format): https://pubs.opengroup.org/onlinepubs/9699919799/utilities/df.html
- Tutorial with full walkthrough: https://tha-shed.com/ruby-for-devops-disk-usage-reporting-that-tells-you-what-grew-overnight/
