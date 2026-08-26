# disk-usage-report

Disk usage reporting and growth tracking for Linux/macOS in one stdlib-only Ruby
script. Answers the two questions `df` can't: **where** the bytes live, and
**where they grew** since the last run.

![Data flow](img/disk_usage_flow.png)

## Prerequisites

- Ruby 2.7+ (tested on 3.0) — stock distro package is fine
- Standard library only: `find`, `json`, `optparse`, `time` — no gems
- Read access to the trees you scan (unreadable paths are counted, not fatal)

## Usage

```bash
ruby disk_usage_report.rb /var /home                    # human-readable report
ruby disk_usage_report.rb --top 15 --min-file-mb 250 /var
ruby disk_usage_report.rb --json /var                   # machine-readable
ruby disk_usage_report.rb --save-snapshot /var/tmp/du.json /var
ruby disk_usage_report.rb --compare /var/tmp/du.json /var
ruby disk_usage_report.rb --warn-gb 80 /var             # exit 1 over threshold
```

Exit codes: `0` ok · `1` a `--warn-gb` threshold was breached · `2` usage error.

## How it works

1. **One walk** — `Find.find` streams every path; `File.lstat` (never `stat`)
   means symlinks are skipped entirely, so link loops can't hang the scan and
   links can't double-count. Permission errors increment a counter instead of
   crashing.
2. **Attribution** — each file's bytes are credited to the scanned root's
   *immediate child directory* (files directly in the root go to a synthetic
   `<root files>` bucket), which is what makes the output read "log holds 50.9%"
   instead of being a raw directory dump. Files ≥ `--min-file-mb` (default
   100 MiB) also enter a global big-file top-N with mtimes.
3. **Snapshots** — `--save-snapshot` writes per-child totals + UTC timestamp as
   JSON; `--compare` unions the keys, subtracts bucket by bucket, and prints
   non-zero deltas sorted by growth (negatives are reported as freed).
4. **Exit codes** — `--warn-gb` turns the report into a cron-able monitor.

## Example output

```
== /tmp/demo/var  (total 1.0 GiB, 0 unreadable)
-- largest immediate subdirectories:
   540.0 MiB   50.9%  log
   460.0 MiB   43.4%  lib
    60.0 MiB    5.7%  cache
-- largest files (>= 100 MiB):
   420.0 MiB  2026-08-26  /tmp/demo/var/log/app/app.log
   310.0 MiB  2026-08-26  /tmp/demo/var/lib/docker/overlay.img

== growth for /tmp/demo/var since 2026-08-26T16:37:30Z: +390.0 MiB
    +240.0 MiB  log
    +150.0 MiB  lib
```

## Troubleshooting

- **Totals differ from `du`** — expected: `du` reports allocated blocks and
  counts hard links once; this sums apparent sizes via `lstat`. Sparse files
  and hard-link farms widen the gap.
- **Large "unreadable" count** — you're not root; re-run with `sudo` or accept
  the partial view (the counter tells you how partial).
- **Scan crosses mounts** — the walk descends into anything under the root,
  including `/proc` or NFS if you scan `/`. Scan specific trees, or add a
  device-boundary check (below).
- **Compare shows nothing after moving files** — moves within the same
  top-level bucket are invisible by design.

## Extending

- Stay on one filesystem: remember `File.lstat(root).dev` and `Find.prune` on
  directories whose `dev` differs (`du -x` behaviour).
- Rank cleanup candidates by `size × age` using the big-file mtimes.
- Ship `--json` to a metrics pipeline; keep nightly snapshots per host.
- Add a second attribution level (`log/app`) for very large trees.

## References

- Blog post: https://tha-shed.com/ (Ruby for DevOps series)
- Ruby stdlib `Find`: https://docs.ruby-lang.org/en/3.3/Find.html
- Ruby stdlib `File::Stat`: https://docs.ruby-lang.org/en/3.3/File/Stat.html
- GNU coreutils `du`: https://www.gnu.org/software/coreutils/manual/html_node/du-invocation.html
