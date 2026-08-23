# inode-usage-monitor

Inode-exhaustion monitor for Linux, in a single stdlib-only Ruby script. A
filesystem can throw **"No space left on device"** while `df -h` shows gigabytes
free — because it ran out of *inodes*, not bytes. This reports inode usage per
filesystem, alerts on thresholds, and hunts the directories hoarding files.

![workflow](img/inode_flow.png)

## Prerequisites

- Ruby 2.7+ (tested on 3.0.2) — stdlib only: `open3`, `find`, `json`, `optparse`. No gems.
- Linux (uses `df -iP`; also works on macOS where `df -i` is available).

## Usage

```bash
# per-filesystem inode table, worst first
ruby inode_usage_monitor.rb

# custom thresholds (percent of inodes used)
ruby inode_usage_monitor.rb --warn 80 --crit 95

# find which directories under /var are eating inodes
ruby inode_usage_monitor.rb --hunt /var --top 20

# machine-readable
ruby inode_usage_monitor.rb --json
```

## How it works

1. **Read `df -iP`.** The `-P` flag gives POSIX one-line-per-filesystem output
   with stable columns; `-i` reports inodes instead of blocks. Pseudo-filesystems
   that report zero inodes (`proc`, `tmpfs`) are skipped.
2. **Threshold check.** Each filesystem's `IUse%` is compared to `--warn`/`--crit`
   and the table is sorted worst-first.
3. **`--hunt`** does one `Find` pass under a directory, incrementing the file count
   of each entry's parent — surfacing the exact directories responsible for inode
   consumption (mail spools, session dirs, cache fan-out).
4. Exit code is `2` on any CRIT, `1` on any WARN, else `0` — cron/Nagios-ready.

## Example output

```
STATE  FILESYSTEM                    IUSED        IFREE   IUSE%  MOUNT
CRIT   /dev/sda1                   1900000        99999   95.0%  /
ok     tmpfs                           510       500666    0.1%  /run

       FILES  INODE-HOG DIRECTORIES under /var
      840213  /var/spool/postfix/deferred
       92110  /var/lib/php/sessions
```

## Troubleshooting

- **All filesystems show 0% / missing** — your `df` lacks `-i`; on some minimal
  images install coreutils, or run on the host rather than a container layer.
- **`--hunt` is slow on huge trees** — it visits every inode by design; scope it
  to the offending mount from the table rather than `/`.
- **Numbers differ from `du`** — this counts inodes (files + directories), not bytes.

## Extending

- Emit to a Prometheus textfile collector for graphing inode headroom over time.
- Add `--exclude` globs to keep `--hunt` off bind-mounts and network filesystems.
- Cross-check against `df -hP` so a single report shows both byte and inode pressure.

## Testing

Verified on Linux (Ruby 3.0.2): live `df -iP` parse, `--warn/--crit` state
classification and exit codes, `--hunt` file-count ranking, and `--json` shape.

## References

- [`df(1)` (coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/df-invocation.html)
- [Ruby `Open3`](https://docs.ruby-lang.org/en/3.4/Open3.html)
- [Ruby `Find`](https://docs.ruby-lang.org/en/3.4/Find.html)
