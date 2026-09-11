# memory-pressure

Linux memory-pressure and OOM-kill detector in pure Ruby. Reads four kernel
signals in one pass — MemAvailable from `/proc/meminfo`, Pressure Stall
Information from `/proc/pressure/memory`, OOM-killer lines from the kernel log,
and per-process RSS/oom_score from `/proc/[pid]/status` — and turns them into
OK / WARN / CRIT with a plain-English reason list and cron-friendly exit codes.

![memory_pressure.rb architecture](img/memory-pressure-architecture.png)

Companion article: https://tha-shed.com/ (Ruby for DevOps: A Memory-Pressure and OOM-Kill Detector)

## Prerequisites

- Ruby 3.0+ (tested on 3.4). Standard library only: `optparse`, `json`, `open3`, `socket`.
- Linux with procfs. `/proc/pressure/memory` needs kernel 4.20+ with `CONFIG_PSI=y`
  (Ubuntu 20.04+, RHEL 8+, Debian 11+). If PSI is absent the script says so and continues.
- OOM history comes from `dmesg`, which is root-only on kernels 5.8+
  (`kernel.dmesg_restrict=1`). Non-root users can point `OOM_LOG=` at
  `/var/log/kern.log` or a `journalctl -k` export instead.

## Usage

```
ruby memory_pressure.rb                     # text report, exit 0/1/2
ruby memory_pressure.rb --json              # JSON for alerting pipelines
ruby memory_pressure.rb --warn 20 --crit 8 --swap-warn 30 --top 15
OOM_LOG=/var/log/kern.log ruby memory_pressure.rb   # non-root OOM history
PROC_ROOT=./fixtures/proc ruby memory_pressure.rb   # run against a captured /proc
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--warn PCT` | 15 | WARN when MemAvailable% <= PCT |
| `--crit PCT` | 5 | CRIT when MemAvailable% <= PCT |
| `--swap-warn PCT` | 50 | WARN when swap used% >= PCT |
| `--psi-some-warn PCT` | 10 | WARN when PSI `some avg10` >= PCT |
| `--psi-full-crit PCT` | 5 | CRIT when PSI `full avg10` >= PCT |
| `--top N` | 10 | rows in the top-RSS table |
| `--json` | off | machine-readable output |

Exit codes: `0` OK, `1` WARN, `2` CRIT. Any OOM kill in the log is CRIT.

## How it works

1. **`MemInfo`** parses every `Key:  value kB` line of `/proc/meminfo` into a Hash and derives
   `available_pct` (from MemAvailable, the kernel's own estimate of allocatable memory — not MemFree),
   `swap_used_pct`, dirty pages, and `Committed_AS / CommitLimit`.
2. **`Psi`** reads the two-line `/proc/pressure/memory` file. `some` is the share of wall-clock
   time in which at least one task stalled on memory; `full` is the share in which every task did.
   Returns `nil` (not `{}`) when the kernel does not expose PSI.
3. **`OomKills`** matches the canonical `Out of memory: Killed process <pid> (<comm>) ... anon-rss:<kB>`
   line from `OOM_LOG` or `dmesg --kernel --notime`. A non-zero dmesg exit is reported as
   "unavailable", which is different from "no kills".
4. **`TopRss`** globs `PROC_ROOT/[0-9]*`, reads `status` (Name, VmRSS) and `oom_score`, rescues
   `ENOENT`/`ESRCH` for processes that exit mid-scan, skips kernel threads (no VmRSS), sorts by RSS.
5. **`evaluate`** owns every threshold. A `bump` lambda raises the level to the max seen and appends
   a reason string, so the final line lists *all* the things that tripped.

Because every path is built from `PROC_ROOT`, the same code runs unchanged against a captured
`/proc` tree — that is how the script is tested.

## Example output

Against a captured fixture from a thrashing host (exit 2):

```
memory_pressure  2026-09-11 15:23:35  host=app-02
------------------------------------------------------------------------
RAM            1.05 GB / 15.54 GB available (6.8%)
Swap           2.77 GB / 4.00 GB used (69.3%)
Dirty          184.0 MB dirty pages waiting for writeback
Committed      161.0% of CommitLimit
PSI            some avg10=23.41 avg60=18.07 | full avg10=7.88 avg60=5.10
OOM            2 kill(s) in kernel log
               pid 21877 java anon-rss=5.92 GB
               pid 22910 node anon-rss=1.47 GB

PID      NAME                              RSS  OOM_SCR
21901    java                          6.11 GB      812
22944    node                          1.56 GB      240
1203     postgres                     510.0 MB       61
1877     redis-server                 206.0 MB       30
2999     ruby                          41.0 MB        5

CRIT: MemAvailable 6.8% <= warn 15.0%; swap 69.3% used; PSI full avg10=7.88% (all tasks stalling); PSI some avg10=23.41% (tasks stalling on memory); OOM killer fired 2x; last victim pid 22910 (node)
```

Against a healthy fixture the last line is `OK: memory looks healthy` and the exit code is 0.

## Troubleshooting

- **"PSI not available" on a modern kernel** — check `grep CONFIG_PSI /boot/config-$(uname -r)` and
  `/proc/cmdline` for `psi=0`. Some images build with `CONFIG_PSI_DEFAULT_DISABLED=y`; boot with `psi=1`.
- **"OOM kernel log unreadable"** — `kernel.dmesg_restrict`. Run from root's crontab, or set
  `OOM_LOG=/var/log/kern.log` (readable by group `adm` on Debian/Ubuntu).
- **Old kernels** (< 4.15) log `Killed process N (name)` without the "Out of memory:" prefix; loosen `LINE_RE`.
- **Always CRIT after one old kill** — the ring buffer remembers kills since boot. Compare the dmesg
  uptime stamp with `/proc/uptime` if you want a time window.
- **Top-N only shows your own processes** — `/proc` mounted with `hidepid=2`; run as root.
- **Testing note** — verified against two captured `/proc`/kernel-log fixtures (thrashing, exit 2; healthy,
  exit 0) plus `--json`. The live `dmesg` branch and `Socket.gethostname` were only exercised for their
  error paths in the harness; both are plain stdlib calls.

## Extending

- Per-cgroup pressure: point `Psi.read` at `/sys/fs/cgroup/<slice>/memory.pressure` and read `memory.events` for per-service `oom_kill` counts.
- Emit `--json` to a Prometheus textfile collector or a webhook.
- Age the OOM history using the dmesg uptime stamp.
- Gate any auto-restart on `full avg10`, never on MemAvailable alone (page cache is not pressure).
- Windows twin via `Win32_OperatingSystem.FreePhysicalMemory` and `Win32_Process.WorkingSetSize`.

## References

- Linux kernel docs, `/proc/meminfo`: https://docs.kernel.org/filesystems/proc.html#meminfo
- Linux kernel docs, PSI: https://docs.kernel.org/accounting/psi.html
- Ruby `Open3`: https://docs.ruby-lang.org/en/3.4/Open3.html
- Ruby `OptionParser`: https://docs.ruby-lang.org/en/3.4/OptionParser.html
