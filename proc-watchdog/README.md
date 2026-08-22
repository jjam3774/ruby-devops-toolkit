# proc-watchdog

A Linux process watchdog built directly on `/proc` — no `ps`, no `pgrep`, no
gems. Give it the names of processes that must be running (sshd, cron, nginx,
your app worker) and it reports per-pattern status with CPU%, RSS, and uptime,
plus **crash-loop detection**: a service that is "up" every time you look but
whose PID keeps changing gets flagged as RESTARTED.

![Architecture](img/proc_watchdog_flow.png)

## Why

`systemctl is-active` tells you a unit is up *right now*. It does not tell you
the daemon has quietly restarted 40 times since lunch, and on boxes without
systemd (containers, ancient appliances, BSD-style init) you don't even get
that. Walking `/proc` yourself is ~100 lines of Ruby, works everywhere Linux
does, and teaches you exactly where tools like `ps` get their numbers.

## Prerequisites

- Linux (anything with `/proc`). Ruby 2.7+ (tested on 3.0), stdlib only
  (`json`, `optparse`).
- Read access to `/proc` (any user for most fields; some processes of other
  users may be invisible in hardened `hidepid` setups).

## Usage

```
# One-shot check
ruby proc_watchdog.rb sshd cron nginx

# From cron every 5 minutes, JSON into your pipeline
*/5 * * * *  ruby /opt/watchdog/proc_watchdog.rb --state /var/tmp/wd.json --json sshd nginx >> /var/log/wd.jsonl
```

Options: `--state PATH` (restart-detection state file, default
`/tmp/proc_watchdog_state.json`), `--interval SEC` (CPU sampling window,
default 1.0), `--json`.

Exit codes: `0` all RUNNING, `1` something RESTARTED, `2` something MISSING.

## How it works

1. Every numeric directory under `/proc` is a PID. For each, the script reads
   `comm` (short name), `cmdline` (argv, NUL-separated) and `stat`.
2. `stat` is parsed by splitting **after the last `)`** — the comm field can
   itself contain spaces and parens, which is the classic bug in naive
   parsers. Fields used: utime+stime (CPU ticks), starttime (uptime), rss.
3. It samples twice, `--interval` apart: CPU% = Δticks / USER_HZ / interval.
4. A pattern matches on `comm` or the basename of argv[0] — **not** the full
   command line. (The first version matched raw cmdline and promptly reported
   `bash -c "sleep 300"` as a match for `sleep`. The tutorial covers this
   false-positive trap in detail.)
5. The PIDs seen for each pattern are written to a JSON state file; on the
   next run, same-pattern-different-PIDs means RESTARTED.

## Example output

```
PATTERN      STATUS         PID COMM               CPU%  RSS(MB) UPTIME(S)  DETAIL
--------------------------------------------------------------------------------------------
sleep        RESTARTED       10 sleep               0.0      1.9         1  pids changed [7] -> [10]
python3      RUNNING          8 python3             0.0      8.5         2
--------------------------------------------------------------------------------------------
running=1 restarted=1 missing=0
```

## Testing notes

Tested live in a Linux sandbox: watched real `sleep` and `python3` processes
plus a deliberately absent `nginx` (MISSING, exit 2); killed and relaunched the
`sleep` between runs to simulate a crash loop (RESTARTED, exit 1); a third
steady-state run returned to all-RUNNING, exit 0. JSON mode verified the same
way.

## Troubleshooting

- **CPU% always 0.0** — your processes are genuinely idle, or your interval is
  too short for slow tickers. Raise `--interval` to 2–5s.
- **Wrong CLK_TCK/PAGE_SIZE** — the constants 100/4096 hold on essentially all
  Linux; if you run exotic kernels check `getconf CLK_TCK` / `getconf PAGESIZE`
  and adjust.
- **RESTARTED after reboot** — expected: all PIDs changed. Delete the state
  file in your boot sequence, or treat the first post-boot run as informational.
- **Processes invisible** — `/proc` mounted with `hidepid=1/2` hides other
  users' processes; run the watchdog as root or the service user.
- **Two watchdogs, one state file** — give each cron entry its own `--state`
  path or they will trample each other's restart detection.

## Extending

- **Threshold alarms**: flag RSS above a per-pattern limit (leak detection) or
  CPU% pegged at 100 for N consecutive runs.
- **Auto-heal**: on MISSING, `systemctl restart <unit>` and record the action.
- **Children/threads**: read `/proc/<pid>/task/` to count threads per process.
- **Prometheus**: export `proc_up{pattern=...}`, `proc_rss_bytes`, etc. —
  pairs with [prometheus-exporter](../prometheus-exporter) in this repo.

## References

- proc(5) man page: https://man7.org/linux/man-pages/man5/proc.5.html
- Kernel docs for /proc: https://www.kernel.org/doc/html/latest/filesystems/proc.html
- Ruby File/Dir stdlib: https://docs.ruby-lang.org/en/master/File.html
