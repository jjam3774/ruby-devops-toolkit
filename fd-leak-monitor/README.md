# fd-leak-monitor

Find processes leaking file descriptors on Linux by reading `/proc` directly —
pure Ruby standard library, no `lsof`, no gems.

![Architecture](img/fd_leak_monitor_flow.png)

## The problem

A slow file-descriptor leak is one of the nastiest production failures there
is. A long-running daemon opens sockets or files and never closes them; its FD
count creeps up for days; then it hits its per-process limit and starts
throwing `Too many open files` — reliably at peak traffic, never in a quiet
window. This script walks `/proc`, counts each process's open descriptors,
compares that to the process's own `RLIMIT_NOFILE` soft limit, and flags the
ones getting close — with a breakdown by descriptor kind so you can see *what*
is leaking, and a `--watch` mode to see one PID's count actually climbing.

## Prerequisites

- Ruby 2.7+ (tested on 3.0) — stdlib only: `optparse`, `json`
- Linux (needs `/proc`). Run as root to see every process; without it you only
  see your own, which the summary states explicitly.

## Usage

```bash
ruby fd_leak_monitor.rb                     # audit every visible process
ruby fd_leak_monitor.rb --top 15 --json
ruby fd_leak_monitor.rb --warn-pct 60 --crit-pct 85
ruby fd_leak_monitor.rb --watch 1234 --interval 5   # trend a single PID
```

Statuses: `CRIT` (>= `--crit-pct` of the FD limit, default 90%) · `WARN`
(>= `--warn-pct`, default 75%) · `OK`. Exit codes: `0` all OK · `1` any WARN ·
`2` any CRIT.

## How it works

1. **Enumerate PIDs** from the numeric directory names in `/proc`.
2. **Count descriptors** by listing `/proc/<pid>/fd` and `readlink`-ing each
   entry — the link target tells you the kind (`socket:[…]`, `pipe:[…]`,
   `anon_inode:[…]`, or an absolute path for a real file).
3. **Read the real limit** from `/proc/<pid>/limits` ("Max open files" soft
   value), so usage is measured against *that process's* ceiling — which may
   differ from the global default after a `ulimit -n`.
4. **Classify** each process by percentage of its limit, and rank the busiest.
5. **Tolerate churn.** Processes come and go while you scan; a PID that
   vanishes mid-read is skipped, never fatal. Unreadable PIDs (no permission)
   are counted and surfaced in the summary.

## Example output

```
fd_leak_monitor — 148 processes scanned

  STAT  COMMAND               PID      FDs   USE%  breakdown
  CRIT  leaky-daemon         4242       92   92.0%  socket:88 file:3 pipe:1
  WARN  nginx                1180      780   76.1%  socket:770 file:10
  OK    sshd                  900        6    0.6%  socket:3 file:2 anon:1

worst status: CRIT
```

The breakdown is the tell: 88 open sockets against a 100 FD limit is a socket
leak, not a busy server — the kind counts point you straight at the bug.

## Testing

`test_fd_leak_monitor.rb` builds a **synthetic `/proc` tree** in a temp dir
(fake `fd/` symlinks, `comm`, and a `limits` file) and points the injectable
reader at it, so severity thresholds and FD classification are verified
deterministically without depending on whatever happens to be running:

```
ruby test_fd_leak_monitor.rb
  socket link -> socket                                        PASS
  95/100 -> CRIT (>=90)                                        PASS
  counts 92 fds for leaky-daemon                               PASS
  breakdown: 88 sockets                                        PASS
  leaky-daemon flagged CRIT (92%)                              PASS
  exit code 2 when a CRIT present                              PASS
all assertions passed
```

The live `/proc` scan was also run against this repo's build host.

## Troubleshooting

- **Only a handful of processes** — you're not root; `/proc/<pid>/fd` for other
  users' processes is `0700`. Run with `sudo` for full coverage.
- **`limit=inf` / USE% shows `?`** — the process has an unlimited soft
  `RLIMIT_NOFILE`; percentage is undefined, so it's never auto-flagged. Watch
  its raw count with `--watch` instead.
- **macOS** — no `/proc`; the script exits with a clear message. Port the
  reader to `lsof -p` if you need macOS support (see Extending).
- **Counts jump around** — normal for busy servers; use `--watch` on a
  suspected PID to see a *sustained* climb, which is what a real leak looks like.

## Extending

- Add an `lsof` backend behind the same injectable interface for macOS/BSD.
- Emit `--json` to Prometheus keyed on `pct`, and alert on sustained upward
  slope rather than a single reading.
- Add `--min-fds N` to ignore trivially small processes and cut noise.
- Correlate with `/proc/<pid>/stat` start time to compute an FDs-per-hour
  growth rate — the cleanest leak signal of all.

## References

- Linux `proc(5)` — `/proc/[pid]/fd` and `/proc/[pid]/limits`: https://man7.org/linux/man-pages/man5/proc.5.html
- `getrlimit(2)` / `RLIMIT_NOFILE`: https://man7.org/linux/man-pages/man2/getrlimit.2.html
- Ruby `Dir` and `File.readlink`: https://docs.ruby-lang.org/en/3.3/Dir.html
