# mem-pressure-monitor

**Platform:** Linux (pure Ruby stdlib, no gems)

Reports on real memory pressure -- not just "percent used" -- by combining `MemAvailable` from `/proc/meminfo`, swap utilization, kernel-reported Pressure Stall Information (PSI) from `/proc/pressure/memory`, and a scan of `journalctl`/`dmesg` for OOM-killer events, into one WARN/CRIT report.

## The problem

`free -h` gives you a number, but "90% memory used" is frequently meaningless -- the kernel deliberately uses spare RAM for page cache, and reclaims it instantly when something else needs it. What actually predicts trouble is `MemAvailable` (which already accounts for reclaimable cache), whether the box is actively swapping, whether processes are stalling waiting on memory (PSI), and whether the OOM killer has already fired. A monitoring check built only on "percent used" pages you constantly for a healthy box and stays silent on a box that's one allocation away from an OOM kill.

## Prerequisites

- Ruby >= 2.7 (tested on 3.0.2)
- No gems -- `optparse`, `json`, and `open3` are all Ruby standard library
- Linux with `/proc/meminfo` (universal). PSI (`/proc/pressure/memory`) needs Linux 4.20+ with `CONFIG_PSI=y` -- most modern distro kernels have it; the script degrades gracefully (reports "unknown", doesn't fail) if it's missing.
- `journalctl` or `dmesg` readable for OOM-kill scanning (needs root or `CAP_SYSLOG` on most distros) -- also degrades gracefully if neither is available.

## Usage

```bash
ruby mem_pressure_monitor.rb [options]
```

| Option | Default | Description |
|---|---|---|
| `--mem-warn PCT` | 15 | `MemAvailable` %% WARN threshold |
| `--mem-crit PCT` | 5 | `MemAvailable` %% CRIT threshold |
| `--swap-warn PCT` | 50 | Swap-used %% WARN threshold |
| `--swap-crit PCT` | 90 | Swap-used %% CRIT threshold |
| `--psi-warn PCT` | 10 | PSI "some avg60" %% WARN threshold |
| `--psi-crit PCT` | 30 | PSI "some avg60" %% CRIT threshold |
| `--oom-lookback MIN` | 60 | Minutes of journal/dmesg history to scan |
| `--meminfo-path PATH` | `/proc/meminfo` | Override, e.g. a container with `/host/proc` mounted |
| `--psi-path PATH` | `/proc/pressure/memory` | Override for the PSI file |
| `--json` | off | Emit machine-readable JSON |

```bash
# Plain snapshot
ruby mem_pressure_monitor.rb

# Tighter thresholds for a memory-sensitive box, JSON for alerting
ruby mem_pressure_monitor.rb --mem-warn 25 --mem-crit 10 --json

# Monitoring container with the host's /proc bind-mounted at /host/proc
ruby mem_pressure_monitor.rb --meminfo-path /host/proc/meminfo --psi-path /host/proc/pressure/memory
```

## How it works

1. **`/proc/meminfo` parsing** -- a plain-text `Key: value kB` file. The script regex-parses every line into a hash and reads `MemTotal`, `MemAvailable`, `SwapTotal`, `SwapFree` off it. `MemAvailable` (not `MemFree`) is what's used for the pressure calculation, since it already accounts for cache the kernel would reclaim under pressure.
2. **Swap analysis** -- `SwapTotal - SwapFree` gives bytes used; a box with no swap configured (`SwapTotal == 0`) reports OK with a note instead of dividing by zero.
3. **PSI parsing** -- `/proc/pressure/memory` has two lines (`some` / `full`), each with `avg10`/`avg60`/`avg300`/`total` fields. The script uses `some avg60` (percent of the last 60 seconds any task spent stalled waiting on memory) as the primary signal -- it reacts faster than a simple used-memory percentage and catches thrashing that hasn't yet shown up as "low available memory."
4. **OOM-kill scanning** -- tries `journalctl -k --since=-<N>min` first, falls back to `dmesg` if that's unavailable, and reports "unknown" (not a failure) if *neither* is readable -- common in a locked-down container. Output is scanned for `Out of memory`, `oom-kill`, and `Killed process` patterns. `Open3.capture3` is used deliberately (not `capture2`) so `journalctl`'s permission-hint noise on stderr doesn't leak into the script's own report.
5. **Severity roll-up** -- each of the four checks (memory, swap, PSI, OOM) produces its own status; the overall result is the worst of the four, and the process exit code follows it.

## Example output

Healthy box:

```
$ ruby mem_pressure_monitor.rb
mem-pressure-monitor: 2026-08-08 12:01:01 -0500

[   OK] memory available: 3512 MB / 3915 MB (89.7% free, 10.3% used)
[   OK] swap: not configured
[   OK] PSI memory pressure: some avg10=0.0 avg60=0.0 avg300=0.0
[UNKWN] OOM scan: neither journalctl nor dmesg were readable in this environment (needs root/CAP_SYSLOG)

Overall: OK
```

Simulated CRIT scenario (fed via `--meminfo-path`/`--psi-path` against fixture files -- see Testing notes):

```
mem-pressure-monitor: 2026-08-08 12:01:35 -0500

[ CRIT] memory available: 88 MB / 3906 MB (2.3% free, 97.7% used)
[ CRIT] swap used: 1904 MB / 1953 MB (97.5%)
[ CRIT] PSI memory pressure: some avg10=45.2 avg60=38.5 avg300=12.1
[UNKWN] OOM scan: neither journalctl nor dmesg were readable in this environment (needs root/CAP_SYSLOG)

Overall: CRIT
```

With a readable journal and a real OOM-kill event present:

```
[ CRIT] OOM scan (journalctl): 2 event(s) in last 60m
        Aug 08 11:58:02 web01 kernel: Out of memory: Killed process 4821 (ruby) total-vm:2048000kB
        Aug 08 11:58:02 web01 kernel: oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cpuset=/,mems_allowed=0,global_oom,task_memcg=/user.slice
```

Exit code: `0` OK, `1` WARN, `2` CRIT.

## Troubleshooting

- **`[UNKWN] OOM scan: neither journalctl nor dmesg were readable`** -- expected in most containers and for non-root users. Run with `sudo`, add `CAP_SYSLOG`, or grant the running user membership in the `systemd-journal` group to enable this check. It's reported as "unknown," not treated as a failure, precisely because it's a permissions issue, not a health issue.
- **`[UNKWN] PSI: PSI not available on this kernel/cgroup`** -- older kernels (<4.20) or `CONFIG_PSI=n` builds don't expose `/proc/pressure/memory` at all; some restrictive container runtimes hide it too. The other three checks (memory, swap, OOM) still work fine without it.
- **`swap: not configured` even though you know the box has swap** -- check you're not accidentally pointed at a container's `/proc` (many containers show `SwapTotal: 0` regardless of the host, since swap accounting is host-level, not namespace-level).
- **Thresholds trip immediately after a large batch job finishes** -- that's often real: a job that allocated a lot of memory and just released it can leave `MemAvailable` briefly low until the kernel reclaims/settles. If this happens routinely at a predictable time, consider scheduling around it rather than lowering `--mem-crit`.

## Extending it

- Add a `--watch N` mode that re-checks every N seconds and only alerts on a state *change*, to avoid re-paging on every cron run while still CRIT.
- Feed the JSON output into `alert-notifier/alert_notifier.rb` (elsewhere in this repo) for de-duplicated Slack/webhook paging.
- Track top memory-consuming processes (via `/proc/*/status`) alongside the OOM scan so an alert arrives with "here's probably who did it" already attached.
- Add cgroup v2 `memory.pressure` / `memory.max` awareness for containerized workloads, which can hit their own limit well before host memory is actually short.

## Testing notes

Tested live in a Linux sandbox against the real `/proc/meminfo` and `/proc/pressure/memory` on the box (both parse and report correctly with no swap configured). Because the sandbox box itself is healthy and has no swap, the WARN/CRIT and swap code paths were exercised deterministically with the `--meminfo-path`/`--psi-path` override flags pointed at hand-built fixture files representing a low-memory, heavily-swapping, high-PSI box -- these overrides exist specifically to make the script container-friendly (pointing at a bind-mounted `/host/proc`) and testable at the same time. The OOM-kill scanning path was exercised by placing a fake `journalctl` executable earlier on `PATH` that emits realistic `Out of memory` / `oom-kill` kernel-log lines, confirming the regex matching and CRIT classification fire correctly; the real `journalctl`/`dmesg` calls were also confirmed to fail safely (reporting `unknown`, not crashing) under this sandbox's actual permissions.

## References

- [`proc(5)` man page -- `/proc/meminfo` and `/proc/pressure`](https://man7.org/linux/man-pages/man5/proc.5.html)
- [Kernel docs: PSI -- Pressure Stall Information](https://docs.kernel.org/accounting/psi.html)
- [Ruby `Open3` module](https://docs.ruby-lang.org/en/3.0/Open3.html)
