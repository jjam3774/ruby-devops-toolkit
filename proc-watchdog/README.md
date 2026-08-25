# proc-watchdog

A `/proc`-based process watchdog for Linux, in ~150 lines of standard-library
Ruby. Watches one or more process patterns, reports **PID / CPU% / RSS /
uptime** for every match, warns when a process crosses a memory ceiling, and
optionally runs a restart command when a watched pattern has no live process
at all.

![sampling pipeline](img/proc_watchdog_flow.png)

## Prerequisites

- Ruby 2.7+ (tested on 3.0) — standard library only, no gems
- Linux (reads `/proc/<pid>/stat`, `/proc/<pid>/cmdline`, `/proc/uptime`)
- No root needed to *observe*; the `--restart` hook needs whatever privileges
  the restart command itself needs

## Usage

```bash
# just report on sshd and cron
ruby proc_watchdog.rb sshd cron

# warn when any matched process exceeds 512 MB RSS
ruby proc_watchdog.rb --max-rss-mb 512 nginx postgres

# self-heal: if nothing matches "myapp", run the restart command
ruby proc_watchdog.rb --restart 'systemctl restart myapp' myapp

# machine-readable, for a monitoring pipeline
ruby proc_watchdog.rb --json --max-rss-mb 512 nginx | jq .
```

Exit codes: `0` all healthy, `1` at least one WARN (memory ceiling), `2` at
least one CRIT (pattern missing; restart attempted if `--restart` given).
Drop it straight into cron or a systemd timer.

## How it works

1. **Two snapshots.** CPU% is a rate, but `/proc/<pid>/stat` only exposes
   cumulative jiffies (`utime` + `stime`). So the script samples every matched
   process twice, `--interval` seconds apart, and computes
   `delta_jiffies / CLK_TCK / interval * 100` — exactly what `top` does.
2. **Careful stat parsing.** Field 2 of `stat` (`comm`) may contain spaces and
   parentheses — `(tmux: server)` is the classic. The parser splits on the
   *last* `)` instead of naively splitting on whitespace.
3. **RSS from pages.** Field 24 is resident pages; multiplied by
   `Etc.sysconf(Etc::SC_PAGESIZE)` for bytes.
4. **Self-exclusion.** The watchdog's own argv contains the patterns, so it
   skips `Process.pid` — otherwise every pattern would always "match".
5. **Race-tolerant.** Processes that exit between the directory listing and the
   file read raise `ENOENT`/`ESRCH`; both are rescued and skipped.

## Example output

```
$ ruby proc_watchdog.rb --max-rss-mb 50 --restart "systemctl restart ghost-svc" "sleep 30" ghost-svc
[WARN] sleep 30 -- 1 process(es) over 50 MB RSS ceiling
        pid 7       ruby            cpu   0.0%  rss     97.3 MB  up      2s  ruby -e arr = "x" * 80_000_000; sleep 30
[CRIT] ghost-svc -- no live process matches pattern -- restart command succeeded
$ echo $?
2
```

## Troubleshooting

- **Everything matches your pattern** — patterns are substring matches against
  `comm` *and* the full cmdline (like `pgrep -f`). A shell whose command text
  contains your pattern will match. Use a more specific pattern.
- **CPU% is always 0.0** — your `--interval` may be too short for a mostly idle
  process; jiffies are coarse (usually 100/s).
- **Kernel threads invisible** — they have an empty cmdline; they're matched by
  `comm` only.
- **`Errno::EACCES` on other users' cmdlines** — hardened kernels
  (`hidepid=2` on `/proc`) restrict visibility; run as root or relax the mount
  option.

## Extending it

- Add `%CPU` ceilings alongside the RSS ceiling
- Track file-descriptor counts from `/proc/<pid>/fd`
- Push the JSON to a Prometheus pushgateway or a webhook
- Back-off logic: don't fire `--restart` more than N times per hour

## References

- [proc(5) man page](https://man7.org/linux/man-pages/man5/proc.5.html)
- [Ruby Etc module docs](https://docs.ruby-lang.org/en/3.0/Etc.html)
- Blog post: https://tha-shed.com/ (Ruby for DevOps series)
