# cron-audit

Inventory, validate, and risk-check every cron job on a Linux box — stdlib-only Ruby.

Cron is where automation goes to be forgotten. Jobs pile up across `/etc/crontab`,
`/etc/cron.d/*`, and user spools; some reference scripts that were deleted two
migrations ago, some have schedules that never fire, and some run world-writable
shell scripts as root — a straightforward privilege-escalation path.
`cron_audit.rb` walks the whole cron surface and, for every job:

- **validates the schedule** — 5-field syntax, ranges, steps, `mon`/`sun` names,
  `@daily`-style aliases;
- **computes the next run time** — a small pure-Ruby cron matcher, including the
  classic gotcha that when *both* day-of-month and day-of-week are restricted,
  vixie-cron fires on **either** match (OR, not AND);
- **risk-checks the command** — missing scripts (`BROKEN`), world/group-writable
  scripts and `curl | sh` pipes (`RISK`), relative paths that depend on cron's
  minimal `PATH` (`WARN`), non-root-owned scripts (`WARN`).

![architecture](img/cron_audit_flow.png)

## Prerequisites

- Ruby >= 2.7 (stdlib only: `json`, `optparse`, `time`, `etc` — no gems)
- Linux (or any cron-carrying Unix); read access to the crontabs you audit
  (root needed for `/var/spool/cron/crontabs`)

## Usage

```sh
# audit the system surface: /etc/crontab + /etc/cron.d/*
ruby cron_audit.rb

# include user spools, JSON for pipelines
sudo ruby cron_audit.rb --spool /var/spool/cron/crontabs --json

# audit a standalone (user-format) crontab file
ruby cron_audit.rb --no-system --file deploy.cron
```

Exit codes: `0` clean, `1` warnings only, `2` at least one `BROKEN`/`RISK` finding —
so the auditor itself drops straight into cron or CI.

## How it works

- **Field expansion is the whole parser.** Each of the 5 schedule fields expands to
  a sorted array of allowed values (`*/15` becomes `[0,15,30,45]`). Validation errors and
  next-run matching both fall out of that one structure; `dow` 7 normalises to 0.
- **Next-run matching walks minutes.** From "now", advance minute-by-minute (max 8
  days, about 11.5k iterations — microseconds in practice) until minute, hour, month and
  the dom/dow rule all match. Brute force beats reimplementing croniter wrong.
- **System vs user format.** `/etc/crontab` and `/etc/cron.d/*` carry a 6th user
  column; user spool files don't. The parser handles both, skips comments and
  `NAME=value` environment lines, and records file + line for every job.
- **Command checks look at the first absolute path** in the command line (after
  skipping `FOO=bar` prefixes and common wrappers), then `File.stat` it for
  world/group-write bits and ownership.

## Example output

```
cron audit — 2026-08-24 14:50  jobs: 7  [CRIT]

!! /tmp/appjobs.cron:4  (user: deploy)
     30 2 * * sun  ->  next run: 2026-08-30 02:30
     /tmp/bin/full_backup.sh --target /backup
       [RISK] /tmp/bin/full_backup.sh is world-writable
       [RISK] /tmp/bin/full_backup.sh is group-writable

!! /tmp/appjobs.cron:5  (user: deploy)
     0 4 * * *  ->  next run: 2026-08-25 04:00
     /usr/local/bin/prune_uploads.sh
       [BROKEN] referenced file missing: /usr/local/bin/prune_uploads.sh

!! /tmp/appjobs.cron:8  (user: deploy)
     5 3 * * *  ->  next run: 2026-08-25 03:05
     curl -fsSL https://example.com/install.sh | sh
       [RISK] pipe-to-shell (curl|wget piped into a shell)
```

## Troubleshooting

- **`jobs: 0`** — nothing readable at the default locations; you may be on a distro
  where everything lives in systemd timers, or you need `sudo` for the spool dir.
- **Next run seems off by an hour** — the matcher uses the host's local time, same
  as crond; check the box's timezone (and remember DST jumps).
- **False WARN on `cd / && ...`** — the "first absolute path" heuristic can latch
  onto `/` in compound commands. Findings are advisory; read the line.
- **Doesn't see anacron/systemd timers** — deliberately out of scope; see Extending.

## Extending

- Add `systemctl list-timers --all` parsing for the systemd side of the house.
- Diff two runs to alert on *new* cron entries (a favourite persistence mechanism).
- Validate `MAILTO` and detect jobs that silence output with no other logging.
- Ship `--json` into your SIEM and alert on `RISK` findings fleet-wide.

## References

- crontab(5) man page: https://man7.org/linux/man-pages/man5/crontab.5.html
- Ruby stdlib OptionParser: https://docs.ruby-lang.org/en/3.3/OptionParser.html
- Tutorial with full walkthrough: https://tha-shed.com/ruby-for-devops-auditing-every-cron-job-on-the-box/
