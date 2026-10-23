# Linting Crontabs and Previewing Run Times

Cron never tells you a schedule is wrong until the job fails to run. The script below parses the five time fields (including `*/15`, ranges, lists and `@daily` macros), rejects out-of-range values, warns about common production mistakes, and prints the next run times so you can verify intent before deploying.

![diagram](img/cron-audit-pipeline.png)

## Prerequisites

- Ruby 2.7+ (tested on 3.3.6), standard library only (`optparse`, `time`)
- A crontab file to check (for example the output of `crontab -l > mycron`)

## Usage

```
ruby cron_audit.rb mycrontab --next 3 --from "2026-10-23 17:00"
```

## How it works

### 1. Expand each field

`expand_field` turns `*/15`, `1-5` or `1,3,7` into an explicit array of integers and raises `CronError` if anything is outside the allowed range.

### 2. Handle macros and the command

`parse_line` expands `@daily`-style macros into five fields and splits the command off with `split(/\s+/, 6)` so spaces inside the command are preserved.

### 3. The dom/dow rule

If both day-of-month and day-of-week are restricted, cron runs when **either** matches. `matches?` implements that, and `0 3 1 * 1` really runs on the 1st **and** every Monday.

### 4. Next-run preview

`next_runs` walks forward minute by minute (max one year) and collects matches. Brute force, but trivially correct and fast enough for a lint tool.

### 5. Warnings

Every-minute jobs, non-absolute commands (cron's PATH is minimal), and missing redirection (cron mails output) are flagged.

## Example output

```
line 2: OK   */15 * * * *  /usr/local/bin/backup.sh > /var/log/backup.log 2>&1
          next: Fri 2026-10-23 17:15
          next: Fri 2026-10-23 17:30
line 3: OK   * * * * *  check.sh
          warn: runs every minute
          warn: command does not start with an absolute path (cron has a minimal PATH)
          warn: no output redirection: cron will try to e-mail output
          next: Fri 2026-10-23 17:01
          next: Fri 2026-10-23 17:02
line 4: OK   0 3 1 * 1  /opt/report.sh
          warn: no output redirection: cron will try to e-mail output
          warn: day-of-month and day-of-week both set: cron ORs them
          next: Mon 2026-10-26 03:00
          next: Sun 2026-11-01 03:00
line 5: OK   0 0 * * *  /usr/bin/logrotate /etc/logrotate.conf >/dev/null
          next: Sat 2026-10-24 00:00
          next: Sun 2026-10-25 00:00
line 6: FAIL '61' outside 0..59  <= 61 * * * * /bin/true
exit code: 1
```

## Troubleshooting

- **Names like MON or JAN:** not supported; the script reports them as unparseable.
- **Time zones:** previews use the local zone of the machine running the script, which should match the cron host's.
- **System crontabs (/etc/crontab):** they have a user column before the command; strip it or extend `parse_line`.

## Extending

- Run it in CI against crontabs kept in git
- Support `/etc/cron.d` files with the user column
- Detect jobs that overlap or stampede at minute 0
- Add month/day names

## References

- [crontab(5) man page](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [Ruby Time](https://docs.ruby-lang.org/en/3.3/Time.html)
- [Ruby OptionParser](https://docs.ruby-lang.org/en/3.3/OptionParser.html)
