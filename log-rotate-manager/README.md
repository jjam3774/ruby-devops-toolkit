# log-rotate-manager

**Platform:** Linux / macOS / Windows &nbsp;|&nbsp; **Gems required:** none (stdlib only)

A ~200-line, dependency-free reimplementation of `logrotate`'s core mechanics. Drop it next to
any log file that never got a real rotation strategy and run it from cron, a systemd timer, or
Windows Task Scheduler.

## The problem

Lots of in-house services just do `File.open("app.log", "a")` and never stop writing. Nobody
wired up `logrotate` for them because they're not a package-managed daemon, or the box is
Windows where `logrotate` doesn't exist at all. Eventually the log fills the disk and pages
someone at 3am.

## Prerequisites

- Ruby 2.7+ (tested on 3.0.2)
- Uses only `optparse`, `json`, `zlib`, `fileutils`, and `time` from the standard library
- Write access to the log file's directory (to create/rename `.N.gz` siblings)

## Usage

```bash
ruby log_rotate.rb --config rotate.json
ruby log_rotate.rb --config rotate.json --dry-run
ruby log_rotate.rb --config rotate.json --json
```

### Config format

```json
{
  "rules": [
    {
      "path": "/var/log/myapp/app.log",
      "max_bytes": 104857600,
      "keep": 7,
      "compress": true,
      "post_rotate": "systemctl kill -s HUP myapp"
    },
    {
      "path": "/var/log/myapp/access.log",
      "max_age_days": 1,
      "keep": 14,
      "compress": true
    }
  ]
}
```

Each rule needs a `path` and at least one trigger (`max_bytes` and/or `max_age_days`), plus
`keep` (retention count), `compress` (gzip old generations), and an optional `post_rotate` shell
command (typically a signal telling the owning process to reopen its log handle).

## How it works

1. **`shift_generations`** — finds existing `path.N`/`path.N.gz` files and walks the generation
   numbers *highest first*, renaming each one up by one slot. This ordering matters: renaming
   from the top down means every move target is empty when you get to it.
2. **`perform_rotation`** — copies (and optionally gzips) the live file's current bytes into the
   new `.1`/`.1.gz`, then `File.truncate`s the *original* file to zero length in place. Because
   it's the same inode before and after, a process with the file already open keeps writing to it
   without interruption — this is the **copytruncate** strategy, and it's why nothing breaks a
   writer's open file descriptor the way renaming the live file away would.
3. **`enforce_retention`** — deletes generations beyond `keep`.
4. **`run_post_rotate`** — shells out to the optional post-rotate command.

## Example output

```
$ ruby log_rotate.rb --config rotate.json
  -> reopened app.log handle
ROTATED /tmp/logtest2/app.log (-> /tmp/logtest2/app.log.1.gz)

1 rotated, 0 skipped, 0 errors

$ ruby log_rotate.rb --config rotate.json   # run again immediately: nothing to do
skip    /tmp/logtest2/app.log (not due)

0 rotated, 1 skipped, 0 errors
exit: 0
```

## Troubleshooting

- **"Not due" every time despite a huge file** — check `max_bytes` is in bytes, not KB/MB.
  `104857600` = 100 MiB.
- **Errno::EACCES** — the script needs write access to both the log file and its parent
  directory. Run as the file's owner or via a scheduled task with the right identity.
- **Writer output looks corrupted after rotation** — only happens if the writer uses buffered
  I/O with an internal byte offset. Use `post_rotate` to signal a reopen, or have the app open
  the file with `O_APPEND`.
- **gzip file won't decompress** — make sure nothing else is rotating the same path
  concurrently; run from a single cron entry, not overlapping timers.

## Testing notes

Tested live in a Linux sandbox: created a log file, rotated it multiple times to verify
generation shifting (`.1.gz` -> `.2.gz` -> `.3.gz`), confirmed retention deletes overflow
generations beyond `keep`, verified gzip contents are intact and byte-identical to the original
via `zcat`, confirmed the `post_rotate` hook fires, and confirmed missing-file and
permission-denied paths are handled as non-fatal skips/errors rather than crashes.

## Extending it

- **Glob-based rules** — accept a glob pattern to cover a dynamic set of worker log files.
- **Parallel rotation** — thread pool for hosts with dozens of independently-rotating logs.
- **Size-based retention** — delete oldest generations until total compressed size is under a
  budget, instead of (or in addition to) a generation count.
- **Remote shipping** — extend `post_rotate` to upload the just-closed `.gz` to S3/blob storage
  before the next cycle would delete it.

## References

- [logrotate(8) man page](https://man7.org/linux/man-pages/man8/logrotate.8.html)
- [Ruby stdlib: Zlib::GzipWriter](https://docs.ruby-lang.org/en/3.3/Zlib/GzipWriter.html)
- [Ruby stdlib: FileUtils](https://docs.ruby-lang.org/en/3.3/FileUtils.html)
