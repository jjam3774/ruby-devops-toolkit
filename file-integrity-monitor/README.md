# File Integrity Monitor (FIM)

A dependency-free file integrity monitor: `baseline` snapshots SHA-256 + size + mtime + permission bits for
every file under one or more watched paths into a single JSON file; `check` re-snapshots and diffs against
that baseline, reporting added/removed/content-changed/permissions-changed files. No daemon, no database --
built to run from cron.

## The problem

You want to know when a file under a sensitive path (`/etc`, a webroot, a deploy directory) changes outside
your normal deploy/config-management flow -- a sign of tampering, a misconfigured process writing where it
shouldn't, or an untracked manual edit. Tools like AIDE/Tripwire/OSSEC solve this at scale, but a lot of
shops just need "tell me what changed under `/etc/nginx` since yesterday," without a real install or config
format. This script is that: two subcommands, one JSON baseline, cron-friendly.

## Prerequisites

- Ruby 3.0 or newer (tested against Ruby 3.0.2). Standard library only (`digest`, `find`, `json`,
  `optparse`) -- nothing to `gem install`.
- Read access to every file under the watched paths. Unreadable files are recorded as unreadable rather than
  silently skipped, so permission problems show up in the diff instead of hiding.
- Write access to store `fim.json` somewhere with restricted permissions -- if an attacker can rewrite your
  baseline, they can hide their own tampering.

## Usage

```bash
# Build a baseline over one or more paths
ruby file_integrity_monitor.rb baseline /etc/nginx /etc/ssh --db fim.json

# Check current state against that baseline
ruby file_integrity_monitor.rb check --db fim.json

# Same, but exit 1 if anything changed (for cron/monitoring)
ruby file_integrity_monitor.rb check --db fim.json --exit-code
```

### Exit codes (`check --exit-code`)

| Code | Meaning |
|------|---------|
| `0`  | No drift detected |
| `1`  | Changes detected (added / removed / content-changed / permissions-changed) |
| `2`  | Usage or IO error (e.g. baseline file missing) |

## How it works

### 1. `baseline`: build the snapshot

`snapshot(paths)` walks every watched root with `Find.find`, skips symlinks (never followed -- avoids
escaping the watched tree and avoids noisy signals from a moving symlink target) and non-files, and calls
`record_for(path)` on everything else: a Hash of SHA-256, size, ISO-8601 UTC mtime, and the last four octal
digits of the file mode. The full state map, watched paths, and a generation timestamp are written to
`fim.json` as pretty-printed JSON.

### 2. `check`: re-snapshot and diff

The same `snapshot` function runs again against the paths recorded **in the baseline file itself** (not
whatever you pass on the command line), so `check` can't accidentally scan the wrong tree. Path sets are
compared with plain `Array` difference: `added = current - baseline`, `removed = baseline - current`; the
intersection is checked for hash or mode mismatches.

### 3. Categorizing modifications

Among files present in both snapshots, a change is split into `permission_only` (hash identical, mode
different) versus `content_changed` (everything else), so the report distinguishes "someone chmod'd this"
from "the bytes are different" -- two different classes of incident.

### 4. Pure, testable diff logic

`fingerprint_tree`/`snapshot` and the comparison logic never touch global state -- they're Hash/Array
operations on two snapshots. That makes every branch (additions, removals, content changes, permission-only
changes) fully exercisable in a plain script with no mocking, which is exactly what the example output below
demonstrates.

## Example output

```
$ ruby file_integrity_monitor.rb baseline /etc/nginx /etc/webapp --db fim.json
Building baseline over: /etc/nginx, /etc/webapp
Baseline saved: fim.json (2 file(s))

$ ruby file_integrity_monitor.rb check --db fim.json --exit-code; echo "exit: $?"
Checking /etc/nginx, /etc/webapp against baseline from 2026-08-06T18:55:00Z
RESULT: no changes detected (2 files checked)
exit: 0

# ...a deploy modifies app.conf content, adds a new file, and nginx.conf goes missing...

$ ruby file_integrity_monitor.rb check --db fim.json --exit-code; echo "exit: $?"
Checking /etc/nginx, /etc/webapp against baseline from 2026-08-06T18:55:00Z
RESULT: CHANGES DETECTED

+ ADDED (1):
    /etc/webapp/backdoor.conf

- REMOVED (1):
    /etc/nginx/nginx.conf

~ CONTENT CHANGED (1):
    /etc/webapp/app.conf
        sha256: 04eeaa6d3c... -> 074cd161f9...
        mtime:  2026-08-06T18:55:00Z -> 2026-08-06T18:55:00Z
exit: 1
```

Also verified separately in the sandbox: a pure `chmod` with no content change (644 -> 600 on an otherwise
untouched file) is correctly reported under `PERMISSIONS CHANGED`, not `CONTENT CHANGED`.

## Troubleshooting

- **"baseline file not found" on check** -- run `baseline` first; `check` refuses to run without an existing
  `fim.json` rather than silently treating every file as "added."
- **Everything shows as content-changed right after baselining** -- check your system clock and filesystem
  mount options; comparisons are hash-based, so a real false positive here would indicate the file content
  actually differs, not a clock skew issue.
- **Watched path grew too large to hash quickly** -- `sha256_of` streams in 64KB chunks so memory isn't the
  bottleneck, but scanning millions of files is I/O bound; narrow watched paths to the security-sensitive
  subset rather than baselining an entire filesystem.
- **Unreadable files silently absent from reports** -- by design, files the running user can't stat/read are
  skipped from the snapshot rather than crashing the run; run as a user with read access to everything you
  actually want monitored (root, for most `/etc` use cases).

## Extending this

- **Store baselines centrally** -- write `fim.json` to a read-only network share or object storage bucket per
  host, so a compromised host can't rewrite its own baseline to hide changes.
- **Add ignore patterns** -- extend `snapshot` with a glob/regex exclude list for noisy paths (logs, caches)
  that change legitimately and constantly.
- **Ship findings to SIEM** -- emit structured JSON from `check` instead of/alongside the human-readable
  report, for ingestion by Splunk/ELK/whatever you run.
- **Track ownership (uid/gid), not just mode** -- `File::Stat` exposes `uid`/`gid` too; add them to
  `record_for` if ownership drift matters as much as permission drift in your environment.

## References

- Ruby `Digest::SHA256` stdlib docs: https://docs.ruby-lang.org/en/3.0/Digest/SHA256.html
- Ruby `Find` stdlib docs: https://docs.ruby-lang.org/en/3.0/Find.html
- Ruby `File::Stat` stdlib docs: https://docs.ruby-lang.org/en/3.0/File/Stat.html
- AIDE (Advanced Intrusion Detection Environment): https://aide.github.io/
