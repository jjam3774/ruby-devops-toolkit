# config_state_engine.rb

A minimal, Chef/Puppet/Ansible-style *idempotent* configuration engine in ~180 lines of pure Ruby: declare the state you want ("this directory should exist", "this file should have this exact content and mode", "this line should be present in this file"), and the engine only touches the filesystem when reality doesn't already match. Running it twice in a row produces zero changes the second time — that's the whole point.

## Why this exists

Pulling in Chef, Puppet, or Ansible for a handful of config-file guarantees on a small fleet is a lot of machinery (agents, a server, a DSL with its own runtime) for something you can express in a few declarative lines. This script shows the *pattern* underneath all of them — check current state, diff against desired state, apply only the delta, report what changed — in a form small enough to read end-to-end and adapt directly.

## Prerequisites

- Ruby >= 2.7 (stdlib only: `fileutils`, `optparse` — no gems required)
- Write access to whatever directory the manifest targets
- Linux or macOS for the exact commands below (the resource classes themselves are pure Ruby file I/O and work on Windows too)

## Usage

```
ruby config_state_engine.rb --target-dir /etc/myapp
ruby config_state_engine.rb --target-dir /etc/myapp --dry-run
ruby config_state_engine.rb --target-dir /etc/myapp --check   # CI-style: exit 1 on drift, no changes made
```

## How it works

1. **`Resource`** — abstract base defining the `#check` / `#apply` contract every resource type implements.
2. **`DirectoryResource` / `FileResource` / `LineInFileResource`** — the three concrete resource types: ensure a directory exists (optionally with a mode), ensure a file has exact content (and mode), and ensure one specific line is present in a file without touching any other line.
3. **`ConfigState.run`** — the DSL entry point; yields an engine instance so a manifest can call `ensure_file`/`ensure_directory`/`ensure_line_in_file`, then runs every declared resource in order.
4. **Three run modes** — a real run applies fixes and prints `CHANGED`; `--dry-run` reports `WOULD CHANGE` without touching anything; `--check` reports `DRIFT` and exits 1 if anything is out of sync, for wiring into CI or a monitoring check.

**Design note:** a single managed file should be owned by exactly one resource. Using both `ensure_file` (exact-content) and `ensure_line_in_file` (append-if-missing) on the *same* file makes them fight over the same bytes and the run never settles — see Troubleshooting.

## Example output

```
$ ruby config_state_engine.rb --target-dir /tmp/cs-sample
CHANGED     directory /tmp/cs-sample (does not exist)
CHANGED     directory /tmp/cs-sample/conf.d (does not exist)
CHANGED     file /tmp/cs-sample/app.yml (does not exist)
CHANGED     line in /tmp/cs-sample/hosts.local: "127.0.0.1 myapp.local" (file does not exist)
---
ok=0 changed=4 would_change=0 drift=0

$ ruby config_state_engine.rb --target-dir /tmp/cs-sample   # run again: fully idempotent
OK          directory /tmp/cs-sample
OK          directory /tmp/cs-sample/conf.d
OK          file /tmp/cs-sample/app.yml
OK          line in /tmp/cs-sample/hosts.local: "127.0.0.1 myapp.local"
---
ok=4 changed=0 would_change=0 drift=0
```

## How this was tested

Ran the demo manifest against a scratch directory six times in a row, covering every code path: a fresh run correctly reported `CHANGED` for all 4 resources; an immediate second run reported all 4 as `OK` with zero changes (true idempotency); after hand-editing a managed file, `--dry-run` correctly reported `WOULD CHANGE` and left the file untouched; `--check` correctly reported `DRIFT` and exited with status 1; a real run then fixed the drift; and a final run confirmed the fix was idempotent too.

## Troubleshooting

- **A resource shows CHANGED on every single run, never settling to OK** — almost always means two resources are managing the same file with incompatible strategies (e.g. an exact-content `ensure_file` and an append-only `ensure_line_in_file` on the same path). Give each managed file exactly one owning resource.
- **Permission denied on apply** — the process needs write access to the target path; on a real box this often means running with appropriate privileges for the directories being managed (e.g. `/etc`).
- **`--check` always exits 0 even with drift** — double check the flag is actually being read; some shells/wrappers swallow flags passed after a script name depending on how they invoke Ruby.

## Extending this script

- Add a `SymlinkResource` (ensure a symlink points at a specific target — handy alongside release-directory deploy patterns).
- Add a `PackageResource` that shells out to `dpkg -l`/`rpm -q` to check (and optionally install) a package idempotently.
- Load the manifest from an external `.rb` file via `load` so different hosts/roles can share the engine but declare different desired state.
- Add a machine-readable `--json` output mode for feeding run results into a compliance dashboard.

## References

- [Ruby FileUtils docs](https://docs.ruby-lang.org/en/3.0/FileUtils.html)
- [Idempotence (Wikipedia)](https://en.wikipedia.org/wiki/Idempotence)
