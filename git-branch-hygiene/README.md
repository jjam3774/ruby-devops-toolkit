# git_branch_hygiene.rb

Audit and prune stale/merged local git branches across a fleet of repos. Full write-up: [Ruby for DevOps: Automated Git Branch Hygiene with git_branch_hygiene.rb](https://tha-shed.com/ruby-for-devops-automated-git-branch-hygiene-with-git_branch_hygiene-rb/)

## The problem it solves

After a year or two of active development, `git branch` on a shared build box or a developer's machine turns into a wall of forgotten feature branches. Most are already merged and just haven't been deleted; a few are genuinely abandoned; a few might still matter. Nobody wants to `git branch -D` their way through 200 branches by hand, and doing it wrong (deleting something unmerged) is exactly the kind of mistake that erodes trust in automation.

`git_branch_hygiene.rb` scans one or many repos, classifies every local branch as `MERGED` / `STALE` / `ACTIVE` / `PROTECTED` relative to a default branch, and only ever deletes a branch two ways: safely (git's own merge check, via `branch -d`) or with an explicit, separately-flagged, force confirmation for stale-but-unmerged branches.

## Prerequisites

- Ruby >= 2.7
- `git` available on `PATH`
- stdlib only — no gems required (`open3`, `optparse`, `json`, `time`, `File.fnmatch`)

## Usage

```
# Report only (safe, default) -- one repo
ruby git_branch_hygiene.rb --repo /srv/myapp

# Report only -- every git repo one level under a directory
ruby git_branch_hygiene.rb --repos-dir /srv/repos

# Actually delete branches already merged into the default branch
ruby git_branch_hygiene.rb --repo /srv/myapp --delete-merged

# Force-delete branches with no activity in 180+ days, even if unmerged
# (requires the explicit --confirm-force flag as a safety rail)
ruby git_branch_hygiene.rb --repo /srv/myapp --delete-stale --stale-days 180 --confirm-force

ruby git_branch_hygiene.rb --repos-dir /srv/repos --json
```

### CLI options

| Flag | Description |
| --- | --- |
| `--repo PATH` | Path to a single git repo |
| `--repos-dir DIR` | Directory containing multiple git repos (one level deep) |
| `--stale-days N` | Days of inactivity before an unmerged branch is "stale" (default 90) |
| `--protect LIST` | Comma-separated glob patterns never touched (default: `main,master,develop,HEAD`) |
| `--delete-merged` | Safely delete branches already merged into the default branch |
| `--delete-stale` | Force-delete unmerged branches past `--stale-days` (needs `--confirm-force` too) |
| `--confirm-force` | Required alongside `--delete-stale` to actually run the destructive force-delete |
| `--json` | Emit machine-readable JSON |
| `-h`, `--help` | Show help |

## How it works

- Determines the default branch by reading `origin/HEAD`, falling back to `main`, then `master`.
- Classifies each local branch by cross-referencing `git branch --merged <default>` against the branch's last commit age and the protected-pattern list (matched via `File.fnmatch`, so patterns like `release/*` work).
- Two independent deletion paths, both opt-in: `--delete-merged` calls `git branch -d`, which git itself refuses on anything not fully merged — a built-in safety net even if this script's own bookkeeping is wrong. `--delete-stale` calls `git branch -D` (force), which can discard unmerged commits, so it additionally requires `--confirm-force` as a second, independent rail.
- Every branch tracks its own `action` (`deleted` / `failed` / `skipped_needs_confirm_force` / `none`) so the report always shows exactly what happened, or would happen.

## Example output

```
== /srv/myapp ==
  default branch: main
  MERGED   old-feature-x                        age=12d    merged=true
  STALE    abandoned-spike                       age=214d   merged=false
  ACTIVE   payments-refactor                      age=3d     merged=false
  PROTECTED main                                  age=0d     merged=true

Summary: 1 merged, 1 stale, 0 deleted across 1 repo(s).
```

## Testing

The git command runner is injected (`runner:` in `GitBranchHygiene.new`), so `git_branch_hygiene_test.rb` exercises the full classification and deletion logic against real throwaway sandbox repos created with actual `git` commands in a temp directory — no mocking of git internals required.

## Troubleshooting

- **"not a git repository" for every repo** — check that `--repo`/`--repos-dir` point at the actual repo root (containing `.git`), not a subdirectory.
- **Nothing gets classified as merged** — the default-branch detection relies on `origin/HEAD`; if the repo has no configured remote, run `git remote set-head origin -a` first, or the script will fall back to `main`/`master` by name.
- **`--delete-stale` does nothing** — this is by design without `--confirm-force`; branches show up with `action: skipped_needs_confirm_force` until both flags are passed together.
- **A branch you expected to be protected got flagged as stale** — check it against your `--protect` glob patterns; the default list is only `main,master,develop,HEAD`.

## Extending

- Add a `--dry-run-verbose` mode that prints the exact `git branch -d/-D` commands that would run.
- Support remote-tracking branch cleanup (`git remote prune`) alongside local branches.
- Emit per-repo summaries suitable for a Slack digest when run across `--repos-dir` on a schedule.

## References

- [git-branch documentation](https://git-scm.com/docs/git-branch)
- [Ruby Open3 documentation](https://docs.ruby-lang.org/en/master/Open3.html)
- [Full tutorial on tha-shed.com](https://tha-shed.com/ruby-for-devops-automated-git-branch-hygiene-with-git_branch_hygiene-rb/)
