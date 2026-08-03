# repo-governance-audit

Audits a list of GitHub repositories for governance hygiene: branch protection on the
default branch, whether force-pushes are still allowed, whether pull request review is
actually required, and whether Dependabot vulnerability alerts are switched on. Built
entirely on Ruby's stdlib `net/http` — no octokit, no bundler.

## Prerequisites

- Ruby 3.x, stdlib only (`net/http`, `uri`, `json`, `optparse`).
- A GitHub personal access token with `repo` scope (classic) or equivalent fine-grained
  permissions, set as `$GITHUB_TOKEN` or passed with `--token`. Reading branch
  protection and vulnerability-alert status both require **admin** rights on each repo —
  without that, the script still runs, it just reports "could not check" for those two
  items.
- Network access to `api.github.com` (or a GitHub Enterprise Server's `/api/v3` via
  `--api-base`).

## Usage

```bash
export GITHUB_TOKEN=ghp_xxx
ruby repo_governance_audit.rb owner/repo1 owner/repo2
ruby repo_governance_audit.rb -f repos.txt --json
ruby repo_governance_audit.rb owner/repo --api-base http://ghe.internal/api/v3
```

Exit codes: `0` no CRIT findings, `1` at least one CRIT finding, `2` usage error.

## How it works

- `GitHubClient#get` centralizes the `Authorization: Bearer` header, the `Accept:
  application/vnd.github+json` header, and secondary-rate-limit handling: on a `403`
  with `X-RateLimit-Remaining: 0`, it sleeps until the reported reset time and retries
  once.
- `audit_repo` makes up to three calls per repo: basic repo info (default branch,
  archived/private flags), the default branch's protection settings, and the
  vulnerability-alerts endpoint (signaled purely by HTTP status — `204` enabled, `404`
  disabled). Archived repos skip the last two calls.
- `classify_repo` is a pure function over the decoded JSON and a couple of status
  integers — never an HTTP response object. Severity depends on visibility: an
  unprotected **public** repo is CRIT, the identical finding on a **private** repo is
  WARN.

## Example output

```
$ ruby repo_governance_audit.rb acme/well-governed acme/no-protection acme/force-push-allowed \
    acme/archived-repo acme/private-no-protection acme/no-admin-token
[ ok ] acme/well-governed
[CRIT] acme/no-protection
        - default branch 'main' has no branch protection (public repo)
        - Dependabot vulnerability alerts are disabled
[CRIT] acme/force-push-allowed
        - force-pushes are allowed on the default branch
        - no required pull request review count set on the default branch
        - branch protection does not apply to repo admins (enforce_admins is off)
        - no required status checks configured on the default branch
[ ok ] acme/archived-repo
        - archived, skipped
[WARN] acme/private-no-protection
        - default branch 'main' has no branch protection (private repo)
[ ok ] acme/no-admin-token
        - could not check branch protection (token lacks admin rights on this repo)
        - could not check vulnerability-alert status (token lacks admin rights)
---
6 repos audited, 2 CRIT, 1 WARN
```

## Testing notes

Direct network access to `api.github.com` was not available in the environment used to
build this script, so it was instead verified against a local WEBrick stub implementing
the same three endpoints (repo info, branch protection, vulnerability-alerts), with
fixtures for a well-governed repo, an unprotected public repo, a force-push-enabled
repo, an archived repo, a private unprotected repo, and a no-admin-token repo. This
exercised the real HTTP/JSON handling, `classify_repo`, and exit codes end to end — only
the hostname changed from the real API.

## Troubleshooting

- **Every repo reports "could not check branch protection"** — the token doesn't have
  admin rights on those repos; both branch protection and vulnerability-alert status
  are admin-only reads.
- **Rate limited on a large repo list** — always pass a token, even for public repos;
  the unauthenticated limit (60/hour) is exhausted after ~20 repos at 3 calls each.
- **404 on the very first call** — check the `owner/repo` spelling; this is reported as
  an "audit failed" CRIT finding for that repo rather than crashing the whole run.

## Extending it

- Page through `GET /orgs/:org/repos` for an org-wide sweep instead of a static list.
- Add secret-scanning / code-scanning status alongside vulnerability alerts.
- Add a `--fix` flag to `PUT` a minimum branch-protection policy onto failing repos.
- Store each run's JSON output and diff against the previous run to flag newly
  non-compliant repos.

## References

- [GitHub REST API: branch protection](https://docs.github.com/en/rest/branches/branch-protection)
- [GitHub REST API: repository vulnerability alerts](https://docs.github.com/en/rest/repos/repos#check-if-vulnerability-alerts-are-enabled-for-a-repository)
- [Ruby stdlib: Net::HTTP](https://docs.ruby-lang.org/en/3.0/Net/HTTP.html)
