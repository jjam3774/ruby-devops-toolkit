# deploy-webhook-orchestrator

Drives a REST-based deployment API end to end from Ruby: triggers a deploy,
polls its status until it finishes (or times out), retries transient network
failures with exponential backoff, and automatically calls a rollback
endpoint when the deploy fails or stalls. Zero gems — `net/http`, `json`,
`uri`, and `optparse` are all standard library.

This is the shape of almost every "deploy button" API a CI system calls:
POST to kick off work, get back an id, poll a status endpoint until it's
done. Wiring that up as a `curl` loop in a shell script works until you need
retry logic, backoff, and a rollback branch — at which point it's much
easier to read (and test) as a few small Ruby classes.

## Prerequisites

- Ruby >= 3.0 (developed and tested on 3.3.6)
- No gems required
- Linux, macOS, or Windows — it's plain `net/http`, no OS-specific calls
- A deploy API that accepts a `POST` to trigger a deploy and returns
  `{"id": "..."}` (or `{"deploy_id": "..."}`), exposes a `GET` status
  endpoint returning `{"status": "running|success|failed"}`, and a `POST`
  rollback endpoint

## Usage

```bash
ruby deploy_webhook_orchestrator.rb \
  --base-url https://deploys.internal.example.com \
  --payload '{"service":"billing-api","version":"1.4.2"}' \
  --poll-interval 3 \
  --timeout 300
```

Options:

| Flag | Default | Meaning |
|---|---|---|
| `--base-url URL` | *(required)* | Base URL of the deploy API |
| `--deploy-path PATH` | `/deploy` | Path to `POST` to trigger a deploy |
| `--status-path-template TPL` | `/status/%<id>s` | `printf`-style path for polling status |
| `--rollback-path-template TPL` | `/rollback/%<id>s` | `printf`-style path for rollback |
| `--payload JSON` | `{}` | JSON body sent with the deploy trigger |
| `--poll-interval SECONDS` | `3` | Seconds between status polls |
| `--timeout SECONDS` | `300` | Give up (and roll back) after this long |
| `--max-retries N` | `4` | Retries per HTTP call on transient network errors |

Exit codes: `0` success, `1` failed+rolled back, `2` timeout+rolled back,
`3` failed and rollback itself also failed, `4` usage error, `5`
orchestration error (e.g. the trigger request never got through).

## How it works

Three small, single-purpose classes:

- **`RetryingHttpClient`** — every HTTP call in the script goes through this
  one class. It retries `Errno::ECONNREFUSED`, `Errno::ECONNRESET`,
  `Errno::ETIMEDOUT`, `Net::OpenTimeout`, `Net::ReadTimeout`, and `EOFError`
  (a connection dropped mid-response) with exponential backoff
  (`base_backoff * 2**(attempt-1)`). A non-2xx HTTP response raises
  `RequestFailed` immediately — that's not transient, retrying it won't help.
- **`DeployOrchestrator`** — the actual state machine: `trigger` → loop
  `poll_until_terminal` → branch to success or `attempt_rollback`. The
  clock and sleeper are constructor arguments (`clock:`, `sleeper:`) so
  tests never have to actually wait out a real timeout.
- The **CLI block** at the bottom just wires `OptionParser` output into the
  two classes above and maps the `Result` struct's `outcome` to an exit code.

One thing worth knowing if you build on this: Ruby's `net/http` silently
retries a `GET` once on its own if the connection resets before any bytes
come back — it does **not** do this for `POST`, since POST isn't assumed
idempotent. That's why `deploy_webhook_orchestrator_test.rb`'s transient-retry
scenario drops the connection on the deploy-triggering `POST`, not a status
`GET` — dropping the GET would have been silently absorbed by net/http
itself before ever reaching `RetryingHttpClient`'s own retry logic, and the
test wouldn't have proven anything about *this* script's behavior.

## Example output

Successful deploy:

```
$ ruby deploy_webhook_orchestrator.rb --base-url http://127.0.0.1:36035 \
    --payload '{"service":"billing-api","version":"1.4.2"}' --poll-interval 1 --timeout 30
Triggering deploy: {"service"=>"billing-api", "version"=>"1.4.2"}
Deploy accepted, id=dep-4821
Status for dep-4821: running
Status for dep-4821: running
Status for dep-4821: success
DEPLOY SUCCESS  id=dep-4821
exit status: 0
```

Failed deploy, automatic rollback:

```
$ ruby deploy_webhook_orchestrator.rb --base-url http://127.0.0.1:45113 \
    --payload '{"service":"billing-api","version":"1.5.0-rc1"}' --poll-interval 1 --timeout 30
Triggering deploy: {"service"=>"billing-api", "version"=>"1.5.0-rc1"}
Deploy accepted, id=dep-4821
Status for dep-4821: running
Status for dep-4821: failed
Rolling back dep-4821...
Rollback request for dep-4821 accepted
DEPLOY FAILED   id=dep-4821 rolled_back=true
exit status: 1
```

## Testing

`deploy_webhook_orchestrator_test.rb` runs against a small hand-rolled HTTP
stub server built directly on `TCPServer` (no `webrick`, no gems — this
keeps the whole repo installable with a stock Ruby and nothing else) and
covers three scenarios: a normal success, a failure that triggers a
successful rollback, and a dropped connection on the trigger request that
the retry logic recovers from transparently. All three were run live in a
Linux sandbox:

```bash
ruby deploy_webhook_orchestrator_test.rb
```

## Troubleshooting

- **`ORCHESTRATION ERROR: POST /deploy failed after N attempts`** — the
  deploy API never became reachable within `--max-retries`. Check
  `--base-url` and that the service is actually listening; this script
  can't distinguish "DNS is broken" from "service is down" any better than
  `curl` can.
- **Deploy times out even though it eventually succeeds** — raise
  `--timeout`, or lower `--poll-interval` if you want a faster true
  signal without changing the deadline.
- **Rollback also fails (`exit 3`)** — the script does not retry the
  rollback call itself beyond the client's normal retry budget; a `3` means
  you have a deploy in a bad state *and* an API that won't take the
  rollback. Treat this as a page, not a log line.
- **A JSON `--payload` with real quoting gets mangled by your shell** — put
  it in a file and use `--payload "$(cat payload.json)"`, or switch to a
  heredoc; this is a shell-quoting problem, not a script bug.

## Extending

- Add a `--config FILE` (YAML) so `--payload`, path templates, and
  timeouts don't all have to live on one command line — useful once you're
  calling this from a dozen different CI jobs, each deploying a different
  service.
- Support bearer-token or HMAC-signed auth headers — most real deploy APIs
  want one of these, and the `RetryingHttpClient#perform` method is the one
  place to add it.
- Add a `--webhook-notify URL` that posts the final `Result` to Slack/Teams
  so the rollback branch actually pages someone instead of just exiting 1
  in a CI log nobody reads until the next morning.
- Stream partial status/log output from the deploy API (if it offers one)
  instead of only polling a single `status` field, for long-running deploys
  where "running" for ten minutes straight is not reassuring on its own.

## References

- [Ruby `net/http` docs](https://docs.ruby-lang.org/en/3.3/Net/HTTP.html)
- [Ruby `Net::HTTP` — Automatic retry on idempotent requests](https://github.com/ruby/net-http)
- [GitHub: ruby-devops-toolkit/deploy-webhook-orchestrator](https://github.com/jjam3774/ruby-devops-toolkit/tree/main/deploy-webhook-orchestrator)
