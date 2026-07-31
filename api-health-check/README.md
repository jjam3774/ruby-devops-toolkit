# api-health-check

Concurrently polls a list of HTTP(S) endpoints, checks status code / latency /
an optional response-body pattern, retries failures with exponential backoff,
and reports pass/degraded/down per endpoint. Built entirely on Ruby's stdlib
(`Net::HTTP` + `Thread` + `Queue`) — no gems required.

## Prerequisites

- Ruby >= 2.7 (tested on 3.0.2; uses `net/http`, `uri`, `json`, `optparse`,
  `timeout`, `time` from the standard library)
- Network access from the box running the script to whatever endpoints you're
  checking

## Usage

```bash
# Quick one-off check of a single URL (expects HTTP 200)
ruby api_health_check.rb --url https://example.com/healthz

# Check a whole fleet from a config file
ruby api_health_check.rb --config endpoints.json

# Tune retries, backoff, and concurrency
ruby api_health_check.rb --config endpoints.json --retries 3 --backoff 1.0 --concurrency 16

# Machine-readable output for a monitoring pipeline
ruby api_health_check.rb --config endpoints.json --json
```

`endpoints.json` format:

```json
[
  { "name": "web-app",  "url": "https://example.com/healthz", "expect_status": 200 },
  { "name": "internal", "url": "http://10.0.0.5:9000/status", "expect_status": 200,
    "expect_body": "\"ok\":\\s*true", "timeout": 3 }
]
```

`expect_status` defaults to `200`, `timeout` defaults to `5` seconds,
`expect_body` is an optional regex checked against the response body.

Exit codes: `0` all healthy, `1` at least one endpoint only passed after a
retry (degraded), `2` at least one endpoint failed every retry (down). Drops
straight into cron, CI, or a Nagios-style check.

## How it works

- Endpoints load either from `--config endpoints.json` or a single `--url`
  passed directly for a quick manual check.
- `run_checks` builds a bounded worker pool: a `Queue` holds every endpoint to
  check, and `min(--concurrency, endpoint count)` threads pop work off it
  until it's empty. This means a config with 200 endpoints doesn't open 200
  sockets simultaneously — only as many as `--concurrency` allows.
- Each `EndpointChecker#call` performs the request, and on any failure
  (wrong status, body mismatch, timeout, connection error) sleeps
  `backoff_base * 2**attempt` seconds before retrying, up to `--retries`
  times, before giving up and recording the endpoint as down.
- A thread-safe `results` `Queue` collects `CheckResult` structs from every
  worker, which are drained into an array once all workers `join`.
- `attempts > 1` on an otherwise-successful result is reported as **degraded**
  (exit 1) rather than fully healthy — it succeeded, but not on the first
  try, which is worth knowing even though it isn't a hard failure.

## Example output

Captured against a local WEBrick mock server exposing `/healthy` (always
200), `/flaky` (fails twice then succeeds), `/down` (always 500), and
`/badbody` (200 but with an unexpected response body):

```
api_health_check: 4 endpoint(s) checked
------------------------------------------------------------------------
[OK  ] web-healthy          status=200 latency=9.0ms attempts=1
[DOWN] bad-content          error=expected status 200 and body matching /"ok":\s*true/, got status 200 attempts=3
[DOWN] svc-down             error=expected status 200, got status 500 attempts=3
[OK  ] api-flaky            status=200 latency=1.4ms attempts=3
```

Note the order is nondeterministic — results come back in whatever order the
worker threads finish, not the order endpoints were listed. If you need a
stable order for a report, sort `results` by `name` before printing.

## Troubleshooting

- **All checks report DOWN immediately with a connection error** — check that
  the box running the script actually has network access to the target
  (firewall, VPN, security group). The error message includes the exception
  class and message (e.g. `Errno::ECONNREFUSED`), which is usually enough to
  diagnose.
- **Everything is "degraded" (attempts > 1) even though the service looks
  fine** — a common cause is a load balancer or reverse proxy briefly
  returning 503s during a deploy; the retry/backoff is doing exactly what
  it's supposed to. Check `--retries`/`--backoff` are tuned for your
  environment's normal blip duration.
- **HTTPS endpoints time out or fail TLS verification** — `Net::HTTP` uses
  the system's default OpenSSL trust store; if you're hitting an internal CA,
  you'll need to extend the script to call `http.ca_file =`/`http.cert_store =`
  before `http.request`.
- **High concurrency doesn't seem to speed things up** — Ruby's default
  interpreter (MRI) has a Global Interpreter Lock, but `Net::HTTP` requests
  release it during I/O wait, so threads are still effective for this
  I/O-bound workload. If you truly need more parallelism than threads give
  you, consider `Process.fork` per batch instead.

## Extending it

- Add a `webhook_url` field per endpoint and `Net::HTTP.post` a Slack/Teams
  message when a result flips from healthy to down (a simple state file on
  disk between runs lets you detect the transition and alert only once).
- Support `POST`/custom headers/auth by extending the config schema and
  `EndpointChecker#perform_request`.
- Add a `--interval N` daemon mode that loops forever, useful for a sidecar
  container instead of a cron-triggered run.
- Export results as Prometheus metrics — see `prometheus-exporter/` elsewhere
  in this repo for a pure-Ruby `/metrics` HTTP server you could feed from
  this script's `results` array.

## References

- [Ruby `Net::HTTP`](https://docs.ruby-lang.org/en/3.0/Net/HTTP.html)
- [Ruby `Queue` (Thread-safe queue)](https://docs.ruby-lang.org/en/3.0/Thread/Queue.html)
- [Ruby `OptionParser`](https://docs.ruby-lang.org/en/3.0/OptionParser.html)
