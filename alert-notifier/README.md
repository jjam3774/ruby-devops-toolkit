# alert_notifier.rb

De-duplicated, rate-limited, retried webhook alerting for cron jobs and monitoring
scripts. Sends to Slack (as a rich attachment) or any generic JSON webhook, with
per-key cooldowns so a flapping check doesn't spam the channel every five minutes.

Full write-up: [Ruby for DevOps: De-Duplicated, Rate-Limited Webhook Alerting with
alert_notifier.rb](https://tha-shed.com/ruby-for-devops-de-duplicated-rate-limited-webhook-alerting-with-alert_notifier-rb/)

## The problem it solves

Most little Ruby check scripts sysadmins write (disk space, service health, cert
expiry, log error spikes...) know perfectly well *when* something is wrong. What
they're usually missing is a reliable, reusable way to tell a human -- one that
doesn't spam Slack every five minutes for the same still-broken thing, and doesn't
silently drop the message the one time the webhook endpoint has a blip.

`alert_notifier.rb` is a small, dependency-free (stdlib-only) Ruby library and CLI
that handles both problems: it tracks per-key cooldown state on disk so repeat
alerts are suppressed until the cooldown expires, and it retries transient HTTP
failures (5xx responses, connection errors) with exponential backoff.

## Prerequisites

- Ruby >= 2.7
- Standard library only: `net/http`, `uri`, `json`, `fileutils`, `optparse` -- no
  gems required
- A Slack incoming webhook URL, or any endpoint that accepts a JSON POST

## Usage

### As a CLI

```bash
ruby alert_notifier.rb --webhook "$SLACK_WEBHOOK_URL" \
  --key disk-root --severity crit --title "Disk / 96% full" \
  --text "Only 1.2G free on / (threshold 90%)" --cooldown 1800
```

Clear cooldown state for a key (or all keys):

```bash
ruby alert_notifier.rb --clear --key disk-root
ruby alert_notifier.rb --clear
```

Full CLI options:

| Flag | Description |
| --- | --- |
| `--webhook URL` | Webhook URL (Slack or generic JSON) |
| `--key KEY` | De-duplication key for this alert |
| `--severity info\|warn\|crit` | Alert severity (controls color for Slack) |
| `--title TEXT` | Alert title |
| `--text TEXT` | Alert body (optional) |
| `--cooldown SECONDS` | Override the default cooldown (900s) for this alert |
| `--state-file PATH` | Where to persist cooldown state (default: `./.alert_notifier_state.json`) |
| `--generic` | Send a plain JSON payload instead of a Slack attachment |
| `--clear` | Clear cooldown state for `--key`, or all keys if `--key` omitted |
| `--dry-run` | Build and log the payload without sending it |

### As a library

```ruby
require_relative "alert_notifier"

notifier = AlertNotifier.new(webhook_url: ENV["SLACK_WEBHOOK_URL"])
notifier.alert(key: "disk-root", severity: :crit,
                title: "Disk / is 96% full", text: "...")
```

`#alert` returns `:sent`, `:suppressed` (within cooldown), or `:dry_run`.

## How it works

- **De-duplication / cooldown**: each call to `#alert` is keyed by the `key:`
  argument. State (last-sent timestamp per key) is persisted to a JSON file via an
  atomic write (temp file + `File.rename`) so concurrent cron runs don't corrupt it.
  If a key was already alerted within its cooldown window, the call returns
  `:suppressed` and nothing is sent.
- **Retry with backoff**: only failures explicitly tagged as retryable (currently,
  any `Net::HTTPServerError` -- a 5xx response -- or a connection-level error) are
  retried, up to `max_retries` times, with delay `0.5 * (2 ** (attempt - 1))`
  seconds between attempts. A 4xx response is treated as non-retryable and raises
  immediately, since retrying a bad request won't fix it.
- **Payload styles**: `:slack` (the default) builds a colored attachment using
  `SEVERITY_COLOR`; `:generic` builds a plain `{severity:, title:, text:, fields:}`
  JSON body for any other webhook consumer.

## Example output

```
$ ruby test_alert_notifier.rb
[1/9] basic send ................................. PASS
[2/9] cooldown suppression ....................... PASS
[3/9] cooldown expiry ............................ PASS
[4/9] clear() resets cooldown .................... PASS
[5/9] independent keys don't interfere ........... PASS
[6/9] retries then succeeds on 503 ............... PASS
[7/9] fails fast on 400 (non-retryable) .......... PASS
[8/9] dry_run doesn't hit the network ............ PASS
[9/9] generic payload style ...................... PASS

9/9 tests passed
```

## Testing

`test_alert_notifier.rb` spins up a real `WEBrick` server as a stub webhook
endpoint and exercises the notifier against it end-to-end -- no HTTP mocking
library involved. It covers: a basic send, cooldown suppression and expiry,
`#clear`, cross-key independence, retry-then-succeed on a 503, fail-fast on a 400,
`dry_run`, and the generic (non-Slack) payload style. Run it with:

```bash
ruby test_alert_notifier.rb
```

## Troubleshooting

- **Alerts aren't sending at all** -- check the state file (default
  `./.alert_notifier_state.json`); if a key's `last_sent` is recent, you're inside
  its cooldown window. Use `--clear` to reset it, or pass a shorter `--cooldown`.
- **`DeliveryError` after retries are exhausted** -- the webhook endpoint returned
  5xx for every attempt, or the connection failed repeatedly. Check the endpoint is
  reachable from the host running the script and that the URL is correct.
- **A 4xx error raises immediately with no retry** -- this is intentional. A 4xx
  (e.g. an invalid Slack webhook URL, or a malformed payload) won't be fixed by
  retrying; fix the request instead.
- **State file corruption under concurrent runs** -- writes use an atomic
  temp-file-then-rename pattern specifically to avoid this, but if you're running
  many parallel cron jobs against the *same* state file on a networked filesystem
  without atomic rename guarantees, consider giving each check its own state file.

## Extending

- Add a payload style for another chat platform (Discord, Microsoft Teams) by
  adding a case to `build_payload` and a matching `SEVERITY_COLOR`-style mapping.
- Add jitter to the backoff delay if you're calling this from many hosts at once
  against the same webhook, to avoid a thundering herd on retry.
- Swap the JSON state file for a small SQLite database if you need cooldown state
  shared safely across many concurrent processes on the same host.

## References

- [Slack incoming webhooks](https://api.slack.com/messaging/webhooks)
- [Ruby `Net::HTTP` documentation](https://ruby-doc.org/stdlib/libdoc/net/http/rdoc/Net/HTTP.html)
- Full tutorial: [tha-shed.com](https://tha-shed.com/ruby-for-devops-de-duplicated-rate-limited-webhook-alerting-with-alert_notifier-rb/)
