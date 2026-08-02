# dns-resolver-checker

Queries one or more DNS record types for a domain against a *fleet* of
resolvers concurrently, then flags disagreement between resolvers
(propagation lag, split-brain internal-vs-external DNS), records that
fail to resolve, and records that don't match an expected value.

No gems required: `resolv`, `socket`, `optparse`, `json`, `timeout`, and
`Queue`/`Thread` are all in the Ruby standard library.

## Why

DNS problems are sneaky because "DNS is fine" almost always means "DNS
is fine *from the one resolver I happened to check*." A record that
just changed can be correct on your laptop's resolver and stale on a
customer's ISP resolver for minutes to hours. An internal split-horizon
resolver can silently diverge from the public record and nobody
notices until someone off the VPN can't reach a service. Checking a
handful of independent public resolvers side by side turns that
invisible class of bug into a one-line alert.

## Prerequisites

- Ruby >= 2.7 (tested on 3.0.2)
- Outbound UDP/53 access to whichever resolvers you point it at for
  live use (public resolvers like `8.8.8.8`, `1.1.1.1`, `9.9.9.9` are
  the defaults)
- No gems -- stdlib only

## Usage

```bash
# Default: check the A record against Google/Cloudflare/Quad9
ruby dns_resolver_checker.rb example.com

# Multiple record types, custom resolver list
ruby dns_resolver_checker.rb example.com --types A,MX,TXT --resolvers 8.8.8.8,1.1.1.1,9.9.9.9

# Assert a specific value -- CRIT if no resolver returns it
ruby dns_resolver_checker.rb example.com --types A --expect 93.184.216.34

# Machine-readable output for a monitoring pipeline
ruby dns_resolver_checker.rb example.com --json

# Point at non-standard ports (this is also how the test suite drives
# it against loopback mock resolvers -- see Testing notes)
ruby dns_resolver_checker.rb internal.example.com --resolvers 10.0.0.53:5353
```

Exit codes (cron/monitoring friendly):

| Code | Meaning |
|------|---------|
| 0 | every record type resolved consistently everywhere (and matched `--expect`, if given) |
| 1 | WARN -- resolvers disagree with each other, or some (not all) resolvers failed to answer |
| 2 | CRIT -- a record failed to resolve on every resolver, or didn't match `--expect` anywhere |

## How it works

1. **Jobs, not nested loops.** `run_checks` builds the full cross
   product of `types x resolvers` up front (`types.product(resolvers)`)
   and loads every pair into a `Queue`, then spins up
   `min(concurrency, jobs.size)` worker threads that each `pop` until
   the queue is empty. This is the same bounded-concurrency shape this
   toolkit uses for other network checkers -- it caps how many sockets
   are open at once regardless of how many record types or resolvers
   you pass.
2. **`fetch_record(resolver, type, domain, timeout)`** parses
   `host[:port]` (defaulting to port 53), builds a fresh
   `Resolv::DNS.new(nameserver_port: [[host, port]])` -- pointing
   `Resolv::DNS` at one specific resolver instead of the system default
   -- and calls `getresources`, wrapped in `Timeout.timeout` and a
   blanket `rescue StandardError`. Every record type's payload lives
   under a different accessor on the returned resource object
   (`.address` for A/AAAA, `.name` for CNAME/NS, `.exchange` for MX,
   `.strings` for TXT); `resource_value` normalizes all of them to a
   plain string.
3. **`evaluate_type(type, resolver_results, expect)`** is a pure
   function -- no sockets, no `Resolv` calls -- that takes the
   `{resolver => {status:, values:/error:}}` hash for one record type
   and classifies it: every resolver erroring is CRIT; an `--expect`ed
   value missing from every resolver's answer is CRIT; resolvers
   returning different answer sets is WARN (propagation drift); some
   (not all) resolvers erroring is WARN; otherwise OK. Because it's
   pure, the test suite exercises every branch with hand-built hashes
   with zero network involved.
4. **The `__FILE__ == $PROGRAM_NAME` guard** wraps CLI parsing and the
   live run so `dns_resolver_checker_test.rb` can
   `require_relative` the file and call `run_checks`/`evaluate_type`
   directly without triggering `ARGV` parsing or `exit`.

## Example output

```
$ ruby dns_resolver_checker.rb app.example. --types A,TXT --resolvers <3 resolvers, one stale>
[WARN] app.example. A
        A: resolvers disagree (resolver-1=203.0.113.10, resolver-2=203.0.113.10, resolver-3=203.0.113.9)
[OK  ] app.example. TXT
        TXT: consistent across 3 resolver(s)

2 record type(s) checked across 3 resolver(s), 0 CRIT, 1 WARN
```

## Troubleshooting

- **A resolver that's completely unreachable comes back as "OK, empty"
  instead of an error.** This is a real, verified quirk of Ruby's
  `Resolv::DNS`, not a bug in this script: when a configured nameserver
  refuses the connection (nothing listening on that UDP port),
  `Resolv::DNS#getresources` swallows it internally and simply returns
  no records, rather than raising. `fetch_record`'s `rescue` clause
  still catches genuine failures like a real `Timeout::Error` against a
  black-holed address, but "port closed" specifically does not surface
  as `status: 'error'`. **Practical takeaway: pair checks against
  resolvers you're not 100% sure are alive with `--expect`,** since an
  unreachable resolver returning nothing will otherwise look identical
  to a resolver correctly reporting "no such record."
- **Everything reports WARN and never settles** -- you're probably
  checking a record type that's mid-propagation (TTL just expired
  after a change) or checking a resolver that caches far longer than
  others. Re-run after the old TTL has fully expired everywhere before
  treating it as a real incident.
- **`Resolv::ResolvError` / garbled responses** -- usually means you're
  pointed at something on that port that isn't actually a DNS server
  (or a DNS server matching the wrong version of the wire protocol,
  e.g. a DNS-over-HTTPS-only endpoint on port 53). Verify with `dig
  @resolver domain type` from a real client library outside Ruby.
- **MX/TXT values look truncated or oddly formatted** -- `resource_value`
  reports the raw preference+exchange pair for MX and the concatenated
  string segments for TXT; very long TXT records (SPF includes, DKIM
  keys) are split across multiple `<character-string>` segments on the
  wire and `.strings.join` reassembles them, which is correct but can
  look surprising if you were expecting quoted segments.

## Testing notes

Two layers, mirroring this toolkit's existing pattern for network
scripts (see `ntp-drift`'s loopback mock SNTP server): `evaluate_type`
was unit-tested directly with hand-built resolver-result hashes
covering agreement/disagreement/all-errored/partial-errored/expect-match/expect-mismatch
(6 checks). Then `fetch_record` and `run_checks` -- the parts that
actually open UDP sockets and speak DNS wire protocol -- were tested
end-to-end against real loopback mock DNS servers built with
`Resolv::DNS::Message` (the same class Ruby's own `Resolv::DNS` uses to
decode/encode packets), covering two resolvers agreeing, two resolvers
disagreeing (drift), a real value present with a mismatched `--expect`,
and the "unreachable resolver returns empty, not an error" behavior
documented above (7 more checks, 13 total, all passing --
`dns_resolver_checker_test.rb`). The CLI itself was also run directly
against three loopback mock resolvers in both text and `--json` mode
(see Example output), including a working `--expect` match. This
sandbox has no route to the public internet, so the default resolvers
(`8.8.8.8`/`1.1.1.1`/`9.9.9.9`) specifically weren't reachable during
testing -- the DNS wire-protocol code is identical regardless of
whether the peer is `127.0.0.1` or a public resolver, so this doesn't
affect confidence in the result.

## Extending

- **More record types**: `RESOURCE_CLASSES` and `resource_value` are
  the only two places that know about a specific record type -- adding
  `SRV`, `CAA`, or `SOA` support is a two-line addition to each.
  Ordering: SRV needs priority/weight/port/target formatting; CAA needs
  flag/tag/value.
  DNSSEC-aware checking would require switching to a validating
  resolver library, since stdlib `Resolv::DNS` doesn't validate
  signatures.
- **Latency tracking**: wrap the `getresources` call in
  `Process.clock_gettime` before/after and add response time to each
  result -- useful for catching a resolver that's technically correct
  but degraded.
- **Per-domain expected-value sets**: extend `--expect` to accept a
  small JSON/YAML file of `{domain => {type => expected_values}}` for
  auditing many domains against a known-good baseline in one run.
- **Historical drift tracking**: append each run's JSON output to a
  log and diff consecutive runs to catch a record that changed
  *between* runs, not just one that's inconsistent *within* a run.
- **Alerting integration**: the same pattern as this toolkit's other
  checkers -- pipe `--json` into a Slack/PagerDuty webhook when
  `findings` contains anything other than `OK`.

## References

- [Ruby Resolv::DNS stdlib docs](https://docs.ruby-lang.org/en/3.0/Resolv/DNS.html)
- [Ruby Resolv::DNS::Message stdlib docs](https://docs.ruby-lang.org/en/3.0/Resolv/DNS/Message.html)
- [RFC 1035 (Domain Names -- Implementation and Specification)](https://www.rfc-editor.org/rfc/rfc1035)
