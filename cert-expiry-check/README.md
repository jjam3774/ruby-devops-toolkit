# cert-expiry-check

A fleet-wide TLS certificate expiry auditor in a single Ruby file. Point it at a
list of `host[:port]` endpoints and it connects to each one concurrently, reads
the presented leaf certificate, and reports days until expiry with
Nagios-style severities and exit codes.

![Architecture](img/cert_expiry_flow.png)

## Why

Expired certificates are one of the most preventable outages in operations, and
they keep happening because the certs that expire are never the ones on the
load balancer everyone watches — they're the internal API on `:8443`, the SMTP
endpoint on `:465`, the one box that didn't get enrolled in ACME. A script you
can run from cron against a flat list of endpoints closes that gap in about two
minutes of setup.

## Prerequisites

- Ruby 2.7+ (tested on 3.0). **Standard library only** — `openssl`, `socket`,
  `json`, `optparse`, `timeout`. No gems.
- Network reachability from the box running the check to the endpoints.

## Usage

```
# Ad-hoc, endpoints on the command line (port defaults to 443)
ruby cert_expiry_check.rb example.com internal.corp:8443 mail.corp:993

# Fleet file + custom thresholds + JSON for your monitoring pipeline
ruby cert_expiry_check.rb --file endpoints.txt --warn 30 --crit 7 --json

# endpoints.txt: one host[:port] per line, # comments allowed
```

Options: `--warn DAYS` (default 30), `--crit DAYS` (default 7),
`--timeout SEC` (default 10), `--threads N` (default 8), `--file PATH`, `--json`.

## How it works

1. Endpoints from `--file` and/or argv go into a `Queue`; a bounded pool of
   worker threads (default 8) drains it, so a large fleet checks in parallel.
2. Each check is `TCPSocket` → `OpenSSL::SSL::SSLSocket` with `ssl.hostname`
   set for **SNI** (required on shared-IP hosting), wrapped in a `Timeout`.
3. Verification is deliberately `VERIFY_NONE`: an expiry auditor must still
   read the date off a self-signed or broken-chain cert instead of erroring
   out before the check happens. This tool audits expiry, it does not validate
   trust.
4. `peer_cert.not_after` minus now, floored to days, is classified against the
   thresholds. Unreachable/broken-TLS endpoints are CRIT — a cert you cannot
   check is a cert you cannot trust to be valid.
5. Exit code is `2` if anything is CRIT, `1` if anything is WARN, else `0`,
   so it drops into cron, CI, or a Nagios-compatible check unmodified.

## Example output

```
ENDPOINT                       STATUS  DAYS LEFT  EXPIRES (UTC)             ISSUER
----------------------------------------------------------------------------------------------------
127.0.0.1:9999                 CRIT            -  -                         Errno::ECONNREFUSED: Connection refused - connect(2) for "127.0.0.1" port 9999
127.0.0.1:8443                 CRIT           -6  2026-08-17T18:59:15Z      expired.test.local
127.0.0.1:8442                 WARN           14  2026-09-06T18:59:15Z      warn.test.local
127.0.0.1:8441                 OK            399  2027-09-26T18:59:15Z      ok.test.local
----------------------------------------------------------------------------------------------------
ok=1 warn=1 crit=2  (warn<=30d crit<=7d)
```

(That's real output from the test run: three local TLS servers presenting a
healthy cert, a 15-day cert, and an already-expired cert, plus one
deliberately closed port.)

## Testing notes

Verified against live local TLS servers: three self-signed certificates were
generated (healthy 400-day, expiring 15-day, and an already-expired one
back-dated via `OpenSSL::X509::Certificate`), served from three in-process
`OpenSSL::SSL::SSLServer` instances, and the script was run against them plus
a closed port. All four severities and both output modes behaved as documented.

## Troubleshooting

- **`SSLError: unexpected eof` / handshake failures** — the endpoint may
  require a client certificate, be plain TCP (not TLS), or need a protocol
  upgrade (e.g. SMTP STARTTLS on 587 — this tool speaks *implicit* TLS only,
  so use port 465 for SMTP or add a STARTTLS preamble; see Extending).
- **Everything times out** — check for an egress firewall; raise `--timeout`.
- **`certificate verify failed`** — should not happen (VERIFY_NONE); if you
  modified the script to verify, your CA bundle is missing.
- **Wrong cert returned** — usually SNI: confirm the hostname you pass is the
  one the server virtual-hosts on. Checking by IP defeats SNI.

## Extending

- **STARTTLS** support for SMTP/IMAP/LDAP: send the protocol preamble before
  wrapping the socket in `SSLSocket`.
- **Chain checks**: walk `ssl.peer_cert_chain` and flag intermediates that
  expire before the leaf.
- **Prometheus**: emit `cert_days_left{endpoint=...}` gauges instead of JSON —
  pairs well with [prometheus-exporter](../prometheus-exporter) in this repo.
- **Weak crypto audit**: flag certs with SHA-1 signatures or RSA < 2048 while
  you're in there (`cert.signature_algorithm`, `cert.public_key.n.num_bits`).

## References

- Ruby OpenSSL stdlib docs: https://docs.ruby-lang.org/en/master/OpenSSL.html
- `OpenSSL::SSL::SSLSocket`: https://docs.ruby-lang.org/en/master/OpenSSL/SSL/SSLSocket.html
- RFC 6066 (TLS SNI): https://datatracker.ietf.org/doc/html/rfc6066
