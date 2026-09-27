# tls-cipher-audit

A pure Ruby stdlib script that connects to a fleet of `host:port` targets, does
real TLS handshakes, and tells you which ones are still speaking SSLv3/TLSv1.0/
TLSv1.1 or would hand a client a NULL/RC4/3DES/anonymous cipher suite -- with a
Nagios-compatible exit code so it drops straight into cron or your existing
monitoring stack.

## The problem

Certificates expire on a schedule you can put in a calendar. Transport
security rot doesn't -- a load balancer someone configured five years ago
quietly keeps answering `TLSv1.0` handshakes forever, because nothing ever
tells it to stop, and nobody re-audits a "working" listener. Multiply that
across a few hundred internal services, VPN gateways, mail servers and
vendor-managed appliances and you get a fleet where every individual cert is
valid and green, and a good chunk of the actual encryption is worthless:

- SSLv3 is broken by POODLE (padding-oracle downgrade).
- RC4 has a measurably biased keystream; RFC 7465 forbids using it in TLS at
  all.
- 3DES's 64-bit block size is vulnerable to Sweet32 birthday-bound attacks
  over long-lived connections.
- NULL and anonymous (`ADH`/`AECDH`) cipher suites exist in the OpenSSL
  cipher list for testing/interop and occasionally end up live in production
  by accident -- NULL means no encryption at all, anonymous means no server
  authentication at all (trivially MITM'd).
- A short (<2048-bit) ephemeral DH modulus is the Logjam class of weakness.
- A cipher with no forward secrecy means a single leaked private key
  retroactively decrypts every session ever captured against it.

None of this shows up if you only check `notAfter`. This toolkit already has
`cert-expiry-check`/`cert-expiry-monitor` for that job -- this script does the
other half: it asks each server, at the protocol level, "what's the weakest
handshake you'll actually agree to?" and reports it.

## Prerequisites

- Ruby >= 2.5 (needs `OpenSSL::SSL::SSLContext#min_version=`/`#max_version=`,
  added in 2.5; developed and tested against Ruby 3.3).
- The `openssl` stdlib gem that ships with Ruby -- no `gem install` needed.
  Tested against a build linked to OpenSSL 3.0.13.
- No other gems, no native extensions, nothing to install.
- Linux/macOS/BSD. Nothing OS-specific is used (just `Socket`/`OpenSSL`), so
  this also runs unmodified on Windows Ruby, though it wasn't specifically
  re-tested there.
- Outbound network access to whatever `host:port` targets you point it at.

## Installation

```bash
git clone https://github.com/jjam3774/ruby-devops-toolkit.git
cd ruby-devops-toolkit/tls-cipher-audit
chmod +x tls_cipher_audit.rb
```

No `bundle install`, no `Gemfile` -- it's one file.

## Usage

```bash
# scan two targets given on the command line
ruby tls_cipher_audit.rb -t www.example.com:443,mail.example.com:993

# scan a whole fleet from a file (one host:port per line, # comments ok)
ruby tls_cipher_audit.rb -f targets.txt

# machine-readable output for feeding a dashboard / log shipper
ruby tls_cipher_audit.rb -f targets.txt --json

# more concurrency, tighter per-connection timeout, full protocol matrix
ruby tls_cipher_audit.rb -f targets.txt -c 25 -T 3 -v
```

```
Usage: tls_cipher_audit.rb -t host:port[,host:port,...] | -f targets.txt [options]
    -t, --targets LIST               Comma-separated host:port targets
    -f, --file FILE                  File with one host:port target per line (# comments ok)
    -c, --concurrency N              Worker threads scanning concurrently (default 10)
    -T, --timeout N                  Per-connection timeout in seconds (default 5.0)
    -j, --json                       Emit machine-readable JSON instead of the text report
    -v, --verbose                    Show the full per-protocol support matrix for every host
    -h, --help                       Show this help
```

**Exit codes** follow the Nagios plugin convention, so this drops straight
into `check_by_ssh`, an Icinga command definition, or a plain cron job that
mails on nonzero:

| Code | Meaning | When |
|------|---------|------|
| `0`  | OK       | every reachable target only speaks TLSv1.2/1.3 with a strong cipher |
| `1`  | WARNING  | a target speaks TLSv1.0/1.1, 3DES, MD5, or lacks forward secrecy |
| `2`  | CRITICAL | a target speaks SSLv3, or negotiates NULL/RC4/EXPORT/anonymous/short-DH |
| `3`  | UNKNOWN  | a target couldn't be reached at all (DNS, refused, timeout) |

The overall exit code is the *worst* status across every target in the run
(CRITICAL beats WARNING beats UNKNOWN beats OK), so one bad host in a batch
of 500 still trips the alert.

## How it works

For every target, the script does three separate rounds of real TLS
handshakes -- see `img/tls-cipher-audit-flow.png` for the full pipeline:

1. **Protocol support matrix.** For each of `SSLv3`, `TLSv1.0`, `TLSv1.1`,
   `TLSv1.2`, `TLSv1.3`, it builds an `OpenSSL::SSL::SSLContext` with
   `min_version` **and** `max_version` pinned to that exact version and
   attempts a handshake. A success proves the server is willing to complete
   that specific version and nothing else influenced the result. Because
   modern OpenSSL (1.1.1+/3.x) refuses to even *offer* TLSv1.0/1.1 at its
   default security level, every probe context also sets
   `security_level = 0` and a permissive cipher string
   (`ALL:eNULL:aNULL:COMPLEMENTOFALL:@SECLEVEL=0`) -- otherwise a server that
   still accepts TLSv1.0 would look falsely "secure" just because *your*
   local OpenSSL policy refuses to ask for it.

2. **Worst-case cipher negotiation.** One more handshake with the same
   permissive context but no version pin, so OpenSSL and the server settle
   on whatever they'd actually agree to if a legacy/misconfigured client
   showed up. The negotiated cipher name (`SSLSocket#cipher`) is checked
   against a table of weak-cipher substrings (`NULL`, `EXPORT`, `RC4`,
   `ADH`/`AECDH`, `3DES`/`DES`, `MD5`, `SEED`, `IDEA`, `RC2`), and the
   ephemeral key (`SSLSocket#tmp_key`) is inspected for a sub-2048-bit DH
   modulus (Logjam) and for the absence of a forward-secret key-exchange
   prefix (`ECDHE-`/`DHE-`/the TLS 1.3 `TLS_*` suites).

3. **Modern-client baseline.** A third, ordinary handshake with
   `min_version = TLS1_2` and OpenSSL's normal defaults -- what a browser or
   `curl` actually gets today. This is purely informational context in the
   report; it never affects severity, because a server that only shows its
   weak listener to old clients (via SNI dispatch, a legacy vhost, a
   different ALPN, etc.) should not get a false "all clear" just because a
   modern client happens not to trigger it.

All of that runs concurrently across a fixed pool of `Thread`s pulling off a
shared `Queue` (`-c`/`--concurrency`, default 10) -- the same worker-pool
shape used by `api-health-check` and `cert-expiry-check` elsewhere in this
toolkit -- so auditing a few hundred hosts takes roughly as long as the
slowest handshake, not the sum of all of them.

`img/tls-cipher-audit-matrix.png` shows the full severity table this script
implements: which protocol versions and which cipher indicators map to
WARNING vs CRITICAL, and why.

## Full code

The complete script is `tls_cipher_audit.rb` in this folder (also embedded in
the interactive widget above). Key structure:

- `permissive_context` -- builds the deliberately weakened `SSLContext` used
  for auditing (see "How it works" above).
- `tls_connect` -- TCP connect + TLS handshake, each under its own timeout.
- `describe_tmp_key` -- pulls a bit-size and key type out of
  `SSLSocket#tmp_key` via `to_text`, since OpenSSL 3.x's provider model
  returns a generic `OpenSSL::PKey::PKey` rather than a typed `EC`/`DH`
  object.
- `scan_target` -- runs the three handshake rounds for one target and turns
  the raw data into a list of findings plus a rolled-up status.
- `run_scans` -- the `Queue` + fixed `Thread` pool that fans `scan_target`
  out concurrently and joins the results back in original target order.
- `parse_options`/`main` -- `OptionParser`-based CLI, human or `--json`
  report, Nagios exit code.

## Step-by-step walkthrough

1. **Targets go in a `Queue`.** `-t host:port,host:port` and/or `-f
   targets.txt` are parsed into `{host:, port:}` hashes (default port 443 if
   you omit it) and pushed onto a thread-safe `Queue`, followed by one `nil`
   sentinel per worker thread so each worker knows when to stop.

2. **A fixed pool of workers drains the queue.** `Thread.new` is called
   `concurrency` times; each thread loops `queue.pop` until it gets its
   `nil`, calling `scan_target` on every real entry in between. Results are
   pushed into a shared array under a `Mutex` -- the only place multiple
   threads touch shared, mutable state.

3. **`scan_target` never raises.** Every handshake attempt is wrapped in its
   own `begin/rescue`; a DNS failure, connection refusal, or protocol-version
   rejection all get folded into the result hash rather than propagating.
   That matters at fleet scale -- one unreachable host must never abort the
   whole run.

4. **Findings, not just a support matrix.** Rather than only reporting
   "TLSv1.0: yes/no", the script converts every weak signal into a `{severity,
   category, detail}` finding so both the text report and the `--json` output
   carry the *why*, not just a boolean.

5. **Status rolls up, worst wins.** `SEVERITY_RANK` orders `unknown < ok <
   warning < critical`; a target's status is the worst finding it produced
   (or `ok` if it produced none), and the run's overall exit code is the
   worst status across every target, using the Nagios precedence rule
   (critical > warning > unknown > ok) so an unreachable host never
   masks a proven-broken one elsewhere in the batch.

## Example output

Captured for real from this script scanning a small local test fleet (four
Ruby `TCPServer`+`OpenSSL::SSL::SSLServer` instances configured to be good,
weak-protocol, NULL-cipher, and anonymous-DH respectively) plus one
unreachable port and one live Internet host, `www.google.com:443`, as a
sanity check. Full transcript, including `--json` mode and `-f` file-based
targets, is in `test_output.txt`.

```
==============================================================================
TLS CIPHER AUDIT -- 6 target(s) -- overall: CRITICAL
critical=2 warning=1 ok=2 unknown=1
==============================================================================

[PASS] 127.0.0.1:8543  (status: OK)
  protocols ok:   TLSv1.2, TLSv1.3
  worst-case negotiated: TLSv1.3 / TLS_AES_256_GCM_SHA384 (256-bit)
  findings: none

[WARN] 127.0.0.1:8544  (status: WARNING)
  protocols ok:   TLSv1.2
  protocols weak: TLSv1.0, TLSv1.1
  worst-case negotiated: TLSv1.2 / ECDHE-RSA-AES256-GCM-SHA384 (256-bit)
  WARNING  [protocol] server accepts TLSv1.0 (deprecated/weak protocol)
  WARNING  [protocol] server accepts TLSv1.1 (deprecated/weak protocol)

[CRIT] 127.0.0.1:8545  (status: CRITICAL)
  protocols ok:   TLSv1.2
  worst-case negotiated: TLSv1.2 / NULL-SHA256 (0-bit)
  CRITICAL [cipher] negotiated cipher NULL-SHA256: NULL cipher -- no bulk
           encryption at all, traffic is plaintext on the wire
  WARNING  [key_exchange] negotiated cipher NULL-SHA256 uses static key
           exchange -- no forward secrecy

[CRIT] 127.0.0.1:8546  (status: CRITICAL)
  protocols ok:   TLSv1.2
  worst-case negotiated: TLSv1.2 / ADH-AES256-GCM-SHA384 (256-bit)
  ephemeral key:  DH Public-Key: (2048 bit)
  CRITICAL [cipher] negotiated cipher ADH-AES256-GCM-SHA384: anonymous DH
           key exchange -- no server authentication, trivially MITM-able

[UNK ] 127.0.0.1:8599  (status: UNKNOWN)
  UNREACHABLE: Errno::ECONNREFUSED: Connection refused - connect(2) for
  "127.0.0.1" port 8599

[PASS] www.google.com:443  (status: OK)
  protocols ok:   TLSv1.2, TLSv1.3
  worst-case negotiated: TLSv1.3 / TLS_AES_256_GCM_SHA384 (256-bit)
  findings: none

==============================================================================
(exit code: 2)
```

## Troubleshooting

- **"Every host reports TLSv1.0/1.1 as supported and I know that's wrong."**
  Check what OpenSSL build Ruby is linked against (`ruby -ropenssl -e "puts
  OpenSSL::OPENSSL_VERSION"`). Some hardened distro builds remove legacy
  protocol support from libssl entirely at compile time; in that case
  `permissive_context`'s `security_level = 0` can't bring back a protocol
  that was never compiled in, and every probe for it will correctly report
  `false`.
- **`NULL`/`EXPORT`/anonymous ciphers never show up even against a server
  you know offers them.** Some OpenSSL 3.x distro builds move RC4/`EXPORT`
  entirely into the (not-loaded-by-default) "legacy" provider. If
  `openssl ciphers -v 'ALL:COMPLEMENTOFALL:@SECLEVEL=0'` on the box running
  this script doesn't list the cipher you expect, the client-side OpenSSL
  simply can't offer it, no matter what this script's context settings say
  -- that's a limitation of the local OpenSSL install, not of the script.
  Enabling the legacy provider (`openssl_conf`/`-provider legacy`) or running
  the audit from a host with an older/unpatched OpenSSL restores full
  coverage.
- **A handshake "hangs" instead of failing fast.** Firewalls that silently
  drop packets (instead of sending `RST`) make the initial `TCPSocket.new`
  hang until `-T`/`--timeout` fires. Lower `-T` for a faster sweep across a
  large, mostly-unreachable range, at the cost of possibly timing out a slow
  but legitimate host.
- **High `-c` values don't seem to speed things up further.** Ruby's default
  `Thread` implementation is fine for this workload because each thread
  spends nearly all its time blocked on network I/O (which releases the
  GVL), but there's still a point of diminishing returns once you're
  saturating either your own outbound bandwidth or the target's accept
  queue. 10-30 is a reasonable range for most fleets; go higher only if
  you've measured it helping.
- **Windows.** Nothing here uses a Windows-only API (just `Socket`/`OpenSSL`
  from stdlib), so it should run as-is under Ruby on Windows, but it was
  developed and captured on Linux only -- if you rely on it in production on
  Windows, do one confirming run there first.

## Extending

- **STARTTLS support.** As written this assumes an implicit-TLS port (443,
  993, 8443, ...). For SMTP/IMAP/FTP-style explicit STARTTLS you'd send the
  protocol's plaintext upgrade command before calling `ssl.connect` --
  swap `tls_connect`'s body for a protocol-aware variant per target.
- **Certificate checks in the same pass.** Since the script already holds an
  open `SSLSocket`, pulling `ssl.peer_cert` and checking `not_after` would
  let a single run replace both this script and `cert-expiry-check` for
  hosts where you want both signals together -- kept separate here to match
  each script's one-job-well philosophy.
- **HSTS/OCSP-stapling checks.** Similarly cheap to bolt on once you already
  have the socket: read the stapled OCSP response
  (`ssl.ocsp_response`) or, for HTTPS specifically, send a minimal `HEAD`
  request and check for a `Strict-Transport-Security` header.
- **Curve/group strength for ECDHE.** `describe_tmp_key` already extracts
  the key kind and bit count from `tmp_key.to_text`; extending it to flag a
  named curve weaker than P-256 (e.g. `secp160r1`) is a small addition to
  the same regex-on-`to_text` approach.
- **Perfect-score baseline / CIS benchmark mode.** Add a `--baseline
  cis-tls-1.2` flag that swaps in a stricter table of required protocols/
  ciphers (e.g. require TLSv1.3-only) instead of the current "anything
  below TLSv1.2 is weak" default.
- **Persistent history.** Pipe `--json` output into a small SQLite table
  (stdlib `json` + the `sqlite3` gem) to track when a host's worst-case
  cipher regresses, not just its current state.

## References

- [Ruby `OpenSSL::SSL::SSLContext` documentation](https://docs.ruby-lang.org/en/3.3/OpenSSL/SSL/SSLContext.html) -- `min_version=`/`max_version=`/`security_level=`/`ciphers=`.
- [Ruby `OpenSSL::SSL::SSLSocket` documentation](https://docs.ruby-lang.org/en/3.3/OpenSSL/SSL/SSLSocket.html) -- `#cipher`, `#tmp_key`, `#hostname=` (SNI).
- [RFC 7465 -- Prohibiting RC4 Cipher Suites in TLS](https://www.rfc-editor.org/rfc/rfc7465)
- [`openssl ciphers` manual page](https://docs.openssl.org/master/man1/openssl-ciphers/) -- cipher-string syntax (`@SECLEVEL`, `COMPLEMENTOFALL`, etc.) used by `permissive_context`.

---

Get the full source, plus every other script in this toolkit, at
[github.com/jjam3774/ruby-devops-toolkit/tree/main/tls-cipher-audit](https://github.com/jjam3774/ruby-devops-toolkit/tree/main/tls-cipher-audit).
