# firewall-drift-audit

Parses `iptables-save` output and flags drift against a JSON security baseline: default
policies that went from DROP to ACCEPT, ports opened wider than the baseline allows, and
baseline ports that quietly disappeared. Built entirely on Ruby's stdlib (`json`,
`optparse`) — no gems, no native extension, and no root privileges of its own (only
whatever produced the snapshot needed root).

## Prerequisites

- Ruby 3.x, stdlib only.
- A JSON baseline file describing expected default policies and allowed TCP/UDP ports
  (see `baseline.example.json`).
- An `iptables-save` snapshot: either pipe `sudo iptables-save` directly on a live Linux
  host, or pass `--input snapshot.txt` to analyze a file captured elsewhere.

## Usage

```bash
# Live host (requires root for iptables-save itself, not for this script)
sudo iptables-save | ruby firewall_drift_audit.rb --baseline baseline.json

# Offline / CI: analyze a captured snapshot
ruby firewall_drift_audit.rb --input snapshot.txt --baseline baseline.json

# Machine-readable output
ruby firewall_drift_audit.rb --input snapshot.txt --baseline baseline.json --json
```

`baseline.example.json`:

```json
{
  "default_policies": { "INPUT": "DROP", "FORWARD": "DROP", "OUTPUT": "ACCEPT" },
  "allowed_tcp_ports": [22, 80, 443],
  "allowed_udp_ports": [53]
}
```

Exit codes: `0` no CRIT findings, `1` at least one CRIT finding, `2` usage/input error.

## How it works

- `parse_iptables_save` walks the `*filter` table block of an `iptables-save` snapshot
  line by line, tracking an `in_filter` flag that flips on at `*filter` and off at
  `COMMIT` (or the start of another table). Chain-policy lines (`:CHAIN POLICY
  [pkts:bytes]`) and rule lines (`-A CHAIN ...`) are matched with small regexes for
  protocol, destination port, source, and jump target. Anything else on a line is
  simply not extracted, not rejected — a real fleet's rulesets have custom chains and
  match modules this parser was never asked to understand.
- `classify(parsed, baseline)` is a pure function: no file or process I/O. It diffs the
  parsed chain policies against `baseline['default_policies']`, and diffs every ACCEPT
  rule with a destination port against `allowed_tcp_ports`/`allowed_udp_ports`.
- Severity tracks exposure, not just presence: a newly-opened port with no `-s` clause
  (or an explicit `0.0.0.0/0`) is CRIT; the same port opened to a specific subnet is
  WARN. A default policy flipped from DROP to ACCEPT is CRIT; the reverse (more
  restrictive than baseline) is WARN. A baseline port with no matching rule at all is
  WARN (possible accidental removal / service-outage risk).

## Example output

Captured against two hand-built `iptables-save` fixtures — one compliant, one
deliberately drifted (default policy flipped to ACCEPT, MySQL opened to the world, an
unlisted port opened to a specific subnet, and two baseline ports missing):

```
$ ruby firewall_drift_audit.rb --baseline baseline.json --input snapshot_drifted.txt
[CRIT] overall firewall drift status: crit
  [CRIT] chain INPUT default policy is ACCEPT, baseline requires DROP
  [CRIT] tcp/3306 accepts from anywhere but is not in the baseline allowlist (-A INPUT -p tcp -m tcp --dport 3306 -j ACCEPT)
  [WARN] tcp/8080 is open to 10.0.5.0/24 (not in baseline) -- verify this is intentional
  [WARN] baseline expects tcp/443 to be open, but no matching ACCEPT rule was found
  [WARN] baseline expects udp/53 to be open, but no matching ACCEPT rule was found
---
2 CRIT, 3 WARN
```

## Testing notes

`iptables-save` and `nft` both require root to read the live ruleset, which wasn't
available in the environment used to build this script. The parser and classifier were
instead verified against two hand-built `iptables-save` snapshots fed through `--input`:
a compliant one (matches the baseline exactly) and a deliberately drifted one (four
different kinds of drift at once). Both exercise the real parsing and classification
code paths end to end — `--input` is a first-class, permanently-useful feature (for
reviewing a snapshot captured on a box you don't have root on, or for CI), not just a
test seam.

## Troubleshooting

- **"no input" error** — pass `--input FILE` or actually pipe `iptables-save` output on
  stdin; the script refuses to silently read an interactive terminal as if it were piped
  data.
- **Rules show a nil protocol/port** — this parser only extracts `-p`, `--dport`, `-s`,
  and `-j`. Port ranges (`--dport 8000:8010`) or `-m multiport --dports` won't match the
  single-port regex.
- **nftables-only hosts** — this script only understands the legacy iptables-save text
  format. Run `iptables-nft-save` for equivalent output, or extend the parser for `nft
  -j list ruleset`'s JSON format.

## Extending it

- Support port ranges and `-m multiport --dports`.
- Add a native `nft -j list ruleset` JSON parser.
- Pair with `ssh-fleet-runner` elsewhere in this repo to sweep a whole fleet in one pass.
- Add a `--freeze` mode that writes the current ruleset out as a new baseline.

## References

- [iptables-save(8) man page](https://man7.org/linux/man-pages/man8/iptables-save.8.html)
- [netfilter/iptables project](https://www.netfilter.org/)
- [Ruby stdlib: JSON](https://docs.ruby-lang.org/en/3.0/JSON.html)
