# env-secret-scanner

Scan a config tree for hardcoded credentials — AWS keys, private keys, Slack
tokens, database passwords — using pattern matching plus Shannon entropy, and
fail a CI job when one turns up.

Pure Ruby stdlib. No gems, no network, no root.

![Scan pipeline](img/secret-scan-pipeline.png)

---

## The problem

Secrets do not usually leak through a dramatic breach. They leak because
somebody put `password: "Xk92mQ7vLp4RtZ8wNc3Jf6Hb"` in `config/database.yml`
to get a deploy working on a Friday, and it was still there eighteen months
later when the repo went public, or when the container image got pushed to a
registry that turned out to be world-readable.

The fix is boring and mechanical: scan the tree, on every commit, and refuse
to ship when something secret-shaped shows up. That is what this script does.

The hard part is not finding secrets — a regex for `AKIA[0-9A-Z]{16}` takes
thirty seconds to write. The hard part is **not drowning the team in false
positives**, because a scanner that cries wolf gets `|| true` appended to it
within a week and then it protects nothing. Most of the code here is about
suppression, not detection.

## Prerequisites

| Requirement | Notes |
|---|---|
| Ruby | 3.0 or newer (uses `Struct` with `keyword_init:` and endless methods are avoided for 3.0 compatibility) |
| Gems | none — `optparse`, `json`, `find`, `digest`, `set` are all stdlib |
| OS | Linux, macOS, or Windows |
| Privileges | read access to whatever you point it at |

Check your version:

```console
$ ruby --version
ruby 3.0.2p107 (2021-07-07 revision 0db68f0233) [x86_64-linux-gnu]
```

## Usage

```console
# scan a tree
ruby secret_scan.rb /srv/app

# scan several, machine-readable output
ruby secret_scan.rb --format json /srv/app /etc/myapp

# only fail on the serious stuff
ruby secret_scan.rb --min-severity high /srv/app

# suppress known-good hits by their stable IDs
ruby secret_scan.rb --allow .secretscan-allow /srv/app
```

Exit codes:

| Code | Meaning |
|---|---|
| `0` | no findings at or above `--min-severity` |
| `1` | findings — the CI job should fail |
| `2` | usage error |

## Example output

Run against a fixture tree containing a `.env`, a `database.yml`, a deploy
script and a stray SSH private key:

```
==========================================================================
  SECRET SCAN  --  2026-08-19 14:51:20
  roots: /tmp/fixture
==========================================================================
  files scanned: 5         bytes: 783.0 B       findings: 6
--------------------------------------------------------------------------

  [CRITICAL]  2 finding(s)
    /tmp/fixture/app/.env:2
      rule    : AWS Access Key ID (aws-access-key-id)
      value   : AKIA************MPLE   entropy=3.68
      id      : ca6f427376a2
    /tmp/fixture/deploy/id_deploy:1
      rule    : PEM private key block (private-key-block)
      value   : -----BEGIN OPENSSH PRIVATE KEY-----   entropy=3.59
      id      : 274cd2c23809

  [HIGH]  4 finding(s)
    /tmp/fixture/app/.env:3
      rule    : High-entropy value assigned to a secret-ish key (generic-assignment)
      value   : wJal************************EKEY   entropy=4.66
      id      : f44a1a3ec8ac
    /tmp/fixture/app/.env:4
      rule    : Credentials embedded in URL (basic-auth-url)
      value   : hunt*********reat   entropy=3.45
      id      : 999b7be328f1
    /tmp/fixture/app/config/database.yml:5
      rule    : High-entropy value assigned to a secret-ish key (generic-assignment)
      value   : Xk92****************f6Hb   entropy=4.58
      id      : df52eaeb9a02
    /tmp/fixture/deploy/notify.sh:3
      rule    : Slack token (slack-token)
      value   : xoxb************************87HG   entropy=4.16
      id      : 0c8457d7a513

--------------------------------------------------------------------------
  Allowlist a false positive:  echo <id> >> allowlist.txt
==========================================================================
```

Note what is **not** in that list. The fixture also contained:

* `ADMIN_PASSWORD=changeme` — killed by the placeholder filter
* `SESSION_SECRET=${SESSION_SECRET}` — killed by the placeholder filter
* `API_KEY=your_api_key_here` in a README — killed by the placeholder filter
* an AWS key inside `node_modules/` — never read, the directory is pruned
* a credential in `.git/config` — never read, same reason
* a 4 KB binary `.png` — skipped by the binary sniff

Five files scanned out of nine. That ratio is the whole point.

## How it works

### 1. Walk, and prune aggressively

`Find.find` with `Find.prune` stops descent into a directory entirely rather
than filtering its results afterwards, which matters enormously when
`node_modules` has 40,000 files in it:

```ruby
Find.find(root) do |path|
  if File.directory?(path)
    Find.prune if SKIP_DIRS.include?(File.basename(path))
    next
  end
  next unless File.file?(path)
  next if File.symlink?(path)
  scan_file(path)
end
```

Skipping `.git` is not laziness — scanning packed object files produces pure
noise, and a secret that is only in git history needs
[a history-rewriting tool](https://github.com/newren/git-filter-repo), not a
line number.

### 2. Filter before you read

Three cheap tests, in increasing order of cost:

```ruby
return if size.zero? || size > MAX_FILE_BYTES   # stat only
return if BINARY_EXT.include?(File.extname(path).downcase)
File.open(path, 'rb') { |f| f.read(4096).to_s.include?("\0") }  # NUL sniff
```

The NUL-byte sniff is the classic "is this binary" heuristic — text files
essentially never contain a zero byte in their first 4 KiB, and binaries
almost always do.

Files are then read with replacement encoding, so one malformed UTF-8
sequence in a log file cannot abort the entire scan:

```ruby
File.open(path, 'r:UTF-8', invalid: :replace, undef: :replace)
```

### 3. Match, specific rules first

Six rules, ordered from most to least confident. Each declares which capture
group holds the actual secret, so redaction and entropy both operate on the
value rather than the whole line:

```ruby
{
  id: 'generic-assignment',
  severity: 'high',
  pattern: /\b([A-Za-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|
             access[_-]?key|private[_-]?key|credential|auth)[A-Za-z0-9_.-]*)
            \s*[:=]\s*
            ["']?([^\s"'#,;]{8,})["']?/xi,
  capture: 2,
  entropy: true
}
```

The `/x` flag lets that regex be written across four readable lines instead of
one 180-character horror.

### 4. Three suppression gates

This is where the false positives die.

**Placeholders.** One regex handles the whole family — literal `changeme`,
templating syntax (`${VAR}`, `{{var}}`, `%(var)s`), angle-bracket
placeholders, and runs of `x`:

```ruby
PLACEHOLDER = /\A(?:
    changeme|placeholder|example|test|dummy|null|nil|xxx+|
    your[_-]?\w+|<[^>]+>|\$\{[^}]+\}|\$[A-Z_]+|\{\{[^}]+\}\}|\*+
  )\z/xi
```

**Entropy.** Shannon entropy in bits per character, applied *only* to the
fuzzy generic rule:

```ruby
def self.entropy(str)
  counts = Hash.new(0)
  str.each_char { |c| counts[c] += 1 }
  len = str.length.to_f
  counts.values.reduce(0.0) { |sum, n| p = n / len; sum - (p * Math.log2(p)) }
end
```

A real key like `Xk92mQ7vLp4RtZ8wNc3Jf6Hb` scores 4.58. `changeme` scores
about 2.5. The threshold sits at 3.5. The specific rules (`AKIA...`,
`xoxb-...`) skip this gate entirely — their *shape* is already proof.

**Rule precedence.** Because `RULES` is ordered specific-first, the scanner
tracks which values a precise rule already claimed on the current line and
refuses to let the fuzzy rule re-report them:

```ruby
claimed = {}
RULES.each do |rule|
  ...
  next if rule[:entropy] && claimed[secret]
  claimed[secret] = true unless rule[:entropy]
  record(...)
end
```

Without this, one `AWS_ACCESS_KEY_ID=AKIA...` line produces two findings.
With it, one.

### 5. Redact, and fingerprint

Findings must be safe to paste into a ticket, so the value is never printed
in full:

```ruby
def self.redact(secret)
  return '*' * secret.length if secret.length <= 8
  "#{secret[0, 4]}#{'*' * [secret.length - 8, 24].min}#{secret[-4, 4]}"
end
```

Each finding also gets a stable 12-character ID:

```ruby
Digest::SHA256.hexdigest("#{path}|#{rule_id}|#{secret}")[0, 12]
```

That ID is what the allowlist stores — **not** the secret. So you can commit
`.secretscan-allow` to the repo without committing the thing you are trying to
keep out of the repo. Change the value and the ID changes, so the suppression
correctly stops applying.

## Wiring it into CI

The exit code is the whole integration:

```yaml
# .github/workflows/secrets.yml
- name: Scan for hardcoded secrets
  run: ruby tools/secret_scan.rb --min-severity high --allow .secretscan-allow .
```

Start with `--min-severity critical` on an existing codebase so the first run
is achievable, work the list down, then tighten the threshold. A pre-commit
hook is the other obvious home:

```sh
#!/bin/sh
# .git/hooks/pre-commit
ruby tools/secret_scan.rb --min-severity high $(git diff --cached --name-only) || {
  echo "Commit blocked: possible secret. Allowlist it if it is a false positive."
  exit 1
}
```

## Troubleshooting

**Too many findings on first run.** Expected. Raise `--min-severity` to
`critical`, fix those, then step down. Do not start at `low`.

**A legitimate high-entropy value keeps flagging** (a public key fingerprint,
a checksum, a test vector). Copy its ID into the allowlist file. It is a
12-character hex string, safe to commit.

**A real secret is being missed.** Check three things in order: is it inside a
pruned directory (`.git`, `node_modules`, `vendor/bundle`)? Is the file over
2 MiB? Is the value under 8 characters, or does the key name not contain one
of `password|secret|token|api_key|access_key|private_key|credential|auth`? The
key-name list is the most common cause — add your own term to the
`generic-assignment` pattern.

**The scan is slow on a large tree.** Add the offending directory to
`SKIP_DIRS`. Pruning a directory is essentially free; scanning it is not.

**Windows line endings.** `each_line` handles `\r\n` fine, but a trailing
`\r` can end up inside a captured value and shift its entropy slightly. If
that bothers you, add `.chomp` before matching.

**Findings only appear in JSON, not text.** The text report groups by
severity and prints nothing for a severity with no hits — check the summary
line's finding count.

## Extending it

* **Verify before you alert.** A finding is much more useful if you know the
  key is *live*. For AWS, `sts:GetCallerIdentity` with the found key answers
  that in one call. Rotate the confirmed-live ones first.
* **Scan git history.** Wrap the scanner in
  `git rev-list --all | while read sha; do git archive $sha | ...` to catch
  secrets that were removed from HEAD but are still in the pack.
* **Baseline mode.** Write every current finding's fingerprint to a file and
  report only *new* IDs, so an existing codebase can adopt the tool without a
  cleanup sprint first.
* **More rules.** Stripe (`sk_live_`), GitHub PATs (`ghp_`), Google API keys
  (`AIza`), Twilio (`SK` + 32 hex) all follow the same shape as the existing
  entries — add a hash to `RULES`.
* **SARIF output.** GitHub code scanning ingests SARIF, which would put every
  finding inline on the pull request diff. The `Finding` struct already
  carries everything SARIF needs.

## References

- [Ruby `Find` module](https://docs.ruby-lang.org/en/3.0/Find.html) — directory traversal with `prune`
- [Ruby `Digest` module](https://docs.ruby-lang.org/en/3.0/Digest.html)
- [Ruby `OptionParser`](https://docs.ruby-lang.org/en/3.0/OptionParser.html)
- [Ruby Regexp — extended `/x` mode](https://docs.ruby-lang.org/en/3.0/Regexp.html)
- [AWS access key ID prefixes](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html)
- [OWASP: Use of Hard-coded Password](https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password)
- [git-filter-repo](https://github.com/newren/git-filter-repo) — for secrets already in history

## License

MIT — see the repository [LICENSE](../LICENSE).
