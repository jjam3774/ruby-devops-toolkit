# ftp-dir-sync

One-way directory sync from a local path up to a remote FTP server, using
only Ruby's bundled `net/ftp` -- no third-party gems. Skips unchanged
files, creates missing remote directories, retries transient failures, and
can optionally delete remote files that no longer exist locally.

## The problem

FTP is not glamorous, but it is still how a surprising number of shared
hosts, print vendors, older EDI trading partners, and some managed CDNs
accept file drops. "Just re-upload everything every time" works until the
directory has thousands of files and the nightly job starts taking an hour
of that time being wasted re-sending bytes that haven't changed. This
script gives that job real sync semantics -- and does it with zero gems, so
it drops onto a box with a stock Ruby install and nothing else.

## Prerequisites

- Ruby >= 3.0. `net/ftp` shipped as part of the standard library through
  Ruby 3.0 and ships today as a **default gem** bundled with every stock
  Ruby install (3.1+) -- either way, `gem install` is never required.
- Network access to the FTP server, including the passive-mode data port
  range if the server/firewall restricts it (see Troubleshooting).
- An FTP account with write (and, for `--delete-orphans`, delete)
  permission on the target directory.

## Usage

```
ruby ftp_dir_sync.rb --host ftp.example.com --user deploy --local ./dist --remote /www/site

FTP_PASSWORD=secret ruby ftp_dir_sync.rb --host ftp.example.com --user deploy \
    --local ./dist --remote /www/site --delete-orphans --dry-run
```

| Flag | Meaning |
|---|---|
| `--host` / `--port` | FTP server (port defaults to 21) |
| `--user` / `--password` | credentials (prefer the `FTP_PASSWORD` env var over the flag) |
| `--local DIR` | local directory to push |
| `--remote DIR` | remote directory to push into (created if missing) |
| `--no-passive` | use active mode instead of passive (default is passive) |
| `--retries N` | retry attempts per file on a transient error (default 3) |
| `--delete-orphans` | delete remote files with no local counterpart |
| `--dry-run` | print what would happen without transferring anything |

Exit codes: `0` sync completed, `1` couldn't connect/log in at all, `2` one
or more files failed to transfer after retries.

## How it works

1. **Local manifest.** `Find.find` walks the local tree into a
   `relative_path => {size, abs_path}` map.
2. **Remote root creation.** Before anything uploads, the script ensures
   the `--remote` directory itself exists, one path component at a time
   (`ftp.mkdir`), tolerating "550 already exists" but re-raising anything
   else.
3. **Change detection without a remote checksum command.** FTP has no
   standard "give me a hash of this file" verb, so the script compares
   sizes first (`ftp.size`, cheap), and only for a same-size file does it
   download it to a temp path and SHA-256-compare against the local copy --
   the expensive path is the rare path.
4. **Retry wrapper.** `with_retries` catches `Net::FTPTempError`,
   `Net::FTPConnectionError`, `ECONNRESET`, and `EOFError` around each
   upload, with a short linear backoff between attempts.
5. **Orphan cleanup (`--delete-orphans`).** `nlst` alone isn't recursive
   and returns directories mixed in with files, so `remote_files_recursive`
   walks the remote tree explicitly, probing each entry with `ftp.size`
   (raises `Net::FTPPermError` for a directory) to tell files from
   directories before ever calling `ftp.delete` -- this is exactly the kind
   of "550 Is a directory" crash the first version of this script hit
   during testing (see Testing notes).

## Example output

```
$ ruby ftp_dir_sync.rb --host ftp.example.com --user deploy --local ./dist --remote /www/site
Found 2 local file(s) under /tmp/ftp_local_src
Connected to ftp.example.com:21 as deploy (passive=true)
uploaded assets/style.css (16 bytes)
uploaded index.html (19 bytes)
Done. uploaded=2 skipped=0 failed=0 deleted=0

$ ruby ftp_dir_sync.rb --host ftp.example.com --user deploy --local ./dist --remote /www/site   # re-run, nothing changed
Found 2 local file(s) under /tmp/ftp_local_src
Connected to ftp.example.com:21 as deploy (passive=true)
Done. uploaded=0 skipped=2 failed=0 deleted=0
```

## Troubleshooting

- **Hangs on `LIST`/upload in passive mode** -- the server's advertised
  passive-mode IP is wrong (common behind NAT) or the passive port range
  is firewalled. Try `--no-passive`, or open the server's configured
  passive port range through the firewall.
- **`550 Is a directory` on delete** -- if you see this, you're likely
  running an older copy of this script; the recursive-walk fix in
  `remote_files_recursive` is what prevents it (see Testing notes below
  for exactly how this bug was caught).
- **`Net::FTPPermError: 530 Login incorrect`** -- double-check the account
  isn't locked to a chroot that doesn't include `--remote`'s parent path.
- **Every file re-uploads every run** -- some FTP servers report directory
  listing sizes inconsistently for files still mid-write on their end;
  re-run once the remote-side write has settled.

## Extending it

- Add a manifest file (`.ftpsync-state.json`) written locally after each
  run so unchanged-file checks never need a same-size download+compare at
  all.
- Add TLS via `Net::FTP.new(host, ssl: true)` (FTPS) for servers that
  support it instead of plaintext FTP.
- Parallelize uploads with a small thread pool for directories with many
  small files.

## Testing notes

Tested live in this environment against a real local FTP server
(`pyftpdlib`, `127.0.0.1:2121`) covering: a fresh sync into a
not-yet-existing remote directory, a no-op re-run against unchanged files,
and a mixed run (one file modified, one file removed locally, one file
added) combined with `--delete-orphans`. That last combination is what
surfaced two real bugs during testing -- `--delete-orphans` crashing with
`550 Is a directory` because top-level `nlst` results include
subdirectories, and a `remote_root`/`rel` join producing a stray `//` in
printed paths -- both fixed (recursive file-only remote walk; trailing-slash
normalization) and re-verified against the same server before this was
published. The retry wrapper's exception handling was verified by
disconnecting mid-run in a scratch test; the connection-refused fatal path
was verified by pointing at a closed port.

## References

- [Ruby `Net::FTP` docs](https://docs.ruby-lang.org/en/3.3/Net/FTP.html)
- [net-ftp on RubyGems](https://rubygems.org/gems/net-ftp)
- [RFC 959 -- File Transfer Protocol](https://www.rfc-editor.org/rfc/rfc959)
