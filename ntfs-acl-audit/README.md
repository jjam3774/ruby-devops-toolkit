# ntfs-acl-audit

**Platform:** Windows (pure Ruby stdlib, no gems -- drives `icacls.exe`)

Audits NTFS folder/file permissions via `icacls.exe` and flags any grant of Modify/Write/FullControl to a broad identity (`Everyone`, `BUILTIN\Users`, `Authenticated Users`) -- the classic "someone ran `icacls /grant Everyone:F` to make a permissions error go away" problem.

## The problem

Windows security auditing tooling tends to cover the registry, services, scheduled tasks, firewall rules, BitLocker -- but rarely the filesystem ACLs themselves, even though an overly-broad NTFS grant is one of the most common and most quietly dangerous things that happens to a Windows box. A deploy script hits an "Access is denied" error, someone runs `icacls C:\inetpub\wwwroot /grant Everyone:F` to unblock themselves, it works, and nobody ever reverts it. This script finds those before an attacker does.

## Prerequisites

- Ruby >= 2.7 for Windows (tested against 3.0-series semantics)
- No gems -- `open3`, `optparse`, and `json` are all Ruby standard library
- `icacls.exe` -- built into every supported version of Windows, no install needed
- Enough privilege to read the ACLs on the paths you're auditing (running elevated is recommended so `icacls` doesn't itself get an Access Denied on protected system paths)

## Usage

```powershell
ruby ntfs_acl_audit.rb <path> [<path> ...] [options]
```

| Option | Default | Description |
|---|---|---|
| `--risky-identities LIST` | `Everyone,BUILTIN\Users,Authenticated Users,NT AUTHORITY\Authenticated Users` | Identities considered "broad" |
| `--risky-perms LIST` | `F,M,W,WD,WDAC` | icacls permission codes considered risky when granted to a broad identity |
| `--json` | off | Emit machine-readable JSON |

```powershell
# Audit a couple of common risk spots
ruby ntfs_acl_audit.rb "C:\inetpub\wwwroot" "C:\ProgramData\MyApp"

# Broaden what counts as "risky" for a stricter policy
ruby ntfs_acl_audit.rb "C:\Deploys" --risky-perms F,M,W,WD,WDAC,DC

# JSON for a compliance pipeline
ruby ntfs_acl_audit.rb "C:\Windows\Temp" --json
```

## How it works

1. **Invocation** -- `run_icacls(path)` shells out to `icacls.exe <path>` via `Open3.capture3` and is the *only* place in the script that touches the OS. Everything else is pure functions, which is what makes this testable without a Windows host (see Testing notes).
2. **Parsing** -- `icacls` output for one path looks like:
   ```
   C:\inetpub\wwwroot BUILTIN\Administrators:(OI)(CI)(F)
                       NT AUTHORITY\SYSTEM:(OI)(CI)(F)
                       BUILTIN\Users:(OI)(CI)(RX)
                       Everyone:(OI)(CI)(F)
   ```
   The path only appears once, on the first ACE's line; every following indented line is another Access Control Entry for the *same* path. `parse_icacls_output` tracks "current path" across lines and stops at the blank line / `Successfully processed` summary. Each ACE's flags are split into inheritance flags (`OI`/`CI`/`IO`/`NP`/`I`) versus actual permission codes (`F`/`M`/`RX`/`W`/...), and an explicit `(DENY)` marker is captured separately.
3. **Risk evaluation** -- `evaluate_ace` treats an explicit DENY as protective (never a finding, regardless of identity), skips known-safe identities (`SYSTEM`, `Administrators`, `CREATOR OWNER`), and for everything else checks whether the identity is in `--risky-identities` *and* the ACE grants at least one of `--risky-perms`. `FullControl`/`Modify` grants are CRIT; a bare `Write` grant is WARN (bad, but less immediately dangerous than Modify/FullControl).
4. **Reporting** -- one line per audited path with its worst finding, plus the specific ACE and reason for every flagged grant; `--json` for machine consumption. Exit code `2` if anything was flagged or a path couldn't be read, `0` otherwise.

## Example output

```
$ ruby ntfs_acl_audit.rb "C:\inetpub\wwwroot" "C:\ProgramData\LegacyApp" "C:\Windows\System32"
ntfs-acl-audit: audited 3 path(s)

[ CRIT] C:\inetpub\wwwroot
        Everyone: F  <-- Everyone granted F on C:\inetpub\wwwroot
[ CRIT] C:\ProgramData\LegacyApp
        BUILTIN\Users: M  <-- BUILTIN\Users granted M on C:\ProgramData\LegacyApp
[   OK] C:\Windows\System32
        (no broad grants found)

Summary: 2 risky ACE(s) across 3 path(s). Overall: CRIT
```

Exit code: `0` clean, `2` at least one risky grant (or a path failed to audit).

## Troubleshooting

- **`[ERROR] ... -- ERROR: The system cannot find the file specified.`** -- the path doesn't exist, or the account running the script can't see it. Quote paths with spaces, and run elevated for protected system directories.
- **A grant you expect to see isn't flagged** -- check it's actually one of `--risky-perms`. `RX` (Read & Execute) and plain `R` (Read) are intentionally never flagged, since read access for `Users`/`Authenticated Users` on shared/application directories is completely normal; this script is specifically about *write*-class access to broad identities.
- **An explicit DENY ACE with `Everyone:(DENY)(F)` isn't showing as a finding** -- that's correct, not a bug. A DENY entry blocks access; it's the opposite of a risky grant.
- **Output looks garbled / paths aren't lining up** -- `icacls`'s column alignment depends on path length and console width in some Windows/locale combinations; if you hit a real-world parsing edge case the regex doesn't handle, please open an issue with the raw (redacted) `icacls` output so `ACE_LINE` can be adjusted.
- **Can't verify this against a real Windows box right now** -- honestly noted: this script's logic was developed and tested entirely with a stub test harness (see below) because no Windows host was available in the environment it was written in. Please treat the parsing regex as "should work" rather than "battle-tested" until it's been run against real `icacls.exe` output on a variety of paths, and open an issue if you hit a shape it doesn't parse.

## Extending it

- Add `/T` (recurse into subdirectories) support and roll findings up per-directory rather than per-top-level-path.
- Cross-reference findings against `local-admin-audit`/`winservice-manager` elsewhere in this repo to catch cases where a broad ACL and a privileged service account combine into a real escalation path.
- Add a `--fix` mode that runs `icacls <path> /remove:g Everyone` for a confirmed-risky grant, gated behind an explicit confirmation flag (never do this unattended).
- Support share-level permissions (`Get-SmbShareAccess` via `powershell_bridge.rb`, elsewhere in this repo) alongside NTFS permissions -- share ACLs and NTFS ACLs combine (most-restrictive-wins), so an audit of one without the other is incomplete.

## Testing notes

**Honest limitation:** this script depends on `icacls.exe`, which only exists on Windows, and no Windows host was available in the sandbox this was developed in. Rather than skip testing, the script was deliberately structured so every piece of logic *except* the single `run_icacls` shell-out is a pure function, and `audit_path` accepts an injectable `runner:` in place of the real one. `ntfs_acl_audit_test.rb` feeds realistic `icacls.exe` output (reproduced fixtures covering a safe system directory, an `Everyone:F` grant, a `Users:M` grant, an explicit `DENY` ACE, a `Write`-only WARN-level grant, and an `icacls` failure) through `parse_icacls_output`, `evaluate_ace`, and `audit_path` end-to-end. All 11 tests pass:

```
$ ruby ntfs_acl_audit_test.rb
Run options: --seed 19576
# Running:
...........
Finished in 0.003006s, 3659.1593 runs/s, 6985.6677 assertions/s.
11 runs, 21 assertions, 0 failures, 0 errors, 0 skips
```

The CLI itself (option parsing, output formatting, exit codes) was additionally exercised end-to-end by placing a fake `icacls.exe` shell script earlier on `PATH` that returns the same fixture text a real Windows box would -- confirming the full pipeline from shell-out through parsing through the printed report. If you run this against a real Windows environment and find output shapes the parser doesn't handle, that's genuinely useful feedback -- please open an issue with the (redacted) raw `icacls` output.

## References

- [`icacls` command reference (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
- [Ruby `Open3` module](https://docs.ruby-lang.org/en/3.0/Open3.html)
- [Ruby `Minitest`](https://docs.ruby-lang.org/en/3.0/Minitest.html)
