# duplicate-file-finder

Find byte-for-byte duplicate files and see how much space you'd reclaim by
keeping one copy of each — a single stdlib-only Ruby script, cross-platform.

![workflow](img/dup_flow.png)

## Prerequisites

- Ruby 2.7+ (tested on 3.0.2) — stdlib only: `find`, `digest`, `json`, `optparse`. No gems.
- Linux, macOS, or Windows.

## Usage

```bash
# scan one or more directories
ruby duplicate_file_finder.rb ~/Downloads ~/Documents

# ignore files under 1 MiB
ruby duplicate_file_finder.rb /data --min-size 1048576

# machine-readable
ruby duplicate_file_finder.rb /data --json

# emit a shell script of rm commands (keeps the first of each group)
ruby duplicate_file_finder.rb /data --script > dedup.sh
```

## How it works — three stages, minimal reads

1. **Group by size.** Files are bucketed by `lstat` size. A file with a unique
   size *cannot* have a duplicate, so it's eliminated before any hashing.
2. **Partial hash.** For each size bucket with 2+ files, only the first 64 KiB
   of each file is SHA-256'd. This cheaply splits most coincidental same-size files.
3. **Full hash.** Only files that *also* share a partial hash are read in full and
   SHA-256'd to confirm a true byte-for-byte duplicate.

The payoff: large unique files (a one-off ISO, a video) are never fully read.
Groups are sorted so the biggest reclaimable wins appear first, and `--script`
emits `rm` commands that keep the first file of each group for you to review.

## Example output

```
duplicate file finder -- scanned 6 files in /tmp/duptest

2 copies x 195.3 KiB  (reclaim 195.3 KiB)
    /tmp/duptest/x/big.bin
    /tmp/duptest/y/big_dup.bin
3 copies x 30 B  (reclaim 60 B)
    /tmp/duptest/x/a.txt
    /tmp/duptest/y/a_copy.txt
    /tmp/duptest/y/a_copy2.txt

2 duplicate groups, 195.4 KiB reclaimable
```

## Troubleshooting

- **Two files look identical but aren't grouped** — they differ by a byte
  (trailing newline, metadata baked into the file); this tool is exact by design.
- **Symlinks** are skipped (`lstat`, not `stat`) so a symlink to a real file
  is never reported as a duplicate of it.
- **Review before deleting.** `--script` never deletes anything itself; it prints
  commands. Always eyeball which copy it keeps.

## Extending

- Add `--hardlink` to replace duplicates with hard links instead of deleting.
- Swap SHA-256 for BLAKE2 (via `Digest`) if you want faster full hashes.
- Add `--exclude` globs to skip `.git`, `node_modules`, and snapshot directories.

## Testing

Verified on Linux (Ruby 3.0.2): identical text files across directories, a large
random binary duplicated once, a unique file correctly ignored; `--json` and
`--script` outputs confirmed.

## References

- [Ruby `Digest`](https://docs.ruby-lang.org/en/3.4/Digest.html)
- [Ruby `Find`](https://docs.ruby-lang.org/en/3.4/Find.html)
- [Ruby `File::Stat`](https://docs.ruby-lang.org/en/3.4/File/Stat.html)
