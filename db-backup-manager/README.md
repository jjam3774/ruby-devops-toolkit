# db-backup-manager

Automated PostgreSQL/MySQL logical backups: gzip-streamed dumps, retention
rotation, and an optional restore-test that proves the backup is actually
usable, not just present on disk.

## The problem

`pg_dump > backup.sql` in a cron job is how most database backups start,
and how most database backup *incidents* start too: nobody notices the disk
filled up until backup #400 is 0 bytes, nobody rotates old dumps until the
partition is full, and nobody finds out a backup was corrupt until the day
they actually need to restore it. This script wraps the platform-native
dump tools with the three things that turn "a dump happened" into "we have
a real backup": streaming compression, a retention policy, and a restore
test.

## Prerequisites

- Ruby >= 3.0 (uses only the standard library: `optparse`, `open3`, `zlib`,
  `digest`, `fileutils` -- no gems to bundle install)
- `pg_dump`/`psql`/`createdb`/`dropdb` on `PATH` for PostgreSQL, or
  `mysqldump` for MySQL
- Database credentials available the way the underlying tool expects them
  (a `~/.pgpass` file or `PGPASSWORD` env var for Postgres; `~/.my.cnf` or
  `MYSQL_PWD` for MySQL) -- this script deliberately never accepts a
  password as a command-line flag, since that leaks into `ps` output and
  shell history

## Usage

```
ruby db_backup_manager.rb --engine postgres --db devopsdemo \
    --host 127.0.0.1 --user postgres --out /var/backups/db --keep 7 --verify

ruby db_backup_manager.rb --engine mysql --db appdb \
    --out /var/backups/db --keep 14 --json
```

| Flag | Meaning |
|---|---|
| `--engine postgres\|mysql` | which dump tool to shell out to |
| `--db NAME` | database name |
| `--host` / `--port` / `--user` | connection details (password via env, not a flag) |
| `--out DIR` | directory backups are written into |
| `--keep N` | how many most-recent backups to retain (default 7) |
| `--verify` | restore-test the dump into a scratch database (Postgres only) before trusting it |
| `--json` | emit a single JSON summary line instead of human text |

Exit codes: `0` backup (and verify, if requested) succeeded, `1` the dump
itself failed, `2` the backup succeeded but verification failed.

## How it works

1. **Command construction.** `pg_dump`/`mysqldump` argv arrays are built
   directly (never through a shell string), so database/user names can
   never break out into shell injection.
2. **Streaming compression.** `Open3.popen3` runs the dump tool and its
   stdout is piped straight into `Zlib::GzipWriter` via `IO.copy_stream` --
   the whole dump is never held in Ruby memory at once, so this scales to
   databases far bigger than the box's RAM. `stderr` is drained on a
   separate thread concurrently so a chatty dump tool can't deadlock the
   pipe.
3. **Retention rotation.** After a successful dump, `rotate_backups` globs
   `<db>_*.sql.gz` in the output directory, sorts by the embedded UTC
   timestamp, and deletes the oldest files beyond `--keep`.
4. **Restore verification (`--verify`).** Creates a throwaway
   `<db>_verify_<pid>` database, replays the compressed dump into it with
   `psql`, runs a cheap `information_schema.tables` count as a sanity
   check, and always drops the scratch database in an `ensure` block --
   even if the restore itself failed.

## Example output

```
Backup OK: /var/backups/db/devopsdemo_20260923T182737Z.sql.gz (801 bytes, 0.11s)
SHA256: e08716f17c077aa1d0edc995851c6752912b63447fd7c48fa007b5426b8f8810
Rotated out 2 old backup(s): devopsdemo_20260923T182747Z.sql.gz, devopsdemo_20260923T182749Z.sql.gz
VERIFY OK: restored 1 table(s) into a scratch database
```

Failure path (bad database name):

```
BACKUP FAILED: pg_dump exited 1: pg_dump: error: connection to server at "127.0.0.1",
port 5432 failed: FATAL:  database "doesnotexist123" does not exist
```

## Troubleshooting

- **`pg_dump: error: ... password authentication failed`** -- set
  `PGPASSWORD`, or better, a `~/.pgpass` line, rather than relying on trust
  auth in production.
- **`--verify` fails with "could not create scratch db"** -- the connecting
  user needs `CREATEDB` privilege; grant it or run verification as a
  superuser account dedicated to backups.
- **MySQL `--verify` is a no-op** -- this script only implements the
  restore-test for Postgres. For MySQL, the same pattern works: create a
  scratch database, pipe the gunzipped dump into `mysql <scratch_db>`, then
  query `information_schema.tables` the same way -- left as an extension
  since it needs a MySQL instance to test against.
- **Backups are tiny / empty** -- check `stderr` in the raised
  `DumpFailed` message first; a truncated dump usually means the connecting
  user lacks `SELECT` on one or more tables, which some dump tools warn
  about without failing the exit code.

## Extending it

- Add an S3/GCS upload step after a successful (and verified) backup.
- Add `--encrypt` piping the gzip stream through `age` or `openssl enc`
  before it touches disk.
- Add point-in-time-recovery awareness for Postgres (WAL archiving) rather
  than relying solely on periodic logical dumps.
- Implement the MySQL restore-test described above.

## Testing notes

Tested live against a real local PostgreSQL 16 instance in this
environment: created a seeded `devopsdemo` database, ran repeated backups
to exercise both the fresh-backup and retention-rotation code paths, and
confirmed `--verify` genuinely restores into a scratch database and reports
the correct table count. The failure path was verified against a
nonexistent database name, and the missing-required-argument path was
verified via the CLI's own validation. MySQL support uses the same
`Open3`-based command pattern as the Postgres path but was not exercised
against a live MySQL server in this environment.

## References

- [pg_dump](https://www.postgresql.org/docs/current/app-pgdump.html) /
  [PostgreSQL backup and restore](https://www.postgresql.org/docs/current/backup.html)
- [mysqldump](https://dev.mysql.com/doc/refman/8.0/en/mysqldump.html)
- [Ruby `Zlib` stdlib docs](https://docs.ruby-lang.org/en/3.3/Zlib.html)
- [Ruby `Open3` stdlib docs](https://docs.ruby-lang.org/en/3.3/Open3.html)
