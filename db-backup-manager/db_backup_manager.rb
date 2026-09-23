#!/usr/bin/env ruby
# frozen_string_literal: true
#
# db_backup_manager.rb -- Automated PostgreSQL/MySQL logical backups with
# gzip compression, retention rotation, and restore verification.
#
# Wraps the platform-native dump tools (pg_dump / mysqldump) rather than
# reimplementing dump logic in Ruby -- Ruby's job here is orchestration:
# picking the right command, compressing the result, enforcing a retention
# policy, and optionally proving the backup is actually restorable.
#
# Usage:
#   ruby db_backup_manager.rb --engine postgres --db devopsdemo --out /var/backups/db --keep 7
#   ruby db_backup_manager.rb --engine mysql    --db appdb      --out /var/backups/db --keep 14 --verify
#
# Exit codes: 0 = backup (and verify, if requested) succeeded
#             1 = backup failed
#             2 = backup succeeded but verification failed

require 'optparse'
require 'open3'
require 'time'
require 'fileutils'
require 'zlib'
require 'digest'

# ---------------------------------------------------------------------------
# Option parsing
# ---------------------------------------------------------------------------
options = {
  engine: nil,
  db: nil,
  host: 'localhost',
  port: nil,
  user: ENV['USER'],
  out_dir: './db_backups',
  keep: 7,
  verify: false,
  json: false
}

OptionParser.new do |o|
  o.banner = 'Usage: db_backup_manager.rb --engine postgres|mysql --db NAME [options]'
  o.on('--engine ENGINE', %w[postgres mysql], 'Database engine: postgres or mysql') { |v| options[:engine] = v }
  o.on('--db NAME', 'Database name to back up') { |v| options[:db] = v }
  o.on('--host HOST', 'Database host (default: localhost)') { |v| options[:host] = v }
  o.on('--port PORT', Integer, 'Database port (defaults: 5432/3306)') { |v| options[:port] = v }
  o.on('--user USER', 'Database user (default: $USER)') { |v| options[:user] = v }
  o.on('--out DIR', 'Directory to write backups into') { |v| options[:out_dir] = v }
  o.on('--keep N', Integer, 'Number of most-recent backups to retain (default: 7)') { |v| options[:keep] = v }
  o.on('--verify', 'Restore-test the backup into a scratch database before trusting it') { options[:verify] = true }
  o.on('--json', 'Emit a JSON summary line instead of human text') { options[:json] = true }
  o.on('-h', '--help', 'Show this help') { puts o; exit 0 }
end.parse!

if options[:engine].nil? || options[:db].nil?
  warn 'Error: --engine and --db are required (see --help)'
  exit 1
end

# PGPASSWORD / MYSQL_PWD are read from the environment by the underlying
# tools themselves -- we never accept a password on the command line, since
# that would leak it into `ps` output and shell history.
class DumpFailed < StandardError; end
class VerifyFailed < StandardError; end

# ---------------------------------------------------------------------------
# Engine-specific command builders. Each returns the argv array to run via
# Open3 (never a shell string -- avoids injection through db/user names).
# ---------------------------------------------------------------------------
def pg_dump_cmd(opts)
  cmd = ['pg_dump', '--no-password', '--format=plain']
  cmd += ['--host', opts[:host]]
  cmd += ['--port', opts[:port].to_s] if opts[:port]
  cmd += ['--username', opts[:user]] if opts[:user]
  cmd << opts[:db]
  cmd
end

def mysqldump_cmd(opts)
  cmd = ['mysqldump', '--single-transaction', '--routines']
  cmd += ['--host', opts[:host]]
  cmd += ['--port', opts[:port].to_s] if opts[:port]
  cmd += ['--user', opts[:user]] if opts[:user]
  cmd << opts[:db]
  cmd
end

# ---------------------------------------------------------------------------
# Run the dump command, streaming stdout straight into a gzip writer so a
# multi-GB database never has to sit fully in Ruby memory at once.
# ---------------------------------------------------------------------------
def run_dump(cmd, dest_path)
  Zlib::GzipWriter.open(dest_path) do |gz|
    stdout_thread_err = nil
    Open3.popen3(*cmd) do |stdin, stdout, stderr, wait_thr|
      stdin.close
      err_reader = Thread.new { stderr.read }
      begin
        IO.copy_stream(stdout, gz)
      rescue IOError => e
        stdout_thread_err = e
      end
      exit_status = wait_thr.value
      stderr_output = err_reader.value
      unless exit_status.success?
        raise DumpFailed, "#{cmd.first} exited #{exit_status.exitstatus}: #{stderr_output.strip}"
      end
      raise DumpFailed, stdout_thread_err.message if stdout_thread_err
    end
  end
end

# ---------------------------------------------------------------------------
# Retention: keep only the N most recent backups for this db+engine.
# ---------------------------------------------------------------------------
def rotate_backups(out_dir, db, keep)
  pattern = File.join(out_dir, "#{db}_*.sql.gz")
  existing = Dir.glob(pattern).sort
  removed = []
  while existing.length > keep
    victim = existing.shift
    File.delete(victim)
    removed << victim
  end
  removed
end

# ---------------------------------------------------------------------------
# Verification: restore the dump into a throwaway scratch database and run a
# cheap sanity check (row count on a system catalog / information_schema
# query) so a truncated or corrupt dump fails loudly instead of silently.
# ---------------------------------------------------------------------------
def verify_postgres(dest_path, opts)
  scratch_db = "#{opts[:db]}_verify_#{Process.pid}"
  create_cmd = ['createdb', '--host', opts[:host]]
  create_cmd += ['--username', opts[:user]] if opts[:user]
  create_cmd << scratch_db
  _out, err, status = Open3.capture3(*create_cmd)
  raise VerifyFailed, "could not create scratch db: #{err}" unless status.success?

  begin
    restore_cmd = ['psql', '--host', opts[:host], '--quiet', '--set', 'ON_ERROR_STOP=1']
    restore_cmd += ['--username', opts[:user]] if opts[:user]
    restore_cmd += ['--dbname', scratch_db]

    Zlib::GzipReader.open(dest_path) do |gz|
      _out, err, status = Open3.capture3(*restore_cmd, stdin_data: gz.read)
      raise VerifyFailed, "restore failed: #{err}" unless status.success?
    end

    count_cmd = ['psql', '--host', opts[:host], '--tuples-only', '--no-align',
                 '--command', "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'"]
    count_cmd += ['--username', opts[:user]] if opts[:user]
    count_cmd += ['--dbname', scratch_db]
    out, err, status = Open3.capture3(*count_cmd)
    raise VerifyFailed, "post-restore check failed: #{err}" unless status.success?

    { tables_restored: out.strip.to_i }
  ensure
    drop_cmd = ['dropdb', '--host', opts[:host]]
    drop_cmd += ['--username', opts[:user]] if opts[:user]
    drop_cmd << scratch_db
    Open3.capture3(*drop_cmd)
  end
end

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
FileUtils.mkdir_p(options[:out_dir])
timestamp = Time.now.utc.strftime('%Y%m%dT%H%M%SZ')
filename = "#{options[:db]}_#{timestamp}.sql.gz"
dest_path = File.join(options[:out_dir], filename)

result = { db: options[:db], engine: options[:engine], file: dest_path, verified: false }

begin
  cmd = options[:engine] == 'postgres' ? pg_dump_cmd(options) : mysqldump_cmd(options)
  start = Time.now
  run_dump(cmd, dest_path)
  result[:duration_s] = (Time.now - start).round(2)
  result[:size_bytes] = File.size(dest_path)
  result[:sha256] = Digest::SHA256.file(dest_path).hexdigest
rescue DumpFailed => e
  File.delete(dest_path) if File.exist?(dest_path)
  if options[:json]
    puts({ db: options[:db], error: e.message }.to_json)
  else
    warn "BACKUP FAILED: #{e.message}"
  end
  exit 1
end

removed = rotate_backups(options[:out_dir], options[:db], options[:keep])
result[:rotated_out] = removed

exit_code = 0
if options[:verify]
  begin
    if options[:engine] == 'postgres'
      verify_info = verify_postgres(dest_path, options)
      result[:verified] = true
      result[:verify_info] = verify_info
    else
      warn 'NOTE: --verify is only implemented for postgres in this script; see README for the MySQL approach.'
    end
  rescue VerifyFailed => e
    result[:verified] = false
    result[:verify_error] = e.message
    exit_code = 2
  end
end

if options[:json]
  require 'json'
  puts result.to_json
else
  puts "Backup OK: #{dest_path} (#{result[:size_bytes]} bytes, #{result[:duration_s]}s)"
  puts "SHA256: #{result[:sha256]}"
  puts "Rotated out #{removed.length} old backup(s): #{removed.join(', ')}" unless removed.empty?
  if options[:verify]
    if result[:verified]
      puts "VERIFY OK: restored #{result[:verify_info][:tables_restored]} table(s) into a scratch database"
    else
      puts "VERIFY FAILED: #{result[:verify_error]}"
    end
  end
end

exit exit_code
