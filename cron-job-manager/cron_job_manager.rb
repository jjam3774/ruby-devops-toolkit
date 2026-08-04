#!/usr/bin/env ruby
# frozen_string_literal: true
#
# cron_job_manager.rb
#
# Safely list, add, update, and remove crontab entries from scripts --
# without ever hand-editing `crontab -e` or risking a typo that wipes out
# someone else's jobs. Every entry this tool writes is wrapped in a
# uniquely-tagged marker block, so add/remove/update only ever touch the
# lines they own; everything else in the crontab is left byte-for-byte
# untouched. Schedules are validated against cron grammar *before* they
# ever reach `crontab -`, so a bad schedule fails loudly in Ruby instead
# of silently corrupting the user's crontab.
#
# Usage:
#   ruby cron_job_manager.rb list [--json]
#   ruby cron_job_manager.rb add    --id ID --schedule "SCHED" --command "CMD" [--dry-run]
#   ruby cron_job_manager.rb remove --id ID [--dry-run]
#
# Options common to all subcommands:
#   --crontab-bin PATH   Path to the crontab binary (default: "crontab").
#                         Overridable so this can be pointed at a stub for
#                         testing, or at a wrapper for a specific user.
#
require 'optparse'
require 'json'
require 'open3'

MARKER_BEGIN = 'BEGIN cron_job_manager'
MARKER_END = 'END cron_job_manager'

# ---------------------------------------------------------------------------
# CronValidator: pure-function validation of the 5 standard cron fields
# (minute hour day-of-month month day-of-week). Deliberately conservative --
# it accepts the common syntaxes (*, N, N-M, N,M,O, */N, N-M/S) and rejects
# anything else with a specific reason, rather than trying to be a full
# cron-grammar parser.
# ---------------------------------------------------------------------------
module CronValidator
  RANGES = [
    (0..59), # minute
    (0..23), # hour
    (1..31), # day of month
    (1..12), # month
    (0..7)   # day of week (0 and 7 both == Sunday)
  ].freeze

  FIELD_NAMES = %w[minute hour day-of-month month day-of-week].freeze

  # Returns nil if the schedule is valid, or a human-readable error string.
  def self.validate(schedule)
    fields = schedule.strip.split(/\s+/)
    return "expected 5 fields (minute hour dom month dow), got #{fields.size}: #{schedule.inspect}" unless fields.size == 5

    fields.each_with_index do |field, idx|
      err = validate_field(field, RANGES[idx])
      return "field #{idx + 1} (#{FIELD_NAMES[idx]}) invalid: #{err} in #{field.inspect}" if err
    end
    nil
  end

  def self.validate_field(field, range)
    field.split(',').each do |part|
      base, step = part.split('/', 2)
      if step && step !~ /\A\d+\z/
        return 'step must be a positive integer'
      end

      case base
      when '*'
        next
      when /\A\d+\z/
        return "value #{base} out of range #{range}" unless range.cover?(base.to_i)
      when /\A(\d+)-(\d+)\z/
        lo, hi = Regexp.last_match(1).to_i, Regexp.last_match(2).to_i
        return "range #{lo}-#{hi} out of bounds #{range}" unless range.cover?(lo) && range.cover?(hi)
        return "range start #{lo} is greater than end #{hi}" if lo > hi
      else
        return "unrecognized token #{base.inspect}"
      end
    end
    nil
  end
end

# ---------------------------------------------------------------------------
# CrontabIO: thin wrapper around `crontab -l` / `crontab -` so the rest of
# the tool never shells out directly. Missing crontab (no entries yet) is
# treated as an empty crontab rather than an error, matching real-world
# `crontab -l` behavior (exit code 1, "no crontab for user" on stderr).
# ---------------------------------------------------------------------------
class CrontabIO
  class Error < StandardError; end

  def initialize(crontab_bin: 'crontab')
    @crontab_bin = crontab_bin
  end

  def read
    out, err, status = Open3.capture3(@crontab_bin, '-l')
    return out if status.success?
    return '' if err =~ /no crontab for/i

    raise Error, "`#{@crontab_bin} -l` failed: #{err.strip}"
  end

  def write(contents)
    out, err, status = Open3.capture3(@crontab_bin, '-', stdin_data: contents)
    raise Error, "`#{@crontab_bin} -` failed: #{err.strip} #{out.strip}" unless status.success?

    true
  end
end

# ---------------------------------------------------------------------------
# ManagedCrontab: parses the raw crontab text into a list of "blocks"
# (either a managed block we can address by id, or an opaque passthrough
# block of everything else), and knows how to add/update/remove a managed
# block by id while preserving line order and untouched content exactly.
# ---------------------------------------------------------------------------
class ManagedCrontab
  ManagedEntry = Struct.new(:id, :schedule, :command, keyword_init: true)

  def initialize(raw_text)
    @lines = raw_text.split("\n")
  end

  def managed_entries
    entries = []
    @lines.each_with_index do |line, idx|
      next unless line.include?(MARKER_BEGIN)

      id = line[/#{MARKER_BEGIN}:(\S+)/, 1]
      body = @lines[idx + 1]
      next unless body

      schedule = body.split(/\s+/, 6)[0, 5].join(' ')
      command = body.split(/\s+/, 6)[5]
      entries << ManagedEntry.new(id: id, schedule: schedule, command: command)
    end
    entries
  end

  # Adds a new managed entry, or replaces the existing one with the same id
  # in place (so re-running `add` for the same id is idempotent and doesn't
  # duplicate or reorder entries).
  def upsert(id, schedule, command)
    block = ["# #{MARKER_BEGIN}:#{id}", "#{schedule} #{command}", "# #{MARKER_END}:#{id}"]

    start_idx = find_block_start(id)
    if start_idx
      end_idx = find_block_end(id, start_idx)
      @lines[start_idx..end_idx] = block
    else
      @lines << "# #{MARKER_BEGIN}:#{id}"
      @lines << "#{schedule} #{command}"
      @lines << "# #{MARKER_END}:#{id}"
    end
    self
  end

  # Removes a managed entry by id. Returns true if something was removed.
  def remove(id)
    start_idx = find_block_start(id)
    return false unless start_idx

    end_idx = find_block_end(id, start_idx)
    @lines.slice!(start_idx..end_idx)
    true
  end

  def to_s
    @lines.join("\n") + "\n"
  end

  private

  def find_block_start(id)
    @lines.index { |l| l.include?("#{MARKER_BEGIN}:#{id}") }
  end

  def find_block_end(id, start_idx)
    idx = @lines[start_idx..].index { |l| l.include?("#{MARKER_END}:#{id}") }
    idx ? start_idx + idx : start_idx + 2
  end
end

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def run_list(crontab_io, json:)
  entries = ManagedCrontab.new(crontab_io.read).managed_entries
  if json
    puts JSON.pretty_generate(entries.map(&:to_h))
  elsif entries.empty?
    puts 'No cron_job_manager-managed entries found.'
  else
    printf("%-24s %-16s %s\n", 'ID', 'SCHEDULE', 'COMMAND')
    puts '-' * 80
    entries.each { |e| printf("%-24s %-16s %s\n", e.id, e.schedule, e.command) }
  end
  0
end

def run_add(crontab_io, id:, schedule:, command:, dry_run:)
  if (err = CronValidator.validate(schedule))
    warn "error: invalid schedule -- #{err}"
    return 1
  end
  if id.nil? || id.strip.empty?
    warn 'error: --id is required'
    return 1
  end
  if command.nil? || command.strip.empty?
    warn 'error: --command is required'
    return 1
  end

  managed = ManagedCrontab.new(crontab_io.read)
  action = managed.managed_entries.any? { |e| e.id == id } ? 'update' : 'add'
  managed.upsert(id, schedule, command)

  if dry_run
    puts "[dry-run] would #{action} entry '#{id}': #{schedule} #{command}"
  else
    crontab_io.write(managed.to_s)
    puts "#{action == 'update' ? 'Updated' : 'Added'} entry '#{id}': #{schedule} #{command}"
  end
  0
end

def run_remove(crontab_io, id:, dry_run:)
  if id.nil? || id.strip.empty?
    warn 'error: --id is required'
    return 1
  end

  managed = ManagedCrontab.new(crontab_io.read)
  found = managed.managed_entries.any? { |e| e.id == id }
  unless found
    warn "error: no managed entry with id '#{id}' found"
    return 1
  end

  if dry_run
    puts "[dry-run] would remove entry '#{id}'"
  else
    managed.remove(id)
    crontab_io.write(managed.to_s)
    puts "Removed entry '#{id}'"
  end
  0
end

if __FILE__ == $PROGRAM_NAME
  options = { crontab_bin: 'crontab', dry_run: false, json: false }
  subcommand = ARGV.shift

  parser = OptionParser.new do |opts|
    opts.banner = 'Usage: ruby cron_job_manager.rb {list|add|remove} [options]'
    opts.on('--id ID', 'Unique identifier for the managed entry') { |v| options[:id] = v }
    opts.on('--schedule SCHED', 'Cron schedule, 5 fields, e.g. "0 2 * * *"') { |v| options[:schedule] = v }
    opts.on('--command CMD', 'Command line to run') { |v| options[:command] = v }
    opts.on('--crontab-bin PATH', 'Path to crontab binary (default: crontab)') { |v| options[:crontab_bin] = v }
    opts.on('--dry-run', 'Preview the change without writing the crontab') { options[:dry_run] = true }
    opts.on('--json', 'JSON output for `list`') { options[:json] = true }
  end
  parser.parse!(ARGV)

  crontab_io = CrontabIO.new(crontab_bin: options[:crontab_bin])

  status =
    begin
      case subcommand
      when 'list'
        run_list(crontab_io, json: options[:json])
      when 'add'
        run_add(crontab_io, id: options[:id], schedule: options[:schedule],
                             command: options[:command], dry_run: options[:dry_run])
      when 'remove'
        run_remove(crontab_io, id: options[:id], dry_run: options[:dry_run])
      else
        warn parser
        1
      end
    rescue CrontabIO::Error => e
      warn "error: #{e.message}"
      2
    end

  exit status
end
