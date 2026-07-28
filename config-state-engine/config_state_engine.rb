#!/usr/bin/env ruby
# frozen_string_literal: true
#
# config_state_engine.rb
#
# A minimal, Chef/Puppet/Ansible-style *idempotent* configuration engine in
# ~180 lines of pure Ruby: declare the state you want ("this directory
# should exist", "this file should have this exact content and mode",
# "this line should be present in this file"), and the engine only touches
# the filesystem when reality doesn't already match. Running it twice in a
# row produces zero changes the second time -- that's the whole point.
#
# Why this exists: pulling in Chef, Puppet, or Ansible for a handful of
# config-file guarantees on a small fleet is a lot of machinery (agents,
# a server, a DSL with its own runtime) for something you can express in a
# few declarative lines. This script shows the *pattern* underneath all of
# them -- check current state, diff against desired state, apply only the
# delta, report what changed -- in a form small enough to read end-to-end
# and adapt directly.
#
# Usage:
#   ruby config_state_engine.rb --target-dir /etc/myapp
#   ruby config_state_engine.rb --target-dir /etc/myapp --dry-run
#   ruby config_state_engine.rb --target-dir /etc/myapp --check   # CI-style: exit 1 on drift, no changes made
#
# Requires: Ruby >= 2.7 (stdlib only: fileutils, optparse -- no gems).

require 'fileutils'
require 'optparse'

# --- Resource base class -----------------------------------------------------
#
# Every resource type implements the same two-step contract: #check reports
# whether the current state already matches the desired state (returning a
# human-readable reason when it doesn't), and #apply makes exactly the
# change needed to reach the desired state. The runner (ConfigState) never
# needs to know the difference between a file, a directory, or a line --
# it just calls #check, and #apply only if #check said something was off.
class Resource
  attr_reader :label

  CheckResult = Struct.new(:in_sync, :reason)

  def initialize(label)
    @label = label
  end

  def check
    raise NotImplementedError
  end

  def apply
    raise NotImplementedError
  end
end

# Ensures a directory exists (optionally with a specific permission mode).
class DirectoryResource < Resource
  def initialize(path, mode: nil)
    super("directory #{path}")
    @path = path
    @mode = mode
  end

  def check
    return CheckResult.new(false, 'does not exist') unless Dir.exist?(@path)

    if @mode && (current = File.stat(@path).mode & 0o777) != @mode
      return CheckResult.new(false, format('mode is %04o, want %04o', current, @mode))
    end

    CheckResult.new(true, nil)
  end

  def apply
    FileUtils.mkdir_p(@path)
    File.chmod(@mode, @path) if @mode
  end
end

# Ensures a file exists with exact content (and optionally an exact mode).
# "Exact content" is deliberate: config drift usually means someone hand-
# edited a managed file, and silently merging changes would hide that.
class FileResource < Resource
  def initialize(path, content:, mode: nil)
    super("file #{path}")
    @path = path
    @content = content
    @mode = mode
  end

  def check
    return CheckResult.new(false, 'does not exist') unless File.exist?(@path)
    return CheckResult.new(false, 'content differs') unless File.read(@path) == @content

    if @mode && (current = File.stat(@path).mode & 0o777) != @mode
      return CheckResult.new(false, format('mode is %04o, want %04o', current, @mode))
    end

    CheckResult.new(true, nil)
  end

  def apply
    FileUtils.mkdir_p(File.dirname(@path))
    File.write(@path, @content)
    File.chmod(@mode, @path) if @mode
  end
end

# Ensures a specific line is present somewhere in a file, without touching
# any other line -- the classic "add this one entry to /etc/hosts (or a
# config file) if it's missing" task, done safely and idempotently.
class LineInFileResource < Resource
  def initialize(path, line:)
    super("line in #{path}: #{line.inspect}")
    @path = path
    @line = line
  end

  def check
    return CheckResult.new(false, 'file does not exist') unless File.exist?(@path)

    lines = File.readlines(@path, chomp: true)
    return CheckResult.new(true, nil) if lines.include?(@line)

    CheckResult.new(false, 'line not present')
  end

  def apply
    FileUtils.touch(@path) unless File.exist?(@path)
    File.open(@path, 'a') { |f| f.puts(@line) }
  end
end

# --- Runner ------------------------------------------------------------------
#
# Collects resources declared via the ensure_* DSL methods, then runs them
# in declaration order, printing one line per resource: OK (already in the
# desired state), CHANGED (drift found and fixed), WOULD CHANGE (drift
# found, --dry-run so nothing was touched), or DRIFT (drift found, --check
# mode so nothing was touched and the run will exit non-zero).
class ConfigState
  Mode = Struct.new(:dry_run, :check_only)

  def self.run(dry_run: false, check_only: false)
    engine = new(Mode.new(dry_run, check_only))
    yield engine
    engine.execute
  end

  def initialize(mode)
    @mode = mode
    @resources = []
  end

  def ensure_directory(path, mode: nil)
    @resources << DirectoryResource.new(path, mode: mode)
  end

  def ensure_file(path, content:, mode: nil)
    @resources << FileResource.new(path, content: content, mode: mode)
  end

  def ensure_line_in_file(path, line:)
    @resources << LineInFileResource.new(path, line: line)
  end

  # Runs every declared resource and returns a summary hash. Also prints a
  # one-line status per resource as it goes, so a long run still shows
  # partial progress if interrupted.
  def execute
    counts = Hash.new(0)

    @resources.each do |resource|
      result = resource.check

      if result.in_sync
        counts[:ok] += 1
        puts "OK          #{resource.label}"
        next
      end

      if @mode.check_only
        counts[:drift] += 1
        puts "DRIFT       #{resource.label} (#{result.reason})"
      elsif @mode.dry_run
        counts[:would_change] += 1
        puts "WOULD CHANGE #{resource.label} (#{result.reason})"
      else
        resource.apply
        counts[:changed] += 1
        puts "CHANGED     #{resource.label} (#{result.reason})"
      end
    end

    counts
  end
end

# --- CLI entry point -----------------------------------------------------
if $PROGRAM_NAME == __FILE__
  options = { target_dir: '/tmp/config-state-demo', dry_run: false, check: false }
  OptionParser.new do |opts|
    opts.banner = 'Usage: config_state_engine.rb [options]'
    opts.on('--target-dir DIR', 'Directory the demo manifest manages (default /tmp/config-state-demo)') { |v| options[:target_dir] = v }
    opts.on('--dry-run', 'Report what would change without touching the filesystem') { options[:dry_run] = true }
    opts.on('--check', 'CI mode: exit 1 if anything is out of sync, without applying changes') { options[:check] = true }
  end.parse!

  dir = options[:target_dir]

  # This is the "manifest" -- the declarative part you'd customize per
  # project. Everything above this line is the reusable engine; everything
  # below is what a sysadmin actually writes day to day.
  counts = ConfigState.run(dry_run: options[:dry_run], check_only: options[:check]) do |c|
    c.ensure_directory dir, mode: 0o755
    c.ensure_directory File.join(dir, 'conf.d'), mode: 0o755
    c.ensure_file File.join(dir, 'app.yml'),
                  content: "env: production\nlog_level: info\n",
                  mode: 0o644
    # Deliberately a *different* file than app.yml above: a single resource
    # should own a given file's exact content, or append single lines to an
    # unmanaged file -- never both, or the two resources will fight over
    # the same bytes and the run will never settle (see Troubleshooting).
    c.ensure_line_in_file File.join(dir, 'hosts.local'), line: '127.0.0.1 myapp.local'
  end

  puts '---'
  puts "ok=#{counts[:ok]} changed=#{counts[:changed]} would_change=#{counts[:would_change]} drift=#{counts[:drift]}"

  exit(1) if options[:check] && counts[:drift].positive?
end
