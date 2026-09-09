#!/usr/bin/env ruby
# frozen_string_literal: true
#
# stale_file_cleaner.rb -- policy-driven cleanup of stale files on Linux.
#
# The classic `find /tmp -mtime +7 -delete` one-liner works until it doesn't:
# it has no dry-run that shows sizes, no per-directory rules, no protection
# for files still held open by a process, and no audit trail. This script
# fixes all of that with a small YAML policy file:
#
#   rules:
#     - path: /var/tmp
#       max_age_days: 14
#       pattern: "**/*"          # glob relative to path (default: everything)
#     - path: /var/log/myapp
#       max_age_days: 30
#       pattern: "**/*.log.*"    # only rotated logs
#       min_size_kb: 0
#     - path: /home/deploy/releases
#       max_age_days: 45
#       keep_newest: 5           # never drop below N newest matches
#   protect:                     # never touch anything matching these globs
#     - "**/.git/**"
#     - "**/*.pid"
#
# Usage:
#   ruby stale_file_cleaner.rb --policy cleanup.yml            # dry-run (default)
#   ruby stale_file_cleaner.rb --policy cleanup.yml --apply    # really delete
#   ruby stale_file_cleaner.rb --policy cleanup.yml --json     # JSON report
#   ruby stale_file_cleaner.rb --policy cleanup.yml --apply --prune-empty-dirs
#
# Safety rails: dry-run by default, never follows symlinks, refuses to run a
# rule whose path is / or a home directory root, skips files that are still
# open (checked via /proc/*/fd), and logs every deletion with size and age.

require 'yaml'
require 'json'
require 'optparse'
require 'time'
require 'pathname'

FORBIDDEN_ROOTS = ['/', '/home', '/root', '/etc', '/usr', '/bin', '/sbin', '/lib', '/boot', '/var', '/proc', '/sys', '/dev'].freeze

# Candidate file plus the facts we decided on.
Candidate = Struct.new(:path, :size, :mtime, :age_days, :rule_path, :action, :reason)

class OpenFileIndex
  # Build a Set of every file path currently held open by any process, by
  # resolving /proc/<pid>/fd/* symlinks. Cheap enough to do once per run.
  def initialize
    @open = {}
    Dir.glob('/proc/[0-9]*/fd/*').each do |fd|
      target = File.readlink(fd)
      @open[target] = true if target.start_with?('/')
    rescue SystemCallError
      next # process exited or permission denied; both fine
    end
  end

  def open?(path)
    @open.key?(path)
  end
end

class StaleFileCleaner
  attr_reader :candidates, :errors

  def initialize(policy, apply: false, prune_empty_dirs: false, now: Time.now, logger: $stderr)
    @rules = Array(policy['rules'])
    @protect = Array(policy['protect'])
    @apply = apply
    @prune_empty_dirs = prune_empty_dirs
    @now = now
    @log = logger
    @candidates = []
    @errors = []
    @open_index = nil
  end

  def run
    @rules.each { |rule| evaluate_rule(rule) }
    execute if @apply
    self
  end

  # ---- evaluation -----------------------------------------------------

  def evaluate_rule(rule)
    root = File.expand_path(rule.fetch('path'))
    if FORBIDDEN_ROOTS.include?(root) || root =~ %r{\A/home/[^/]+\z}
      @errors << "refusing to clean #{root}: too dangerous as a rule root"
      return
    end
    unless File.directory?(root)
      @errors << "skipping #{root}: not a directory"
      return
    end

    max_age = Float(rule.fetch('max_age_days'))
    min_size = Integer(rule.fetch('min_size_kb', 0)) * 1024
    keep_newest = Integer(rule.fetch('keep_newest', 0))
    pattern = rule.fetch('pattern', '**/*')

    # File::FNM_DOTMATCH so dotfiles count; we filter dirs/symlinks ourselves.
    matches = Dir.glob(File.join(root, pattern), File::FNM_DOTMATCH)
                 .reject { |p| File.symlink?(p) || !File.file?(p) }
                 .reject { |p| protected?(p) }
                 .map { |p| [p, File.stat(p)] }
                 .sort_by { |_, st| -st.mtime.to_f } # newest first

    matches.each_with_index do |(path, st), idx|
      age = (@now - st.mtime) / 86_400.0
      c = Candidate.new(path, st.size, st.mtime, age.round(1), root, :keep, nil)
      if idx < keep_newest
        c.reason = "within keep_newest=#{keep_newest}"
      elsif age < max_age
        c.reason = "younger than #{max_age.to_i}d"
      elsif st.size < min_size
        c.reason = "smaller than #{min_size / 1024}KB"
      elsif open_index.open?(path)
        c.reason = 'still open by a process'
      else
        c.action = :delete
        c.reason = "#{age.round}d old > #{max_age.to_i}d"
      end
      @candidates << c
    end
  end

  def protected?(path)
    @protect.any? { |glob| File.fnmatch?(glob, path, File::FNM_PATHNAME | File::FNM_DOTMATCH | File::FNM_EXTGLOB) }
  end

  def open_index
    @open_index ||= OpenFileIndex.new
  end

  # ---- execution ------------------------------------------------------

  def execute
    deletable.each do |c|
      File.delete(c.path)
      c.action = :deleted
      @log.puts "deleted #{c.path} (#{human(c.size)}, #{c.age_days}d)"
    rescue SystemCallError => e
      c.action = :failed
      c.reason = e.message
      @errors << "#{c.path}: #{e.message}"
    end
    prune_dirs if @prune_empty_dirs
  end

  # Remove now-empty directories under each rule root, deepest first, but
  # never the rule root itself.
  def prune_dirs
    @rules.each do |rule|
      root = File.expand_path(rule['path'])
      next unless File.directory?(root)

      Dir.glob(File.join(root, '**/'), File::FNM_DOTMATCH).map { |d| d.chomp('/') }
         .reject { |d| d == root || d.end_with?('/.', '/..') }
         .sort_by { |d| -d.count('/') }
         .each do |d|
        next unless (Dir.children(d) rescue [nil]).empty?

        Dir.rmdir(d)
        @log.puts "pruned empty dir #{d}"
      rescue SystemCallError => e
        @errors << "#{d}: #{e.message}"
      end
    end
  end

  # ---- reporting ------------------------------------------------------

  def deletable
    @candidates.select { |c| c.action == :delete }
  end

  def summary
    done = @candidates.select { |c| c.action == :deleted }
    {
      mode: @apply ? 'apply' : 'dry-run',
      scanned: @candidates.size,
      to_delete: deletable.size + done.size,
      bytes_reclaimable: (deletable + done).sum(&:size),
      deleted: done.size,
      bytes_freed: done.sum(&:size),
      failed: @candidates.count { |c| c.action == :failed },
      errors: @errors
    }
  end

  def to_json(*_args)
    JSON.pretty_generate(summary.merge(files: @candidates.map(&:to_h)))
  end

  def to_text
    s = summary
    lines = ["stale_file_cleaner  mode=#{s[:mode]}  scanned=#{s[:scanned]}"]
    lines << ('-' * 72)
    @candidates.select { |c| c.action != :keep }.sort_by(&:path).each do |c|
      lines << format('%-8s %9s %6.1fd  %s', c.action.to_s.upcase, human(c.size), c.age_days, c.path)
    end
    lines << ('-' * 72)
    lines << "would reclaim #{human(s[:bytes_reclaimable])} across #{s[:to_delete]} file(s)" unless @apply
    lines << "freed #{human(s[:bytes_freed])} across #{s[:deleted]} file(s), #{s[:failed]} failed" if @apply
    s[:errors].each { |e| lines << "ERROR #{e}" }
    lines.join("\n")
  end

  def human(bytes)
    units = %w[B KB MB GB TB]
    i = 0
    b = bytes.to_f
    while b >= 1024 && i < units.size - 1
      b /= 1024
      i += 1
    end
    i.zero? ? "#{bytes}B" : format('%.1f%s', b, units[i])
  end
end

if __FILE__ == $PROGRAM_NAME
  opts = { policy: nil, apply: false, json: false, prune: false }
  OptionParser.new do |o|
    o.banner = 'Usage: stale_file_cleaner.rb --policy FILE [--apply] [--json] [--prune-empty-dirs]'
    o.on('--policy FILE', 'YAML policy file (required)') { |f| opts[:policy] = f }
    o.on('--apply', 'Actually delete (default is dry-run)') { opts[:apply] = true }
    o.on('--json', 'JSON report on stdout') { opts[:json] = true }
    o.on('--prune-empty-dirs', 'Remove directories left empty after deletion') { opts[:prune] = true }
  end.parse!
  abort 'error: --policy FILE is required' unless opts[:policy]

  policy = YAML.safe_load(File.read(opts[:policy]))
  cleaner = StaleFileCleaner.new(policy, apply: opts[:apply], prune_empty_dirs: opts[:prune]).run
  puts(opts[:json] ? cleaner.to_json : cleaner.to_text)
  exit(cleaner.errors.empty? ? 0 : 1)
end
