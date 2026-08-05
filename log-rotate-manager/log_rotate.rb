#!/usr/bin/env ruby
# frozen_string_literal: true
#
# log_rotate.rb -- A small, dependency-free logrotate reimplementation in Ruby.
#
# Problem it solves: lots of in-house services (a Sinatra app, a background
# worker, a custom daemon) just do `File.open("app.log", "a")` and never stop
# writing. Nobody wired up logrotate for them, so six months later a box
# fills its disk with a single 40GB log file. This script is a portable,
# no-gems tool you can drop next to any app and run from cron (or on a timer
# on Windows) to keep log files bounded: rotate by size or age, compress old
# generations, enforce a retention count, and optionally signal the owning
# process to reopen its log handle after rotation (the same "copytruncate"
# vs "signal" trade-off real logrotate makes).
#
# Usage:
#   ruby log_rotate.rb --config rotate.json
#   ruby log_rotate.rb --config rotate.json --dry-run
#   ruby log_rotate.rb --config rotate.json --json
#
# Exit codes: 0 = ok (rotated 0+ files, no errors), 1 = one or more rotation
# errors occurred (permissions, missing file, etc.) -- cron/monitoring
# friendly.

require 'optparse'
require 'json'
require 'zlib'
require 'fileutils'
require 'time'

module LogRotate
  # A single log file's rotation policy, loaded from the JSON config.
  RuleResult = Struct.new(:path, :action, :detail, :error, keyword_init: true)

  class Rule
    attr_reader :path, :max_bytes, :max_age_days, :keep, :compress, :post_rotate

    def initialize(cfg)
      @path         = cfg.fetch('path')
      @max_bytes    = cfg['max_bytes']                # nil means "no size trigger"
      @max_age_days = cfg['max_age_days']              # nil means "no age trigger"
      @keep         = cfg.fetch('keep', 7)
      @compress     = cfg.fetch('compress', true)
      @post_rotate  = cfg['post_rotate']                # optional shell command, e.g. signal to reopen
      raise ArgumentError, "rule for #{@path} needs max_bytes and/or max_age_days" if @max_bytes.nil? && @max_age_days.nil?
    end

    # Should this file rotate right now?
    def due?(stat)
      return true if max_bytes && stat.size >= max_bytes
      return true if max_age_days && (Time.now - stat.mtime) >= max_age_days * 86_400
      false
    end
  end

  class Rotator
    def initialize(rules, dry_run: false)
      @rules = rules
      @dry_run = dry_run
    end

    def run
      @rules.map { |rule| rotate_one(rule) }
    end

    private

    # Find the existing rotated generations for a path, e.g.
    # app.log.1, app.log.2.gz, app.log.3.gz -> [1, 2, 3]
    def existing_generations(path)
      dir  = File.dirname(path)
      base = File.basename(path)
      Dir.children(dir)
         .filter_map { |f| f[/\A#{Regexp.escape(base)}\.(\d+)(\.gz)?\z/, 1]&.to_i }
         .sort
    rescue Errno::ENOENT
      []
    end

    def rotate_one(rule)
      path = rule.path
      unless File.exist?(path)
        return RuleResult.new(path: path, action: :skipped, detail: 'file does not exist', error: false)
      end

      stat = File.stat(path)
      unless rule.due?(stat)
        return RuleResult.new(path: path, action: :skipped, detail: 'not due', error: false)
      end

      begin
        shift_generations(rule)
        rotated_to = perform_rotation(rule)
        enforce_retention(rule)
        run_post_rotate(rule)
        RuleResult.new(path: path, action: :rotated, detail: "-> #{rotated_to}", error: false)
      rescue StandardError => e
        RuleResult.new(path: path, action: :error, detail: e.message, error: true)
      end
    end

    # Shift app.log.2 -> app.log.3, app.log.1 -> app.log.2, etc. (highest
    # first so we never clobber a lower generation before it's moved).
    def shift_generations(rule)
      gens = existing_generations(rule.path)
      gens.sort.reverse_each do |n|
        src = generation_path(rule.path, n, rule.compress)
        dst = generation_path(rule.path, n + 1, rule.compress)
        next unless File.exist?(src)

        if @dry_run
          puts "[dry-run] would move #{src} -> #{dst}"
        else
          FileUtils.mv(src, dst, force: true)
        end
      end
    end

    def generation_path(path, n, compressed)
      compressed ? "#{path}.#{n}.gz" : "#{path}.#{n}"
    end

    # copytruncate strategy: copy current contents to .1 (compressing if
    # asked), then truncate the live file to zero length in place. This
    # matters because it never breaks a process's already-open file handle
    # -- unlike renaming the live file out from under it, which would leave
    # the writer appending to a now-unlinked inode forever.
    def perform_rotation(rule)
      target = generation_path(rule.path, 1, rule.compress)

      if @dry_run
        puts "[dry-run] would copy #{rule.path} -> #{target} and truncate #{rule.path}"
        return target
      end

      if rule.compress
        Zlib::GzipWriter.open(target) { |gz| gz.write(File.binread(rule.path)) }
      else
        FileUtils.cp(rule.path, target)
      end

      File.truncate(rule.path, 0)
      target
    end

    def enforce_retention(rule)
      gens = existing_generations(rule.path)
      overflow = gens.sort.select { |n| n > rule.keep }
      overflow.each do |n|
        victim = generation_path(rule.path, n, rule.compress)
        if @dry_run
          puts "[dry-run] would delete #{victim} (exceeds keep=#{rule.keep})"
        elsif File.exist?(victim)
          File.delete(victim)
        end
      end
    end

    def run_post_rotate(rule)
      return unless rule.post_rotate

      if @dry_run
        puts "[dry-run] would run post_rotate: #{rule.post_rotate}"
      else
        system(rule.post_rotate)
      end
    end
  end
end

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  options = { config: nil, dry_run: false, json: false }

  OptionParser.new do |opts|
    opts.banner = 'Usage: log_rotate.rb --config rotate.json [--dry-run] [--json]'
    opts.on('-c', '--config PATH', 'Path to JSON rotation config') { |v| options[:config] = v }
    opts.on('--dry-run', 'Show what would happen without touching files') { options[:dry_run] = true }
    opts.on('--json', 'Emit machine-readable JSON instead of text') { options[:json] = true }
  end.parse!

  unless options[:config]
    warn 'Error: --config PATH is required'
    exit 1
  end

  raw = JSON.parse(File.read(options[:config]))
  rules = raw.fetch('rules').map { |cfg| LogRotate::Rule.new(cfg) }
  results = LogRotate::Rotator.new(rules, dry_run: options[:dry_run]).run

  had_error = results.any?(&:error)

  if options[:json]
    puts JSON.pretty_generate(results.map(&:to_h))
  else
    results.each do |r|
      marker = case r.action
               when :rotated then 'ROTATED'
               when :skipped then 'skip   '
               when :error   then 'ERROR  '
               end
      puts "#{marker} #{r.path}#{r.detail ? " (#{r.detail})" : ''}"
    end
    puts "\n#{results.count { |r| r.action == :rotated }} rotated, " \
         "#{results.count { |r| r.action == :skipped }} skipped, " \
         "#{results.count(&:error)} errors"
  end

  exit(had_error ? 1 : 0)
end
