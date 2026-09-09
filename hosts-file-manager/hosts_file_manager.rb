#!/usr/bin/env ruby
# frozen_string_literal: true
#
# hosts_file_manager.rb - idempotent hosts-file management for Linux and Windows
#
# Adds, removes, lists and verifies entries in /etc/hosts (Linux/macOS) or
# C:\Windows\System32\drivers\etc\hosts (Windows) without clobbering anything
# you did not ask it to touch. Every managed line is tagged with a marker
# comment so the script can find its own entries later, and every write goes
# through: backup -> atomic temp-file write -> rename.
#
# Usage:
#   ruby hosts_file_manager.rb list
#   ruby hosts_file_manager.rb add    10.0.5.20 db01.internal db01
#   ruby hosts_file_manager.rb remove db01.internal
#   ruby hosts_file_manager.rb apply  hosts.yml        # declarative bulk sync
#   ruby hosts_file_manager.rb verify hosts.yml        # exit 1 if drift detected
#
# Global flags:
#   --file PATH   operate on a different hosts file (great for testing)
#   --dry-run     show the diff, change nothing
#   --tag NAME    marker used to identify managed lines (default: "hostsmgr")
#
# Ruby >= 2.7, stdlib only (yaml, fileutils, tmpdir, optparse).

require 'fileutils'
require 'optparse'
require 'tempfile'
require 'yaml'

module HostsManager
  VERSION = '1.0.0'

  def self.default_path
    if Gem.win_platform?
      File.join(ENV.fetch('SystemRoot', 'C:/Windows'), 'System32', 'drivers', 'etc', 'hosts')
    else
      '/etc/hosts'
    end
  end

  # A single "ip  name1 name2 ...  # managed-by:tag" line.
  Entry = Struct.new(:ip, :names, :managed, :raw) do
    def key
      names.first.downcase
    end

    def to_line(tag)
      "#{ip.ljust(15)} #{names.join(' ')}  # managed-by:#{tag}"
    end
  end

  class HostsFile
    IPV4 = /\A\d{1,3}(?:\.\d{1,3}){3}\z/.freeze
    IPV6 = /\A[0-9a-f:]+\z/i.freeze
    HOSTNAME = /\A[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\z/i.freeze

    attr_reader :path, :lines, :tag

    def initialize(path, tag: 'hostsmgr')
      @path = path
      @tag = tag
      @lines = File.exist?(path) ? File.read(path).split(/\r?\n/, -1) : []
      @lines.pop if @lines.last == '' # drop trailing empty from final newline
    end

    # Parse every non-comment line into an Entry (managed or not).
    def entries
      @lines.filter_map do |raw|
        body, comment = raw.split('#', 2)
        parts = body.to_s.split
        next if parts.size < 2

        Entry.new(parts[0], parts[1..], comment.to_s.include?("managed-by:#{tag}"), raw)
      end
    end

    def managed
      entries.select(&:managed)
    end

    def add(ip, names)
      validate!(ip, names)
      entry = Entry.new(ip, names, true, nil)
      existing = @lines.index { |l| managed_line_for?(l, entry.key) }
      if existing
        return false if @lines[existing] == entry.to_line(tag) # already identical -> no-op

        @lines[existing] = entry.to_line(tag)
      else
        @lines << entry.to_line(tag)
      end
      true
    end

    def remove(name)
      before = @lines.size
      @lines.reject! { |l| managed_line_for?(l, name.downcase) }
      @lines.size != before
    end

    # Declarative sync: desired = [{ip:, names:[]}], removes managed lines not in desired.
    def sync(desired)
      changed = false
      desired_keys = desired.map { |d| d[:names].first.downcase }
      managed.each do |e|
        changed |= remove(e.key) unless desired_keys.include?(e.key)
      end
      desired.each { |d| changed |= add(d[:ip], d[:names]) }
      changed
    end

    def drift(desired)
      current = managed.map { |e| [e.key, [e.ip, e.names]] }.to_h
      wanted  = desired.map { |d| [d[:names].first.downcase, [d[:ip], d[:names]]] }.to_h
      {
        missing: wanted.keys - current.keys,
        extra:   current.keys - wanted.keys,
        changed: (wanted.keys & current.keys).reject { |k| wanted[k] == current[k] }
      }
    end

    def content
      @lines.join(line_ending) + line_ending
    end

    # backup + atomic write. Returns the backup path.
    def save!(backup_dir: nil)
      backup = nil
      if File.exist?(path)
        dir = backup_dir || File.dirname(path)
        backup = File.join(dir, "#{File.basename(path)}.#{Time.now.strftime('%Y%m%d-%H%M%S%L')}.bak")
        FileUtils.cp(path, backup, preserve: true)
      end
      tmp = Tempfile.create(['hosts', '.tmp'], File.dirname(path))
      begin
        tmp.write(content)
        tmp.flush
        tmp.fsync
      ensure
        tmp.close
      end
      File.chmod(0o644, tmp.path) unless Gem.win_platform?
      File.rename(tmp.path, path) # atomic on POSIX; Windows replaces in one step
      backup
    end

    private

    def line_ending
      Gem.win_platform? ? "\r\n" : "\n"
    end

    def managed_line_for?(line, key)
      return false unless line.include?("managed-by:#{tag}")

      parts = line.split('#', 2).first.split
      parts.size >= 2 && parts[1].downcase == key
    end

    def validate!(ip, names)
      v4_ok = ip.match?(IPV4) && ip.split('.').all? { |o| o.to_i <= 255 }
      raise ArgumentError, "invalid IP address: #{ip}" unless v4_ok || ip.match?(IPV6)
      raise ArgumentError, 'at least one hostname required' if names.empty?

      names.each { |n| raise ArgumentError, "invalid hostname: #{n}" unless n.match?(HOSTNAME) }
    end
  end

  # Minimal unified-style diff so --dry-run shows exactly what will change.
  def self.diff(old_text, new_text)
    old_l = old_text.split("\n")
    new_l = new_text.split("\n")
    out = []
    (old_l - new_l).each { |l| out << "- #{l}" }
    (new_l - old_l).each { |l| out << "+ #{l}" }
    out.empty? ? '(no changes)' : out.join("\n")
  end

  def self.load_desired(yaml_path)
    data = YAML.safe_load(File.read(yaml_path)) || {}
    Array(data['hosts']).map do |h|
      { ip: h['ip'].to_s, names: Array(h['names']).map(&:to_s) }
    end
  end

  def self.run(argv)
    opts = { file: default_path, dry_run: false, tag: 'hostsmgr' }
    parser = OptionParser.new do |o|
      o.banner = 'Usage: hosts_file_manager.rb [options] <list|add IP NAME...|remove NAME|apply FILE|verify FILE>'
      o.on('--file PATH') { |v| opts[:file] = v }
      o.on('--dry-run')   { opts[:dry_run] = true }
      o.on('--tag NAME')  { |v| opts[:tag] = v }
      o.on('-v', '--version') { puts VERSION; exit }
    end
    parser.parse!(argv)
    cmd = argv.shift or (puts parser; exit 2)

    hf = HostsFile.new(opts[:file], tag: opts[:tag])
    before = hf.content
    changed = false

    case cmd
    when 'list'
      puts format('%-16s %-40s %s', 'IP', 'NAMES', 'MANAGED')
      hf.entries.each { |e| puts format('%-16s %-40s %s', e.ip, e.names.join(' '), e.managed ? 'yes' : '-') }
      exit 0
    when 'add'
      ip, *names = argv
      changed = hf.add(ip, names)
    when 'remove'
      changed = hf.remove(argv.fetch(0))
    when 'apply'
      changed = hf.sync(load_desired(argv.fetch(0)))
    when 'verify'
      d = hf.drift(load_desired(argv.fetch(0)))
      if d.values.all?(&:empty?)
        puts "OK - #{hf.managed.size} managed entries match #{argv[0]}"
        exit 0
      end
      puts "DRIFT - missing: #{d[:missing]} extra: #{d[:extra]} changed: #{d[:changed]}"
      exit 1
    else
      puts parser
      exit 2
    end

    unless changed
      puts 'No changes needed (already in desired state).'
      exit 0
    end

    puts diff(before, hf.content)
    if opts[:dry_run]
      puts "\n--dry-run: #{opts[:file]} not modified."
    else
      backup = hf.save!
      puts "\nWrote #{opts[:file]} (backup: #{backup || 'none'})"
    end
    exit 0
  rescue ArgumentError, Errno::EACCES, Errno::ENOENT, IndexError => e
    warn "error: #{e.message}"
    exit 2
  end
end

HostsManager.run(ARGV) if $PROGRAM_NAME == __FILE__
