#!/usr/bin/env ruby
# frozen_string_literal: true
#
# perm_audit.rb -- File Permission & SUID/SGID Security Auditor
#
# Walks one or more directory trees and flags three classes of
# permission risk that show up in almost every CIS/STIG hardening
# checklist:
#
#   1. World-writable files/directories (mode & 0002) that aren't
#      also sticky (the classic "anyone can overwrite this" bug).
#   2. SUID binaries (mode & 04000) -- programs that run as their
#      *owner* (often root) no matter who executes them.
#   3. SGID binaries/directories (mode & 02000) -- programs that run
#      as their *group*, or directories where new files inherit the
#      parent's group.
#
# Pure Ruby stdlib only (Find, Etc, OptionParser) -- nothing to
# install, safe to drop on a box with no network access.
#
# Usage:
#   ruby perm_audit.rb /etc /home /var/www
#   ruby perm_audit.rb --json /etc            # machine-readable output
#   ruby perm_audit.rb --baseline known_suid.txt /  # diff against a baseline
#
require 'find'
require 'etc'
require 'optparse'
require 'json'
require 'set'

# A well-known allowlist of SUID/SGID binaries that ship with most
# Linux distros. Anything SUID/SGID that is NOT on this list is far
# more interesting to a security review than e.g. /usr/bin/passwd.
KNOWN_SUID_SGID = %w[
  /usr/bin/passwd /usr/bin/chsh /usr/bin/chfn /usr/bin/gpasswd
  /usr/bin/newgrp /usr/bin/su /usr/bin/sudo /usr/bin/mount
  /usr/bin/umount /usr/bin/pkexec /usr/bin/crontab /usr/bin/at
  /usr/sbin/pppd /usr/lib/dbus-1.0/dbus-daemon-launch-helper
  /usr/lib/openssh/ssh-keysign /usr/bin/fusermount /usr/bin/fusermount3
  /usr/bin/ssh-agent /usr/bin/wall /usr/bin/write /usr/bin/mount.nfs
].freeze

# Directories that are *expected* to be world-writable because they
# rely on the sticky bit to stay safe (e.g. /tmp). We still report
# them, but at INFO instead of WARN/CRIT, unless the sticky bit is
# actually missing.
STICKY_OK_PREFIXES = %w[/tmp /var/tmp /dev/shm /var/spool/cron].freeze

Finding = Struct.new(:severity, :category, :path, :mode_octal, :owner, :group, :detail) do
  def to_h
    { severity: severity, category: category, path: path, mode: mode_octal,
      owner: owner, group: group, detail: detail }
  end
end

class PermAuditor
  SEVERITY_RANK = { 'CRIT' => 3, 'WARN' => 2, 'INFO' => 1 }.freeze

  def initialize(roots, baseline: nil, follow_symlinks: false)
    @roots = roots
    @baseline = baseline ? load_baseline(baseline) : nil
    @follow_symlinks = follow_symlinks
    @findings = []
    @scanned = 0
    @errors = 0
  end

  attr_reader :findings, :scanned, :errors

  def run
    @roots.each { |root| walk(root) }
    @findings.sort_by! { |f| -SEVERITY_RANK.fetch(f.severity, 0) }
    self
  end

  private

  def walk(root)
    unless File.exist?(root)
      warn "skip: #{root} does not exist"
      return
    end

    Find.find(root) do |path|
      begin
        stat = File.lstat(path)
        # Don't dereference symlinks unless explicitly asked -- a
        # symlink's own permission bits are not meaningful on Linux,
        # but a *target* we don't intend to scan could live outside
        # the tree we were asked to audit.
        Find.prune if stat.symlink? && !@follow_symlinks

        next if stat.symlink?

        @scanned += 1
        inspect_stat(path, stat)
      rescue Errno::EACCES, Errno::ENOENT, Errno::ELOOP => e
        @errors += 1
        next
      end
    end
  end

  def inspect_stat(path, stat)
    mode = stat.mode
    perm = mode & 0o7777
    suid = perm & 0o4000 != 0
    sgid = perm & 0o2000 != 0
    sticky = perm & 0o1000 != 0
    world_writable = perm & 0o0002 != 0

    owner = user_name(stat.uid)
    group = group_name(stat.gid)

    check_suid_sgid(path, perm, owner, group, suid, sgid) if suid || sgid
    check_world_writable(path, perm, owner, group, stat.directory?, sticky) if world_writable
  end

  def check_suid_sgid(path, perm, owner, group, suid, sgid)
    kind = [suid ? 'SUID' : nil, sgid ? 'SGID' : nil].compact.join('+')
    known = KNOWN_SUID_SGID.include?(path)
    baseline_hit = @baseline&.include?(path)

    severity =
      if baseline_hit
        'INFO'
      elsif known
        'WARN'
      else
        'CRIT'
      end

    detail = known ? 'matches distro-standard allowlist' : 'NOT in known-good allowlist'
    detail += ' (also in operator baseline)' if baseline_hit

    @findings << Finding.new(severity, kind, path, format('%04o', perm), owner, group, detail)
  end

  def check_world_writable(path, perm, owner, group, is_dir, sticky)
    expected_sticky = STICKY_OK_PREFIXES.any? { |p| path == p || path.start_with?("#{p}/") }

    severity =
      if is_dir && !sticky
        'CRIT'
      elsif !is_dir
        'WARN'
      else
        'INFO'
      end

    kind = is_dir ? 'WORLD_WRITABLE_DIR' : 'WORLD_WRITABLE_FILE'
    detail = is_dir ? (sticky ? 'sticky bit set (safe pattern)' : 'sticky bit MISSING') : 'world-writable regular file'

    @findings << Finding.new(severity, kind, path, format('%04o', perm), owner, group, detail)
  end

  def load_baseline(file)
    File.readlines(file, chomp: true).reject { |l| l.empty? || l.start_with?('#') }.to_set
  rescue Errno::ENOENT
    nil
  end

  def user_name(uid)
    Etc.getpwuid(uid).name
  rescue ArgumentError
    uid.to_s
  end

  def group_name(gid)
    Etc.getgrgid(gid).name
  rescue ArgumentError
    gid.to_s
  end
end

def print_text_report(auditor, roots)
  counts = Hash.new(0)
  auditor.findings.each { |f| counts[f.severity] += 1 }

  puts '=' * 72
  puts "PERMISSION AUDIT: #{roots.join(', ')}"
  puts '=' * 72
  puts "Scanned: #{auditor.scanned} entries  |  Errors (permission denied etc.): #{auditor.errors}"
  puts "Findings: #{counts['CRIT']} CRIT, #{counts['WARN']} WARN, #{counts['INFO']} INFO"
  puts '-' * 72

  if auditor.findings.empty?
    puts 'No findings. Clean bill of health.'
  else
    auditor.findings.each do |f|
      tag = f.severity.ljust(4)
      puts "[#{tag}] #{f.category.ljust(20)} #{f.mode_octal}  #{f.owner}:#{f.group}  #{f.path}"
      puts "         -> #{f.detail}"
    end
  end
  puts '=' * 72

  counts['CRIT']
end

if $PROGRAM_NAME == __FILE__
  options = { json: false, baseline: nil, follow_symlinks: false }
  parser = OptionParser.new do |o|
    o.banner = 'Usage: perm_audit.rb [options] PATH [PATH ...]'
    o.on('--json', 'Emit JSON instead of a text report') { options[:json] = true }
    o.on('--baseline FILE', 'Newline-delimited list of SUID/SGID paths to treat as pre-approved') { |f| options[:baseline] = f }
    o.on('--follow-symlinks', 'Also stat symlink targets (off by default)') { options[:follow_symlinks] = true }
  end
  parser.parse!

  roots = ARGV.empty? ? ['.'] : ARGV
  auditor = PermAuditor.new(roots, baseline: options[:baseline], follow_symlinks: options[:follow_symlinks]).run

  if options[:json]
    puts JSON.pretty_generate(
      scanned: auditor.scanned,
      errors: auditor.errors,
      findings: auditor.findings.map(&:to_h)
    )
    exit(auditor.findings.any? { |f| f.severity == 'CRIT' } ? 2 : 0)
  else
    crit_count = print_text_report(auditor, roots)
    exit(crit_count.positive? ? 2 : 0)
  end
end
