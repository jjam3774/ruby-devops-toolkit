#!/usr/bin/env ruby
# frozen_string_literal: true
#
# orphan_file_audit.rb — find files and directories owned by users or groups
# that no longer exist (CIS Linux Benchmark 6.1.11 / 6.1.12), rank them by
# how dangerous they are, and print the exact chown commands to fix them.
#
# Why it matters: when an account is deleted its UID is freed. The next
# "useradd" hands that UID to someone new, who silently inherits every file
# the old account left behind — home directories, cron spool, SUID helpers,
# world-writable drop boxes. Orphaned files are a privilege-escalation path
# and an audit finding; both are easy to close once you can see them.
#
# Usage:
#   sudo ruby orphan_file_audit.rb                        # walk / (one filesystem)
#   sudo ruby orphan_file_audit.rb /srv /home /var        # specific roots
#   ruby orphan_file_audit.rb --from-find files.txt       # analyse captured find output:
#       find / -xdev \( -nouser -o -nogroup \) -printf '%U %G %m %y %s %p\n' > files.txt
#   ruby orphan_file_audit.rb --passwd ./passwd --group ./group --from-find files.txt
#   ruby orphan_file_audit.rb --json
#
# Exit codes: 0 nothing orphaned, 1 orphans found, 2 orphans that are
# world-writable, SUID/SGID, or sit under a sensitive path.
#
# Stdlib only. The walker uses File.lstat so it never follows symlinks, and
# stays on one filesystem per root (like find -xdev) unless --cross-fs.

require 'optparse'
require 'json'
require 'find'

SENSITIVE_PREFIXES = %w[/etc /usr /bin /sbin /lib /lib64 /boot /var/spool/cron /var/lib /root /opt].freeze

# ---------------------------------------------------------------------------
# Account databases — parsed directly so the audit works on captured files
# from another host (fleet mode) and on any OS for testing.
# ---------------------------------------------------------------------------
def read_ids(path, name_col: 0, id_col: 2)
  File.readlines(path).each_with_object({}) do |line, h|
    next if line.strip.empty? || line.start_with?('#')
    f = line.chomp.split(':')
    next if f.size <= id_col
    h[f[id_col].to_i] = f[name_col]
  end
end

# ---------------------------------------------------------------------------
# One record per filesystem object. mode is the permission bits as an Integer,
# type is a single char like find -printf %y: f d l s p c b
# ---------------------------------------------------------------------------
Entry = Struct.new(:uid, :gid, :mode, :type, :size, :path, keyword_init: true)

def walk(roots, cross_fs: false)
  roots.flat_map do |root|
    dev = File.lstat(root).dev
    out = []
    Find.find(root) do |p|
      st = File.lstat(p)
      if st.directory? && !cross_fs && st.dev != dev
        Find.prune # like find -xdev: do not descend into other filesystems
        next
      end
      out << Entry.new(uid: st.uid, gid: st.gid, mode: st.mode & 0o7777, type: type_char(st), size: st.size, path: p)
    rescue Errno::EACCES, Errno::ENOENT, Errno::ELOOP
      next # unreadable or vanished mid-walk
    end
    out
  end
end

def type_char(st)
  return 'l' if st.symlink?
  return 'd' if st.directory?
  return 's' if st.socket?
  return 'p' if st.pipe?
  return 'c' if st.chardev?
  return 'b' if st.blockdev?
  'f'
end

# find / -xdev \( -nouser -o -nogroup \) -printf '%U %G %m %y %s %p\n'
def read_find_output(path)
  File.readlines(path).filter_map do |line|
    uid, gid, mode, type, size, p = line.chomp.split(' ', 6)
    next unless p
    Entry.new(uid: uid.to_i, gid: gid.to_i, mode: mode.to_i(8), type: type, size: size.to_i, path: p)
  end
end

# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------
Orphan = Struct.new(:entry, :reasons, :severity, keyword_init: true)

def classify(entries, users, groups)
  entries.filter_map do |e|
    reasons = []
    reasons << "uid #{e.uid} has no passwd entry" unless users.key?(e.uid)
    reasons << "gid #{e.gid} has no group entry" unless groups.key?(e.gid)
    next if reasons.empty?

    risk = []
    risk << 'world-writable'    if e.mode & 0o002 != 0 && e.type != 'l'
    risk << 'setuid'            if e.mode & 0o4000 != 0
    risk << 'setgid'            if e.mode & 0o2000 != 0
    risk << 'sensitive-path'    if SENSITIVE_PREFIXES.any? { |pre| e.path == pre || e.path.start_with?(pre + '/') }
    risk << 'executable'        if e.type == 'f' && e.mode & 0o111 != 0
    sev = risk.any? { |r| %w[world-writable setuid setgid sensitive-path].include?(r) } ? 'CRIT' : 'WARN'
    Orphan.new(entry: e, reasons: reasons + risk, severity: sev)
  end
end

# Group orphans by (uid, gid) so the fix is one chown per former account,
# and suggest a target owner: the parent directory's owner if it is valid,
# else root.
def remediation(orphans, users, groups, entries_by_path)
  orphans.group_by { |o| [o.entry.uid, o.entry.gid] }.map do |(uid, gid), list|
    sample = list.first.entry
    parent = entries_by_path[File.dirname(sample.path)]
    # keep whichever half is still valid; replace the orphaned half with the
    # parent directory's owner/group when that is valid, else root
    new_uid = users.key?(uid)  ? uid : (parent && users.key?(parent.uid)  ? parent.uid : 0)
    new_gid = groups.key?(gid) ? gid : (parent && groups.key?(parent.gid) ? parent.gid : 0)
    {
      uid: uid, gid: gid, count: list.size, bytes: list.sum { |o| o.entry.size },
      suggested_owner: "#{users[new_uid] || new_uid}:#{groups[new_gid] || new_gid}",
      command: "find #{common_root(list.map { |o| o.entry.path })} -xdev #{users.key?(uid) ? '' : "-uid #{uid} "}#{groups.key?(gid) ? '' : "-gid #{gid} "}-exec chown -h #{new_uid}:#{new_gid} {} +".squeeze(' ')
    }
  end
end

def common_root(paths)
  parts = paths.map { |p| p.split('/') }
  common = parts.first
  parts.each { |p| common = common.zip(p).take_while { |a, b| a == b }.map(&:first) }
  root = common.join('/')
  root.empty? ? '/' : root
end

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
opts = { passwd: '/etc/passwd', group: '/etc/group', from_find: nil, json: false, cross_fs: false, limit: 40 }
OptionParser.new do |o|
  o.banner = 'Usage: orphan_file_audit.rb [options] [ROOT ...]'
  o.on('--passwd FILE', 'passwd file (default /etc/passwd)') { |v| opts[:passwd] = v }
  o.on('--group FILE', 'group file (default /etc/group)') { |v| opts[:group] = v }
  o.on('--from-find FILE', 'analyse captured find -printf output instead of walking') { |v| opts[:from_find] = v }
  o.on('--cross-fs', 'descend into other filesystems (default: stay on one, like -xdev)') { opts[:cross_fs] = true }
  o.on('--limit N', Integer, 'max rows to print in text mode (default 40)') { |v| opts[:limit] = v }
  o.on('--json', 'JSON output') { opts[:json] = true }
end.parse!

users  = read_ids(opts[:passwd])
groups = read_ids(opts[:group])
roots  = ARGV.empty? ? ['/'] : ARGV
entries = opts[:from_find] ? read_find_output(opts[:from_find]) : walk(roots, cross_fs: opts[:cross_fs])
by_path = entries.each_with_object({}) { |e, h| h[e.path] = e }

orphans = classify(entries, users, groups)
crit = orphans.count { |o| o.severity == 'CRIT' }
fixes = remediation(orphans, users, groups, by_path)
status = crit.positive? ? 'CRIT' : (orphans.empty? ? 'OK' : 'WARN')

if opts[:json]
  puts JSON.pretty_generate(status: status, scanned: entries.size, orphaned: orphans.size, critical: crit,
                            orphans: orphans.map { |o| o.entry.to_h.merge(severity: o.severity, reasons: o.reasons) },
                            remediation: fixes)
else
  puts "orphan_file_audit  scanned #{entries.size} entries (#{opts[:from_find] ? "from #{opts[:from_find]}" : roots.join(' ')})  " \
       "passwd=#{users.size} users  group=#{groups.size} groups"
  puts '-' * 96
  if orphans.empty?
    puts 'no files owned by unknown users or groups'
  else
    puts format('%-4s %-6s %-6s %-5s %-2s %9s  %-40s %s', 'SEV', 'UID', 'GID', 'MODE', 'T', 'SIZE', 'PATH', 'WHY')
    orphans.sort_by { |o| [o.severity == 'CRIT' ? 0 : 1, o.entry.path] }.first(opts[:limit]).each do |o|
      e = o.entry
      puts format('%-4s %-6d %-6d %-5s %-2s %9d  %-40s %s', o.severity, e.uid, e.gid, e.mode.to_s(8).rjust(4, '0'), e.type, e.size, e.path[0, 40], o.reasons.join(', '))
    end
    puts "... #{orphans.size - opts[:limit]} more (raise --limit or use --json)" if orphans.size > opts[:limit]
    puts
    puts 'Remediation (review before running):'
    fixes.each do |fx|
      puts format('  uid %-6d gid %-6d %5d files %10d bytes  -> chown to %s', fx[:uid], fx[:gid], fx[:count], fx[:bytes], fx[:suggested_owner])
      puts "    #{fx[:command]}"
    end
  end
  puts
  puts "#{status}: #{orphans.size} orphaned entries, #{crit} critical"
end
exit(crit.positive? ? 2 : (orphans.empty? ? 0 : 1))
