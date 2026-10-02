#!/usr/bin/env ruby
# frozen_string_literal: true
#
# inotify_audit.rb - who is using your inotify watches, and how close are you to the limit?
# "ENOSPC: System limit for number of file watchers reached" (IDEs, webpack, Tail, Syncthing...)
# Ruby 3.0+, stdlib only, Linux. Run as root to see every process.
# Usage: ruby inotify_audit.rb [--top 10] [--warn 80] [--json] [--proc DIR]
require 'optparse'
require 'json'

Proc_ = Struct.new(:pid, :user, :comm, :instances, :watches, keyword_init: true)

def read_int(path)
  Integer(File.read(path).strip, 10)
rescue Errno::ENOENT, ArgumentError
  nil
end

def uid_name(uid, cache = {})
  cache[uid] ||= begin
    File.foreach('/etc/passwd') { |l| f = l.split(':'); return (cache[uid] = f[0]) if f[2].to_i == uid }
    uid.to_s
  rescue Errno::ENOENT
    uid.to_s
  end
end

# Every inotify instance is an fd whose /proc/PID/fd/N link reads "anon_inode:inotify".
# Each watch is one "inotify wd:" line in /proc/PID/fdinfo/N.
def scan(proc_root)
  Dir.children(proc_root).grep(/\A\d+\z/).filter_map do |pid|
    fd_dir = File.join(proc_root, pid, 'fd')
    instances = 0
    watches = 0
    begin
      Dir.children(fd_dir).each do |fd|
        next unless File.readlink(File.join(fd_dir, fd)) == 'anon_inode:inotify'
        instances += 1
        File.foreach(File.join(proc_root, pid, 'fdinfo', fd)) { |l| watches += 1 if l.start_with?('inotify wd:') }
      end
    rescue Errno::EACCES, Errno::ENOENT, Errno::ESRCH, Errno::EPERM
      next # process vanished or not ours
    end
    next if instances.zero?
    uid = File.stat(File.join(proc_root, pid)).uid
    comm = File.read(File.join(proc_root, pid, 'comm')).strip rescue '?'
    Proc_.new(pid: pid.to_i, user: uid_name(uid), comm: comm, instances: instances, watches: watches)
  end
end

opts = { top: 10, warn: 80, json: false, proc: '/proc' }
OptionParser.new do |o|
  o.on('--top N', Integer) { |v| opts[:top] = v }
  o.on('--warn PCT', Integer) { |v| opts[:warn] = v }
  o.on('--json') { opts[:json] = true }
  o.on('--proc DIR', 'procfs root (for testing)') { |v| opts[:proc] = v }
end.parse!

max_watches   = read_int(File.join(opts[:proc], 'sys/fs/inotify/max_user_watches'))   || read_int('/proc/sys/fs/inotify/max_user_watches')
max_instances = read_int(File.join(opts[:proc], 'sys/fs/inotify/max_user_instances')) || read_int('/proc/sys/fs/inotify/max_user_instances')
procs = scan(opts[:proc])
# The kernel limits are PER USER, so aggregate by user before comparing.
users = procs.group_by(&:user).map do |u, ps|
  w = ps.sum(&:watches)
  i = ps.sum(&:instances)
  { user: u, watches: w, instances: i,
    watch_pct: (100.0 * w / max_watches).round(1), inst_pct: (100.0 * i / max_instances).round(1) }
end.sort_by { |u| -u[:watches] }
top = procs.sort_by { |p| -p.watches }.first(opts[:top])
flagged = users.select { |u| [u[:watch_pct], u[:inst_pct]].max >= opts[:warn] }

if opts[:json]
  puts JSON.pretty_generate(limits: { max_user_watches: max_watches, max_user_instances: max_instances },
                            users: users, top_processes: top.map(&:to_h), flagged: flagged.map { |u| u[:user] })
else
  puts "Limits (per user): max_user_watches=#{max_watches} max_user_instances=#{max_instances}"
  puts format("\n%-12s %9s %7s %9s %7s", 'USER', 'WATCHES', 'WATCH%', 'INSTANCES', 'INST%')
  users.each { |u| puts format('%-12s %9d %6.1f%% %9d %6.1f%%%s', u[:user], u[:watches], u[:watch_pct], u[:instances], u[:inst_pct], flagged.include?(u) ? '  <-- NEAR LIMIT' : '') }
  puts format("\n%-7s %-12s %-18s %9s %9s", 'PID', 'USER', 'COMMAND', 'WATCHES', 'INSTANCES')
  top.each { |p| puts format('%-7d %-12s %-18s %9d %9d', p.pid, p.user, p.comm, p.watches, p.instances) }
  puts "\nFix: sudo sysctl fs.inotify.max_user_watches=524288  (persist in /etc/sysctl.d/)" if flagged.any?
end
exit(flagged.any? ? 2 : 0)
