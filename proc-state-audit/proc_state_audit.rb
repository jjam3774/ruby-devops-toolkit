#!/usr/bin/env ruby
# frozen_string_literal: true
# proc_state_audit.rb - find zombie and stuck (D-state) processes from /proc.
# Zombies pile up when a parent never wait()s; D-state processes are blocked in
# the kernel (usually dead NFS / failing disk). Neither shows up in CPU graphs.
# Usage: ruby proc_state_audit.rb [--root DIR] [--json] [--zombie-warn N] [--dstate-secs N]
# Exit: 0 OK, 1 WARN, 2 CRIT.  Stdlib only.
require 'optparse'
require 'json'

Proc_ = Struct.new(:pid, :ppid, :name, :state, :start_ticks, :wchan, keyword_init: true)

opts = { root: '/proc', json: false, zombie_warn: 1, zombie_crit: 20, d_crit: 3 }
OptionParser.new do |o|
  o.on('--root DIR', 'proc root (fixtures)') { |v| opts[:root] = v }
  o.on('--json') { opts[:json] = true }
  o.on('--zombie-warn N', Integer) { |v| opts[:zombie_warn] = v }
  o.on('--zombie-crit N', Integer) { |v| opts[:zombie_crit] = v }
  o.on('--d-crit N', Integer, 'D-state count that is CRIT') { |v| opts[:d_crit] = v }
end.parse!

# /proc/PID/stat is "pid (comm) state ppid ...". comm may contain spaces and
# parentheses, so split on the LAST ')' rather than on whitespace.
def parse_stat(line)
  open_i  = line.index('(')
  close_i = line.rindex(')')
  return nil unless open_i && close_i
  rest = line[(close_i + 2)..].split
  { pid: line[0...open_i].to_i, name: line[(open_i + 1)...close_i],
    state: rest[0], ppid: rest[1].to_i, start: rest[19].to_i }
end

def scan(root)
  Dir.children(root).grep(/\A\d+\z/).filter_map do |pid|
    st = parse_stat(File.read(File.join(root, pid, 'stat')))
    next unless st
    wchan = File.read(File.join(root, pid, 'wchan')).strip rescue '?'
    Proc_.new(pid: st[:pid], ppid: st[:ppid], name: st[:name], state: st[:state],
              start_ticks: st[:start], wchan: wchan)
  rescue Errno::ENOENT, Errno::EACCES, Errno::ESRCH
    nil # process exited while we were reading - normal on a live box
  end
end

procs   = scan(opts[:root])
by_pid  = procs.to_h { |p| [p.pid, p] }
zombies = procs.select { |p| p.state == 'Z' }
dstate  = procs.select { |p| p.state == 'D' }

# Group zombies by parent: the parent is the process that needs fixing.
parents = zombies.group_by(&:ppid).map do |ppid, kids|
  { ppid: ppid, parent: by_pid[ppid]&.name || '?', zombies: kids.size, pids: kids.map(&:pid).first(10) }
end.sort_by { |h| -h[:zombies] }

status = if zombies.size >= opts[:zombie_crit] || dstate.size >= opts[:d_crit] then 'CRIT'
         elsif zombies.size >= opts[:zombie_warn] || !dstate.empty? then 'WARN'
         else 'OK' end

report = { status: status, total: procs.size, zombie_count: zombies.size, dstate_count: dstate.size,
           zombie_parents: parents,
           dstate: dstate.map { |p| { pid: p.pid, name: p.name, wchan: p.wchan } } }

if opts[:json]
  puts JSON.pretty_generate(report)
else
  puts "proc-state-audit: #{status}  (#{procs.size} processes, #{zombies.size} zombie, #{dstate.size} D-state)"
  parents.each { |h| puts format('  ZOMBIES  parent=%-6d %-14s count=%-3d e.g. pids %s', h[:ppid], h[:parent], h[:zombies], h[:pids].join(',')) }
  dstate.each  { |p| puts format('  D-STATE  pid=%-6d %-14s blocked in: %s', p.pid, p.name, p.wchan) }
end
exit({ 'OK' => 0, 'WARN' => 1, 'CRIT' => 2 }[status])
