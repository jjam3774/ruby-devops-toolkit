#!/usr/bin/env ruby
# frozen_string_literal: true
#
# test_fd_leak_monitor.rb — unit tests using a synthetic /proc tree so the
# severity + FD-classification logic is verified deterministically, without
# depending on whatever happens to be running. Builds the fixture in a temp
# dir and points the (injectable) proc reader at it. Runs on any Linux/macOS
# with a writable tmp: ruby test_fd_leak_monitor.rb

require_relative 'fd_leak_monitor'
require 'fileutils'
require 'tmpdir'

$fail = 0
def assert(label, cond)
  puts format('  %-60s %s', label, cond ? 'PASS' : 'FAIL')
  $fail += 1 unless cond
end

# --- pure-function tests (no filesystem) ---
puts 'classify():'
assert 'socket link -> socket', FdLeakMonitor.classify('socket:[12345]') == 'socket'
assert 'pipe link -> pipe',     FdLeakMonitor.classify('pipe:[999]') == 'pipe'
assert 'anon_inode -> anon',    FdLeakMonitor.classify('anon_inode:[eventfd]') == 'anon'
assert 'absolute path -> file', FdLeakMonitor.classify('/var/log/app.log') == 'file'

puts 'classify_severity():'
assert '95/100 -> CRIT (>=90)', FdLeakMonitor.classify_severity(95, 100, 75, 90) == 'CRIT'
assert '80/100 -> WARN (>=75)', FdLeakMonitor.classify_severity(80, 100, 75, 90) == 'WARN'
assert '10/100 -> OK',          FdLeakMonitor.classify_severity(10, 100, 75, 90) == 'OK'
assert 'unlimited (nil) -> OK', FdLeakMonitor.classify_severity(9999, nil, 75, 90) == 'OK'

# --- synthetic /proc tree ---
Dir.mktmpdir do |root|
  def make_proc(root, pid, comm, limit, links)
    base = File.join(root, pid.to_s)
    FileUtils.mkdir_p(File.join(base, 'fd'))
    File.write(File.join(base, 'comm'), "#{comm}\n")
    lim = limit == 'unlimited' ? 'unlimited' : limit.to_s
    File.write(File.join(base, 'limits'),
               "Limit                     Soft Limit           Hard Limit           Units\n" \
               "Max open files            #{lim}                 #{lim}                 files\n")
    links.each_with_index do |target, i|
      # Emulate an fd symlink by creating a real symlink to a sentinel path;
      # readlink returns exactly that string.
      File.symlink(target, File.join(base, 'fd', i.to_s))
    end
  end

  # pid 4242: 92 fds against a 100 limit -> CRIT, mostly sockets (a socket leak)
  links = (['socket:[1]'] * 88) + (['/var/log/app.log'] * 3) + (['pipe:[7]'])
  make_proc(root, 4242, 'leaky-daemon', 100, links)
  # pid 4243: 3 fds, unlimited -> OK
  make_proc(root, 4243, 'tiny', 'unlimited', ['/dev/null', 'anon_inode:[eventfd]', 'socket:[9]'])

  puts 'synthetic /proc scan:'
  assert 'pids() finds both fake PIDs', FdLeakMonitor.pids(root).sort == [4242, 4243]

  a = FdLeakMonitor.inspect_pid(4242, root)
  assert 'counts 92 fds for leaky-daemon', a[:count] == 92
  assert 'reads soft limit 100',           a[:limit] == 100
  assert 'reads comm',                      a[:comm] == 'leaky-daemon'
  assert 'breakdown: 88 sockets',           a[:kinds]['socket'] == 88
  assert 'breakdown: 3 files',              a[:kinds]['file'] == 3

  rows = FdLeakMonitor.audit(procs: [a, FdLeakMonitor.inspect_pid(4243, root)],
                             warn_pct: 75, crit_pct: 90)
  leaky = rows.find { |r| r[:pid] == 4242 }
  assert 'leaky-daemon flagged CRIT (92%)', leaky[:status] == 'CRIT'
  assert 'exit code 2 when a CRIT present', FdLeakMonitor.worst_exit(rows) == 2
end

puts
puts $fail.zero? ? 'all assertions passed' : "#{$fail} FAILED"
exit($fail.zero? ? 0 : 1)
