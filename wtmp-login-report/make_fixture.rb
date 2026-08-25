#!/usr/bin/env ruby
# frozen_string_literal: true
# make_fixture.rb -- writes realistic utmp-format fixture files so
# wtmp_login_report.rb can be tested on machines with empty/absent wtmp.
# Uses the exact same 384-byte struct layout the parser reads.
RECORD_SIZE = 384

def rec(type:, pid: 0, line: '', id: '', user: '', host: '', time:)
  [type, pid, line, id, user, host, 0, 0, 0, time.to_i, 0, '', '']
    .pack('s<x2l<a32a4a32a256s<s<l<l<l<a16a20')
end

t = Time.parse('2026-08-25 06:58:00')
File.open('fixture.wtmp', 'wb') do |f|
  f << rec(type: 2, line: '~', user: 'reboot', host: '6.8.0-generic', time: t)           # boot
  f << rec(type: 7, pid: 901, line: 'tty1',  user: 'root',   time: t + 120)              # console login
  f << rec(type: 7, pid: 1204, line: 'pts/0', user: 'deploy', host: '10.0.4.17', time: t + 3600)
  f << rec(type: 8, pid: 1204, line: 'pts/0', time: t + 3600 + 1500)                     # deploy logs out
  f << rec(type: 7, pid: 1830, line: 'pts/0', user: 'ana',    host: '10.0.4.99', time: t + 7200)
  f << rec(type: 7, pid: 1922, line: 'pts/1', user: 'deploy', host: '10.0.4.17', time: t + 7500)
  f << rec(type: 8, pid: 1830, line: 'pts/0', time: t + 9000)                            # ana logs out
end

File.open('fixture.btmp', 'wb') do |f|
  # a slow trickle from one host, then a burst from another
  3.times  { |i| f << rec(type: 6, line: 'ssh:notty', user: 'root',  host: '203.0.113.7',  time: t + 100 + i * 600) }
  14.times { |i| f << rec(type: 6, line: 'ssh:notty', user: %w[root admin oracle git][i % 4],
                          host: '198.51.100.23', time: t + 4000 + i * 7) }
end
puts "wrote fixture.wtmp (#{File.size('fixture.wtmp')} bytes) and fixture.btmp (#{File.size('fixture.btmp')} bytes)"
