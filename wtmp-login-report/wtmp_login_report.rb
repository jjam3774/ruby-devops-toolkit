#!/usr/bin/env ruby
# frozen_string_literal: true
#
# wtmp_login_report.rb -- read Linux login history straight from the binary
# wtmp/btmp files, in pure standard-library Ruby. No `last`, no `lastb`,
# no gems -- just String#unpack against glibc's on-disk utmp struct.
#
# What it reports:
#   * login sessions (login -> logout, paired per tty) with durations
#   * who is still logged in
#   * reboots
#   * from btmp: FAILED login attempts, grouped by user and by source host,
#     with burst detection (possible brute force) and a non-zero exit code
#
# Usage:
#   ruby wtmp_login_report.rb                          # /var/log/wtmp
#   ruby wtmp_login_report.rb --btmp                   # /var/log/btmp (needs root)
#   ruby wtmp_login_report.rb --file ./fixture.wtmp    # any utmp-format file
#   ruby wtmp_login_report.rb --btmp --burst 10 --json
#
# Exit codes: 0 ok, 1 at least one failed-login burst over --burst threshold.
#
require 'optparse'
require 'json'
require 'time'

# ---------------------------------------------------------------------------
# The on-disk record: struct utmp from glibc (bits/utmp.h), x86_64 layout.
# 384 bytes per record, little-endian, fixed-width NUL-padded strings.
#
#   offset size field
#        0    2 ut_type      (short)  -- what kind of record this is
#        2    2 (padding)
#        4    4 ut_pid       (int)
#        8   32 ut_line      (char[32])  tty name, e.g. "pts/0"
#       40    4 ut_id        (char[4])
#       44   32 ut_user      (char[32])
#       76  256 ut_host      (char[256]) remote host or IP
#      332    4 ut_exit      (2 x short)
#      336    4 ut_session   (int)
#      340    8 ut_tv        (int32 sec, int32 usec) -- 32-bit even on x86_64!
#      348   16 ut_addr_v6   (int32[4])
#      364   20 unused
# ---------------------------------------------------------------------------
RECORD_SIZE = 384
UNPACK      = 's<x2l<a32a4a32a256s<s<l<l<l<a16a20'

TYPES = { 0 => :empty, 1 => :run_lvl, 2 => :boot_time, 3 => :new_time,
          4 => :old_time, 5 => :init_process, 6 => :login_process,
          7 => :user_process, 8 => :dead_process, 9 => :accounting }.freeze

def cstr(bytes) # fixed-width field -> Ruby string (stop at first NUL)
  bytes.unpack1('Z*').force_encoding('UTF-8').scrub
end

def read_records(path)
  records = []
  File.open(path, 'rb') do |f|
    while (chunk = f.read(RECORD_SIZE))
      break if chunk.bytesize < RECORD_SIZE
      type, _pid, line, _id, user, host, _e1, _e2, _sess, sec, _usec = chunk.unpack(UNPACK)
      records << { type: TYPES.fetch(type, :unknown), line: cstr(line),
                   user: cstr(user), host: cstr(host), time: Time.at(sec) }
    end
  end
  records
end

# Pair USER_PROCESS (login) with the next DEAD_PROCESS on the same tty (logout).
def sessions(records)
  open_by_line = {}
  finished = []
  records.each do |r|
    case r[:type]
    when :user_process
      open_by_line[r[:line]] = r
    when :dead_process
      if (login = open_by_line.delete(r[:line]))
        finished << { user: login[:user], line: login[:line], host: login[:host],
                      from: login[:time], to: r[:time],
                      seconds: (r[:time] - login[:time]).round }
      end
    when :boot_time
      # a reboot implicitly ends every open session
      open_by_line.each_value do |login|
        finished << { user: login[:user], line: login[:line], host: login[:host],
                      from: login[:time], to: r[:time],
                      seconds: (r[:time] - login[:time]).round, ended_by: 'reboot' }
      end
      open_by_line.clear
    end
  end
  [finished, open_by_line.values]
end

def duration(s)
  s < 3600 ? format('%dm%02ds', s / 60, s % 60) : format('%dh%02dm', s / 3600, (s % 3600) / 60)
end

opts = { file: nil, btmp: false, burst: 10, json: false }
OptionParser.new do |o|
  o.banner = 'Usage: wtmp_login_report.rb [options]'
  o.on('--file PATH', 'Read this utmp-format file instead of the default') { |v| opts[:file] = v }
  o.on('--btmp', 'Failed-login mode: default file becomes /var/log/btmp') { opts[:btmp] = true }
  o.on('--burst N', Integer, 'Failed logins from one host to count as a burst (default 10)') { |v| opts[:burst] = v }
  o.on('--json', 'Emit JSON instead of text') { opts[:json] = true }
end.parse!

path = opts[:file] || (opts[:btmp] ? '/var/log/btmp' : '/var/log/wtmp')
abort "cannot read #{path} (btmp usually needs root)" unless File.readable?(path)
records = read_records(path)

if opts[:btmp]
  fails = records.select { |r| %i[user_process login_process].include?(r[:type]) }
  by_host = fails.group_by { |r| r[:host].empty? ? '(local)' : r[:host] }
  by_user = fails.group_by { |r| r[:user] }
  bursts  = by_host.select { |_, v| v.size >= opts[:burst] }
  if opts[:json]
    puts JSON.pretty_generate(
      file: path, failed_attempts: fails.size,
      by_host: by_host.transform_values(&:size).sort_by { |_, v| -v }.to_h,
      by_user: by_user.transform_values(&:size).sort_by { |_, v| -v }.to_h,
      bursts: bursts.map { |h, v| { host: h, attempts: v.size,
                                    first: v.first[:time].iso8601, last: v.last[:time].iso8601 } })
  else
    puts "== #{path} -- #{fails.size} failed login attempt(s) =="
    puts '-- by source host --'
    by_host.sort_by { |_, v| -v.size }.first(10).each do |host, v|
      badge = v.size >= opts[:burst] ? '[BURST]' : '       '
      puts format('%s %5d  %-30s targets: %s', badge, v.size, host,
                  v.group_by { |r| r[:user] }.keys.first(5).join(', '))
    end
  end
  exit bursts.empty? ? 0 : 1
else
  finished, still_open = sessions(records)
  reboots = records.select { |r| r[:type] == :boot_time }
  if opts[:json]
    puts JSON.pretty_generate(
      file: path, sessions: finished.map { |s| s.merge(from: s[:from].iso8601, to: s[:to].iso8601) },
      logged_in: still_open.map { |r| { user: r[:user], line: r[:line], host: r[:host], since: r[:time].iso8601 } },
      reboots: reboots.map { |r| r[:time].iso8601 })
  else
    puts "== #{path} -- #{finished.size} completed session(s), #{reboots.size} reboot(s) =="
    finished.last(15).each do |s|
      note = s[:ended_by] ? "  <- ended by #{s[:ended_by]}" : ''
      puts format('%-12s %-10s %-24s %s -> %s  (%s)%s',
                  s[:user], s[:line], s[:host].empty? ? '(local)' : s[:host],
                  s[:from].strftime('%m-%d %H:%M'), s[:to].strftime('%H:%M'),
                  duration(s[:seconds]), note)
    end
    unless still_open.empty?
      puts '-- still logged in --'
      still_open.each do |r|
        puts format('%-12s %-10s %-24s since %s', r[:user], r[:line],
                    r[:host].empty? ? '(local)' : r[:host], r[:time].strftime('%m-%d %H:%M'))
      end
    end
  end
  exit 0
end
