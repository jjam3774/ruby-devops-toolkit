#!/usr/bin/env ruby
# frozen_string_literal: true
#
# scheduled_task_audit_test.rb -- stub test harness for the audit logic.
#
# The COM layer (Schedule.Service) only exists on Windows, but everything
# that decides CRIT/WARN/INFO lives in TaskAudit.classify, which is pure
# Ruby. This harness feeds it realistic task fixtures and asserts on the
# findings, so the detection logic is verified on any platform.
#
#   ruby scheduled_task_audit_test.rb

require_relative 'scheduled_task_audit'
require 'time'

NOW = Time.parse('2026-08-23 12:00:00')
$failures = 0

def fixture(over = {})
  { name: 'T', path: '\\T', enabled: true, hidden: false,
    principal: 'CORP\\svc_app', logon_type: 3,
    actions: [{ type: 0, exe: 'C:\\Windows\\System32\\cmd.exe', args: '' }],
    last_run: NOW - 3600 }.merge(over)
end

def expect(desc, task, expected_codes)
  got = TaskAudit.classify(task, stale_days: 90, now: NOW).map { |f| f[:code] }.sort
  if got == expected_codes.sort
    puts "PASS  #{desc}"
  else
    $failures += 1
    puts "FAIL  #{desc}: expected #{expected_codes.sort.inspect}, got #{got.inspect}"
  end
end

expect('clean system task', fixture, [])

expect('SYSTEM task with exe in user-writable dir',
       fixture(principal: 'SYSTEM',
               actions: [{ type: 0, exe: 'C:\\Users\\Public\\update.exe', args: '' }]),
       ['writable-binary-dir'])

expect('non-privileged task in user dir is NOT writable-binary-dir',
       fixture(actions: [{ type: 0, exe: 'C:\\Users\\alice\\tool.exe', args: '' }]),
       [])

expect('exe under AppData flags temp-path-binary',
       fixture(actions: [{ type: 0, exe: 'C:\\Users\\bob\\AppData\\Roaming\\x.exe', args: '' }]),
       ['temp-path-binary'])

expect('SYSTEM + Windows\\Temp flags both CRITs',
       fixture(principal: 'NT AUTHORITY\\SYSTEM',
               actions: [{ type: 0, exe: 'C:\\Windows\\Temp\\svc.exe', args: '' }]),
       ['writable-binary-dir', 'temp-path-binary'])

expect('unquoted path with spaces',
       fixture(actions: [{ type: 0, exe: 'C:\\Program Files\\My App\\run.exe', args: '' }]),
       ['unquoted-spacey-path'])

expect('quoted spacey path is fine',
       fixture(actions: [{ type: 0, exe: '"C:\\Program Files\\My App\\run.exe"', args: '' }]),
       [])

expect('hidden task', fixture(hidden: true), ['hidden-task'])

expect('stored credentials (logon type 1)',
       fixture(logon_type: 1), ['stored-credentials'])

expect('stale enabled task',
       fixture(last_run: NOW - 200 * 86_400), ['stale-task'])

expect('old last_run on DISABLED task is not stale',
       fixture(enabled: false, last_run: NOW - 200 * 86_400), [])

expect('non-exec action (e.g. email) is ignored',
       fixture(actions: [{ type: 6 }]), [])

puts
if $failures.zero?
  puts 'all tests passed'
else
  puts "#{$failures} test(s) FAILED"
  exit 1
end
