#!/usr/bin/env ruby
# frozen_string_literal: true
#
# path_env_audit_test.rb -- tests for the pure PATH classification logic.
# Runs on any platform; injects a stub writability probe so no real dirs are
# touched.  ruby path_env_audit_test.rb

require_relative 'path_env_audit'
$fail = 0

def check(desc, entries, windows, writable_set, expected)
  probe = ->(d) { writable_set.include?(d) }
  got = PathAudit.classify(entries, windows: windows, writable: probe).map { |f| f[:code] }.sort
  if got == expected.sort
    puts "PASS  #{desc}"
  else
    $fail += 1
    puts "FAIL  #{desc}: expected #{expected.sort.inspect}, got #{got.inspect}"
  end
end

# Unix: writable /tmp before /usr/bin is the classic CRIT.
check('unix writable dir before system',
      ['/tmp/bin', '/usr/bin', '/bin'], false, ['/tmp/bin'],
      ['writable-before-system'])

# Unix: writable dir AFTER system dirs is only a WARN.
check('unix writable dir after system',
      ['/usr/bin', '/opt/tools'], false, ['/opt/tools'],
      ['writable-entry'])

check('unix clean path', ['/usr/bin', '/bin', '/usr/local/bin'], false, [], [])

check('empty entry flagged', ['/usr/bin', ''], false, [], ['empty-entry'])

check('relative entry flagged', ['bin', '/usr/bin'], false, [], ['relative-entry'])

check('duplicate entry flagged',
      ['/usr/bin', '/bin', '/usr/bin'], false, [], ['duplicate-entry'])

# Windows: user-writable dir before C:\Windows\System32 => CRIT.
check('windows writable before system',
      ['C:\\Users\\Public\\bin', 'C:\\Windows\\System32'], true, ['C:\\Users\\Public\\bin'],
      ['writable-before-system'])

check('windows clean path',
      ['C:\\Windows\\System32', 'C:\\Windows'], true, [], [])

check('windows relative entry',
      ['tools', 'C:\\Windows\\System32'], true, [], ['relative-entry'])

puts
if $fail.zero?
  puts 'all tests passed'
else
  puts "#{$fail} test(s) FAILED"; exit 1
end
