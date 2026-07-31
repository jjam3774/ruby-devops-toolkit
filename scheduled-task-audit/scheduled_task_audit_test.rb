#!/usr/bin/env ruby
# frozen_string_literal: true
#
# scheduled_task_audit_test.rb
#
# Platform-independent stub test harness for scheduled_task_audit.rb.
#
# Schedule.Service is a Windows-only COM object, so `TaskFetcher` (which
# talks to WIN32OLE) cannot be exercised on Linux/macOS. Instead this test
# feeds `evaluate_task` -- the pure risk-scoring function -- realistic fixture
# hashes shaped exactly like what `TaskFetcher#build_task_hash` produces from
# a live ITaskService/IRegisteredTask/IPrincipal/IExecAction COM tree. This
# mirrors how service_audit.rb and registry_drift.rb in this same repo are
# tested: the WIN32OLE plumbing is verified by code review against
# Microsoft's documented object model, and the decision logic is verified
# with fixtures. Run with: ruby scheduled_task_audit_test.rb

require_relative 'scheduled_task_audit'

$failures = 0
$assertions = 0

def assert(description, condition)
  $assertions += 1
  if condition
    puts "  PASS  #{description}"
  else
    $failures += 1
    puts "  FAIL  #{description}"
  end
end

def fixture(overrides = {})
  {
    name: 'CleanupTask',
    path: '\\Custom\\CleanupTask',
    enabled: true,
    hidden: false,
    run_as: 'SYSTEM',
    run_level: 'Highest',
    actions: [{ execute: 'C:\\Windows\\System32\\cleanup.exe', arguments: '' }]
  }.merge(overrides)
end

puts 'scheduled_task_audit_test.rb -- exercising evaluate_task() against WIN32OLE-shaped fixtures'
puts '=' * 78

puts "\n[1] Healthy task: trusted path, quoted, not hidden"
findings = evaluate_task(fixture)
assert('no findings for a clean SYSTEM task in C:\\Windows\\System32', findings.empty?)

puts "\n[2] Unquoted path with a space -- classic hijack vector"
task = fixture(actions: [{ execute: 'C:\\Program Files\\Vendor App\\run.exe', arguments: '' }])
findings = evaluate_task(task)
assert('flags unquoted-action-path', findings.any? { |f| f.check == 'unquoted-action-path' })
assert('severity is crit', findings.find { |f| f.check == 'unquoted-action-path' }.severity == :crit)

puts "\n[3] Same path, properly quoted -- should NOT flag unquoted-action-path"
task = fixture(actions: [{ execute: '"C:\\Program Files\\Vendor App\\run.exe"', arguments: '' }])
findings = evaluate_task(task)
assert('does not flag a properly quoted path', findings.none? { |f| f.check == 'unquoted-action-path' })

puts "\n[4] SYSTEM task launching a script from a user-writable Temp directory"
task = fixture(actions: [{ execute: 'C:\\Users\\svc-deploy\\AppData\\Local\\Temp\\run.bat', arguments: '' }])
findings = evaluate_task(task)
assert('flags writable-action-directory', findings.any? { |f| f.check == 'writable-action-directory' })
assert('also flags privileged-task-untrusted-path (SYSTEM + outside trusted roots)',
       findings.any? { |f| f.check == 'privileged-task-untrusted-path' })

puts "\n[5] Non-privileged task in an untrusted path -- should NOT trigger the privileged check"
task = fixture(run_as: 'DOMAIN\\alice', run_level: 'LUA',
                actions: [{ execute: 'C:\\Users\\alice\\tools\\backup.exe', arguments: '' }])
findings = evaluate_task(task)
assert('does not flag privileged-task-untrusted-path for a non-privileged user task',
       findings.none? { |f| f.check == 'privileged-task-untrusted-path' })
assert('still flags writable-action-directory (it is under \\Users\\)',
       findings.any? { |f| f.check == 'writable-action-directory' })

puts "\n[6] Hidden + highest run level -- stealth persistence pattern"
task = fixture(hidden: true, run_level: 'Highest')
findings = evaluate_task(task)
assert('flags hidden-and-elevated', findings.any? { |f| f.check == 'hidden-and-elevated' })

puts "\n[7] Hidden but LUA (not elevated) -- should NOT flag hidden-and-elevated"
task = fixture(hidden: true, run_level: 'LUA', run_as: 'DOMAIN\\alice')
findings = evaluate_task(task)
assert('does not flag hidden-and-elevated when run level is LUA',
       findings.none? { |f| f.check == 'hidden-and-elevated' })

puts "\n[8] Multiple actions on one task -- each action evaluated independently"
task = fixture(actions: [
                  { execute: 'C:\\Windows\\System32\\cleanup.exe', arguments: '' },
                  { execute: 'C:\\ProgramData\\legacyapp\\worker.exe', arguments: '' }
                ])
findings = evaluate_task(task)
assert('flags exactly one writable-action-directory (second action only)',
       findings.count { |f| f.check == 'writable-action-directory' } == 1)

puts "\n#{'=' * 78}"
puts "#{$assertions} assertions, #{$failures} failures"
exit($failures.zero? ? 0 : 1)
