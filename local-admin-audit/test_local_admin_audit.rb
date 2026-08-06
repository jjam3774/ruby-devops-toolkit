#!/usr/bin/env ruby
# frozen_string_literal: true
#
# test_local_admin_audit.rb — Stub-based test harness for local_admin_audit.rb.
#
# WMI/win32ole don't exist off Windows, so this harness swaps in
# StubAdminGroupSource (fixture-backed, no WMI calls at all) in place of
# WmiAdminGroupSource, and drives the exact same `run()` / `AdminAudit`
# code paths the real script uses. This is the "mock/stub harness for
# Windows-only APIs" approach — it proves the comparison/reporting logic
# is correct; it does not (and cannot, outside Windows) prove the WMI
# ASSOCIATORS OF query itself is syntactically valid against a live host.
#
# Run:
#   ruby test_local_admin_audit.rb

require_relative 'local_admin_audit'
require 'tmpdir'
require 'yaml'

failures = 0

def check(name, condition)
  if condition
    puts "  PASS  #{name}"
  else
    puts "  FAIL  #{name}"
    $failures_local += 1
  end
end

$failures_local = 0

puts '== AdminAudit.evaluate (pure logic) =='

# Case 1: exact match, no findings
r = AdminAudit.evaluate(%w[CORP\\Domain\ Admins CORP\\svc-edr], %w[CORP\\Domain\ Admins CORP\\svc-edr])
check('clean host -> no unauthorized', r[:unauthorized].empty?)
check('clean host -> no missing', r[:missing].empty?)

# Case 2: an extra account was added -> unauthorized
r = AdminAudit.evaluate(
  ['CORP\\Domain Admins', 'CORP\\svc-edr', 'CORP\\jsmith'],
  ['CORP\\Domain Admins', 'CORP\\svc-edr']
)
check('extra member flagged unauthorized', r[:unauthorized] == ['CORP\\jsmith'])
check('no false missing', r[:missing].empty?)

# Case 3: a required account is absent -> missing
r = AdminAudit.evaluate(
  ['CORP\\Domain Admins'],
  ['CORP\\Domain Admins', 'CORP\\svc-edr']
)
check('absent required member flagged missing', r[:missing] == ['CORP\\svc-edr'])
check('no false unauthorized', r[:unauthorized].empty?)

# Case 4: case-insensitive comparison (Windows account names aren't case sensitive)
r = AdminAudit.evaluate(['CORP\\JSmith'], ['corp\\jsmith'])
check('case-insensitive match treated as OK', r[:unauthorized].empty? && r[:missing].empty?)

puts "\n== End-to-end run() with StubAdminGroupSource =="

Dir.mktmpdir('fim-admin-audit-test-') do |dir|
  allowlist_path = File.join(dir, 'allowlist.yml')
  File.write(allowlist_path, YAML.dump(
                'default' => ['CORP\\Domain Admins', 'CORP\\svc-edr'],
                'overrides' => {
                  'WEB01' => ['CORP\\Domain Admins', 'CORP\\svc-edr', 'CORP\\jsmith']
                }
              ))

  fixture = {
    'WEB01' => ['CORP\\Domain Admins', 'CORP\\svc-edr', 'CORP\\jsmith'],   # matches its override exactly -> OK
    'WEB02' => ['CORP\\Domain Admins', 'CORP\\bcompromised'],              # unauthorized extra, missing svc-edr
    'DB01'  => ['CORP\\Domain Admins', 'CORP\\svc-edr']                    # matches default -> OK
  }

  inventory_path = File.join(dir, 'hosts.txt')
  File.write(inventory_path, fixture.keys.join("\n"))

  out_path = File.join(dir, 'report.json')
  options = {
    inventory: inventory_path,
    allowlist: allowlist_path,
    out: out_path,
    source: StubAdminGroupSource.new(fixture)
  }

  exit_code = run(options)

  check('run() returns 1 when findings exist', exit_code == 1)

  report = JSON.parse(File.read(out_path))
  check('WEB01 status OK', report['hosts']['WEB01']['status'] == 'OK')
  check('DB01 status OK', report['hosts']['DB01']['status'] == 'OK')
  check('WEB02 status FINDINGS', report['hosts']['WEB02']['status'] == 'FINDINGS')
  check('WEB02 unauthorized includes bcompromised', report['hosts']['WEB02']['unauthorized'].include?('CORP\\bcompromised'))
  check('WEB02 missing includes svc-edr', report['hosts']['WEB02']['missing'].include?('CORP\\svc-edr'))
end

puts "\n#{$failures_local.zero? ? 'ALL TESTS PASSED' : "#{$failures_local} TEST(S) FAILED"}"
exit($failures_local.zero? ? 0 : 1)
