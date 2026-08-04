#!/usr/bin/env ruby
# frozen_string_literal: true
#
# windows_update_audit_test.rb
#
# Unit tests for Analyzer (the pure classification logic in
# windows_update_audit.rb) using hand-built SystemSnapshot fixtures.
# Windows Update Agent COM objects and WMI don't exist off Windows, so
# this test suite never touches WIN32OLE at all -- it feeds Analyzer
# realistic snapshots directly and checks the OK/WARN/CRIT verdict and
# reasons, exactly like the fixture files under test/fixtures/ that the
# CLI's --fixture flag exercises end-to-end. Run with: ruby windows_update_audit_test.rb
#
require_relative 'windows_update_audit'

$failures = 0
$checks = 0

def check(desc)
  $checks += 1
  if yield
    puts "  ok - #{desc}"
  else
    $failures += 1
    puts "  FAIL - #{desc}"
  end
end

def snapshot(reboot_required: false, pending: [], hotfixes: [])
  SystemSnapshot.new(
    hostname: 'TEST-HOST',
    collected_at: '2026-08-04T00:00:00Z',
    reboot_required: reboot_required,
    pending_updates: pending.map { |u| PendingUpdate.new(**u) },
    hotfixes: hotfixes.map { |h| Hotfix.new(**h) }
  )
end

analyzer = Analyzer.new(warn_days: 45, crit_days: 90)

puts 'clean system with recent patching -> OK'
snap = snapshot(hotfixes: [{ hotfix_id: 'KB1', installed_on: '8/1/2026', description: 'x' }])
v = analyzer.classify(snap)
check('status is OK') { v.status == 'OK' }
check('days_since_last_patch is 3') { v.days_since_last_patch == 3 }

puts 'one Critical pending update -> CRIT regardless of anything else'
snap = snapshot(
  hotfixes: [{ hotfix_id: 'KB1', installed_on: '8/1/2026', description: 'x' }],
  pending: [{ title: 'Sec update', kb_ids: ['KB9'], severity: 'Critical', is_downloaded: false }]
)
v = analyzer.classify(snap)
check('status is CRIT') { v.status == 'CRIT' }
check('reason mentions Critical') { v.reasons.any? { |r| r.include?('Critical-severity') } }

puts 'only Important pending update -> WARN, not CRIT'
snap = snapshot(
  hotfixes: [{ hotfix_id: 'KB1', installed_on: '8/1/2026', description: 'x' }],
  pending: [{ title: 'Cumulative update', kb_ids: ['KB9'], severity: 'Important', is_downloaded: true }]
)
v = analyzer.classify(snap)
check('status is WARN') { v.status == 'WARN' }

puts 'reboot required with no pending updates -> WARN'
snap = snapshot(reboot_required: true, hotfixes: [{ hotfix_id: 'KB1', installed_on: '8/1/2026', description: 'x' }])
v = analyzer.classify(snap)
check('status is WARN') { v.status == 'WARN' }
check('reason mentions reboot') { v.reasons.any? { |r| r.include?('reboot pending') } }

puts 'patching stale beyond crit_days -> CRIT even with nothing pending'
snap = snapshot(hotfixes: [{ hotfix_id: 'KB1', installed_on: '1/1/2026', description: 'x' }])
v = analyzer.classify(snap)
check('status is CRIT') { v.status == 'CRIT' }
check('days_since_last_patch > 90') { v.days_since_last_patch > 90 }

puts 'no hotfix history at all -> WARN (cannot confirm patching is active)'
snap = snapshot
v = analyzer.classify(snap)
check('status is WARN') { v.status == 'WARN' }
check('days_since_last_patch is nil') { v.days_since_last_patch.nil? }

puts 'US-locale M/D/Y InstalledOn strings are parsed correctly (regression: not D/M/Y)'
snap = snapshot(hotfixes: [{ hotfix_id: 'KB1', installed_on: '7/10/2026', description: 'x' }])
v = analyzer.classify(snap)
check('7/10/2026 means July 10th (25 days before Aug 4), not Oct 7th') { v.days_since_last_patch == 25 }

puts 'Critical + Important + reboot + stale all combine and CRIT wins'
snap = snapshot(
  reboot_required: true,
  hotfixes: [{ hotfix_id: 'KB1', installed_on: '1/1/2026', description: 'x' }],
  pending: [
    { title: 'Sec update', kb_ids: ['KB9'], severity: 'Critical', is_downloaded: false },
    { title: 'Cumulative', kb_ids: ['KB8'], severity: 'Important', is_downloaded: true }
  ]
)
v = analyzer.classify(snap)
check('status is CRIT') { v.status == 'CRIT' }
check('collects all 4 reasons') { v.reasons.size == 4 }

puts
puts "#{$checks - $failures}/#{$checks} checks passed"
exit($failures.zero? ? 0 : 1)
