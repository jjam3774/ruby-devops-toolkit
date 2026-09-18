#!/usr/bin/env ruby
# frozen_string_literal: true
#
# test_harness.rb -- verifies the audit logic without Windows.
#
# win32ole only exists on Windows Ruby, so the WMI call itself cannot execute on
# Linux or macOS. Everything *around* it can: the InstallState decoding, the
# prefix-based risk matching, the severity ranking and the exit codes are pure
# Ruby operating on plain hashes. Those are also where the bugs live -- a WMI
# query that returns rows is the easy part.
#
# This harness feeds the Analyzer the exact row shape WmiProvider produces and
# asserts on the result, so the logic is covered on any OS.
#
#   ruby test_harness.rb

require_relative 'win_optional_features_audit'

include WinOptionalFeaturesAudit

PASS = []
FAIL = []

def check(desc)
  ok = yield
  (ok ? PASS : FAIL) << desc
  puts format('  %s %s', ok ? 'ok  ' : 'FAIL', desc)
rescue StandardError => e
  FAIL << desc
  puts format('  FAIL %s  (%s: %s)', desc, e.class, e.message)
end

def row(name, state, caption = '')
  { 'Name' => name, 'Caption' => caption, 'InstallState' => state }
end

puts 'win_optional_features_audit -- logic tests'
puts '-' * 62

# --- InstallState decoding -------------------------------------------------
puts "\nInstallState decoding"
a = Analyzer.new([row('TelnetClient', 1), row('TFTP', 2),
                  row('SimpleTCP', 3), row('Whatever', 9)])
check('state 1 decodes to :enabled')  { a.features[0].state == :enabled }
check('state 2 decodes to :disabled') { a.features[1].state == :disabled }
check('state 3 decodes to :absent')   { a.features[2].state == :absent }
check('unknown state falls back to :unknown') { a.features[3].state == :unknown }

# This is the whole point of decoding rather than truthiness-testing: a
# disabled feature has a NON-ZERO InstallState, so `if row['InstallState']`
# would report every disabled feature as enabled.
check('disabled feature is not reported as risky') { a.features[1].risky? == false }
check('absent feature is not reported as risky')   { a.features[2].risky? == false }

# --- Risk matching ---------------------------------------------------------
puts "\nRisk catalogue matching"
b = Analyzer.new([
  row('SMB1Protocol', 1),
  row('SMB1Protocol-Server', 1),
  row('SMB1Protocol-Client', 1),
  row('MicrosoftWindowsPowerShellV2Root', 1),
  row('Printing-Foundation-Features', 1),
  row('NetFx4-AdvSrvs', 1)
])
check('parent SMB1Protocol matches')            { b.features[0].risk&.severity == :high }
check('child SMB1Protocol-Server matches too')  { b.features[1].risk&.severity == :high }
check('child SMB1Protocol-Client matches too')  { b.features[2].risk&.severity == :high }
check('PowerShellV2Root matches V2 entry')      { b.features[3].risk&.severity == :high }
check('unlisted feature has no risk')           { b.features[4].risk.nil? }
# Guards against a real prefix collision: "NetFx4-AdvSrvs" must NOT match the
# "NetFx3" catalogue entry. It does not share the prefix, but a sloppier
# `include?` match would have caught it.
check('NetFx4 does not match the NetFx3 entry') { b.features[5].risk.nil? }

# --- Severity ordering and exit codes --------------------------------------
puts "\nSeverity ordering"
c = Analyzer.new([row('WindowsMediaPlayer', 1), row('TFTP', 1), row('SMB1Protocol', 1)])
check('worst severity is :high')   { c.worst_severity == :high }
check('risky list is high-first')  { c.risky.map { |f| f.risk.severity } == %i[high medium low] }

d = Analyzer.new([row('TelnetClient', 1), row('WindowsMediaPlayer', 1)])
check('medium is worst when no high present') { d.worst_severity == :medium }

e = Analyzer.new([row('SMB1Protocol', 2), row('TelnetClient', 3)])
check('clean host reports no worst severity')  { e.worst_severity.nil? }
check('clean host has empty risky list')       { e.risky.empty? }

# --- Malformed input -------------------------------------------------------
puts "\nMalformed / defensive input"
f = Analyzer.new([{ 'Name' => nil, 'Caption' => nil, 'InstallState' => nil }])
check('nil row does not raise')             { f.features.size == 1 }
check('nil InstallState becomes :unknown')  { f.features[0].state == :unknown }
check('empty feature list is handled')      { Analyzer.new([]).risky.empty? }

# --- Reporting -------------------------------------------------------------
puts "\nReporting"
g = Analyzer.new([row('SMB1Protocol', 1, 'SMB 1.0/CIFS File Sharing Support')])
txt = Report.text(g, '.', false)
check('text report names the feature')   { txt.include?('SMB1Protocol') }
check('text report includes a fix line') { txt.include?('Disable-WindowsOptionalFeature') }
json = JSON.parse(Report.json(g, 'FILESRV01'))
check('json reports computer name')      { json['computer'] == 'FILESRV01' }
check('json emits remediation script')   { json['remediation_script'].size == 1 }
check('json worst_severity is high')     { json['worst_severity'] == 'high' }

puts "\n" + ('-' * 62)
puts format('%d passed, %d failed', PASS.size, FAIL.size)
exit(FAIL.empty? ? 0 : 1)
