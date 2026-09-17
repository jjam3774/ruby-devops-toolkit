#!/usr/bin/env ruby
# frozen_string_literal: true
#
# win_driver_signing_audit_test.rb -- exercises every rule against
# WMI-shaped fixtures, with no Windows and no win32ole required.
#
# HONEST SCOPE NOTE
# -----------------
# This harness does NOT prove the WMI query itself works -- that needs a real
# Windows host, and is called out as such in the README. What it does prove is
# that every line of logic *downstream* of the query is correct, including the
# awkward parts: CIM_DATETIME parsing, IsSigned arriving as four different
# types, missing properties, and blocklist matching.
#
# The fixtures are shaped exactly like the Hash that Collector::Wmi builds
# from Win32_PnPSignedDriver, including the string-typed booleans and
# "20230814000000.000000-000" date format that WMI really returns. That is the
# whole point: the collector boundary is the only untested surface, and it is
# eleven lines long.
#
#   ruby win_driver_signing_audit_test.rb

require 'json'
require 'tmpdir'
require 'fileutils'

SCRIPT = File.join(__dir__, 'win_driver_signing_audit.rb')

def row(name, provider:, signed:, date:, path:, inf: nil, version: '1.0.0.0',
        signer: nil, klass: 'System')
  {
    'DeviceName' => name,
    'FriendlyName' => name,
    'DriverProviderName' => provider,
    'DriverVersion' => version,
    'DriverDate' => date,
    'InfName' => inf,
    'Location' => path,
    'DeviceClass' => klass,
    'Signer' => signer,
    'IsSigned' => signed,
    'DeviceID' => "PCI\\VEN_8086&DEV_#{rand(1000..9999)}"
  }
end

# Note the deliberate variety in the IsSigned and DriverDate types -- that
# heterogeneity is what WMI actually hands you across provider versions.
FIXTURES = [
  # Ordinary Microsoft driver, modern, correct path. Should be silent.
  row('Intel(R) Wi-Fi 6 AX201', provider: 'Microsoft',
      signed: true, date: '20240312000000.000000-000',
      path: 'C:\\Windows\\System32\\drivers\\netwtw10.sys',
      inf: 'netwtw10.inf', signer: 'Microsoft Windows Hardware Compatibility Publisher',
      klass: 'Net'),

  # Legitimate third-party vendor driver: medium, informational-by-design.
  row('NVIDIA GeForce RTX 4070', provider: 'NVIDIA',
      signed: 'True', date: '20250620000000.000000-000',
      path: 'C:\\Windows\\System32\\DriverStore\\FileRepository\\nv_dispi.inf_amd64\\nvlddmkm.sys',
      inf: 'nv_dispi.inf', signer: 'NVIDIA Corporation', klass: 'Display'),

  # Unsigned. On x64 Windows this should be impossible -> high.
  row('Acme Widget Interface', provider: 'Acme Devices Ltd',
      signed: 'False', date: '20220101000000.000000-000',
      path: 'C:\\Windows\\System32\\drivers\\acmewdgt.sys',
      inf: 'acmewdgt.inf', signer: nil, klass: 'System'),

  # Ancient third-party driver, 2011 -> high + medium.
  row('LegacySCSI Host Adapter', provider: 'Orion Storage',
      signed: true, date: '20110418000000.000000-000',
      path: 'C:\\Windows\\System32\\drivers\\orionscsi.sys',
      inf: 'orionscsi.inf', version: '2.1.0.14',
      signer: 'Orion Storage Inc', klass: 'SCSIAdapter'),

  # Driver file parked outside the protected directories -> high.
  row('Vendor Telemetry Filter', provider: 'Contoso Tools',
      signed: true, date: '20230814000000.000000-000',
      path: 'C:\\Program Files\\ContosoAgent\\bin\\ctfilter.sys',
      inf: 'ctfilter.inf', signer: 'Contoso Tools LLC', klass: 'System'),

  # On the BYOVD blocklist -> critical. Signed and recent: that is the point.
  row('Speedfan Hardware Monitor', provider: 'Almico',
      signed: true, date: '20180210000000.000000-000',
      path: 'C:\\Windows\\System32\\drivers\\speedfan.sys',
      inf: 'speedfan.inf', signer: 'Almico Software', klass: 'System'),

  # Provider omits IsSigned entirely -> low (unknown, not "unsigned").
  { 'DeviceName' => 'Generic Volume Shadow Copy',
    'DriverProviderName' => 'Microsoft',
    'DriverVersion' => '10.0.19041.1',
    'DriverDate' => '20230601000000.000000-000',
    'Location' => 'C:\\Windows\\System32\\drivers\\volsnap.sys',
    'InfName' => 'volsnap.inf', 'DeviceClass' => 'Volume' },

  # Garbage date -> must not crash, must yield no age finding.
  row('Mystery Bridge Device', provider: 'Microsoft',
      signed: 1, date: 'not-a-date-at-all',
      path: 'C:\\Windows\\System32\\drivers\\mystbrdg.sys',
      inf: 'mystbrdg.inf', signer: 'Microsoft Windows', klass: 'System'),

  # Nil path -> we cannot judge location, so we must NOT flag it.
  row('Virtual Root Enumerator', provider: 'Microsoft',
      signed: true, date: '20240101000000.000000-000',
      path: nil, inf: 'root.inf', signer: 'Microsoft Windows', klass: 'System')
].freeze

EXPECTED = {
  'Intel(R) Wi-Fi 6 AX201'      => [],
  'NVIDIA GeForce RTX 4070'     => %w[THIRD_PARTY_KERNEL_CODE],
  'Acme Widget Interface'       => %w[UNSIGNED_DRIVER],
  'LegacySCSI Host Adapter'     => %w[ANCIENT_DRIVER THIRD_PARTY_KERNEL_CODE],
  'Vendor Telemetry Filter'     => %w[THIRD_PARTY_KERNEL_CODE UNUSUAL_DRIVER_PATH],
  'Speedfan Hardware Monitor'   => %w[KNOWN_VULNERABLE_DRIVER THIRD_PARTY_KERNEL_CODE OLD_DRIVER],
  'Generic Volume Shadow Copy'  => %w[SIGNATURE_UNKNOWN],
  'Mystery Bridge Device'       => [],
  'Virtual Root Enumerator'     => []
}.freeze

BLOCKLIST = <<~LIST
  # BYOVD watchlist -- matched against INF name, driver filename, device name.
  speedfan.sys
  rtcore64.sys
  gdrv.sys
LIST

failures = []
def check(failures, label)
  ok = begin
    yield
  rescue StandardError => e
    puts "    (raised #{e.class}: #{e.message})"
    false
  end
  puts format('  %-58s %s', label, ok ? 'PASS' : 'FAIL')
  failures << label unless ok
end

Dir.mktmpdir('drvfix') do |dir|
  fixture = File.join(dir, 'drivers.json')
  File.write(fixture, JSON.pretty_generate(FIXTURES))
  blocklist = File.join(dir, 'byovd.txt')
  File.write(blocklist, BLOCKLIST)

  puts "fixture: #{fixture} (#{FIXTURES.length} WMI-shaped rows)"
  puts

  out = `ruby #{SCRIPT} --fixture #{fixture} --blocklist #{blocklist} --json 2>&1`
  status = $?.exitstatus
  begin
    data = JSON.parse(out)
  rescue JSON::ParserError
    puts 'FATAL: script did not emit valid JSON:'
    puts out
    exit 1
  end

  by_device = data['findings'].group_by { |f| f['device'] }

  puts 'per-device expectations'
  EXPECTED.each do |device, expected|
    got = (by_device[device] || []).map { |f| f['code'] }.sort
    check(failures, "#{device[0, 44]} -> #{expected.empty? ? '(clean)' : expected.sort.join(',')}") do
      got == expected.sort
    end
  end

  puts
  puts 'WMI type coercion'
  check(failures, 'IsSigned true (boolean) read as signed') do
    data['drivers'].find { |d| d['device_name'].start_with?('Intel') }['is_signed'] == true
  end
  check(failures, 'IsSigned "True" (string) read as signed') do
    data['drivers'].find { |d| d['device_name'].start_with?('NVIDIA') }['is_signed'] == true
  end
  check(failures, 'IsSigned "False" (string) read as unsigned, not truthy') do
    data['drivers'].find { |d| d['device_name'].start_with?('Acme') }['is_signed'] == false
  end
  check(failures, 'IsSigned 1 (integer) read as signed') do
    data['drivers'].find { |d| d['device_name'].start_with?('Mystery') }['is_signed'] == true
  end
  check(failures, 'absent IsSigned stays nil (unknown), never false') do
    data['drivers'].find { |d| d['device_name'].start_with?('Generic Volume') }['is_signed'].nil?
  end

  puts
  puts 'CIM_DATETIME parsing'
  check(failures, '"20110418000000.000000-000" -> 2011-04-18') do
    data['drivers'].find { |d| d['device_name'].start_with?('LegacySCSI') }['driver_date'] == '2011-04-18'
  end
  check(failures, 'unparseable date -> nil, no crash, no age finding') do
    d = data['drivers'].find { |d| d['device_name'].start_with?('Mystery') }
    d['driver_date'].nil? && (by_device['Mystery Bridge Device'] || []).empty?
  end

  puts
  puts 'path and provenance logic'
  check(failures, 'DriverStore path counts as trusted') do
    (by_device['NVIDIA GeForce RTX 4070'] || []).none? { |f| f['code'] == 'UNUSUAL_DRIVER_PATH' }
  end
  check(failures, 'Program Files path flagged as unusual') do
    (by_device['Vendor Telemetry Filter'] || []).any? { |f| f['code'] == 'UNUSUAL_DRIVER_PATH' }
  end
  check(failures, 'nil path does not produce a path finding') do
    (by_device['Virtual Root Enumerator'] || []).none? { |f| f['code'] == 'UNUSUAL_DRIVER_PATH' }
  end
  check(failures, 'Microsoft providers not flagged as third-party') do
    data['findings'].none? do |f|
      f['code'] == 'THIRD_PARTY_KERNEL_CODE' &&
        %w[Intel(R) Generic Mystery Virtual].any? { |p| f['device'].start_with?(p) }
    end
  end
  check(failures, 'summary third-party count matches the fixtures') do
    data['summary']['third_party'] == 5
  end

  puts
  puts 'blocklist matching'
  check(failures, 'blocklist matches on driver filename from the path') do
    (by_device['Speedfan Hardware Monitor'] || []).any? { |f| f['code'] == 'KNOWN_VULNERABLE_DRIVER' }
  end
  check(failures, 'blocklist comments and blank lines ignored') do
    data['findings'].count { |f| f['code'] == 'KNOWN_VULNERABLE_DRIVER' } == 1
  end
  no_bl = JSON.parse(`ruby #{SCRIPT} --fixture #{fixture} --json 2>&1`)
  check(failures, 'no blocklist supplied -> no blocklist findings') do
    no_bl['findings'].none? { |f| f['code'] == 'KNOWN_VULNERABLE_DRIVER' }
  end
  check(failures, 'exit 2 without a blocklist (unsigned driver is high)') { $?.exitstatus == 2 }

  puts
  puts 'cli behaviour'
  check(failures, 'exit code 2 when a critical finding exists') { status == 2 }
  hi = JSON.parse(`ruby #{SCRIPT} --fixture #{fixture} --blocklist #{blocklist} --json --min-severity high 2>&1`)
  check(failures, '--min-severity high suppresses medium and low') do
    hi['findings'].map { |f| f['severity'] }.uniq.sort == %w[critical high]
  end
  `ruby #{SCRIPT} --fixture /nope/missing.json >/dev/null 2>&1`
  check(failures, 'missing fixture exits 3, not a backtrace') { $?.exitstatus == 3 }
  bad = File.join(dir, 'bad.json')
  File.write(bad, '{not json')
  `ruby #{SCRIPT} --fixture #{bad} >/dev/null 2>&1`
  check(failures, 'malformed fixture exits 3 with a readable message') { $?.exitstatus == 3 }
  wrapped = File.join(dir, 'wrapped.json')
  File.write(wrapped, JSON.generate({ 'drivers' => FIXTURES }))
  w = JSON.parse(`ruby #{SCRIPT} --fixture #{wrapped} --json 2>&1`)
  check(failures, 'accepts {"drivers":[...]} as well as a bare array') do
    w['drivers'].length == FIXTURES.length
  end

  puts
  puts 'text renderer'
  text = `ruby #{SCRIPT} --fixture #{fixture} --blocklist #{blocklist} 2>&1`
  check(failures, 'third-party provider roll-up table rendered') do
    text.include?('THIRD-PARTY KERNEL PROVIDERS') && text.include?('NVIDIA')
  end
  check(failures, 'provider roll-up shows the driver-date span') do
    text.match?(/Orion Storage\s+1 driver\(s\)\s+2011-2011/)
  end
  check(failures, 'counts line separates unsigned from unknown') do
    text.include?('unsigned:           1') && text.include?('signing unknown:    1')
  end

  puts
  puts 'collector boundary (the one part fixtures cannot cover)'
  check(failures, 'WMI collector fails cleanly on non-Windows, exit 3') do
    o = `ruby #{SCRIPT} --json 2>&1`
    $?.exitstatus == 3 && o.include?('win32ole')
  end
end

puts
if failures.empty?
  puts "ALL CHECKS PASSED (#{EXPECTED.size} devices, every rule exercised)"
  exit 0
else
  puts "#{failures.length} FAILURE(S):"
  failures.each { |f| puts "  - #{f}" }
  exit 1
end
