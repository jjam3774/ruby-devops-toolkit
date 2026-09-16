#!/usr/bin/env ruby
# frozen_string_literal: true
#
# test_spooler_audit.rb -- Mock-collector test harness for win_print_spooler_audit.rb
#
# The live audit needs WMI and the Windows registry, neither of which exists on
# Linux or macOS. Rather than leave the logic untested until it reaches a real
# domain controller, every OS call in the audit sits behind the collector
# interface, and this harness drives that interface with hand-built data.
#
# That means the decision logic -- which values are FAIL, which are WARN, how a
# domain controller differs from a print server -- is exercised on any machine
# with Ruby on it, including CI. Only the ~40 lines of WMI/registry plumbing in
# WindowsCollector remain untested off Windows, and those are thin wrappers
# around single queries.
#
#   ruby test_spooler_audit.rb
#
# Exit code 0 = all assertions passed, 1 = at least one failed.

require 'json'
require 'tmpdir'

$PROGRAM_NAME_BACKUP = $PROGRAM_NAME
require_relative 'win_print_spooler_audit'

PASSED = []
FAILED = []

def check(label)
  if yield
    PASSED << label
    puts "  ok    #{label}"
  else
    FAILED << label
    puts "  FAIL  #{label}"
  end
rescue StandardError => e
  FAILED << label
  puts "  ERROR #{label}: #{e.class}: #{e.message}"
end

# A collector built from a plain Hash -- no files, no OS, no WMI.
class MockCollector
  def initialize(data) = @data = data
  def service(name) = (@data['services'] || {})[name]
  def printers = @data['printers'] || []
  def drivers = @data['drivers'] || []
  def os_role = @data['os'] || {}
  def reg_value(key, name) = (@data.dig('registry', key) || {})[name]
end

def base(overrides = {})
  {
    'os' => { 'product_type' => 1, 'caption' => 'Windows 11 Enterprise' },
    'services' => { 'Spooler' => { 'name' => 'Spooler', 'state' => 'Stopped',
                                   'start_mode' => 'Disabled', 'start_name' => 'LocalSystem' } },
    'printers' => [],
    'drivers' => [],
    'registry' => {
      PRINTERS_POLICY => { 'RestrictDriverInstallationToAdministrators' => 1,
                           'RegisterSpoolerRemoteRpcEndPoint' => 2 },
      POINT_AND_PRINT => { 'NoWarningNoElevationOnInstall' => 0, 'UpdatePromptSettings' => 0,
                           'Restricted' => 1, 'TrustedServers' => 1,
                           'ServerList' => 'printsrv01.corp.example',
                           'PackagePointAndPrintOnly' => 1 },
      PRINT_CONTROL => { 'RpcAuthnLevelPrivacyEnabled' => 1 },
      PRINTERS_POLICY + '\PackagePointAndPrintServerList' =>
        { 'PackagePointAndPrintServerList' => 'printsrv01.corp.example' }
    }
  }.merge(overrides)
end

def run(data, role: nil)
  SpoolerAudit.new(MockCollector.new(data), role: role).run
end

def sev_of(findings, id_prefix)
  findings.find { |f| f['id'].start_with?(id_prefix) }&.fetch('severity')
end

puts
puts '=' * 70
puts '  win_print_spooler_audit.rb -- mock collector test harness'
puts "  ruby #{RUBY_VERSION} on #{RUBY_PLATFORM}"
puts '=' * 70
puts
puts 'baseline: fully hardened workstation'

findings, facts = run(base)
check('hardened host yields zero FAIL findings') { findings.none? { |f| f['severity'] == 'FAIL' } }
check('hardened host yields zero WARN findings') { findings.none? { |f| f['severity'] == 'WARN' } }
check('stopped spooler reported as PASS')        { sev_of(findings, 'spooler.state') == 'PASS' }
check('role inferred as workstation')            { facts['role'] == 'workstation' }

puts
puts 'registry regressions'

d = base
d['registry'][PRINTERS_POLICY] = { 'RestrictDriverInstallationToAdministrators' => 0 }
f, = run(d)
check('RestrictDriverInstallation=0 is FAIL') { sev_of(f, 'pnp.restrict_driver_install') == 'FAIL' }

d = base
d['registry'][PRINTERS_POLICY] = {}
f, = run(d)
check('RestrictDriverInstallation unset is WARN, not PASS') do
  sev_of(f, 'pnp.restrict_driver_install') == 'WARN'
end

d = base
d['registry'][POINT_AND_PRINT]['NoWarningNoElevationOnInstall'] = 1
f, = run(d)
check('NoWarningNoElevationOnInstall=1 is FAIL') { sev_of(f, 'pnp.no_warning') == 'FAIL' }

d = base
d['registry'][POINT_AND_PRINT]['UpdatePromptSettings'] = 1
f, = run(d)
check('UpdatePromptSettings=1 is FAIL') { sev_of(f, 'pnp.update_prompt') == 'FAIL' }

d = base
d['registry'][PRINT_CONTROL]['RpcAuthnLevelPrivacyEnabled'] = 0
f, = run(d)
check('RpcAuthnLevelPrivacyEnabled=0 is FAIL') { sev_of(f, 'rpc.authn_privacy') == 'FAIL' }

d = base
d['registry'][PRINT_CONTROL] = {}
f, = run(d)
check('RpcAuthnLevelPrivacyEnabled absent is PASS (patched default)') do
  sev_of(f, 'rpc.authn_privacy') == 'PASS'
end

d = base
d['registry'][POINT_AND_PRINT]['TrustedServers'] = 0
f, = run(d)
check('Restricted without TrustedServers is WARN') { sev_of(f, 'pnp.trusted_servers') == 'WARN' }

d = base
d['registry'][POINT_AND_PRINT]['PackagePointAndPrintOnly'] = 0
f, = run(d)
check('PackagePointAndPrintOnly=0 is WARN') { sev_of(f, 'pnp.package_only') == 'WARN' }

puts
puts 'host role logic'

d = base
d['os']['product_type'] = 2
d['services']['Spooler'] = { 'state' => 'Running', 'start_mode' => 'Auto', 'start_name' => 'LocalSystem' }
f, facts = run(d)
check('running spooler on a DC is FAIL') { sev_of(f, 'spooler.on_dc') == 'FAIL' }
check('DC role inferred from ProductType=2') { facts['role'] == 'domain-controller' }

f, = run(d, role: 'print-server')
check('--role print-server downgrades the spooler finding to INFO') do
  sev_of(f, 'spooler.on_print_server') == 'INFO' && sev_of(f, 'spooler.on_dc').nil?
end

d = base
d['os']['product_type'] = 3
d['services']['Spooler'] = { 'state' => 'Running', 'start_mode' => 'Auto', 'start_name' => 'LocalSystem' }
f, = run(d)
check('running spooler on a plain member server is WARN') do
  sev_of(f, 'spooler.on_member_server') == 'WARN'
end

puts
puts 'printer and driver inventory'

d = base
d['printers'] = [{ 'name' => 'Archive', 'shared' => true, 'share_name' => 'ARCH',
                   'port' => 'FILE:', 'driver' => 'Microsoft Print To PDF' }]
f, = run(d)
check('shared FILE: port printer is FAIL') { sev_of(f, 'printer.file_port') == 'FAIL' }

d = base
d['printers'] = [{ 'name' => 'Archive', 'shared' => false, 'port' => 'FILE:', 'driver' => 'x' }]
f, = run(d)
check('unshared FILE: port printer is WARN') { sev_of(f, 'printer.file_port') == 'WARN' }

d = base
d['drivers'] = [{ 'name' => 'Vendor', 'path' => 'C:\\Program Files\\Acme\\bin\\prn.dll' }]
f, = run(d)
check('driver outside the driver store is WARN') { sev_of(f, 'driver.outside_store') == 'WARN' }
check('remediation shows the Windows parent dir, not "."') do
  f.find { |x| x['id'].start_with?('driver.outside_store') }['remediation']
   .include?('C:\\Program Files\\Acme\\bin')
end

d = base
d['drivers'] = [{ 'name' => 'HP', 'path' => 'C:\\Windows\\system32\\spool\\drivers\\x64\\3\\unidrv.dll' }]
f, = run(d)
check('driver inside the driver store is not flagged') { sev_of(f, 'driver.outside_store').nil? }

puts
puts 'fixture round-trip and JSON shape'

Dir.mktmpdir do |dir|
  path = File.join(dir, 'snap.json')
  File.write(path, JSON.pretty_generate(base))
  fc = FixtureCollector.new(path)
  ff, = SpoolerAudit.new(fc, role: nil).run
  check('FixtureCollector reproduces the MockCollector result') do
    ff.none? { |x| x['severity'] == 'FAIL' }
  end
end

f, = run(base)
check('every finding carries severity, id and message') do
  f.all? { |x| x['severity'] && x['id'] && x['message'] }
end
check('every FAIL/WARN carries a remediation') do
  run(base({ 'registry' => base['registry'] }))
  bad = base
  bad['registry'][PRINTERS_POLICY] = { 'RestrictDriverInstallationToAdministrators' => 0 }
  ff, = run(bad)
  ff.select { |x| %w[FAIL WARN].include?(x['severity']) }
    .reject { |x| x['id'].start_with?('printer.shared') }
    .all? { |x| x['remediation'] }
end

puts
puts '-' * 70
puts "  #{PASSED.size} passed, #{FAILED.size} failed"
puts '-' * 70
puts

exit(FAILED.empty? ? 0 : 1)
