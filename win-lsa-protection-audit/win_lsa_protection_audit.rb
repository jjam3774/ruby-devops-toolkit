#!/usr/bin/env ruby
# frozen_string_literal: true
#
# win_lsa_protection_audit.rb - Audit Windows credential-protection registry settings.
#
# Checks: LSA protected process (RunAsPPL), WDigest cleartext caching
# (UseLogonCredential), NTLM compatibility level (LmCompatibilityLevel) and
# "Everyone includes Anonymous" (everyoneincludesanonymous).
#
# Windows only for real use (needs the win32/registry stdlib). The checking logic
# takes any object responding to #read(key, name), so it is unit-testable on Linux.
#
# Usage:  ruby win_lsa_protection_audit.rb [--json] [--self-test]
# Exit:   0 = compliant, 1 = findings
require 'json'
require 'optparse'

# key path (under HKLM), value name, predicate, severity, why, remediation
CHECKS = [
  { key: 'SYSTEM\CurrentControlSet\Control\Lsa', name: 'RunAsPPL', sev: 'HIGH',
    ok: ->(v) { [1, 2].include?(v) }, want: '1 or 2',
    why: 'LSASS is not a protected process; credential dumpers can read its memory.' },
  { key: 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest', name: 'UseLogonCredential', sev: 'CRITICAL',
    ok: ->(v) { v.nil? || v.zero? }, want: '0 or absent',
    why: 'WDigest keeps cleartext passwords in LSASS memory.' },
  { key: 'SYSTEM\CurrentControlSet\Control\Lsa', name: 'LmCompatibilityLevel', sev: 'MEDIUM',
    ok: ->(v) { !v.nil? && v >= 5 }, want: '5',
    why: 'Allows LM/NTLMv1 authentication, which is trivially crackable.' },
  { key: 'SYSTEM\CurrentControlSet\Control\Lsa', name: 'everyoneincludesanonymous', sev: 'MEDIUM',
    ok: ->(v) { v.nil? || v.zero? }, want: '0',
    why: 'Anonymous users receive the permissions granted to Everyone.' }
].freeze

# Real reader: uses Ruby's bundled win32/registry (Windows only).
class RegistryReader
  def initialize
    require 'win32/registry'
  end

  def read(key, name)
    Win32::Registry::HKEY_LOCAL_MACHINE.open(key, Win32::Registry::KEY_READ) { |r| r[name] }
  rescue Win32::Registry::Error
    nil # key or value absent
  end
end

# Test double: hash of "KEY\\NAME" => value
class FakeReader
  def initialize(data) = @data = data
  def read(key, name) = @data["#{key}\\#{name}"]
end

def run_checks(reader)
  CHECKS.map do |c|
    val = reader.read(c[:key], c[:name])
    pass = c[:ok].call(val)
    { setting: c[:name], value: val.nil? ? 'absent' : val, expected: c[:want],
      status: pass ? 'PASS' : 'FAIL', severity: pass ? '-' : c[:sev], why: pass ? '' : c[:why] }
  end
end

def self_test
  lsa = 'SYSTEM\CurrentControlSet\Control\Lsa'
  wd  = 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
  good = FakeReader.new("#{lsa}\\RunAsPPL" => 1, "#{lsa}\\LmCompatibilityLevel" => 5)
  bad  = FakeReader.new("#{wd}\\UseLogonCredential" => 1, "#{lsa}\\LmCompatibilityLevel" => 3)
  g = run_checks(good); b = run_checks(bad)
  raise 'good config should pass' unless g.all? { |r| r[:status] == 'PASS' }
  raise 'bad config should fail 3 checks' unless b.count { |r| r[:status] == 'FAIL' } == 3
  puts 'self-test OK (good: 4/4 PASS, bad: 3 FAIL)'
  puts 'sample findings for a weak host:'
  b
end

opts = { json: false, self_test: false }
OptionParser.new do |o|
  o.on('--json') { opts[:json] = true }
  o.on('--self-test', 'run against fake registry data (any OS)') { opts[:self_test] = true }
end.parse!

results = opts[:self_test] ? self_test : run_checks(RegistryReader.new)

if opts[:json]
  puts JSON.pretty_generate(results)
else
  results.each do |r|
    puts format('%-28s %-7s value=%-7s want=%-11s %s', r[:setting], r[:status], r[:value], r[:expected], r[:severity])
    puts "    -> #{r[:why]}" unless r[:why].empty?
  end
end
exit(results.any? { |r| r[:status] == 'FAIL' } ? 1 : 0)
