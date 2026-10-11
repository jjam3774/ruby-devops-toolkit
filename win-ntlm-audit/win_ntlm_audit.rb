#!/usr/bin/env ruby
# frozen_string_literal: true
# win_ntlm_audit.rb - audit Windows NTLM hardening settings in the registry.
# Live mode (Windows): reads HKLM via win32/registry (stdlib on Windows Ruby).
# Snapshot mode (any OS): --snapshot FILE.json  {"<key path>|<value>": <data>, ...}
require 'json'
require 'optparse'

LSA   = 'SYSTEM\CurrentControlSet\Control\Lsa'
MSV   = 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
NTLM_SEC = 0x20080000 # require NTLMv2 session security + 128-bit encryption

# [id, key, value, description, predicate, expected text, severity, default-when-missing]
CHECKS = [
  ['lm-level',  LSA, 'LmCompatibilityLevel', 'LAN Manager auth level', ->(v) { v >= 5 }, '>= 5 (NTLMv2 only, refuse LM/NTLM)', :high, 3],
  ['no-lm-hash', LSA, 'NoLMHash', 'Do not store LM hash', ->(v) { v == 1 }, '1', :high, 1],
  ['client-sec', MSV, 'NtlmMinClientSec', 'Min client session security', ->(v) { (v & NTLM_SEC) == NTLM_SEC }, '0x20080000 bits set', :medium, 0],
  ['server-sec', MSV, 'NtlmMinServerSec', 'Min server session security', ->(v) { (v & NTLM_SEC) == NTLM_SEC }, '0x20080000 bits set', :medium, 0],
  ['restrict-out', MSV, 'RestrictSendingNTLMTraffic', 'Outgoing NTLM restriction', ->(v) { v >= 1 }, '>= 1 (audit or deny)', :low, 0]
].freeze

def read_live(key, name)
  require 'win32/registry'
  Win32::Registry::HKEY_LOCAL_MACHINE.open(key) { |r| r[name] }
rescue LoadError
  abort 'win32/registry unavailable: run on Windows or use --snapshot'
rescue StandardError
  nil # key or value missing
end

opts = { snapshot: nil, json: false }
OptionParser.new do |o|
  o.on('--snapshot FILE') { |v| opts[:snapshot] = v }
  o.on('--json') { opts[:json] = true }
end.parse!
snap = opts[:snapshot] ? JSON.parse(File.read(opts[:snapshot])) : nil

results = CHECKS.map do |id, key, name, desc, pred, want, sev, default|
  raw = snap ? snap["#{key}|#{name}"] : read_live(key, name)
  effective = raw.nil? ? default : raw
  status = pred.call(effective) ? 'pass' : 'fail'
  { id: id, setting: desc, value: raw, effective: effective, expected: want,
    severity: sev, status: status, note: raw.nil? ? 'not set; OS default applied' : nil }
end

if opts[:json]
  puts JSON.pretty_generate(results)
else
  results.each do |r|
    shown = r[:value].nil? ? '(unset)' : r[:value].to_s
    puts format('%-5s %-30s value=%-12s want %s%s', r[:status].upcase, r[:setting], shown, r[:expected], r[:status] == 'fail' ? "  [#{r[:severity]}]" : '')
  end
  fails = results.count { |r| r[:status] == 'fail' }
  puts fails.zero? ? 'NTLM posture: HARDENED' : "NTLM posture: #{fails} setting(s) need attention"
end
exit(results.any? { |r| r[:status] == 'fail' } ? 1 : 0)
