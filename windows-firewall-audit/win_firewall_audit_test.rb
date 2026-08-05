#!/usr/bin/env ruby
# frozen_string_literal: true
#
# win_firewall_audit_test.rb -- Unit tests for the risk-scoring logic in
# win_firewall_audit.rb, using WIN32OLE-shaped stub fixtures.
#
# This script requires MSFT_NetFirewallRule / MSFT_NetFirewallPortFilter /
# MSFT_NetFirewallAddressFilter, which only exist on a real Windows host, so
# the join + risk-scoring logic (RuleBuilder + WinFirewallAudit.evaluate_rule)
# is instead exercised here against plain-Ruby stand-ins that expose the
# exact same property names (DisplayName, Enabled, Direction, Profiles,
# InstanceID, ...) a real WIN32OLE SWbemObject would. No gems, no mocking
# framework -- just Struct-based fixtures and manual asserts, run with:
#
#   ruby win_firewall_audit_test.rb

require_relative 'win_firewall_audit'

# Stand-ins shaped exactly like the WMI classes they fake.
StubRule = Struct.new(:InstanceID, :DisplayName, :Enabled, :Direction, :Action, :Profiles, :EdgeTraversalPolicy)
StubPortFilter = Struct.new(:InstanceID, :Protocol, :LocalPort)
StubAddressFilter = Struct.new(:InstanceID, :RemoteAddress)

StubSource = Struct.new(:rules, :port_filters, :address_filters)

$failures = 0
$assertions = 0

def assert(condition, message)
  $assertions += 1
  unless condition
    $failures += 1
    puts "FAIL: #{message}"
  end
end

def assert_equal(expected, actual, message)
  assert(expected == actual, "#{message} (expected #{expected.inspect}, got #{actual.inspect})")
end

# --- Fixture: the classic "Allow any/any inbound rule left on the Public
# profile" -- e.g. someone opened RDP wide for a debugging session in 2019
# and forgot to scope or remove it. Direction=1 is Inbound, Action=1 is
# Allow, Profiles=4 is Public-only per MSFT_NetFirewallProfile's bitmask.
rdp_wide_open = StubRule.new('{RULE-1}', 'RDP - temp debug access', true, 1, 1, 4, 'Block')
rdp_port  = StubPortFilter.new('{RULE-1}', 'TCP', 'Any')
rdp_addr  = StubAddressFilter.new('{RULE-1}', 'Any')

# --- Fixture: a properly scoped internal rule -- inbound allow, but locked
# to the Private profile and a specific /24, so it should NOT be flagged.
internal_ok = StubRule.new('{RULE-2}', 'Internal file share', true, 1, 1, 2, 'Block')
internal_port = StubPortFilter.new('{RULE-2}', 'TCP', '445')
internal_addr = StubAddressFilter.new('{RULE-2}', '10.0.5.0/24')

# --- Fixture: EdgeTraversalPolicy=Allow on an otherwise-scoped rule -- still
# risky because it lets the traffic bypass NAT/edge blocking regardless of
# how the address filter is scoped.
edge_bypass = StubRule.new('{RULE-3}', 'IoT management port', true, 1, 1, 2, 'Allow')
edge_port = StubPortFilter.new('{RULE-3}', 'TCP', '8443')
edge_addr = StubAddressFilter.new('{RULE-3}', '10.0.5.0/24')

# --- Fixture: disabled rule -- should never be flagged regardless of how
# permissive it looks, since it isn't active.
disabled_wide_open = StubRule.new('{RULE-4}', 'Old test rule (disabled)', false, 1, 1, 4, 'Block')
disabled_port = StubPortFilter.new('{RULE-4}', 'TCP', 'Any')
disabled_addr = StubAddressFilter.new('{RULE-4}', 'Any')

# --- Fixture: outbound rule -- outbound Allow-any is normal and expected,
# should never be flagged (this auditor only cares about inbound exposure).
outbound_any = StubRule.new('{RULE-5}', 'Default outbound allow', true, 2, 1, 7, 'Block')
outbound_port = StubPortFilter.new('{RULE-5}', 'Any', 'Any')
outbound_addr = StubAddressFilter.new('{RULE-5}', 'Any')

source = StubSource.new(
  [rdp_wide_open, internal_ok, edge_bypass, disabled_wide_open, outbound_any],
  [rdp_port, internal_port, edge_port, disabled_port, outbound_port],
  [rdp_addr, internal_addr, edge_addr, disabled_addr, outbound_addr]
)

# --- Test the WMI-shaped join (RuleBuilder) ---
built = WinFirewallAudit::RuleBuilder.build(source)
assert_equal(5, built.size, 'RuleBuilder should produce one RuleView per input rule')

rdp_view = built.find { |r| r.display_name == 'RDP - temp debug access' }
assert_equal('Inbound', rdp_view.direction, 'Direction=1 should decode to Inbound')
assert_equal('Allow', rdp_view.action, 'Action=1 should decode to Allow')
assert_equal(['Public'], rdp_view.profiles, 'Profiles=4 should decode to just Public')

outbound_view = built.find { |r| r.display_name == 'Default outbound allow' }
assert_equal('Outbound', outbound_view.direction, 'Direction=2 should decode to Outbound')
assert_equal(%w[Domain Private Public], outbound_view.profiles, 'Profiles=7 should decode to all three profiles')

# --- Test the risk engine (WinFirewallAudit.evaluate_rule) end to end ---
auditor = WinFirewallAudit::Auditor.new(source)
findings = auditor.run
by_name = findings.each_with_object({}) { |f, h| h[f.rule_name] = f }

assert(by_name.key?('RDP - temp debug access'), 'wide-open Public inbound rule should be flagged')
assert_equal(:crit, by_name['RDP - temp debug access']&.severity, 'any/any/Public inbound rule should be CRIT')

assert(!by_name.key?('Internal file share'), 'a properly scoped Private-profile rule should NOT be flagged')

assert(by_name.key?('IoT management port'), 'EdgeTraversalPolicy=Allow should be flagged even when address-scoped')
assert_equal(:crit, by_name['IoT management port']&.severity, 'EdgeTraversalPolicy=Allow should be CRIT')

assert(!by_name.key?('Old test rule (disabled)'), 'a disabled rule should never be flagged')
assert(!by_name.key?('Default outbound allow'), 'outbound rules are out of scope and should never be flagged')

# --- Test the --profile filter ---
public_only = auditor.run(profile_filter: 'Public')
assert_equal(1, public_only.size, '--profile Public should only return rules that apply to the Public profile')

puts "\n#{$assertions} assertions, #{$failures} failures"
exit($failures.positive? ? 1 : 0)
