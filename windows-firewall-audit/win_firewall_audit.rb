#!/usr/bin/env ruby
# frozen_string_literal: true
#
# win_firewall_audit.rb -- Audits the Windows Defender Firewall rule set via
# WMI for the risky patterns that build up over years of "just add a rule to
# get it working": inbound-allow-any-any rules exposed on the Public profile,
# edge-traversal enabled on rules that don't need it (lets traffic reach a
# host straight through NAT, bypassing one of the main protections a
# firewall provides), and wide-open port ranges on enabled inbound rules.
# `Get-NetFirewallRule` in PowerShell can show you this one rule at a time,
# but nobody reads 400 rules by hand -- this script queries the same WMI
# classes PowerShell's firewall cmdlets are built on (MSFT_NetFirewallRule
# and its associated port/address filters, in the ROOT\StandardCimv2
# namespace) directly via WIN32OLE, joins them, and prints a prioritized
# findings list.
#
# Prerequisites: Windows 8/Server 2012 or later (root\StandardCimv2 is where
# the modern firewall WMI provider lives), Ruby with the win32ole stdlib
# gem (ships with the standard one-click Ruby installer on Windows), and a
# shell with rights to query WMI (typically an admin PowerShell/cmd; the
# firewall provider does allow non-admin reads on most builds, but run
# elevated if you get access-denied errors).
#
# Usage (on Windows):
#   ruby win_firewall_audit.rb
#   ruby win_firewall_audit.rb --json
#   ruby win_firewall_audit.rb --profile Public
#
# Exit codes: 0 = no CRIT findings, 2 = one or more CRIT findings, 1 = error
# talking to WMI (e.g. run on a non-Windows host, or without rights).

require 'optparse'
require 'json'

module WinFirewallAudit
  Finding = Struct.new(:severity, :rule_name, :reasons, keyword_init: true)

  # Plain-data shape for one firewall rule plus its joined filters. Kept
  # independent of WIN32OLE so the risk engine below can be exercised with
  # plain Ruby objects in tests, with no Windows host required.
  RuleView = Struct.new(
    :display_name, :enabled, :direction, :action, :profiles,
    :edge_traversal_policy, :protocol, :local_port, :remote_address,
    keyword_init: true
  )

  # NET_FW profile bitmask, per the MSFT_NetFirewallProfile documentation.
  PROFILE_BITS = { 1 => 'Domain', 2 => 'Private', 4 => 'Public' }.freeze

  def self.profiles_from_bitmask(mask)
    return ['Any'] if mask.nil? || mask.zero? || mask == 2_147_483_647

    PROFILE_BITS.each_with_object([]) { |(bit, name), acc| acc << name if (mask & bit) != 0 }
  end

  # ---------------------------------------------------------------------
  # Risk engine -- pure function of a RuleView, fully unit-testable without
  # touching WMI at all. This is the part that actually encodes "what does
  # a risky firewall rule look like", and it's the part with real unit
  # tests in win_firewall_audit_test.rb.
  # ---------------------------------------------------------------------
  def self.evaluate_rule(rule)
    reasons = []

    return nil unless rule.enabled
    return nil unless rule.direction == 'Inbound'
    return nil unless rule.action == 'Allow'

    wide_open_port = %w[Any *].include?(rule.local_port.to_s) || rule.local_port.to_s.include?('-')
    any_remote     = %w[Any *].include?(rule.remote_address.to_s) || rule.remote_address.to_s == '0.0.0.0-255.255.255.255'
    public_scope   = rule.profiles.include?('Public') || rule.profiles.include?('Any')
    edge_bypass    = rule.edge_traversal_policy.to_s.casecmp('Allow').zero?

    if wide_open_port && any_remote && public_scope
      reasons << 'inbound ALLOW rule open to any remote address, any port, on the Public profile'
    elsif wide_open_port && any_remote
      reasons << 'inbound ALLOW rule open to any remote address on all/ranged local ports'
    elsif any_remote && public_scope
      reasons << 'inbound ALLOW rule reachable from any remote address on the Public profile'
    end

    reasons << 'EdgeTraversalPolicy=Allow lets this rule bypass NAT edge protection' if edge_bypass

    return nil if reasons.empty?

    severity = (wide_open_port && any_remote && public_scope) || edge_bypass ? :crit : :warn
    Finding.new(severity: severity, rule_name: rule.display_name, reasons: reasons)
  end

  # ---------------------------------------------------------------------
  # WMI data source -- the only part of this file that touches Windows.
  # ---------------------------------------------------------------------
  class WmiSource
    def initialize
      require 'win32ole'
      @wmi = WIN32OLE.connect('winmgmts:\\\\.\\root\\StandardCimv2')
    end

    def rules
      @wmi.ExecQuery('SELECT * FROM MSFT_NetFirewallRule').to_enum.map { |r| r }
    end

    def port_filters
      @wmi.ExecQuery('SELECT * FROM MSFT_NetFirewallPortFilter').to_enum.map { |f| f }
    end

    def address_filters
      @wmi.ExecQuery('SELECT * FROM MSFT_NetFirewallAddressFilter').to_enum.map { |f| f }
    end
  end

  # Builds RuleView objects by joining raw rule/port-filter/address-filter
  # WMI instances (or their stub equivalents) on InstanceID, the way the
  # real MSFT_NetFirewallPortFilter/AddressFilter classes key back to their
  # owning MSFT_NetFirewallRule.
  class RuleBuilder
    def self.build(source)
      port_by_id = index_by_instance_id(source.port_filters)
      addr_by_id = index_by_instance_id(source.address_filters)

      source.rules.map do |r|
        pf = port_by_id[r.InstanceID]
        af = addr_by_id[r.InstanceID]

        RuleView.new(
          display_name: r.DisplayName,
          enabled: truthy(r.Enabled),
          direction: %w[Inbound Outbound][r.Direction.to_i - 1] || r.Direction.to_s,
          action: %w[Undefined Allow Block][r.Action.to_i] || r.Action.to_s,
          profiles: WinFirewallAudit.profiles_from_bitmask(r.Profiles),
          edge_traversal_policy: r.EdgeTraversalPolicy.to_s,
          protocol: pf&.Protocol.to_s,
          local_port: pf&.LocalPort.to_s,
          remote_address: af&.RemoteAddress.to_s
        )
      end
    end

    def self.index_by_instance_id(items)
      items.each_with_object({}) { |i, h| h[i.InstanceID] = i }
    end

    def self.truthy(v)
      v == true || v.to_s == 'true' || v.to_s == '1'
    end
  end

  class Auditor
    def initialize(source)
      @source = source
    end

    def run(profile_filter: nil)
      rules = RuleBuilder.build(@source)
      rules = rules.select { |r| r.profiles.include?(profile_filter) } if profile_filter
      rules.filter_map { |r| WinFirewallAudit.evaluate_rule(r) }
    end
  end
end

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  options = { json: false, profile: nil }

  OptionParser.new do |opts|
    opts.banner = 'Usage: win_firewall_audit.rb [--json] [--profile Domain|Private|Public]'
    opts.on('--json', 'Emit machine-readable JSON instead of text') { options[:json] = true }
    opts.on('--profile NAME', 'Only audit rules that apply to this profile') { |v| options[:profile] = v }
  end.parse!

  begin
    source = WinFirewallAudit::WmiSource.new
  rescue LoadError, StandardError => e
    warn "Could not connect to WMI (this script requires Windows): #{e.message}"
    exit 1
  end

  findings = WinFirewallAudit::Auditor.new(source).run(profile_filter: options[:profile])
  crit_count = findings.count { |f| f.severity == :crit }

  if options[:json]
    puts JSON.pretty_generate(findings.map(&:to_h))
  elsif findings.empty?
    puts 'No risky inbound-allow rules found.'
  else
    findings.sort_by { |f| f.severity == :crit ? 0 : 1 }.each do |f|
      tag = f.severity == :crit ? 'CRIT' : 'WARN'
      puts "[#{tag}] #{f.rule_name}"
      f.reasons.each { |r| puts "       - #{r}" }
    end
    puts "\n#{crit_count} critical, #{findings.size - crit_count} warnings out of #{findings.size} flagged rules"
  end

  exit(crit_count.positive? ? 2 : 0)
end
