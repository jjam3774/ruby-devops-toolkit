#!/usr/bin/env ruby
# frozen_string_literal: true
#
# local_admin_audit.rb — Audit local Administrators group membership across
# a fleet of Windows hosts via WMI, and flag anyone who shouldn't be there.
#
# Problem this solves:
#   "Who has local admin on our servers?" is a question every security
#   review, SOC 2 audit, and incident response asks — and the honest answer
#   at most shops is "nobody's sure, someone got added six months ago for a
#   one-off task and never got removed." This script queries the
#   Administrators group on every host in an inventory file via WMI,
#   compares the membership against a YAML allow-list, and reports:
#     - UNAUTHORIZED members (present, not on the allow-list — privilege
#       creep, the main thing you're hunting for)
#     - MISSING required members (on the allow-list, e.g. a break-glass or
#       EDR service account, but absent — a different kind of drift)
#   It's designed to run from a jump box / management host over WinRM-backed
#   WMI (DCOM), not on each server individually, so it can scan a whole
#   fleet in one pass and dump a single JSON report.
#
# Prerequisites:
#   - Ruby with the `win32ole` stdlib (bundled with all Windows Ruby builds,
#     e.g. RubyInstaller — nothing extra to gem-install)
#   - Run from a domain-joined Windows host with network access to WMI
#     (TCP 135 + dynamic RPC ports, or DCOM configured) on each target
#   - An account with permission to query WMI on the targets (local admin
#     or a delegated read-only WMI namespace ACL)
#
# Usage:
#   ruby local_admin_audit.rb --inventory hosts.txt --allowlist allowlist.yml [--out report.json]
#   ruby local_admin_audit.rb --host WEB01 --allowlist allowlist.yml
#
# allowlist.yml format:
#   default:                 # applies to any host without a specific entry
#     - CORP\Domain Admins
#     - CORP\svc-edr
#   overrides:
#     WEB01:
#       - CORP\Domain Admins
#       - CORP\svc-edr
#       - CORP\jsmith        # temporary, ticket #4821
#
# Exit codes:
#   0  every host's Administrators membership matches the allow-list
#   1  at least one host has unauthorized or missing members
#   2  usage / connection error
#
# --- Testing note (read this before filing a bug) --------------------------
# WMI and win32ole only exist on Windows, so the WMI *collection* step
# (`WmiAdminGroupSource`) cannot execute in a Linux CI sandbox. The
# comparison/reporting logic that actually decides "unauthorized" vs.
# "missing" — the part with real bugs to catch — is isolated in the
# `AdminAudit.evaluate` method below, which takes plain Ruby data in and
# returns plain Ruby data out. That method has zero WMI dependency and is
# exercised directly by the test harness (`test_local_admin_audit.rb`,
# included alongside this script) using a `StubAdminGroupSource` in place
# of the real WMI query. See the tutorial's "output" tab for that test run.

require 'optparse'
require 'yaml'
require 'json'
require 'time'

# ---------------------------------------------------------------------------
# WMI collection (Windows-only; requires win32ole)
# ---------------------------------------------------------------------------
class WmiAdminGroupSource
  # Returns an Array of "DOMAIN\username" strings currently in the local
  # Administrators group on `host`.
  def members_for(host)
    require 'win32ole' # deferred require: only needed on the real code path
    locator = WIN32OLE.new('WbemScripting.SWbemLocator')
    connection = locator.ConnectServer(host, 'root\\cimv2')
    connection.Security_.ImpersonationLevel = 3 # impersonate

    # Win32_GroupUser associates a Win32_Group with its member accounts.
    # We scope to the local "Administrators" group by name + domain.
    query = <<~WQL
      ASSOCIATORS OF {Win32_Group.Domain='#{host}',Name='Administrators'}
      WHERE AssocClass=Win32_GroupUser
    WQL

    members = []
    connection.ExecQuery(query).each do |account|
      members << "#{account.Domain}\\#{account.Name}"
    end
    members
  rescue LoadError
    # win32ole isn't available on this platform (e.g. developing/testing on
    # macOS or Linux). Surface a clear, actionable error instead of a raw
    # Ruby backtrace — this is the expected failure mode off Windows.
    raise "win32ole is not available on this platform (this script's WMI " \
          'collection step only runs on Windows). Use --host with a stub ' \
          'source for local testing, or run this on a Windows host.'
  rescue StandardError => e
    raise "WMI query failed for host #{host}: #{e.message}"
  end
end

# A drop-in replacement for WmiAdminGroupSource used by the test harness
# (and usable for --dry-run style local testing on non-Windows machines).
# Takes a Hash of { host => [members] } and just looks values up.
class StubAdminGroupSource
  def initialize(fixture)
    @fixture = fixture
  end

  def members_for(host)
    @fixture.fetch(host) { raise "no fixture data for host #{host}" }
  end
end

# ---------------------------------------------------------------------------
# Pure comparison logic — no WMI, no I/O, fully unit-testable
# ---------------------------------------------------------------------------
module AdminAudit
  # current:   Array<String> of "DOMAIN\user" currently in the group
  # allowed:   Array<String> of "DOMAIN\user" permitted to be in the group
  # Returns a Hash: { unauthorized: [...], missing: [...], ok: [...] }
  def self.evaluate(current, allowed)
    current_norm = current.map { |m| normalize(m) }
    allowed_norm = allowed.map { |m| normalize(m) }

    unauthorized = current.select { |m| !allowed_norm.include?(normalize(m)) }
    missing = allowed.select { |m| !current_norm.include?(normalize(m)) }
    ok = current.select { |m| allowed_norm.include?(normalize(m)) }

    { unauthorized: unauthorized, missing: missing, ok: ok }
  end

  # Case-insensitive, so "CORP\JSmith" and "corp\jsmith" are treated the same
  # (matches Windows account-name semantics).
  def self.normalize(name)
    name.to_s.downcase.strip
  end
end

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def load_allowlist(path, host)
  data = YAML.safe_load(File.read(path)) || {}
  overrides = data['overrides'] || {}
  overrides[host] || data['default'] || []
end

def run(options)
  hosts =
    if options[:inventory]
      File.readlines(options[:inventory]).map(&:strip).reject(&:empty?).reject { |l| l.start_with?('#') }
    else
      [options[:host]]
    end

  source = options[:source] || WmiAdminGroupSource.new
  report = { generated_at: Time.now.utc.iso8601, hosts: {} }
  any_findings = false

  hosts.each do |host|
    print "Auditing #{host}... "
    begin
      current = source.members_for(host)
      allowed = load_allowlist(options[:allowlist], host)
      result = AdminAudit.evaluate(current, allowed)

      status = result[:unauthorized].empty? && result[:missing].empty? ? 'OK' : 'FINDINGS'
      any_findings ||= status == 'FINDINGS'
      puts status

      report[:hosts][host] = {
        status: status,
        current_members: current,
        allowed_members: allowed,
        unauthorized: result[:unauthorized],
        missing: result[:missing]
      }
    rescue StandardError => e
      puts "ERROR (#{e.message})"
      any_findings = true
      report[:hosts][host] = { status: 'ERROR', error: e.message }
    end
  end

  puts "\n--- Summary ---"
  report[:hosts].each do |host, r|
    next if r[:status] == 'OK'
    puts "#{host}: #{r[:status]}"
    Array(r[:unauthorized]).each { |m| puts "    UNAUTHORIZED: #{m}" }
    Array(r[:missing]).each { |m| puts "    MISSING REQUIRED: #{m}" }
    puts "    ERROR: #{r[:error]}" if r[:status] == 'ERROR'
  end
  puts 'All hosts clean.' unless any_findings

  if options[:out]
    File.write(options[:out], JSON.pretty_generate(report))
    puts "\nFull report written to #{options[:out]}"
  end

  any_findings ? 1 : 0
end

if $PROGRAM_NAME == __FILE__
  options = {}
  OptionParser.new do |o|
    o.banner = 'Usage: local_admin_audit.rb (--inventory FILE | --host NAME) --allowlist FILE [--out FILE]'
    o.on('--inventory FILE', 'File with one hostname per line') { |v| options[:inventory] = v }
    o.on('--host NAME', 'Single hostname to audit') { |v| options[:host] = v }
    o.on('--allowlist FILE', 'YAML allow-list (see header comment for format)') { |v| options[:allowlist] = v }
    o.on('--out FILE', 'Write full JSON report to FILE') { |v| options[:out] = v }
  end.parse!

  if !options[:inventory] && !options[:host]
    warn 'ERROR: must pass --inventory or --host'
    exit 2
  end
  unless options[:allowlist]
    warn 'ERROR: must pass --allowlist'
    exit 2
  end

  exit run(options)
end
