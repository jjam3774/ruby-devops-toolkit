#!/usr/bin/env ruby
# frozen_string_literal: true
#
# ntfs_acl_audit.rb -- Audits NTFS folder/file permissions via icacls.exe.
#
# Registry drift, BitLocker compliance, firewall rules, service accounts --
# most Windows security auditing tools cover those. The filesystem ACLs
# rarely get the same treatment, even though "someone ran icacls /grant
# Everyone:F on a deploy folder to make a permissions error go away" is one
# of the most common, most quietly dangerous things that happens to a
# Windows box. This script walks a list of paths, runs icacls on each,
# parses the ACL, and flags any grant of Modify/Write/FullControl to a
# broad identity (Everyone, Users, Authenticated Users) so you can find
# those before an attacker does.
#
# No gems required -- Ruby stdlib only (open3, optparse, json). Requires
# Windows + icacls.exe (built into every supported Windows release) to run
# for real; the parsing and risk-scoring logic is pure-Ruby and unit-tested
# separately in ntfs_acl_audit_test.rb against realistic icacls fixtures,
# since this environment doesn't have a Windows host available.
#
# Usage:
#   ruby ntfs_acl_audit.rb <path> [<path> ...] [options]
#
# Examples:
#   ruby ntfs_acl_audit.rb "C:\inetpub\wwwroot" "C:\ProgramData\MyApp"
#   ruby ntfs_acl_audit.rb "C:\Windows\Temp" --json
#   ruby ntfs_acl_audit.rb "C:\Deploys" --risky-perms F,M,W,WD,WDAC,DC
#
# Exit codes (cron/Task Scheduler/CI friendly):
#   0 - no risky grants found
#   1 - reserved (not currently used; parsing errors count as CRIT)
#   2 - at least one risky ACE found, or a path could not be audited

require 'open3'
require 'optparse'
require 'json'

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------

# NOTE: option parsing and ARGV validation happen inside the
# `$PROGRAM_NAME == __FILE__` guard near the bottom of this file, not here --
# that keeps `require_relative 'ntfs_acl_audit'` side-effect-free (no ARGV
# parsing, no exit calls) so the test suite can load just the pure functions.

# ---------------------------------------------------------------------------
# icacls invocation -- isolated behind a single method so it can be swapped
# out for a fake in tests (see ntfs_acl_audit_test.rb).
# ---------------------------------------------------------------------------

def run_icacls(path)
  Open3.capture3('icacls.exe', path)
end

# ---------------------------------------------------------------------------
# Parsing -- icacls output for a single path looks like:
#
#   C:\inetpub\wwwroot BUILTIN\Administrators:(OI)(CI)(F)
#                       NT AUTHORITY\SYSTEM:(OI)(CI)(F)
#                       BUILTIN\Users:(OI)(CI)(RX)
#                       Everyone:(OI)(CI)(F)
#
#   Successfully processed 1 files; Failed processing 0 files
#
# The first line carries the path; every following indented line is another
# ACE for the SAME path, until a blank line or the summary line.
# ---------------------------------------------------------------------------

ACE_LINE = /^\s*(?:(?<path>[A-Za-z]:\\[^\t]*?)\s+)?(?<identity>(?:[\w .\\-]+))\:(?<deny>\(DENY\))?(?<flags>(?:\([A-Z]+\))*)$/.freeze

def parse_icacls_output(raw)
  entries = []
  current_path = nil

  raw.each_line do |line|
    line = line.rstrip
    next if line.strip.empty?
    break if line =~ /^Successfully processed/i

    m = ACE_LINE.match(line)
    next unless m

    current_path = m[:path] if m[:path]
    next unless current_path # a stray line before we've seen a path yet

    perms = m[:flags].to_s.scan(/\(([A-Z]+)\)/).flatten
    # Inheritance flags aren't permissions -- split them out.
    inheritance = perms & %w[OI CI IO NP I]
    perm_codes = perms - inheritance

    entries << {
      path: current_path,
      identity: m[:identity].strip,
      deny: !m[:deny].nil?,
      inherited: inheritance.include?('I'),
      inheritance_flags: inheritance,
      perms: perm_codes
    }
  end

  entries
end

# ---------------------------------------------------------------------------
# Risk evaluation
# ---------------------------------------------------------------------------

def evaluate_ace(ace, risky_identities, risky_perms, safe_identities)
  return { severity: :ok, reasons: [] } if ace[:deny] # an explicit DENY is protective, never a finding
  return { severity: :ok, reasons: [] } if safe_identities.any? { |s| s.casecmp?(ace[:identity]) }

  is_broad = risky_identities.any? { |id| id.casecmp?(ace[:identity]) }
  return { severity: :ok, reasons: [] } unless is_broad

  hit_perms = ace[:perms] & risky_perms
  return { severity: :ok, reasons: [] } if hit_perms.empty?

  severity = hit_perms.include?('F') || hit_perms.include?('M') ? :crit : :warn
  reason = "#{ace[:identity]} granted #{hit_perms.join('+')} on #{ace[:path]}"
  { severity: severity, reasons: [reason] }
end

def audit_path(path, risky_identities, risky_perms, safe_identities, runner: method(:run_icacls))
  stdout, stderr, status = runner.call(path)

  unless status && status.success?
    return { path: path, status: :error, error: (stderr || 'icacls.exe failed').strip, aces: [] }
  end

  aces = parse_icacls_output(stdout)
  findings = aces.map { |ace| ace.merge(evaluate_ace(ace, risky_identities, risky_perms, safe_identities)) }

  worst = findings.map { |f| f[:severity] }.reduce(:ok) { |acc, s| SEVERITY_RANK[s] > SEVERITY_RANK[acc] ? s : acc }

  { path: path, status: worst, aces: findings }
end

SEVERITY_RANK = { ok: 0, warn: 1, crit: 2, error: 2 }.freeze

# ---------------------------------------------------------------------------
# Run (only executed when this file is the main program -- lets the test
# suite `require` it for the pure functions without shelling out).
# ---------------------------------------------------------------------------

if $PROGRAM_NAME == __FILE__
  options = {
    risky_identities: ['Everyone', 'BUILTIN\\Users', 'Authenticated Users', 'NT AUTHORITY\\Authenticated Users'],
    risky_perms: %w[F M W WD WDAC],
    safe_identities: ['NT AUTHORITY\\SYSTEM', 'BUILTIN\\Administrators', 'CREATOR OWNER'],
    json: false
  }

  OptionParser.new do |opts|
    opts.banner = 'Usage: ntfs_acl_audit.rb <path> [<path> ...] [options]'
    opts.on('--risky-identities LIST', String, 'Comma-separated identities considered "broad" (default: Everyone,BUILTIN\\Users,Authenticated Users)') do |v|
      options[:risky_identities] = v.split(',')
    end
    opts.on('--risky-perms LIST', String, 'Comma-separated icacls perm codes considered risky when granted to a broad identity (default: F,M,W,WD,WDAC)') do |v|
      options[:risky_perms] = v.split(',')
    end
    opts.on('--json', 'Emit machine-readable JSON instead of text') { options[:json] = true }
    opts.on('-h', '--help', 'Show this help') { puts opts; exit 0 }
  end.parse!

  paths = ARGV
  if paths.empty?
    warn 'ntfs_acl_audit: at least one path is required'
    exit 3
  end

  results = paths.map { |p| audit_path(p, options[:risky_identities], options[:risky_perms], options[:safe_identities]) }

  overall = results.map { |r| r[:status] }.reduce(:ok) { |acc, s| SEVERITY_RANK[s] > SEVERITY_RANK[acc] ? s : acc }
  exit_code = overall == :ok ? 0 : 2

  if options[:json]
    puts JSON.pretty_generate(results: results, overall: overall, exit_code: exit_code)
  else
    puts "ntfs-acl-audit: audited #{results.size} path(s)"
    puts
    results.each do |r|
      if r[:status] == :error
        puts "[ERROR] #{r[:path]} -- #{r[:error]}"
        next
      end

      tag = r[:status].to_s.upcase.rjust(5)
      puts "[#{tag}] #{r[:path]}"
      r[:aces].each do |a|
        next if a[:severity] == :ok && a[:reasons].empty?

        marker = a[:deny] ? 'DENY' : a[:perms].join('+')
        line = "        #{a[:identity]}: #{marker}"
        line += "  <-- #{a[:reasons].join('; ')}" unless a[:reasons].empty?
        puts line
      end
      if r[:aces].none? { |a| !a[:reasons].empty? }
        puts '        (no broad grants found)'
      end
    end
    puts
    findings = results.sum { |r| r[:aces].count { |a| !a[:reasons].empty? } }
    puts "Summary: #{findings} risky ACE(s) across #{results.size} path(s). Overall: #{overall.to_s.upcase}"
  end

  exit exit_code
end
