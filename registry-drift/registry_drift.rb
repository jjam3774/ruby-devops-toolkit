#!/usr/bin/env ruby
# frozen_string_literal: true
#
# registry_drift.rb - Compare a machine's Windows Registry settings against a
# JSON "security baseline" (the kind of thing a CIS benchmark or internal
# hardening standard defines) and report which keys have drifted, which are
# missing, and which match. Built for security/compliance auditing across a
# fleet where you can't practically run a GUI tool on every box.
#
# Two ways to get the "actual" values to compare against the baseline:
#   1. --live      Read directly from the registry using Win32::Registry.
#                  Only works when run ON a Windows host with a Ruby that
#                  ships win32/registry (RubyInstaller's Ruby does).
#   2. --snapshot  Read from a JSON snapshot file instead of the live
#                  registry. This is how you audit machines OFFLINE (dump
#                  a snapshot on the target with the included
#                  `dump_snapshot` helper task, copy the file to your
#                  workstation, and audit it there) and it's also how this
#                  script's logic is unit-tested on non-Windows CI runners.
#
# Usage:
#   ruby registry_drift.rb --baseline baseline.json --live
#   ruby registry_drift.rb --baseline baseline.json --snapshot snapshot.json
#   ruby registry_drift.rb --baseline baseline.json --snapshot snapshot.json --json
#
# Exit codes:
#   0 - every check passed (no drift, nothing missing)
#   1 - drift or missing keys found
#   2 - usage / input error

require 'optparse'
require 'json'

MISSING = :__registry_key_missing__

# A single expectation from the baseline file.
BaselineCheck = Struct.new(:name, :hive, :path, :value, :expected, :severity) do
  def full_path
    "#{hive}\\#{path}\\#{value}"
  end
end

# Result of comparing one BaselineCheck against reality.
CheckResult = Struct.new(:check, :actual, :status) do
  def drifted?
    status != :pass
  end
end

# ---- Registry readers ----------------------------------------------------
# Both readers implement #read(hive, path, value) -> actual value, or the
# MISSING sentinel if the key/value doesn't exist. Swapping readers is what
# lets the same drift-detection logic run live on Windows or offline
# anywhere Ruby runs.

# Reads directly from the Windows registry. Only require'd (and only
# instantiated) when --live is requested, so this file loads cleanly on
# Linux/macOS too.
class LiveWindowsRegistryReader
  HIVE_MAP = {
    'HKEY_LOCAL_MACHINE' => :HKEY_LOCAL_MACHINE,
    'HKLM' => :HKEY_LOCAL_MACHINE,
    'HKEY_CURRENT_USER' => :HKEY_CURRENT_USER,
    'HKCU' => :HKEY_CURRENT_USER
  }.freeze

  def initialize
    require 'win32/registry'
  rescue LoadError
    raise "win32/registry is not available on this Ruby/platform. " \
          "--live mode only works on Windows with RubyInstaller's Ruby. " \
          "Use --snapshot for offline/cross-platform auditing."
  end

  def read(hive, path, value)
    hive_const = ::Win32::Registry.const_get(HIVE_MAP.fetch(hive))
    hive_const.open(path) { |reg| reg[value] }
  rescue ::Win32::Registry::Error
    MISSING
  end
end

# Reads "actual" values from a JSON snapshot instead of a live registry.
# Snapshot format:
#   { "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\...\\EnableLUA": 1, ... }
# A value simply absent from the snapshot is treated as MISSING, matching
# what a real registry lookup returns for a key that doesn't exist.
class SnapshotRegistryReader
  def initialize(snapshot_hash)
    @snapshot = snapshot_hash
  end

  def read(hive, path, value)
    key = "#{hive}\\#{path}\\#{value}"
    @snapshot.key?(key) ? @snapshot[key] : MISSING
  end
end

# ---- Drift detection ------------------------------------------------------

class DriftAuditor
  def initialize(reader)
    @reader = reader
  end

  # checks: Array<BaselineCheck> -> Array<CheckResult>
  def audit(checks)
    checks.map do |check|
      actual = @reader.read(check.hive, check.path, check.value)
      status =
        if actual == MISSING
          :missing
        elsif normalize(actual) == normalize(check.expected)
          :pass
        else
          :drift
        end
      CheckResult.new(check, actual, status)
    end
  end

  private

  # String vs Integer comparisons from JSON round-tripping ("1" vs 1)
  # shouldn't count as drift, so compare on a normalized string form.
  def normalize(value)
    value.to_s
  end
end

# ---- Baseline loading -------------------------------------------------

def load_baseline(path)
  raw = JSON.parse(File.read(path))
  raw.map do |entry|
    BaselineCheck.new(
      entry.fetch('name', entry['value']),
      entry.fetch('hive'),
      entry.fetch('path'),
      entry.fetch('value'),
      entry.fetch('expected'),
      entry.fetch('severity', 'medium')
    )
  end
rescue Errno::ENOENT
  warn "registry_drift: baseline file not found: #{path}"
  exit 2
rescue JSON::ParserError => e
  warn "registry_drift: baseline file is not valid JSON: #{e.message}"
  exit 2
rescue KeyError => e
  warn "registry_drift: baseline entry missing required field: #{e.message}"
  exit 2
end

# ---- Reporting -------------------------------------------------------

def print_text_report(results)
  puts 'registry_drift report'
  puts '-' * 70
  results.each do |r|
    icon = { pass: 'PASS   ', drift: 'DRIFT  ', missing: 'MISSING' }[r.status]
    puts format('[%s] (%-6s) %s', icon, r.check.severity.upcase, r.check.full_path)
    next if r.status == :pass

    puts "           expected=#{r.check.expected.inspect} actual=#{r.actual == MISSING ? '(not present)' : r.actual.inspect}"
  end
  puts '-' * 70
  drifted = results.count(&:drifted?)
  puts "#{results.size} checks, #{results.size - drifted} passed, #{drifted} flagged"
end

def build_json_report(results)
  {
    total: results.size,
    passed: results.count { |r| r.status == :pass },
    flagged: results.count(&:drifted?),
    results: results.map do |r|
      { name: r.check.name, path: r.check.full_path, severity: r.check.severity,
        status: r.status, expected: r.check.expected,
        actual: r.actual == MISSING ? nil : r.actual }
    end
  }
end

# ---- CLI ----------------------------------------------------------------

if $PROGRAM_NAME == __FILE__
  opts = {}
  parser = OptionParser.new do |o|
    o.banner = 'Usage: registry_drift.rb --baseline FILE (--live | --snapshot FILE) [--json]'
    o.on('-b', '--baseline FILE', 'Baseline JSON file (required)') { |v| opts[:baseline] = v }
    o.on('-l', '--live', 'Read the live registry (Windows only)') { opts[:live] = true }
    o.on('-n', '--snapshot FILE', 'Read actual values from a JSON snapshot instead of live registry') { |v| opts[:snapshot] = v }
    o.on('-j', '--json', 'Emit machine-readable JSON instead of a text report') { opts[:json] = true }
    o.on('-h', '--help', 'Show this help') { puts o; exit 0 }
  end
  parser.parse!(ARGV)

  unless opts[:baseline]
    warn parser
    exit 2
  end

  unless opts[:live] || opts[:snapshot]
    warn 'registry_drift: specify either --live or --snapshot FILE'
    exit 2
  end

  checks = load_baseline(opts[:baseline])

  reader =
    if opts[:live]
      begin
        LiveWindowsRegistryReader.new
      rescue RuntimeError => e
        warn "registry_drift: #{e.message}"
        exit 2
      end
    else
      begin
        SnapshotRegistryReader.new(JSON.parse(File.read(opts[:snapshot])))
      rescue Errno::ENOENT
        warn "registry_drift: snapshot file not found: #{opts[:snapshot]}"
        exit 2
      rescue JSON::ParserError => e
        warn "registry_drift: snapshot file is not valid JSON: #{e.message}"
        exit 2
      end
    end

  results = DriftAuditor.new(reader).audit(checks)

  if opts[:json]
    puts JSON.pretty_generate(build_json_report(results))
  else
    print_text_report(results)
  end

  exit(results.any?(&:drifted?) ? 1 : 0)
end
