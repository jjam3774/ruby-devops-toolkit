#!/usr/bin/env ruby
# frozen_string_literal: true
#
# package_drift_audit.rb — audit installed OS packages against an approved
# manifest and report drift, in pure Ruby stdlib. Debian/Ubuntu (dpkg) and
# RHEL/Fedora (rpm) supported; no gems.
#
# Configuration drift on long-lived servers is silent and dangerous: someone
# apt-installs a debugging tool during an incident and never removes it, a
# base image ships packages you never audited, or a compromised box grows an
# extra binary nobody notices. This script snapshots what's installed and
# diffs it against a manifest of what's *supposed* to be there, reporting:
#
#   MISSING    — in the manifest, not installed (drifted away / failed deploy)
#   UNEXPECTED — installed, not in the manifest (scope creep or worse)
#   VERSION    — installed but a different version than pinned in the manifest
#   OK         — installed and matches
#
# Exit codes (cron/CI friendly):
#   0 = no drift, 1 = only VERSION/MISSING drift, 2 = any UNEXPECTED package
#
# Usage:
#   # Snapshot the current box into a manifest you then review & commit
#   ruby package_drift_audit.rb --snapshot > baseline.txt
#
#   # Audit this box against that manifest
#   ruby package_drift_audit.rb --manifest baseline.txt
#   ruby package_drift_audit.rb --manifest baseline.txt --json
#
#   # Ignore version differences (presence-only audit)
#   ruby package_drift_audit.rb --manifest baseline.txt --no-versions
#
# Manifest format: one "name version" per line (version optional), '#' comments.
#
# Pure stdlib: optparse, json, open3. The package-list source is injectable,
# so the diff logic is unit-testable without a real package database.

require 'optparse'
require 'json'
require 'open3'

module PackageDriftAudit
  module_function

  # Detect the platform's package manager and return a lambda that yields
  # { name => version } for everything currently installed.
  def default_source
    if which('dpkg-query')
      -> { parse_dpkg(run('dpkg-query', '-W', '-f=${Package} ${Version}\n')) }
    elsif which('rpm')
      -> { parse_rpm(run('rpm', '-qa', '--qf', '%{NAME} %{VERSION}-%{RELEASE}\n')) }
    else
      -> { abort 'error: no supported package manager found (need dpkg-query or rpm)' }
    end
  end

  def which(cmd)
    ENV['PATH'].to_s.split(File::PATH_SEPARATOR).any? do |dir|
      File.executable?(File.join(dir, cmd))
    end
  end

  def run(*cmd)
    out, status = Open3.capture2(*cmd)
    abort "error: #{cmd.first} exited #{status.exitstatus}" unless status.success?
    out
  end

  def parse_dpkg(text)
    installed = {}
    text.each_line do |line|
      name, version = line.split(' ', 2)
      next unless name
      installed[name] = version.to_s.strip
    end
    installed
  end

  # rpm -qa can emit the same package name for multiple arches; keep the last.
  def parse_rpm(text)
    installed = {}
    text.each_line do |line|
      name, version = line.split(' ', 2)
      next unless name
      installed[name.strip] = version.to_s.strip
    end
    installed
  end

  # Parse a manifest file into { name => version_or_nil }.
  def parse_manifest(text)
    manifest = {}
    text.each_line do |line|
      line = line.sub(/#.*/, '').strip
      next if line.empty?
      name, version = line.split(/\s+/, 2)
      manifest[name] = version && !version.empty? ? version : nil
    end
    manifest
  end

  # Core diff. installed/manifest are hashes; returns an array of finding hashes.
  # check_versions=false makes it a presence-only audit.
  def diff(installed:, manifest:, check_versions: true)
    findings = []
    manifest.each do |name, want|
      if !installed.key?(name)
        findings << { status: 'MISSING', name: name, want: want, have: nil }
      elsif check_versions && want && installed[name] != want
        findings << { status: 'VERSION', name: name, want: want, have: installed[name] }
      else
        findings << { status: 'OK', name: name, want: want, have: installed[name] }
      end
    end
    (installed.keys - manifest.keys).sort.each do |name|
      findings << { status: 'UNEXPECTED', name: name, want: nil, have: installed[name] }
    end
    findings
  end

  def exit_code(findings)
    return 2 if findings.any? { |f| f[:status] == 'UNEXPECTED' }
    return 1 if findings.any? { |f| %w[MISSING VERSION].include?(f[:status]) }
    0
  end
end

if __FILE__ == $PROGRAM_NAME
  options = { manifest: nil, json: false, snapshot: false, versions: true, source: nil }
  OptionParser.new do |o|
    o.banner = 'Usage: ruby package_drift_audit.rb [--snapshot | --manifest FILE] [options]'
    o.on('--snapshot', 'Print current installed packages as a manifest') { options[:snapshot] = true }
    o.on('--manifest FILE', 'Audit against this manifest') { |v| options[:manifest] = v }
    o.on('--installed FILE', 'Use this dpkg/rpm-style list instead of querying (testing/offline)') { |v| options[:source] = v }
    o.on('--[no-]versions', 'Compare pinned versions (default on)') { |v| options[:versions] = v }
    o.on('--json', 'Emit JSON') { options[:json] = true }
  end.parse!

  source =
    if options[:source]
      -> { PackageDriftAudit.parse_dpkg(File.read(options[:source])) }
    else
      PackageDriftAudit.default_source
    end

  installed = source.call

  if options[:snapshot]
    puts '# package manifest — generated by package_drift_audit.rb --snapshot'
    puts "# #{Time.now.strftime('%Y-%m-%d %H:%M')}  (#{installed.size} packages)"
    installed.sort.each { |name, ver| puts "#{name} #{ver}" }
    exit 0
  end

  abort 'error: give me --manifest FILE (or --snapshot to make one)' unless options[:manifest]
  manifest = PackageDriftAudit.parse_manifest(File.read(options[:manifest]))
  findings = PackageDriftAudit.diff(installed: installed, manifest: manifest, check_versions: options[:versions])
  code = PackageDriftAudit.exit_code(findings)

  order = { 'UNEXPECTED' => 0, 'MISSING' => 1, 'VERSION' => 2, 'OK' => 3 }
  drift = findings.reject { |f| f[:status] == 'OK' }.sort_by { |f| [order[f[:status]], f[:name]] }

  if options[:json]
    puts JSON.pretty_generate(
      installed: installed.size, manifest: manifest.size,
      counts: findings.group_by { |f| f[:status] }.transform_values(&:size),
      exit_code: code, drift: drift
    )
  else
    puts "package_drift_audit — #{installed.size} installed vs #{manifest.size} in manifest"
    counts = findings.group_by { |f| f[:status] }.transform_values(&:size)
    puts "summary: #{%w[OK MISSING VERSION UNEXPECTED].map { |k| "#{k}=#{counts[k] || 0}" }.join('  ')}"
    puts
    if drift.empty?
      puts '  no drift — installed packages match the manifest'
    else
      drift.each do |f|
        detail = case f[:status]
                 when 'MISSING'    then "expected #{f[:want] || '(any version)'}"
                 when 'VERSION'    then "want #{f[:want]}, have #{f[:have]}"
                 when 'UNEXPECTED' then "installed #{f[:have]} — not in manifest"
                 end
        puts format('  %-10s %-28s %s', f[:status], f[:name][0, 28], detail)
      end
    end
  end
  exit code
end
