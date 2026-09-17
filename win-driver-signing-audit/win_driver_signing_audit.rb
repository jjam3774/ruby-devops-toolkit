#!/usr/bin/env ruby
# frozen_string_literal: true
#
# win_driver_signing_audit.rb -- audit installed Windows kernel-mode drivers
#                                for signing status, age, and provenance.
#
# WHY THIS EXISTS
# ---------------
# A kernel-mode driver is the most privileged code on a Windows box. It runs
# in ring 0, below every EDR hook and every user-mode protection you have
# bought. Which means the interesting question for any Windows fleet is not
# "what software is installed" -- your inventory tool already answers that --
# but "what code is currently allowed to run in the kernel, who signed it,
# and when was it last touched."
#
# That question has become sharply practical. "Bring Your Own Vulnerable
# Driver" (BYOVD) is now the standard opening move for kernel-level attacks:
# the attacker does not exploit your driver stack, they *install a legitimately
# signed, known-vulnerable driver* and drive through it. Microsoft's own
# blocklist exists precisely because the signature on a driver tells you it
# was authentic, not that it was safe.
#
# This script enumerates Win32_PnPSignedDriver over WMI and reports:
#   * drivers with no digital signature at all
#   * drivers signed by something other than Microsoft (third-party ring 0)
#   * drivers whose binaries are very old and thus predate modern mitigations
#   * drivers whose files live outside the protected system driver directories
#   * drivers matching a configurable known-bad list (your BYOVD watchlist)
#
# Ruby >= 2.7 with win32ole (bundled with Ruby for Windows). Windows 7+.
# Run from an elevated prompt: driver enumeration needs Administrator.
#
# Usage (on Windows):
#   ruby win_driver_signing_audit.rb
#   ruby win_driver_signing_audit.rb --json > drivers.json
#   ruby win_driver_signing_audit.rb --host SERVER01 --min-severity high
#   ruby win_driver_signing_audit.rb --blocklist byovd.txt
#
# Offline / CI use (works on Linux, which is how this script is tested):
#   ruby win_driver_signing_audit.rb --fixture drivers.json
#
# Exit codes:
#   0 = clean at the reporting threshold
#   1 = warnings only (medium/low)
#   2 = at least one high or critical finding
#   3 = could not enumerate (not Windows, WMI failure, bad arguments)

require 'optparse'
require 'json'
require 'time'
require 'date'

module Policy
  # Drivers built before this are not automatically dangerous, but they
  # predate the mitigations (KMDF updates, HVCI compatibility, the modern
  # signing portal) that make a driver auditable at all.
  ANCIENT_DRIVER_YEAR = 2015
  OLD_DRIVER_YEAR     = 2019

  # Anything outside these is unusual for a kernel driver and worth a look.
  TRUSTED_PATH_PREFIXES = [
    'c:\\windows\\system32\\drivers',
    'c:\\windows\\system32\\driverstore',
    'c:\\windows\\syswow64\\drivers'
  ].freeze

  # Providers whose drivers are expected in bulk on any Windows install.
  MICROSOFT_PROVIDERS = ['microsoft', 'microsoft corporation'].freeze
end

SEVERITIES = %w[critical high medium low].freeze
SEV_RANK   = SEVERITIES.each_with_index.to_h.freeze

# ==========================================================================
# Driver -- one Win32_PnPSignedDriver instance, normalised.
#
# WMI is a hostile data source for tidy code: every property can be nil, and
# the ones that are supposed to be dates arrive as either a WbemScripting
# date object or a CIM_DATETIME string like "20230814000000.000000-000",
# depending on how you asked. Normalising once at the boundary means the
# rules below never have to think about it.
# ==========================================================================
class Driver
  attr_reader :device_name, :friendly_name, :provider, :version,
              :driver_date, :inf_name, :path, :device_class,
              :signer, :is_signed, :device_id

  def initialize(raw)
    @device_name   = str(raw['DeviceName']) || str(raw['FriendlyName']) || '(unnamed device)'
    @friendly_name = str(raw['FriendlyName'])
    @provider      = str(raw['DriverProviderName'])
    @version       = str(raw['DriverVersion'])
    @inf_name      = str(raw['InfName'])
    @path          = str(raw['Location']) || str(raw['DriverPath'])
    @device_class  = str(raw['DeviceClass'])
    @signer        = str(raw['Signer'])
    @device_id     = str(raw['DeviceID'])
    @driver_date   = parse_wmi_date(raw['DriverDate'])

    # IsSigned comes back as a real boolean over OLE but as a string from
    # JSON fixtures and from some remote WMI providers. Accept all shapes.
    @is_signed = case raw['IsSigned']
                 when true, 'true', 'True', 1, '1' then true
                 when false, 'false', 'False', 0, '0' then false
                 else infer_signed
                 end
  end

  def microsoft?
    return false if @provider.nil?

    Policy::MICROSOFT_PROVIDERS.include?(@provider.downcase) ||
      @provider.downcase.start_with?('microsoft')
  end

  def signed?
    @is_signed == true
  end

  def driver_year
    @driver_date&.year
  end

  def in_trusted_path?
    return true if @path.nil? || @path.empty? # nothing to judge; do not cry wolf

    p = @path.downcase.tr('/', '\\')
    Policy::TRUSTED_PATH_PREFIXES.any? { |prefix| p.start_with?(prefix) }
  end

  # Normalised identity for blocklist matching. Vendors ship the same
  # vulnerable driver under several product names, but the INF/service name
  # stays stable, so that is what a BYOVD list keys on.
  def match_keys
    [@inf_name, File.basename(@path.to_s.tr('\\', '/')), @device_name]
      .compact.map(&:downcase).reject(&:empty?)
  end

  def to_h
    {
      device_name: @device_name, provider: @provider, version: @version,
      driver_date: @driver_date&.strftime('%Y-%m-%d'), inf_name: @inf_name,
      path: @path, device_class: @device_class, signer: @signer,
      is_signed: @is_signed, device_id: @device_id
    }
  end

  private

  def str(val)
    return nil if val.nil?

    s = val.to_s.strip
    s.empty? ? nil : s
  end

  # If IsSigned is absent entirely (older providers omit it), the presence of
  # a Signer string is the next best evidence. Guessing is documented rather
  # than hidden: "unknown" is a distinct state from "unsigned" in the report.
  def infer_signed
    @signer.nil? ? nil : true
  end

  # WMI dates arrive in two shapes. CIM_DATETIME is
  # "yyyymmddHHMMSS.mmmmmmsUUU"; the OLE variant is already a Time-like
  # object. Anything unparseable becomes nil rather than raising -- one
  # mangled date must not abort a fleet-wide audit.
  def parse_wmi_date(val)
    return nil if val.nil?

    s = val.to_s.strip
    return nil if s.empty?

    if (m = s.match(/\A(\d{4})(\d{2})(\d{2})/))
      year, month, day = m.captures.map(&:to_i)
      return nil if year < 1980 || month.zero? || day.zero?

      return Time.new(year, month, day)
    end

    Time.parse(s)
  rescue ArgumentError, TypeError, RangeError
    nil
  end
end

# ==========================================================================
# Collectors -- the only platform-specific code in the script.
#
# WmiCollector talks to real Windows. FixtureCollector reads the same shape
# from JSON. Everything downstream consumes the identical Hash, which is what
# makes the whole auditor testable on a Linux CI runner.
# ==========================================================================
module Collector
  FIELDS = %w[DeviceName FriendlyName DriverProviderName DriverVersion
              DriverDate InfName Location DeviceClass Signer IsSigned
              DeviceID].freeze

  class WmiError < StandardError; end

  class Wmi
    def initialize(host: '.')
      @host = host
    end

    def collect
      require 'win32ole'

      locator = WIN32OLE.new('WbemScripting.SWbemLocator')
      service = locator.ConnectServer(@host, 'root\\CIMV2')

      # Selecting explicit columns rather than * matters here: the default
      # Win32_PnPSignedDriver projection is enormous (every PnP property) and
      # on a laptop with a few hundred devices the difference between SELECT *
      # and a named list is seconds, not milliseconds.
      query = "SELECT #{FIELDS.join(', ')} FROM Win32_PnPSignedDriver"
      rows = []
      service.ExecQuery(query).each do |row|
        rows << FIELDS.each_with_object({}) do |field, h|
          h[field] = begin
            row.send(field)
          rescue StandardError
            nil # property genuinely absent on this provider version
          end
        end
      end
      rows
    rescue LoadError
      raise WmiError, 'win32ole is unavailable -- this collector requires Ruby on Windows'
    rescue WIN32OLERuntimeError => e
      raise WmiError, "WMI query failed: #{e.message.lines.first.to_s.strip}"
    end
  end

  class Fixture
    def initialize(path)
      @path = path
    end

    def collect
      data = JSON.parse(File.read(@path))
      rows = data.is_a?(Hash) ? data['drivers'] : data
      raise WmiError, "#{@path}: expected a JSON array of driver rows" unless rows.is_a?(Array)

      rows
    rescue Errno::ENOENT
      raise WmiError, "#{@path}: no such file"
    rescue JSON::ParserError => e
      raise WmiError, "#{@path}: invalid JSON (#{e.message})"
    end
  end
end

# ==========================================================================
# Auditor -- the rules.
# ==========================================================================
class Auditor
  Finding = Struct.new(:device, :severity, :code, :detail, :evidence, keyword_init: true)

  def initialize(blocklist: [])
    # Blocklist entries are matched case-insensitively against the INF name,
    # the driver filename, and the device name.
    @blocklist = blocklist.map(&:downcase)
  end

  def audit_all(drivers)
    drivers.flat_map { |d| audit(d) }
  end

  def audit(d)
    out = []

    # ---- the blocklist comes first: it is the only rule that can be
    # ---- critical, because a known-vulnerable driver is not a posture
    # ---- problem, it is a live kernel-level foothold.
    hit = @blocklist.find { |entry| d.match_keys.any? { |k| k.include?(entry) } }
    if hit
      out << f(d, 'critical', 'KNOWN_VULNERABLE_DRIVER',
               "matches blocklist entry '#{hit}' -- a driver on your BYOVD watchlist is " \
               'loaded; a valid signature does not make it safe, it makes it usable',
               "inf=#{d.inf_name || '?'} path=#{d.path || '?'} version=#{d.version || '?'}")
    end

    # ---- signing ---------------------------------------------------------
    if d.is_signed == false
      out << f(d, 'high', 'UNSIGNED_DRIVER',
               'reports no digital signature -- on a correctly configured 64-bit Windows ' \
               'install this should be impossible, so either enforcement is disabled or ' \
               'the driver was installed in test-signing mode',
               "signer=#{d.signer || '(none)'} provider=#{d.provider || '?'}")
    elsif d.is_signed.nil?
      out << f(d, 'low', 'SIGNATURE_UNKNOWN',
               'WMI returned no IsSigned value for this device, so signing status could ' \
               'not be established either way -- verify manually with signtool',
               "signer=#{d.signer || '(none)'}")
    end

    # ---- provenance ------------------------------------------------------
    # Not a vulnerability. But on most fleets the third-party kernel drivers
    # are a list of five to fifteen vendors, and anything that is not on that
    # list arrived recently and deliberately. That is a question worth asking.
    if d.signed? && !d.microsoft?
      out << f(d, 'medium', 'THIRD_PARTY_KERNEL_CODE',
               "third-party kernel-mode code from '#{d.provider}' -- inventory it: every " \
               'non-Microsoft driver is an independent ring-0 trust decision',
               "provider=#{d.provider} version=#{d.version || '?'} signer=#{d.signer || '?'}")
    end

    # ---- age -------------------------------------------------------------
    year = d.driver_year
    if year && year < Policy::ANCIENT_DRIVER_YEAR
      out << f(d, 'high', 'ANCIENT_DRIVER',
               "driver binary dates from #{year}, predating the mitigations that make " \
               'kernel code auditable -- and old third-party drivers are the exact ' \
               'population BYOVD blocklists are drawn from',
               "driverDate=#{d.driver_date.strftime('%Y-%m-%d')} version=#{d.version || '?'}")
    elsif year && year < Policy::OLD_DRIVER_YEAR
      out << f(d, 'low', 'OLD_DRIVER',
               "driver binary dates from #{year}; check whether the vendor has shipped " \
               'anything since',
               "driverDate=#{d.driver_date.strftime('%Y-%m-%d')}")
    end

    # ---- file location ---------------------------------------------------
    unless d.in_trusted_path?
      out << f(d, 'high', 'UNUSUAL_DRIVER_PATH',
               'driver file lives outside the protected system driver directories, which ' \
               'is both unusual and a weaker place to defend -- a writable directory here ' \
               'means the driver binary itself can be swapped',
               "path=#{d.path}")
    end

    out
  end

  private

  def f(driver, severity, code, detail, evidence)
    Finding.new(device: driver.device_name, severity: severity, code: code,
                detail: detail, evidence: evidence)
  end
end

# ==========================================================================
# Reporting
# ==========================================================================
module Report
  COLORS = { 'critical' => "\e[1;31m", 'high' => "\e[31m",
             'medium' => "\e[33m", 'low' => "\e[36m" }.freeze
  RESET = "\e[0m"

  def self.tint(text, severity)
    return text unless $stdout.tty? && ENV['NO_COLOR'].nil?

    "#{COLORS.fetch(severity, '')}#{text}#{RESET}"
  end

  def self.text(drivers, findings, opts)
    lines = []
    lines << "Windows driver signing audit -- #{Time.now.strftime('%Y-%m-%d %H:%M:%S %Z')}"
    lines << "source: #{opts[:fixture] ? "fixture #{opts[:fixture]}" : "WMI on #{opts[:host]}"}"
    lines << '=' * 78
    lines << ''

    third_party = drivers.select { |d| !d.microsoft? }
    unsigned    = drivers.select { |d| d.is_signed == false }

    lines << "DRIVERS: #{drivers.length} enumerated"
    lines << "  Microsoft-provided: #{drivers.count(&:microsoft?)}"
    lines << "  third-party:        #{third_party.length}"
    lines << "  unsigned:           #{unsigned.length}"
    lines << "  signing unknown:    #{drivers.count { |d| d.is_signed.nil? }}"
    lines << ''

    unless third_party.empty?
      lines << 'THIRD-PARTY KERNEL PROVIDERS'
      lines << '-' * 78
      third_party.group_by { |d| d.provider || '(unknown)' }
                 .sort_by { |_, v| -v.length }.each do |provider, group|
        years = group.map(&:driver_year).compact
        span = years.empty? ? 'no dates' : "#{years.min}-#{years.max}"
        lines << format('  %-38s %3d driver(s)  %s', provider[0, 38], group.length, span)
      end
      lines << ''
    end

    if findings.empty?
      lines << 'No findings at or above the configured severity threshold.'
    else
      lines << "FINDINGS (#{findings.length})"
      lines << '-' * 78
      findings.each do |fd|
        lines << tint("[#{fd.severity.upcase}] #{fd.code}", fd.severity)
        lines << "    device:   #{fd.device}"
        lines << "    #{fd.detail}"
        lines << "    evidence: #{fd.evidence}"
        lines << ''
      end
    end

    counts = findings.group_by(&:severity).transform_values(&:length)
    lines << '=' * 78
    lines << "#{drivers.length} driver(s); " +
             SEVERITIES.map { |s| "#{counts.fetch(s, 0)} #{s}" }.join(', ')
    lines.join("\n")
  end

  def self.json(drivers, findings, opts)
    JSON.pretty_generate(
      generated_at: Time.now.utc.iso8601,
      source: opts[:fixture] ? { fixture: opts[:fixture] } : { wmi_host: opts[:host] },
      drivers: drivers.map(&:to_h),
      findings: findings.map(&:to_h),
      summary: {
        drivers: drivers.length,
        microsoft: drivers.count(&:microsoft?),
        third_party: drivers.count { |d| !d.microsoft? },
        unsigned: drivers.count { |d| d.is_signed == false },
        findings: findings.group_by(&:severity).transform_values(&:length)
      }
    )
  end
end

# ==========================================================================
# CLI
# ==========================================================================
def parse_options(argv)
  opts = { host: '.', fixture: nil, blocklist: [], json: false, min_severity: 'low' }

  parser = OptionParser.new do |o|
    o.banner = 'Usage: win_driver_signing_audit.rb [options]'
    o.on('--host NAME', 'remote host to query over WMI (default local)') { |v| opts[:host] = v }
    o.on('--fixture PATH', 'read driver rows from a JSON file instead of WMI') do |v|
      opts[:fixture] = v
    end
    o.on('--blocklist PATH', 'file of known-vulnerable driver names, one per line') do |v|
      opts[:blocklist_file] = v
    end
    o.on('--json', 'emit JSON instead of text') { opts[:json] = true }
    o.on('--min-severity SEV', SEVERITIES, "report SEV and above (#{SEVERITIES.join('|')})") do |v|
      opts[:min_severity] = v
    end
    o.on('-h', '--help') { puts o; exit 0 }
  end
  parser.parse!(argv)

  if opts[:blocklist_file]
    begin
      opts[:blocklist] = File.readlines(opts[:blocklist_file], chomp: true)
                             .map(&:strip)
                             .reject { |l| l.empty? || l.start_with?('#') }
    rescue Errno::ENOENT
      warn "argument error: blocklist #{opts[:blocklist_file]} not found"
      exit 3
    end
  end

  opts
rescue OptionParser::ParseError => e
  warn "argument error: #{e.message}"
  exit 3
end

def main(argv)
  opts = parse_options(argv)

  collector = if opts[:fixture]
                Collector::Fixture.new(opts[:fixture])
              else
                Collector::Wmi.new(host: opts[:host])
              end

  begin
    rows = collector.collect
  rescue Collector::WmiError => e
    warn "error: #{e.message}"
    warn 'hint: on Linux/macOS, run with --fixture to audit an exported driver list.'
    exit 3
  end

  drivers = rows.map { |r| Driver.new(r) }
  if drivers.empty?
    warn 'error: no drivers were returned. On Windows, run from an elevated prompt.'
    exit 3
  end

  auditor  = Auditor.new(blocklist: opts[:blocklist])
  findings = auditor.audit_all(drivers)

  cutoff   = SEV_RANK.fetch(opts[:min_severity])
  findings = findings.select { |fd| SEV_RANK.fetch(fd.severity) <= cutoff }
  findings.sort_by! { |fd| [SEV_RANK.fetch(fd.severity), fd.code, fd.device.to_s] }

  puts(opts[:json] ? Report.json(drivers, findings, opts) : Report.text(drivers, findings, opts))

  worst = findings.map { |fd| SEV_RANK.fetch(fd.severity) }.min
  return 0 if worst.nil?
  return 2 if worst <= SEV_RANK.fetch('high')

  1
end

exit main(ARGV) if __FILE__ == $PROGRAM_NAME
