#!/usr/bin/env ruby
# frozen_string_literal: true
#
# win_optional_features_audit.rb -- Windows optional feature / role attack-surface audit
#
# THE PROBLEM
# -----------
# "Installed programs" inventories miss the most dangerous software on a Windows
# box, because that software is not a program -- it is a Windows *optional
# feature*. SMBv1, Telnet Client, TFTP Client, PowerShell 2.0 and the legacy
# .NET 3.5 runtime all ship inside Windows itself, are enabled by a checkbox or
# a one-line DISM call, and never appear in Add/Remove Programs.
#
# They matter because each one re-opens something the platform already fixed:
#
#   * SMBv1 is the protocol WannaCry and NotPetya spread over. Microsoft has
#     deprecated it since 2014 and it still turns up enabled on file servers
#     because an old scanner or NAS "needed" it once.
#   * PowerShell 2.0 has no script-block logging, no AMSI, and no constrained
#     language mode. Leaving it installed gives an attacker a documented,
#     signed, one-flag downgrade (`powershell -version 2`) that bypasses the
#     logging your SOC is watching.
#   * Telnet and TFTP clients are living-off-the-land transfer tools that let
#     an intruder move files without dropping a binary AV would notice.
#
# This script enumerates Win32_OptionalFeature (and optionally Win32_ServerFeature
# on Server SKUs) over WMI, classifies every enabled feature against a risk
# catalogue, and prints the exact DISM/PowerShell remediation command for each
# finding -- so the output is a work order, not just a list.
#
# USAGE
#   ruby win_optional_features_audit.rb
#   ruby win_optional_features_audit.rb --computer FILESRV01
#   ruby win_optional_features_audit.rb --format json
#   ruby win_optional_features_audit.rb --all            # list every feature, not just risky ones
#   ruby win_optional_features_audit.rb --mock fixtures/mock_features.json   # offline/self-test
#
# EXIT CODES
#   0  no risky features enabled
#   1  medium-risk features enabled
#   2  high-risk features enabled, or WMI unreachable
#
# Requires: Ruby for Windows (RubyInstaller) >= 2.7. Uses win32ole from stdlib.
# Remote queries (--computer) need admin rights on the target and DCOM reachable.

require 'json'
require 'optparse'
require 'time'

module WinOptionalFeaturesAudit
  VERSION = '1.0.0'

  # Win32_OptionalFeature.InstallState is a uint32, not a boolean. 1 means
  # enabled; 2 means the payload is absent from the image entirely (which is
  # *better* than merely disabled, because it cannot be turned back on without
  # source media). Treating anything non-zero as "installed" is the classic
  # mistake here and produces a report full of false positives.
  INSTALL_STATE = {
    1 => :enabled,
    2 => :disabled,
    3 => :absent,
    4 => :unknown
  }.freeze

  Risk = Struct.new(:name, :severity, :why, :remediation, keyword_init: true)

  # ---------------------------------------------------------------------------
  # Risk catalogue.
  #
  # Keys are matched case-insensitively against the *start* of the feature name,
  # because Microsoft versions these ("SMB1Protocol", "SMB1Protocol-Client",
  # "SMB1Protocol-Server", "SMB1Protocol-Deprecation") and a hardcoded exact
  # match silently misses the child features that actually carry the protocol.
  # ---------------------------------------------------------------------------
  CATALOGUE = [
    Risk.new(
      name: 'SMB1Protocol', severity: :high,
      why: 'SMBv1 is the protocol WannaCry/NotPetya spread over. Deprecated ' \
           'since 2014, removed by default since 1709, and unfixable by design ' \
           '-- it has no pre-auth integrity and no secure dialect negotiation.',
      remediation: 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart'
    ),
    Risk.new(
      name: 'MicrosoftWindowsPowerShellV2', severity: :high,
      why: 'PowerShell 2.0 predates AMSI, script-block logging and constrained ' \
           'language mode. While installed, `powershell -version 2` is a signed, ' \
           'documented downgrade that silently defeats PowerShell logging.',
      remediation: 'Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart'
    ),
    Risk.new(
      name: 'TelnetClient', severity: :medium,
      why: 'A built-in, unencrypted network client. Rarely needed post-2010 and ' \
           'commonly used by intruders for banner grabbing and lateral movement ' \
           'without dropping a new binary.',
      remediation: 'Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart'
    ),
    Risk.new(
      name: 'TelnetServer', severity: :high,
      why: 'Accepts plaintext credentials over the network. There is no ' \
           'configuration that makes this safe.',
      remediation: 'Disable-WindowsOptionalFeature -Online -FeatureName TelnetServer -NoRestart'
    ),
    Risk.new(
      name: 'TFTP', severity: :medium,
      why: 'Unauthenticated file transfer client. A standard living-off-the-land ' \
           'tool for staging payloads.',
      remediation: 'Disable-WindowsOptionalFeature -Online -FeatureName TFTP -NoRestart'
    ),
    Risk.new(
      name: 'SimpleTCP', severity: :medium,
      why: 'Simple TCPIP Services revives echo/discard/daytime/chargen -- 1980s ' \
           'services with known amplification-DoS abuse.',
      remediation: 'Disable-WindowsOptionalFeature -Online -FeatureName SimpleTCP -NoRestart'
    ),
    Risk.new(
      name: 'NetFx3', severity: :medium,
      why: '.NET Framework 3.5 carries the legacy CLR 2.0 runtime. Keep it only ' \
           'if an application genuinely requires it; it widens the patch surface ' \
           'and is a common target for older exploit chains.',
      remediation: 'Disable-WindowsOptionalFeature -Online -FeatureName NetFx3 -NoRestart'
    ),
    Risk.new(
      name: 'IIS-WebServerRole', severity: :medium,
      why: 'A web server listening on a host that is not meant to be a web ' \
           'server is unmonitored attack surface. Verify this is intentional.',
      remediation: 'Disable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole -NoRestart'
    ),
    Risk.new(
      name: 'IIS-FTPServer', severity: :high,
      why: 'FTP transmits credentials in plaintext unless FTPS is explicitly ' \
           'configured, which it usually is not.',
      remediation: 'Disable-WindowsOptionalFeature -Online -FeatureName IIS-FTPServer -NoRestart'
    ),
    Risk.new(
      name: 'WindowsMediaPlayer', severity: :low,
      why: 'Large media-parsing codebase with a long CVE history. Unnecessary on ' \
           'servers and on most managed workstations.',
      remediation: 'Disable-WindowsOptionalFeature -Online -FeatureName WindowsMediaPlayer -NoRestart'
    ),
    Risk.new(
      name: 'Printing-XPSServices', severity: :low,
      why: 'XPS document services add a parser nobody uses. Low value, non-zero ' \
           'surface.',
      remediation: 'Disable-WindowsOptionalFeature -Online -FeatureName Printing-XPSServices-Features -NoRestart'
    ),
    Risk.new(
      name: 'WorkFolders-Client', severity: :low,
      why: 'Sync client that can move corporate data to unmanaged endpoints if ' \
           'not governed by policy.',
      remediation: 'Disable-WindowsOptionalFeature -Online -FeatureName WorkFolders-Client -NoRestart'
    )
  ].freeze

  SEVERITY_RANK = { low: 0, medium: 1, high: 2 }.freeze

  Feature = Struct.new(:name, :caption, :state, :risk, keyword_init: true) do
    def enabled?
      state == :enabled
    end

    def risky?
      enabled? && !risk.nil?
    end

    def to_h
      {
        name: name, caption: caption, state: state,
        severity: risk&.severity, why: risk&.why, remediation: risk&.remediation
      }.compact
    end
  end

  # ---------------------------------------------------------------------------
  # WMI provider -- the only part that needs Windows.
  #
  # It is isolated behind a tiny interface (#features returns an array of
  # hashes) so the whole analysis and reporting path can be exercised on any OS
  # with the MockProvider below. This is the difference between "I think this
  # script works" and "I ran the logic 200 times on Linux."
  # ---------------------------------------------------------------------------
  class WmiProvider
    def initialize(computer: '.')
      @computer = computer
    end

    def features
      require 'win32ole'

      # Connect explicitly rather than using winmgmts: moniker shorthand, so a
      # remote connection failure raises here with a useful message instead of
      # failing later during enumeration.
      locator = WIN32OLE.new('WbemScripting.SWbemLocator')
      service = locator.ConnectServer(@computer, 'root\\CIMV2')
      service.Security_.ImpersonationLevel = 3   # RPC_C_IMP_LEVEL_IMPERSONATE

      rows = []
      query = 'SELECT Name, Caption, InstallState FROM Win32_OptionalFeature'
      service.ExecQuery(query).each do |f|
        rows << {
          'Name' => safe(f, :Name),
          'Caption' => safe(f, :Caption),
          'InstallState' => safe(f, :InstallState).to_i
        }
      end
      rows
    rescue LoadError
      raise 'win32ole is unavailable -- this script must run on Windows Ruby ' \
            '(RubyInstaller), not WSL or Linux. Use --mock to test the logic.'
    rescue WIN32OLERuntimeError => e
      raise "WMI query failed against '#{@computer}': #{e.message.lines.first.to_s.strip}"
    end

    private

    # Individual WMI properties can be NULL, and touching a NULL property on
    # some providers raises rather than returning nil. Reading each one
    # defensively keeps a single malformed row from aborting the whole audit.
    def safe(obj, prop)
      obj.send(prop)
    rescue StandardError
      nil
    end
  end

  # Offline provider: reads the same row shape from a JSON fixture.
  class MockProvider
    def initialize(path)
      @path = path
    end

    def features
      JSON.parse(File.read(@path))
    end
  end

  # ---------------------------------------------------------------------------
  # Analyzer -- pure logic, no I/O, trivially testable
  # ---------------------------------------------------------------------------
  class Analyzer
    def initialize(rows)
      @rows = rows
    end

    def features
      @features ||= @rows.map do |row|
        name = row['Name'].to_s
        Feature.new(
          name: name,
          caption: row['Caption'].to_s,
          state: INSTALL_STATE.fetch(row['InstallState'].to_i, :unknown),
          risk: match_risk(name)
        )
      end
    end

    def risky
      features.select(&:risky?)
              .sort_by { |f| [-SEVERITY_RANK[f.risk.severity], f.name.downcase] }
    end

    def worst_severity
      risky.map { |f| f.risk.severity }.max_by { |s| SEVERITY_RANK[s] }
    end

    def summary
      counts = Hash.new(0)
      features.each { |f| counts[f.state] += 1 }
      counts
    end

    private

    # Prefix match, longest-first, so "SMB1Protocol-Server" binds to the
    # SMB1Protocol entry rather than falling through, and a future exact entry
    # for a child feature would win over its parent.
    def match_risk(name)
      n = name.downcase
      CATALOGUE.select { |r| n.start_with?(r.name.downcase) }
               .max_by { |r| r.name.length }
    end
  end

  # ---------------------------------------------------------------------------
  # Reporting
  # ---------------------------------------------------------------------------
  module Report
    MARK = { high: '[HIGH]', medium: '[MED ]', low: '[LOW ]' }.freeze

    def self.text(analyzer, computer, show_all)
      l = []
      l << '=' * 76
      l << "Windows optional feature audit -- #{computer == '.' ? 'localhost' : computer}"
      l << '=' * 76

      s = analyzer.summary
      l << format('  %d features known: %d enabled, %d disabled, %d absent from image',
                  analyzer.features.size, s[:enabled], s[:disabled], s[:absent])
      l << ''

      risky = analyzer.risky
      l << 'RISKY FEATURES ENABLED'
      l << '-' * 76
      if risky.empty?
        l << '  [ OK ] no catalogued risky features are enabled on this host'
      else
        risky.each do |f|
          l << format('%s %s', MARK[f.risk.severity], f.name)
          l << "       #{f.caption}" unless f.caption.empty?
          wrap(f.risk.why, 68).each { |w| l << "       #{w}" }
          l << "       fix: #{f.risk.remediation}"
          l << ''
        end
      end

      if show_all
        l << 'ALL ENABLED FEATURES'
        l << '-' * 76
        analyzer.features.select(&:enabled?).sort_by { |f| f.name.downcase }
                .each { |f| l << "  #{f.name}" }
        l << ''
      end

      worst = analyzer.worst_severity
      l << "RESULT: #{worst ? "#{worst.to_s.upcase} risk features present" : 'CLEAN'}"
      l.join("\n")
    end

    def self.json(analyzer, computer)
      JSON.pretty_generate(
        generated_at: Time.now.utc.iso8601,
        version: VERSION,
        computer: computer,
        summary: analyzer.summary,
        worst_severity: analyzer.worst_severity,
        risky_features: analyzer.risky.map(&:to_h),
        remediation_script: analyzer.risky.map { |f| f.risk.remediation }
      )
    end

    def self.wrap(text, width)
      text.split(/\s+/).each_with_object(['']) do |word, acc|
        if (acc.last.length + word.length + 1) > width
          acc << word
        else
          acc[-1] = acc.last.empty? ? word : "#{acc.last} #{word}"
        end
      end
    end
  end

  # ---------------------------------------------------------------------------
  # CLI
  # ---------------------------------------------------------------------------
  def self.run(argv)
    opts = { computer: '.', format: 'text', all: false, mock: nil }

    OptionParser.new do |o|
      o.banner = 'Usage: ruby win_optional_features_audit.rb [options]'
      o.on('--computer NAME', 'Remote computer to query (default: local)') { |v| opts[:computer] = v }
      o.on('--format FMT', %w[text json], 'text (default) or json') { |v| opts[:format] = v }
      o.on('--all', 'Also list every enabled feature') { opts[:all] = true }
      o.on('--mock PATH', 'Read features from a JSON fixture instead of WMI') { |v| opts[:mock] = v }
      o.on('-v', '--version') { puts VERSION; exit 0 }
      o.on('-h', '--help') { puts o; exit 0 }
    end.parse!(argv)

    provider = opts[:mock] ? MockProvider.new(opts[:mock]) : WmiProvider.new(computer: opts[:computer])
    analyzer = Analyzer.new(provider.features)

    puts(if opts[:format] == 'json'
           Report.json(analyzer, opts[:computer])
         else
           Report.text(analyzer, opts[:computer], opts[:all])
         end)

    case analyzer.worst_severity
    when :high then 2
    when :medium then 1
    else 0
    end
  rescue RuntimeError, Errno::ENOENT, JSON::ParserError => e
    warn "error: #{e.message}"
    2
  end
end

exit WinOptionalFeaturesAudit.run(ARGV) if $PROGRAM_NAME == __FILE__
