#!/usr/bin/env ruby
# frozen_string_literal: true
#
# autorun_audit.rb -- inventory and risk-score every autorun entry on a
# Windows host.
#
# "Persistence" is the boring part of an intrusion: something writes a value
# under HKCU\...\Run, or drops a .lnk in the Startup folder, and it comes back
# every login. The same mechanisms are also where legitimate vendor bloat
# lives, so the job is not "list them" -- it is "list them, score them, and
# tell me what changed since last week".
#
# Sources collected:
#   * HKLM / HKCU  Run, RunOnce, RunServices, RunServicesOnce
#     (including the Wow6432Node 32-bit views)
#   * The All-Users and per-user Startup folders
#   * WMI Win32_StartupCommand (catches entries the above two miss)
#
# Usage:
#   ruby autorun_audit.rb                            # audit this host
#   ruby autorun_audit.rb --format json
#   ruby autorun_audit.rb --write-baseline base.json
#   ruby autorun_audit.rb --baseline base.json       # drift check
#   ruby autorun_audit.rb --self-test                # runs anywhere, no Windows
#
# Exit codes: 0 = nothing notable  1 = high-risk entry or drift  2 = error
#
# Requires: Ruby 3.0+ on Windows (RubyInstaller). No gems -- win32ole and
# win32/registry both ship with Ruby. --self-test runs on any platform.

require 'optparse'
require 'json'
require 'time'
require 'set'

module AutorunAudit
  VERSION = '1.0.0'

  # Registry autorun locations. :view is the registry redirection view so the
  # 32-bit (Wow6432Node) entries are not silently missed on a 64-bit host --
  # a classic blind spot when auditing with a 64-bit tool.
  RUN_KEYS = [
    { hive: :HKLM, path: 'Software\Microsoft\Windows\CurrentVersion\Run',            view: 64 },
    { hive: :HKLM, path: 'Software\Microsoft\Windows\CurrentVersion\RunOnce',        view: 64 },
    { hive: :HKLM, path: 'Software\Microsoft\Windows\CurrentVersion\RunServices',    view: 64 },
    { hive: :HKLM, path: 'Software\Microsoft\Windows\CurrentVersion\RunServicesOnce', view: 64 },
    { hive: :HKLM, path: 'Software\Microsoft\Windows\CurrentVersion\Run',            view: 32 },
    { hive: :HKLM, path: 'Software\Microsoft\Windows\CurrentVersion\RunOnce',        view: 32 },
    { hive: :HKCU, path: 'Software\Microsoft\Windows\CurrentVersion\Run',            view: 64 },
    { hive: :HKCU, path: 'Software\Microsoft\Windows\CurrentVersion\RunOnce',        view: 64 },
    { hive: :HKCU, path: 'Software\Microsoft\Windows\CurrentVersion\Run',            view: 32 }
  ].freeze

  # Directories no legitimate vendor uses as a permanent home for an autorun
  # binary. Matched case-insensitively against the resolved image path.
  SUSPICIOUS_DIRS = [
    [/\\Users\\[^\\]+\\AppData\\Local\\Temp\\/i, 'runs from the user TEMP directory'],
    [/\\Windows\\Temp\\/i,                        'runs from C:\Windows\Temp'],
    [/\\Users\\Public\\/i,                        'runs from C:\Users\Public'],
    [/\\Users\\[^\\]+\\Downloads\\/i,             'runs from a Downloads folder'],
    [/\\\$Recycle\.Bin\\/i,                       'runs from the Recycle Bin'],
    [/\\ProgramData\\[^\\]*\\?$/i,                'runs from the root of ProgramData']
  ].freeze

  # Living-off-the-land binaries. Their mere presence is not proof of anything
  # -- plenty of installers legitimately call rundll32 -- but an autorun entry
  # that launches an interpreter deserves a human look every single time.
  LOLBINS = {
    'powershell.exe' => 'PowerShell interpreter',
    'pwsh.exe'       => 'PowerShell 7 interpreter',
    'cmd.exe'        => 'command interpreter',
    'wscript.exe'    => 'Windows Script Host',
    'cscript.exe'    => 'Windows Script Host',
    'mshta.exe'      => 'HTML application host',
    'rundll32.exe'   => 'DLL entry-point launcher',
    'regsvr32.exe'   => 'COM registration utility',
    'msiexec.exe'    => 'installer engine',
    'certutil.exe'   => 'certificate utility (used for downloads)',
    'bitsadmin.exe'  => 'BITS transfer utility'
  }.freeze

  # Command-line shapes that are strong signals on their own.
  CMD_PATTERNS = [
    [/-enc(?:odedcommand)?\s+[A-Za-z0-9+\/=]{20,}/i, 'high',
     'base64-encoded PowerShell command'],
    [/-(?:w|windowstyle)\s+hidden/i, 'high', 'launches with a hidden window'],
    [/-(?:ep|executionpolicy)\s+bypass/i, 'high', 'bypasses PowerShell execution policy'],
    [/-nop\b|-noprofile\b/i, 'medium', 'skips the PowerShell profile'],
    [/(?:iex|invoke-expression)/i, 'high', 'evaluates a string as code'],
    [/https?:\/\//i, 'high', 'fetches content from a URL at startup'],
    [/\\\\[^\\]+\\[^\\]+/, 'medium', 'runs from a UNC network path'],
    [/frombase64string/i, 'high', 'decodes base64 at runtime'],
    [/\.(?:vbs|js|jse|wsf|hta|ps1|bat|cmd|scr|pif)\b/i, 'medium',
     'autoruns a script rather than a signed executable']
  ].freeze

  SEV = { 'low' => 0, 'medium' => 1, 'high' => 2 }.freeze

  Entry = Struct.new(:source, :location, :name, :command, :image, :user,
                     keyword_init: true)

  Finding = Struct.new(:severity, :reason, keyword_init: true)

  Result = Struct.new(:entry, :findings, :severity, :fingerprint,
                      keyword_init: true) do
    def to_h
      {
        source: entry.source, location: entry.location, name: entry.name,
        command: entry.command, image: entry.image, user: entry.user,
        severity: severity, fingerprint: fingerprint,
        findings: findings.map { |f| { severity: f.severity, reason: f.reason } }
      }
    end
  end

  # ==========================================================================
  # Analyzer -- pure logic. Takes Entry objects from anywhere (live registry,
  # WMI, or a JSON fixture) and scores them. Keeping this free of any Windows
  # API call is what makes the whole tool testable on a Linux CI runner.
  # ==========================================================================
  class Analyzer
    def initialize(file_exists: nil)
      # Injectable so --self-test can answer "does this path exist" from a
      # fixture instead of touching a real filesystem.
      @file_exists = file_exists || ->(p) { !p.nil? && File.exist?(p) }
    end

    def analyze(entries)
      entries.map { |e| score(e) }
    end

    def score(entry)
      findings = []
      cmd   = entry.command.to_s
      image = entry.image || AutorunAudit.extract_image(cmd)

      SUSPICIOUS_DIRS.each do |re, why|
        findings << Finding.new(severity: 'high', reason: why) if image.to_s.match?(re)
      end

      base = image.to_s.split(/[\\\/]/).last.to_s.downcase
      if (desc = LOLBINS[base])
        findings << Finding.new(severity: 'medium',
                                reason: "launches #{base} (#{desc})")
      end

      CMD_PATTERNS.each do |re, sev, why|
        findings << Finding.new(severity: sev, reason: why) if cmd.match?(re)
      end

      # Unquoted path containing a space: CreateProcess tries C:\Program.exe
      # first, so anyone who can write to C:\ gets code execution. Only applies
      # to values Windows parses as a *command line* -- a file sitting in the
      # Startup folder is launched by the shell as a file, so there is no
      # argument boundary to misparse and no finding to raise.
      if entry.source != 'startup-folder' && unquoted_path_with_space?(cmd)
        findings << Finding.new(severity: 'high',
                                reason: 'unquoted image path containing spaces')
      end

      # HKCU entries only need user-level write access -- cheapest persistence
      # there is, and the first place to look after a phishing click.
      if entry.location.to_s.start_with?('HKCU')
        findings << Finding.new(severity: 'low',
                                reason: 'user-writable location (no admin needed)')
      end

      if image && !@file_exists.call(image)
        findings << Finding.new(severity: 'medium',
                                reason: 'target executable does not exist (stale or hidden)')
      end

      Result.new(
        entry: Entry.new(**entry.to_h.merge(image: image)),
        findings: findings,
        severity: highest(findings),
        fingerprint: AutorunAudit.fingerprint(entry)
      )
    end

    private

    def highest(findings)
      return 'none' if findings.empty?

      %w[high medium low].find { |s| findings.any? { |f| f.severity == s } } || 'low'
    end

    # "C:\Program Files\x\y.exe --flag"  -> quoted, fine
    # C:\Program Files\x\y.exe --flag    -> unquoted with a space, dangerous
    def unquoted_path_with_space?(cmd)
      c = cmd.to_s.strip
      return false if c.start_with?('"')
      return false unless c.match?(/\A[A-Za-z]:\\/)

      head = c.split(/\s+(?=[-\/])/).first.to_s
      head.include?(' ')
    end
  end

  def self.extract_image(cmd)
    c = cmd.to_s.strip
    return nil if c.empty?

    # Quoted image path is unambiguous -- take it verbatim.
    return Regexp.last_match(1) if c =~ /\A"([^"]+)"/

    # Unquoted: take the shortest prefix that ends in an executable extension
    # at a token boundary. Handles "C:\Program Files\App\app.exe -bg".
    if c =~ /\A([A-Za-z]:\\.*?\.(?:exe|com|bat|cmd|scr|pif))(?=\s|\z)/i
      return Regexp.last_match(1)
    end

    # An absolute path with no argument-looking token: the whole value *is*
    # the path. Startup-folder entries (".../My Shortcut.lnk") land here, and
    # splitting them on whitespace would silently truncate the path. The
    # absolute-path guard keeps "rundll32.exe shell32.dll,Foo" out of here.
    return c if c.match?(/\A(?:[A-Za-z]:\\|\\\\)/) && !c.match?(/\s[-\/]\S/)

    c.split(/\s/).first
  end

  def self.fingerprint(entry)
    require 'digest'
    Digest::SHA256.hexdigest(
      "#{entry.location}|#{entry.name}|#{entry.command}"
    )[0, 12]
  end

  # ==========================================================================
  # Collector -- the only Windows-specific code in the file.
  # ==========================================================================
  class WindowsCollector
    def self.available?
      RUBY_PLATFORM.match?(/mswin|mingw|cygwin/)
    end

    def collect
      entries = []
      entries.concat(registry_entries)
      entries.concat(startup_folder_entries)
      entries.concat(wmi_entries)
      dedupe(entries)
    end

    private

    def registry_entries
      require 'win32/registry'
      out = []

      RUN_KEYS.each do |spec|
        root = spec[:hive] == :HKLM ? Win32::Registry::HKEY_LOCAL_MACHINE
                                    : Win32::Registry::HKEY_CURRENT_USER
        # KEY_WOW64_32KEY / _64KEY select which registry view we read. Without
        # this a 64-bit Ruby never sees the 32-bit Run key at all.
        access = Win32::Registry::KEY_READ |
                 (spec[:view] == 32 ? 0x0200 : 0x0100)

        begin
          root.open(spec[:path], access) do |key|
            key.each_value do |name, _type, value|
              out << Entry.new(
                source: 'registry',
                location: "#{spec[:hive]}\\#{spec[:path]} (#{spec[:view]}-bit)",
                name: name, command: value.to_s, image: nil,
                user: spec[:hive] == :HKCU ? ENV['USERNAME'] : 'ALL'
              )
            end
          end
        rescue Win32::Registry::Error
          # Key genuinely absent on this build of Windows -- not an error.
          next
        end
      end
      out
    end

    def startup_folder_entries
      dirs = [
        [ENV['ProgramData'].to_s + '\Microsoft\Windows\Start Menu\Programs\Startup', 'ALL'],
        [ENV['APPDATA'].to_s + '\Microsoft\Windows\Start Menu\Programs\Startup',
         ENV['USERNAME'].to_s]
      ]

      dirs.flat_map do |dir, user|
        next [] unless File.directory?(dir)

        Dir.children(dir).reject { |f| f.casecmp('desktop.ini').zero? }.map do |f|
          full = File.join(dir, f)
          Entry.new(source: 'startup-folder', location: dir, name: f,
                    command: full, image: full, user: user)
        end
      rescue SystemCallError
        []
      end
    end

    # WMI catches a few providers the registry walk does not (and gives us the
    # owning user for entries under other profiles).
    def wmi_entries
      require 'win32ole'
      wmi = WIN32OLE.connect('winmgmts://./root/cimv2')
      wmi.ExecQuery('SELECT Caption,Command,Location,User FROM Win32_StartupCommand')
         .to_enum.map do |s|
        Entry.new(source: 'wmi', location: s.Location.to_s, name: s.Caption.to_s,
                  command: s.Command.to_s, image: nil, user: s.User.to_s)
      end
    rescue LoadError, WIN32OLERuntimeError => e
      warn "autorun_audit: WMI query failed (#{e.class}); continuing without it"
      []
    end

    # The same entry legitimately shows up in both the registry walk and WMI.
    # Collapse on command+name, preferring the richer registry record.
    def dedupe(entries)
      seen = {}
      entries.each do |e|
        key = [e.name.to_s.downcase, e.command.to_s.downcase]
        seen[key] = e if !seen.key?(key) || e.source == 'registry'
      end
      seen.values
    end
  end

  # ==========================================================================
  # Baseline
  # ==========================================================================
  module Baseline
    def self.write(file, results)
      File.write(file, JSON.pretty_generate(
        generated: Time.now.utc.iso8601,
        host: ENV['COMPUTERNAME'] || 'unknown',
        entries: results.map { |r| { fingerprint: r.fingerprint,
                                     name: r.entry.name,
                                     location: r.entry.location } }
      ))
    end

    def self.load(file)
      data = JSON.parse(File.read(file))
      Set.new(data.fetch('entries', []).map { |e| e['fingerprint'] })
    end
  end

  # ==========================================================================
  # Reporting
  # ==========================================================================
  module Report
    MARK = { 'high' => '!!', 'medium' => ' !', 'low' => '  ', 'none' => '  ' }.freeze

    def self.text(results, added, removed, host)
      o = []
      o << '=' * 78
      o << "  WINDOWS AUTORUN AUDIT   #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}"
      o << "  host: #{host}"
      o << '=' * 78

      counts = Hash.new(0)
      results.each { |r| counts[r.severity] += 1 }
      o << format('  entries: %-4d   high: %-3d  medium: %-3d  low: %-3d  clean: %d',
                  results.size, counts['high'], counts['medium'],
                  counts['low'], counts['none'])
      o << '-' * 78

      %w[high medium low none].each do |sev|
        group = results.select { |r| r.severity == sev }
        next if group.empty?

        o << ''
        o << "  #{sev.upcase} (#{group.size})"
        group.sort_by { |r| r.entry.name.to_s.downcase }.each do |r|
          o << format('  %s %s', MARK[sev], r.entry.name)
          o << "       location : #{r.entry.location}"
          o << "       command  : #{truncate(r.entry.command, 88)}"
          o << "       image    : #{r.entry.image}"
          o << "       user     : #{r.entry.user}"
          o << "       id       : #{r.fingerprint}"
          r.findings.each { |f| o << "       [#{f.severity}] #{f.reason}" }
        end
      end

      unless added.empty?
        o << ''
        o << "  NEW SINCE BASELINE (#{added.size})"
        o << '  ' + '-' * 74
        added.each { |r| o << "    + #{r.entry.name}  [#{r.severity}]  #{r.fingerprint}" }
      end

      unless removed.empty?
        o << ''
        o << "  GONE SINCE BASELINE (#{removed.size})"
        o << '  ' + '-' * 74
        removed.each { |fp| o << "    - #{fp}" }
      end

      o << ''
      o << '=' * 78
      o.join("\n")
    end

    def self.truncate(s, n)
      s = s.to_s
      s.length > n ? "#{s[0, n - 3]}..." : s
    end
  end

  # ==========================================================================
  # Self-test -- runs on Linux, macOS or Windows. Feeds known-bad and
  # known-good entries through the Analyzer and asserts the scoring. This is
  # how the Windows-only code path gets meaningful coverage on a CI runner
  # that has never seen a registry hive.
  # ==========================================================================
  module SelfTest
    FIXTURES = [
      { name: 'SecurityHealth',
        location: 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run (64-bit)',
        command: '"C:\\Windows\\system32\\SecurityHealthSystray.exe"',
        exists: true, expect: 'none' },
      { name: 'OneDrive',
        location: 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run (64-bit)',
        command: '"C:\\Users\\jam\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background',
        exists: true, expect: 'low' },
      { name: 'UpdateChecker',
        location: 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run (64-bit)',
        command: 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA',
        exists: true, expect: 'high' },
      { name: 'BackupSvc',
        location: 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run (64-bit)',
        command: 'C:\\Program Files\\Acme Backup\\backup.exe --daemon',
        exists: true, expect: 'high' },   # unquoted path with spaces
      { name: 'tmp_helper',
        location: 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run (64-bit)',
        command: '"C:\\Users\\jam\\AppData\\Local\\Temp\\svchost.exe"',
        exists: false, expect: 'high' },
      { name: 'LegacyTool',
        location: 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run (32-bit)',
        command: '"C:\\Program Files (x86)\\Legacy\\tool.exe" -quiet',
        exists: false, expect: 'medium' },
      { name: 'Acme Sync.lnk', source: 'startup-folder',
        location: 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup',
        command: 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Acme Sync.lnk',
        exists: true, expect: 'none' }
    ].freeze

    def self.run
      exists = FIXTURES.each_with_object({}) do |f, h|
        h[AutorunAudit.extract_image(f[:command])] = f[:exists]
      end
      analyzer = Analyzer.new(file_exists: ->(p) { exists.fetch(p, false) })

      passed = 0
      failed = 0
      puts '--- autorun_audit self-test (fixture-driven, no Windows APIs) ---'

      FIXTURES.each do |f|
        entry = Entry.new(source: f.fetch(:source, 'registry'), location: f[:location],
                          name: f[:name], command: f[:command],
                          image: nil, user: 'test')
        r = analyzer.score(entry)
        ok = r.severity == f[:expect]
        ok ? passed += 1 : failed += 1
        puts format('  %-4s %-16s expected=%-6s got=%-6s  %s',
                    ok ? 'PASS' : 'FAIL', f[:name], f[:expect], r.severity,
                    r.findings.map(&:reason).first || '(no findings)')
      end

      # extract_image is the piece most likely to break on odd command lines.
      cases = {
        '"C:\\Program Files\\A B\\x.exe" -q'      => 'C:\\Program Files\\A B\\x.exe',
        'C:\\Program Files\\A B\\x.exe -q'        => 'C:\\Program Files\\A B\\x.exe',
        'rundll32.exe shell32.dll,Control_RunDLL' => 'rundll32.exe',
        'C:\\tools\\run.bat'                      => 'C:\\tools\\run.bat'
      }
      puts '--- extract_image ---'
      cases.each do |input, want|
        got = AutorunAudit.extract_image(input)
        ok = got == want
        ok ? passed += 1 : failed += 1
        puts format('  %-4s %-42s -> %s', ok ? 'PASS' : 'FAIL',
                    AutorunAudit::Report.truncate(input, 42), got)
      end

      puts format('--- %d passed, %d failed ---', passed, failed)
      failed.zero? ? 0 : 1
    end

    # Render the real report from fixture data. Same Analyzer, same Report --
    # only the collector is swapped out. Useful for seeing the output format
    # without a Windows box, and for eyeballing report changes in review.
    def self.demo
      exists = FIXTURES.each_with_object({}) do |f, h|
        h[AutorunAudit.extract_image(f[:command])] = f[:exists]
      end
      analyzer = Analyzer.new(file_exists: ->(p) { exists.fetch(p, false) })
      entries = FIXTURES.map do |f|
        Entry.new(source: f.fetch(:source, 'registry'), location: f[:location],
                  name: f[:name], command: f[:command], image: nil,
                  user: f[:location].to_s.start_with?('HKCU') ? 'CORP\\jam' : 'ALL')
      end
      results = analyzer.analyze(entries)
      puts AutorunAudit::Report.text(results, results.last(1), [], 'WIN-FIXTURE (demo data)')
      0
    end
  end
end

# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  opts = { format: 'text', baseline: nil, write_baseline: nil, self_test: false, demo: false }

  parser = OptionParser.new do |o|
    o.banner = 'Usage: ruby autorun_audit.rb [options]'
    o.on('-f', '--format F', %w[text json], 'text (default) or json') { |v| opts[:format] = v }
    o.on('-b', '--baseline FILE', 'compare against baseline JSON') { |v| opts[:baseline] = v }
    o.on('-w', '--write-baseline FILE', 'write current state as baseline') do |v|
      opts[:write_baseline] = v
    end
    o.on('--self-test', 'run the fixture test suite (any OS)') { opts[:self_test] = true }
    o.on('--demo', 'render the report from fixture data (any OS)') { opts[:demo] = true }
    o.on('--version', 'print version') { puts AutorunAudit::VERSION; exit 0 }
    o.on('-h', '--help', 'show this help') { puts o; exit 0 }
  end

  begin
    parser.parse!
  rescue OptionParser::ParseError => e
    warn "autorun_audit: #{e.message}"
    exit 2
  end

  exit AutorunAudit::SelfTest.run  if opts[:self_test]
  exit AutorunAudit::SelfTest.demo if opts[:demo]

  unless AutorunAudit::WindowsCollector.available?
    warn 'autorun_audit: this audit needs Windows (registry + WMI).'
    warn 'autorun_audit: run with --self-test to exercise the scoring engine here.'
    exit 2
  end

  begin
    entries = AutorunAudit::WindowsCollector.new.collect
  rescue StandardError => e
    warn "autorun_audit: collection failed: #{e.class}: #{e.message}"
    exit 2
  end

  results = AutorunAudit::Analyzer.new.analyze(entries)

  if opts[:write_baseline]
    AutorunAudit::Baseline.write(opts[:write_baseline], results)
    warn "autorun_audit: wrote #{results.size} entries to #{opts[:write_baseline]}"
    exit 0
  end

  added = []
  removed = []
  if opts[:baseline]
    known = AutorunAudit::Baseline.load(opts[:baseline])
    current = Set.new(results.map(&:fingerprint))
    added   = results.reject { |r| known.include?(r.fingerprint) }
    removed = (known - current).to_a.sort
  end

  host = ENV['COMPUTERNAME'] || 'unknown'

  if opts[:format] == 'json'
    puts JSON.pretty_generate(
      audited_at: Time.now.utc.iso8601, host: host,
      added: added.map(&:fingerprint), removed: removed,
      entries: results.map(&:to_h)
    )
  else
    puts AutorunAudit::Report.text(results, added, removed, host)
  end

  bad = results.any? { |r| r.severity == 'high' } || !added.empty?
  exit(bad ? 1 : 0)
end
