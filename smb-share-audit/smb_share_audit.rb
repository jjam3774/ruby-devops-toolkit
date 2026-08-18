#!/usr/bin/env ruby
# frozen_string_literal: true
#
# smb_share_audit.rb -- SMB share and share-permission auditor for Windows
#
# File shares are where "temporary" access grants go to die. Someone creates
# \\FS01\ProjectX for a two-week migration, ticks Everyone / Full Control
# because the deadline is tomorrow, and five years later it is still there with
# 400 GB of finance data behind it. Nothing in Windows reminds you.
#
# This script walks every non-hidden share on a host via WMI, pulls the share
# level DACL (which is a separate, and usually far looser, ACL from the NTFS
# permissions on the folder underneath), decodes the access mask, and flags the
# dangerous combinations: broad trustees with write or full control, shares
# pointing at the root of a drive, shares whose backing path no longer exists.
#
# WMI classes used:
#   Win32_Share                        -- the share list
#   Win32_LogicalShareSecuritySetting  -- GetSecurityDescriptor() -> Win32_SecurityDescriptor
#
# TESTING NOTE: win32ole only exists on Windows, so the WMI access is isolated
# behind a source object. `--self-test` swaps in a fixture source and runs the
# whole classification pipeline with no WMI at all, which means the risk logic
# is verifiable on any platform (including CI on Linux). See the README.
#
# Exit codes:
#   0  no findings at or above the fail threshold
#   1  findings present
#   2  the audit could not run
#
# Usage (on Windows):
#   ruby smb_share_audit.rb
#   ruby smb_share_audit.rb --host FS01 --json
#   ruby smb_share_audit.rb --include-hidden --fail-on medium
#
# Usage (anywhere):
#   ruby smb_share_audit.rb --self-test
#
# Ruby >= 2.7 (Windows build with win32ole for live mode), stdlib only.

require 'json'
require 'optparse'

module SmbShareAudit
  VERSION = '1.0.0'

  # ---------------------------------------------------------------------------
  # Windows constants. These are the values WMI actually hands back, so they
  # are declared once here rather than as magic numbers in the logic.
  # ---------------------------------------------------------------------------
  module Win
    # Win32_Share.Type
    SHARE_TYPES = {
      0 => 'Disk Drive', 1 => 'Print Queue', 2 => 'Device', 3 => 'IPC',
      2_147_483_648 => 'Disk Drive Admin', 2_147_483_649 => 'Print Queue Admin',
      2_147_483_650 => 'Device Admin', 2_147_483_651 => 'IPC Admin'
    }.freeze

    # ACE types
    ACCESS_ALLOWED = 0
    ACCESS_DENIED  = 1

    # Share-level access mask bits that matter for this audit.
    FILE_READ_DATA    = 0x00000001
    FILE_WRITE_DATA   = 0x00000002
    FILE_APPEND_DATA  = 0x00000004
    FILE_EXECUTE      = 0x00000020
    DELETE            = 0x00010000
    WRITE_DAC         = 0x00040000  # can rewrite the ACL itself
    WRITE_OWNER       = 0x00080000  # can take ownership
    GENERIC_ALL       = 0x10000000
    FULL_CONTROL      = 0x001F01FF

    WRITE_BITS = FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE
    OWN_BITS   = WRITE_DAC | WRITE_OWNER | GENERIC_ALL

    # Trustees that effectively mean "anyone who can reach the share".
    BROAD_TRUSTEES = [
      'Everyone', 'ANONYMOUS LOGON', 'Authenticated Users', 'Users',
      'Domain Users', 'INTERACTIVE', 'NETWORK', 'Guests', 'Guest'
    ].freeze

    # Well-known SIDs, for hosts where WMI returns a SID with no resolvable name
    # (deleted accounts, broken trusts, offline DCs).
    WELL_KNOWN_SIDS = {
      'S-1-1-0' => 'Everyone', 'S-1-5-7' => 'ANONYMOUS LOGON',
      'S-1-5-11' => 'Authenticated Users', 'S-1-5-32-545' => 'Users',
      'S-1-5-32-546' => 'Guests', 'S-1-5-32-544' => 'Administrators',
      'S-1-5-4' => 'INTERACTIVE', 'S-1-5-2' => 'NETWORK'
    }.freeze

    def self.decode_mask(mask)
      return ['FullControl'] if (mask & FULL_CONTROL) == FULL_CONTROL || (mask & GENERIC_ALL) != 0

      rights = []
      rights << 'Read'         if (mask & FILE_READ_DATA)  != 0
      rights << 'Write'        if (mask & FILE_WRITE_DATA) != 0
      rights << 'Append'       if (mask & FILE_APPEND_DATA) != 0
      rights << 'Execute'      if (mask & FILE_EXECUTE)    != 0
      rights << 'Delete'       if (mask & DELETE)          != 0
      rights << 'ChangePerms'  if (mask & WRITE_DAC)       != 0
      rights << 'TakeOwnership' if (mask & WRITE_OWNER)    != 0
      rights.empty? ? [format('0x%08X', mask)] : rights
    end
  end

  # ---------------------------------------------------------------------------
  # Normalised data model -- identical shape whether it came from WMI or a fixture.
  # ---------------------------------------------------------------------------
  Ace = Struct.new(:trustee, :domain, :sid, :mask, :ace_type, keyword_init: true) do
    def allow?  = ace_type == Win::ACCESS_ALLOWED
    def rights  = Win.decode_mask(mask.to_i)

    # Resolve a bare SID to its well-known name so "S-1-1-0" does not silently
    # slip past the broad-trustee check.
    def effective_name
      return trustee unless trustee.nil? || trustee.empty?

      Win::WELL_KNOWN_SIDS.fetch(sid.to_s, sid.to_s)
    end

    def broad?        = Win::BROAD_TRUSTEES.include?(effective_name)
    def full_control? = rights.include?('FullControl')
    def writable?     = full_control? || (mask.to_i & Win::WRITE_BITS) != 0
    def ownership?    = (mask.to_i & Win::OWN_BITS) != 0

    def display
      who = domain.to_s.empty? ? effective_name : "#{domain}\\#{effective_name}"
      "#{allow? ? 'Allow' : 'Deny '} #{who} : #{rights.join(',')}"
    end
  end

  Share = Struct.new(:name, :path, :type, :description, :hidden, :aces,
                     :path_exists, :error, keyword_init: true) do
    def type_name = Win::SHARE_TYPES.fetch(type.to_i, "Unknown(#{type})")

    # C:\ or D:\ -- sharing a whole volume is almost never intentional.
    def drive_root? = !path.nil? && path.match?(/\A[A-Za-z]:\\?\z/)
  end

  # ---------------------------------------------------------------------------
  # Source 1: live WMI. Only this class touches win32ole.
  # ---------------------------------------------------------------------------
  class WmiSource
    def initialize(host: '.')
      require 'win32ole'
      @host = host
      @wmi = WIN32OLE.connect("winmgmts://#{host}/root/cimv2")
    rescue LoadError
      raise "win32ole is unavailable -- this mode only runs on Windows. Try --self-test."
    rescue WIN32OLERuntimeError => e
      raise "cannot reach WMI on #{host}: #{e.message}"
    end

    def name = "WMI://#{@host}"

    def shares
      @wmi.ExecQuery('SELECT * FROM Win32_Share').map do |s|
        name = s.Name.to_s
        Share.new(
          name: name,
          path: s.Path.to_s,
          type: s.Type.to_i,
          description: s.Description.to_s,
          hidden: name.end_with?('$'),
          path_exists: s.Path.to_s.empty? ? true : Dir.exist?(s.Path.to_s),
          aces: security_for(name),
          error: nil
        )
      end
    rescue WIN32OLERuntimeError => e
      raise "share enumeration failed: #{e.message}"
    end

    private

    # The share DACL lives on a different class from the share itself. If the
    # share has no explicit descriptor WMI returns a non-zero status, which we
    # surface rather than silently reporting "no permissions".
    def security_for(share_name)
      setting = @wmi.ExecQuery(
        "SELECT * FROM Win32_LogicalShareSecuritySetting WHERE Name='#{share_name.gsub("'", "''")}'"
      ).each.first
      return [] if setting.nil?

      sd = nil
      status = setting.GetSecurityDescriptor(sd)
      return [] unless status.to_i.zero?

      descriptor = setting.GetSecurityDescriptor_(nil) rescue nil
      dacl = extract_dacl(descriptor, setting)
      return [] if dacl.nil?

      dacl.map do |ace|
        trustee = ace.Trustee
        Ace.new(trustee: trustee.Name.to_s, domain: trustee.Domain.to_s,
                sid: trustee.SIDString.to_s, mask: ace.AccessMask.to_i,
                ace_type: ace.AceType.to_i)
      end
    rescue WIN32OLERuntimeError, NoMethodError
      []
    end

    # WMI out-parameters are awkward from Ruby: depending on the ruby/win32ole
    # build the descriptor arrives as a return value or via the ExecMethod_
    # path. Try both rather than assuming.
    def extract_dacl(descriptor, setting)
      return descriptor.DACL if descriptor.respond_to?(:DACL)

      out = setting.ExecMethod_('GetSecurityDescriptor')
      out.Descriptor.DACL
    rescue StandardError
      nil
    end
  end

  # ---------------------------------------------------------------------------
  # Source 2: fixtures. Lets the whole risk pipeline be exercised off-Windows.
  # ---------------------------------------------------------------------------
  class FixtureSource
    def initialize(data) = @data = data
    def name = 'fixture'

    def shares
      @data.map do |s|
        Share.new(
          name: s[:name], path: s[:path], type: s[:type] || 0,
          description: s[:description].to_s,
          hidden: s[:name].to_s.end_with?('$'),
          path_exists: s.fetch(:path_exists, true),
          error: nil,
          aces: Array(s[:aces]).map do |a|
            Ace.new(trustee: a[:trustee], domain: a[:domain].to_s, sid: a[:sid].to_s,
                    mask: a[:mask], ace_type: a[:ace_type] || Win::ACCESS_ALLOWED)
          end
        )
      end
    end

    # A deliberately nasty but entirely realistic file server.
    def self.sample
      new([
        { name: 'Finance', path: 'D:\\Finance', description: 'Finance department',
          aces: [
            { trustee: 'Everyone', sid: 'S-1-1-0', mask: Win::FULL_CONTROL },
            { trustee: 'Domain Admins', domain: 'CORP', sid: 'S-1-5-21-1-512',
              mask: Win::FULL_CONTROL }
          ] },
        { name: 'Public', path: 'D:\\Public', description: 'Scratch space',
          aces: [
            { trustee: 'Authenticated Users', sid: 'S-1-5-11',
              mask: Win::FILE_READ_DATA | Win::FILE_WRITE_DATA | Win::FILE_EXECUTE }
          ] },
        { name: 'Reports', path: 'D:\\Reports', description: 'Read-only reporting drop',
          aces: [
            { trustee: 'Domain Users', domain: 'CORP', sid: 'S-1-5-21-1-513',
              mask: Win::FILE_READ_DATA | Win::FILE_EXECUTE },
            { trustee: 'Backup Operators', domain: 'BUILTIN', sid: 'S-1-5-32-551',
              mask: Win::FILE_READ_DATA }
          ] },
        { name: 'Wholedisk', path: 'E:\\', description: 'shared for the 2019 migration',
          aces: [
            { trustee: 'svc_migrate', domain: 'CORP', sid: 'S-1-5-21-1-1104',
              mask: Win::FULL_CONTROL }
          ] },
        { name: 'OldProject', path: 'D:\\Projects\\Gone', description: 'decommissioned',
          path_exists: false,
          aces: [
            { trustee: '', sid: 'S-1-1-0', mask: Win::FILE_READ_DATA }
          ] },
        { name: 'ADMIN$', path: 'C:\\Windows', description: 'Remote Admin',
          type: 2_147_483_648, aces: [] }
      ])
    end
  end

  # ---------------------------------------------------------------------------
  # Risk rules. Each returns a Finding or nil; adding a rule is a one-method change.
  # ---------------------------------------------------------------------------
  Finding = Struct.new(:severity, :share, :path, :rule, :detail, keyword_init: true)

  class RiskEngine
    SEVERITIES = %w[low medium high critical].freeze

    def evaluate(share)
      findings = []
      findings.concat(broad_trustee_findings(share))
      findings << drive_root_finding(share)
      findings << missing_path_finding(share)
      findings << no_dacl_finding(share)
      findings.compact
    end

    private

    # The headline rule: a broad trustee with anything beyond read.
    def broad_trustee_findings(share)
      share.aces.select { |a| a.allow? && a.broad? }.filter_map do |ace|
        who = ace.effective_name

        if ace.full_control?
          finding('critical', share, 'broad_full_control',
                  "#{who} has FullControl on the share DACL")
        elsif ace.ownership?
          finding('critical', share, 'broad_can_reperm',
                  "#{who} can change permissions or take ownership (#{ace.rights.join(',')})")
        elsif ace.writable?
          finding('high', share, 'broad_write',
                  "#{who} has write access (#{ace.rights.join(',')})")
        elsif who == 'ANONYMOUS LOGON'
          finding('high', share, 'anonymous_read',
                  'ANONYMOUS LOGON can read this share')
        else
          finding('low', share, 'broad_read',
                  "#{who} has read access -- confirm this is intended")
        end
      end
    end

    def drive_root_finding(share)
      return nil unless share.drive_root?
      return nil if share.hidden # C$/D$ are the built-in admin shares

      finding('high', share, 'drive_root_share',
              "share exposes the root of #{share.path}, not a subfolder")
    end

    def missing_path_finding(share)
      return nil if share.path_exists
      return nil if share.path.to_s.empty?

      finding('medium', share, 'dangling_path',
              "backing path #{share.path} does not exist -- stale share definition")
    end

    # An empty DACL on a disk share is not "locked down", it usually means the
    # descriptor could not be read, which is itself worth knowing about.
    def no_dacl_finding(share)
      return nil unless share.type.to_i.zero?
      return nil unless share.aces.empty?

      finding('medium', share, 'no_share_dacl',
              'no share-level DACL was returned; permissions may be inherited or unreadable')
    end

    def finding(sev, share, rule, detail)
      Finding.new(severity: sev, share: share.name, path: share.path,
                  rule: rule, detail: detail)
    end
  end

  # ---------------------------------------------------------------------------
  # Output
  # ---------------------------------------------------------------------------
  class Report
    RANK = { 'critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3 }.freeze
    MARK = { 'critical' => '[CRIT]', 'high' => '[HIGH]', 'medium' => '[MED ]',
             'low' => '[LOW ]' }.freeze

    def initialize(shares, findings, source)
      @shares = shares
      @findings = findings
      @source = source
    end

    def at_or_above(threshold)
      floor = RANK.fetch(threshold, 3)
      @findings.select { |f| RANK.fetch(f.severity, 9) <= floor }
    end

    def text
      w = 76
      out = []
      out << '=' * w
      out << "  SMB SHARE AUDIT   source=#{@source}   #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}"
      out << '=' * w
      out << "  #{@shares.size} share(s) enumerated, #{@findings.size} finding(s)"
      out << ''

      @shares.each do |s|
        flag = s.hidden ? ' (hidden)' : ''
        out << "  #{s.name}#{flag}  ->  #{s.path.to_s.empty? ? '-' : s.path}   [#{s.type_name}]"
        if s.aces.empty?
          out << '      (no share-level ACEs returned)'
        else
          s.aces.each { |a| out << "      #{a.display}" }
        end
        mine = @findings.select { |f| f.share == s.name }
        mine.sort_by { |f| RANK.fetch(f.severity, 9) }.each do |f|
          out << "      #{MARK[f.severity]} #{f.rule}: #{f.detail}"
        end
        out << ''
      end

      out << '-' * w
      out << "  #{summary}"
      out << '=' * w
      out.join("\n")
    end

    def json
      JSON.pretty_generate(
        source: @source,
        generated_at: Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ'),
        summary: counts,
        shares: @shares.map do |s|
          { name: s.name, path: s.path, type: s.type_name, hidden: s.hidden,
            aces: s.aces.map { |a| { trustee: a.effective_name, domain: a.domain,
                                     sid: a.sid, rights: a.rights, allow: a.allow? } } }
        end,
        findings: @findings.map(&:to_h)
      )
    end

    def counts = @findings.group_by(&:severity).transform_values(&:size)

    private

    def summary
      c = counts
      "#{@shares.size} shares | " + RANK.keys.map { |s| "#{s}=#{c.fetch(s, 0)}" }.join(' ')
    end
  end

  # ---------------------------------------------------------------------------
  # Self-test: proves the risk pipeline without WMI.
  # ---------------------------------------------------------------------------
  def self.self_test
    shares = FixtureSource.sample.shares
    findings = shares.flat_map { |s| RiskEngine.new.evaluate(s) }
    report = Report.new(shares, findings, 'fixture (self-test)')
    puts report.text

    expectations = [
      ['Finance flagged critical for Everyone/FullControl',
       findings.any? { |f| f.share == 'Finance' && f.rule == 'broad_full_control' }],
      ['Public flagged high for Authenticated Users write',
       findings.any? { |f| f.share == 'Public' && f.rule == 'broad_write' }],
      ['Reports NOT flagged above low (read-only by design)',
       findings.select { |f| f.share == 'Reports' }.all? { |f| f.severity == 'low' }],
      ['Wholedisk flagged for sharing a drive root',
       findings.any? { |f| f.share == 'Wholedisk' && f.rule == 'drive_root_share' }],
      ['OldProject flagged for a dangling backing path',
       findings.any? { |f| f.share == 'OldProject' && f.rule == 'dangling_path' }],
      ['Bare SID S-1-1-0 resolved to Everyone',
       shares.find { |s| s.name == 'OldProject' }.aces.first.effective_name == 'Everyone'],
      ['ADMIN$ (hidden admin share) not flagged as a drive-root share',
       findings.none? { |f| f.share == 'ADMIN$' && f.rule == 'drive_root_share' }],
      ['FULL_CONTROL mask decodes to FullControl',
       Win.decode_mask(Win::FULL_CONTROL) == ['FullControl']],
      ['Read+Execute mask decodes without write rights',
       Win.decode_mask(Win::FILE_READ_DATA | Win::FILE_EXECUTE) == %w[Read Execute]]
    ]

    puts "\nSELF-TEST"
    puts '-' * 60
    passed = 0
    expectations.each do |label, ok|
      puts "  #{ok ? 'ok  ' : 'FAIL'}  #{label}"
      passed += 1 if ok
    end
    puts '-' * 60
    puts "  #{passed}/#{expectations.size} assertions passed"
    passed == expectations.size
  end
end

# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  opts = { host: '.', format: :text, fail_on: 'high', include_hidden: false }

  OptionParser.new do |o|
    o.banner = 'Usage: smb_share_audit.rb [options]'
    o.on('-H', '--host NAME', 'audit a remote host via WMI') { |v| opts[:host] = v }
    o.on('-j', '--json', 'emit JSON')                        { opts[:format] = :json }
    o.on('--include-hidden', 'include $-suffixed admin shares') { opts[:include_hidden] = true }
    o.on('--fail-on SEV', %w[low medium high critical],
         'exit 1 at or above this severity (default high)') { |v| opts[:fail_on] = v }
    o.on('--self-test', 'run the risk engine against fixtures (no WMI)') { opts[:self_test] = true }
    o.on('-v', '--version') { puts "smb_share_audit #{SmbShareAudit::VERSION}"; exit 0 }
    o.on('-h', '--help')    { puts o; exit 0 }
  end.parse!

  begin
    if opts[:self_test]
      exit(SmbShareAudit.self_test ? 0 : 1)
    end

    source = SmbShareAudit::WmiSource.new(host: opts[:host])
    shares = source.shares
    shares = shares.reject(&:hidden) unless opts[:include_hidden]

    engine = SmbShareAudit::RiskEngine.new
    findings = shares.flat_map { |s| engine.evaluate(s) }
    report = SmbShareAudit::Report.new(shares, findings, source.name)

    puts opts[:format] == :json ? report.json : report.text
    exit(report.at_or_above(opts[:fail_on]).empty? ? 0 : 1)
  rescue StandardError => e
    warn "smb_share_audit: #{e.message}"
    exit 2
  end
end
