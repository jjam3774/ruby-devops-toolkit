#!/usr/bin/env ruby
# frozen_string_literal: true
#
# win_profile_cleanup.rb - Find (and optionally remove) stale Windows user
# profiles via WMI's Win32_UserProfile class.
#
# Every user who has ever logged on to a shared workstation, RDS host or
# jump box leaves a C:\Users\<name> folder behind. On a busy box that is
# tens of gigabytes of stale roaming data, and the built-in GPO
# ("Delete user profiles older than N days") is blunt and frequently
# broken by apps that touch NTUSER.DAT. This script gives you the report
# first and the delete second, with safeguards.
#
# Usage (Windows, run as Administrator for delete):
#   ruby win_profile_cleanup.rb                       # report profiles unused > 90 days
#   ruby win_profile_cleanup.rb --days 30 --min-size-mb 500
#   ruby win_profile_cleanup.rb --days 90 --delete --dry-run
#   ruby win_profile_cleanup.rb --days 90 --delete --yes   # actually delete
#   ruby win_profile_cleanup.rb --json > profiles.json
#
# Testing off-Windows: WIN_PROFILE_MOCK=1 ruby win_profile_cleanup.rb
#   (uses an in-memory fake WMI provider - no win32ole required)
#
# Exit codes: 0 = no stale profiles, 1 = stale profiles found, 2 = runtime error.
# Tested with Ruby 3.x. Uses only stdlib (win32ole ships with Ruby on Windows).

require 'optparse'
require 'json'
require 'time'

opts = { days: 90, min_size_mb: 0, delete: false, dry_run: false, yes: false,
         json: false, size: true, exclude: [] }

OptionParser.new do |o|
  o.banner = 'Usage: win_profile_cleanup.rb [options]'
  o.on('--days N', Integer, 'Profiles not used for N days are stale (default 90)') { |v| opts[:days] = v }
  o.on('--min-size-mb N', Integer, 'Only report profiles at least N MB (default 0)') { |v| opts[:min_size_mb] = v }
  o.on('--exclude LIST', Array, 'Comma-separated account names to never touch') { |v| opts[:exclude] = v.map(&:downcase) }
  o.on('--no-size', 'Skip the (slow) folder size walk') { opts[:size] = false }
  o.on('--delete', 'Delete stale profiles (needs --yes, or --dry-run)') { opts[:delete] = true }
  o.on('--dry-run', 'Show what --delete would do without doing it') { opts[:dry_run] = true }
  o.on('--yes', 'Confirm deletion non-interactively') { opts[:yes] = true }
  o.on('--json', 'Emit JSON') { opts[:json] = true }
  o.on('-h', '--help') { puts o; exit 0 }
end.parse!

# ---------------------------------------------------------------------------
# WMI access, isolated behind one tiny interface so it can be mocked.
# ---------------------------------------------------------------------------
# Win32_UserProfile fields we use:
#   SID, LocalPath, LastUseTime (CIM_DATETIME string), Loaded, Special,
#   RoamingConfigured, Status (bitmask: 1=Temporary 2=Roaming 4=Mandatory 8=Corrupted)
class WmiProfiles
  def initialize
    require 'win32ole'
    @wmi = WIN32OLE.connect('winmgmts://./root/cimv2')
  rescue LoadError
    raise 'win32ole is only available on Windows. Set WIN_PROFILE_MOCK=1 to test elsewhere.'
  end

  def each_profile
    @wmi.ExecQuery('SELECT * FROM Win32_UserProfile').each do |p|
      yield({
        sid: p.SID, path: p.LocalPath, last_use: p.LastUseTime,
        loaded: p.Loaded, special: p.Special, roaming: p.RoamingConfigured,
        status: p.Status.to_i, _obj: p
      })
    end
  end

  # Win32_UserProfile.Delete() removes the folder AND the registry ProfileList
  # entry - the same thing "System Properties > User Profiles > Delete" does.
  def delete(profile)
    profile[:_obj].Delete_
  end

  def account_name(sid)
    acct = @wmi.Get("Win32_SID.SID='#{sid}'")
    domain = acct.ReferencedDomainName.to_s
    name = acct.AccountName.to_s
    name.empty? ? sid : (domain.empty? ? name : "#{domain}\\#{name}")
  rescue WIN32OLERuntimeError
    sid # orphaned SID (user deleted from AD/local SAM) - very common for stale profiles
  end
end

# In-memory stand-in with the same three methods, so the whole decision
# path can be exercised on Linux/macOS CI.
class MockProfiles
  def initialize
    now = Time.now
    cim = ->(t) { t.strftime('%Y%m%d%H%M%S.000000-000') }
    @rows = [
      { sid: 'S-1-5-18', path: 'C:\\Windows\\system32\\config\\systemprofile', last_use: cim.call(now), loaded: true, special: true, roaming: false, status: 0, name: 'NT AUTHORITY\\SYSTEM' },
      { sid: 'S-1-5-21-1-1001', path: 'C:\\Users\\jsmith', last_use: cim.call(now - 3600), loaded: true, special: false, roaming: false, status: 0, name: 'CORP\\jsmith' },
      { sid: 'S-1-5-21-1-1002', path: 'C:\\Users\\contractor.old', last_use: cim.call(now - 210 * 86_400), loaded: false, special: false, roaming: false, status: 0, name: 'CORP\\contractor.old', size_mb: 4120 },
      { sid: 'S-1-5-21-1-1003', path: 'C:\\Users\\svc_backup', last_use: cim.call(now - 400 * 86_400), loaded: false, special: false, roaming: false, status: 0, name: 'CORP\\svc_backup', size_mb: 35 },
      { sid: 'S-1-5-21-1-1004', path: 'C:\\Users\\tmp.LAB', last_use: cim.call(now - 120 * 86_400), loaded: false, special: false, roaming: false, status: 1, name: 'S-1-5-21-1-1004', size_mb: 12 },
      { sid: 'S-1-5-21-1-1005', path: 'C:\\Users\\amartinez', last_use: cim.call(now - 95 * 86_400), loaded: false, special: false, roaming: true, status: 2, name: 'CORP\\amartinez', size_mb: 1890 },
      { sid: 'S-1-5-21-1-1006', path: 'C:\\Users\\ci-runner', last_use: cim.call(now - 20 * 86_400), loaded: false, special: false, roaming: false, status: 0, name: 'CORP\\ci-runner', size_mb: 22_400 }
    ]
    @deleted = []
  end

  attr_reader :deleted

  def each_profile
    @rows.each { |r| yield r.merge(_obj: r) }
  end

  def delete(profile)
    @deleted << profile[:path]
  end

  def account_name(sid)
    @rows.find { |r| r[:sid] == sid }[:name]
  end
end

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
# CIM_DATETIME looks like 20260901143022.000000-300 (UTC offset in minutes).
def parse_cim_datetime(s)
  return nil if s.nil? || s.to_s.empty?
  m = s.to_s.match(/\A(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\.\d+([+-]\d{3})\z/)
  return nil unless m
  offset_min = m[7].to_i
  Time.new(m[1].to_i, m[2].to_i, m[3].to_i, m[4].to_i, m[5].to_i, m[6].to_i,
           format('%s%02d:%02d', offset_min.negative? ? '-' : '+', offset_min.abs / 60, offset_min.abs % 60))
end

def folder_size_mb(path)
  return nil unless File.directory?(path)
  total = 0
  Dir.glob(File.join(path, '**', '*'), File::FNM_DOTMATCH) do |f|
    total += File.size(f) if File.file?(f)
  rescue SystemCallError
    next # locked NTUSER.DAT, junctions, ACL denials - keep walking
  end
  (total / 1024.0 / 1024.0).round
end

STATUS_FLAGS = { 1 => 'temporary', 2 => 'roaming', 4 => 'mandatory', 8 => 'corrupted' }.freeze
def status_words(bits)
  words = STATUS_FLAGS.select { |bit, _| bits & bit != 0 }.values
  words.empty? ? 'local' : words.join('+')
end

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
begin
  provider = ENV['WIN_PROFILE_MOCK'] ? MockProfiles.new : WmiProfiles.new
rescue StandardError => e
  warn "error: #{e.message}"
  exit 2
end
cutoff = Time.now - opts[:days] * 86_400
rows = []

provider.each_profile do |p|
  next if p[:special]                       # SYSTEM, LocalService, NetworkService...
  name = provider.account_name(p[:sid])
  # --exclude matches the bare account name (no DOMAIN\), the full name, or the folder name
  short = name.split('\\').last.downcase
  folder = p[:path].to_s.split(/[\\\/]/).last.to_s.downcase
  next if (opts[:exclude] & [name.downcase, short, folder]).any?

  last = parse_cim_datetime(p[:last_use])
  age_days = last ? ((Time.now - last) / 86_400).floor : nil
  size = if !opts[:size] then nil
         elsif p[:size_mb] then p[:size_mb]          # mock
         else folder_size_mb(p[:path])
         end

  stale = !p[:loaded] && (age_days.nil? || age_days >= opts[:days])
  orphaned = name == p[:sid]                # SID no longer resolves to an account
  next if size && size < opts[:min_size_mb]

  rows << { account: name, path: p[:path], sid: p[:sid], loaded: p[:loaded],
            last_use: last&.iso8601, age_days: age_days, size_mb: size,
            status: status_words(p[:status]), orphaned: orphaned, stale: stale,
            _raw: p }
end

stale_rows = rows.select { |r| r[:stale] }.sort_by { |r| -(r[:size_mb] || 0) }

if opts[:json]
  puts JSON.pretty_generate(host: ENV['COMPUTERNAME'] || 'localhost', cutoff_days: opts[:days],
                            profiles: rows.map { |r| r.reject { |k, _| k == :_raw } })
else
  puts "Windows user-profile audit  host=#{ENV['COMPUTERNAME'] || 'localhost'}  stale after #{opts[:days]} days"
  puts '=' * 92
  puts format('  %-22s %-28s %-8s %-9s %-10s %-9s %s', 'ACCOUNT', 'PATH', 'AGE(d)', 'SIZE(MB)', 'TYPE', 'LOADED', 'FLAGS')
  rows.sort_by { |r| [r[:stale] ? 0 : 1, -(r[:size_mb] || 0)] }.each do |r|
    flags = []
    flags << 'STALE' if r[:stale]
    flags << 'ORPHANED-SID' if r[:orphaned]
    puts format('  %-22s %-28s %-8s %-9s %-10s %-9s %s',
                r[:account][0, 22], r[:path][0, 28], r[:age_days] || '?', r[:size_mb] || '-',
                r[:status], r[:loaded] ? 'yes' : 'no', flags.join(','))
  end
  puts
  reclaim = stale_rows.sum { |r| r[:size_mb] || 0 }
  puts "Stale profiles: #{stale_rows.size} / #{rows.size}   reclaimable: #{reclaim} MB (#{(reclaim / 1024.0).round(1)} GB)"
end

# ---------------------------------------------------------------------------
# Deletion (guarded)
# ---------------------------------------------------------------------------
if opts[:delete] && !stale_rows.empty?
  unless opts[:dry_run] || opts[:yes]
    warn 'Refusing to delete without --yes (or use --dry-run).'
    exit 2
  end
  puts
  stale_rows.each do |r|
    if r[:loaded]
      puts "  skip   #{r[:path]} (profile is loaded)"
      next
    end
    if opts[:dry_run]
      puts "  would delete #{r[:path]}  (#{r[:account]}, #{r[:size_mb] || '?'} MB, #{r[:age_days]}d)"
    else
      begin
        provider.delete(r[:_raw])
        puts "  deleted #{r[:path]}"
      rescue StandardError => e
        puts "  FAILED  #{r[:path]}: #{e.message}"
      end
    end
  end
end

exit(stale_rows.empty? ? 0 : 1)
