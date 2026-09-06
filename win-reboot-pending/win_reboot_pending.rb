#!/usr/bin/env ruby
# frozen_string_literal: true
#
# win_reboot_pending.rb -- answer "does this Windows box need a reboot?" honestly.
#
# Windows has no single "reboot pending" flag. The truth is scattered across
# five or six registry locations written by different subsystems (Component
# Based Servicing, Windows Update, the Session Manager, the SCCM client, the
# computer-rename path). Patch tooling reads all of them; most humans read
# none. This script checks every known indicator, reports *which* ones tripped
# and *why*, and returns an exit code you can gate a deploy or a maintenance
# window on.
#
# Usage (run in an elevated PowerShell/CMD on Windows):
#   ruby win_reboot_pending.rb              # human-readable report
#   ruby win_reboot_pending.rb --json       # machine-readable, for monitoring
#   ruby win_reboot_pending.rb --quiet      # exit code only (0 = clean, 1 = reboot pending)
#
# Testing on Linux/macOS (no registry): ruby win_reboot_pending.rb --self-test
#
# Requires: Ruby 3.x for Windows (RubyInstaller); uses only stdlib (win32/registry).

require 'json'
require 'optparse'
require 'time'

module WinRebootPending
  # ---------------------------------------------------------------------------
  # Registry access is isolated behind one tiny interface so the detection
  # logic can be unit-tested anywhere with a fake in-memory registry.
  # ---------------------------------------------------------------------------
  class RealRegistry
    def initialize
      require 'win32/registry' # only exists on Windows
    end

    # Returns true if HKLM\<path> exists.
    def key_exists?(path)
      Win32::Registry::HKEY_LOCAL_MACHINE.open(path, Win32::Registry::KEY_READ) { true }
    rescue Win32::Registry::Error
      false
    end

    # Returns the value at HKLM\<path>\<name>, or nil if missing.
    def value(path, name)
      Win32::Registry::HKEY_LOCAL_MACHINE.open(path, Win32::Registry::KEY_READ) { |k| k[name] }
    rescue Win32::Registry::Error
      nil
    end

    # Returns true if HKLM\<path> has at least one value or subkey.
    def non_empty?(path)
      Win32::Registry::HKEY_LOCAL_MACHINE.open(path, Win32::Registry::KEY_READ) do |k|
        k.each_value { return true }
        k.each_key { return true }
      end
      false
    rescue Win32::Registry::Error
      false
    end
  end

  # Fake registry for --self-test and for CI on non-Windows hosts.
  # keys:   Set of existing key paths
  # values: { "path" => { "name" => value } }
  class FakeRegistry
    def initialize(keys: [], values: {})
      @keys = keys.to_a
      @values = values
    end

    def key_exists?(path) = @keys.include?(path) || @values.key?(path)
    def value(path, name) = @values.dig(path, name)
    def non_empty?(path) = @values.fetch(path, {}).any? || @keys.any? { |k| k.start_with?("#{path}\\") }
  end

  # ---------------------------------------------------------------------------
  # Each check returns a Finding: { id, pending, detail, source }.
  # ---------------------------------------------------------------------------
  Finding = Struct.new(:id, :label, :pending, :detail, :source, keyword_init: true)

  class Detector
    CBS   = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing'
    WU    = 'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update'
    SESS  = 'SYSTEM\CurrentControlSet\Control\Session Manager'
    NAME_ACTIVE  = 'SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName'
    NAME_PENDING = 'SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName'
    SCCM  = 'SOFTWARE\Microsoft\SMS\Mobile Client\Reboot Management\RebootData'
    DOMAIN_JOIN = 'SYSTEM\CurrentControlSet\Services\Netlogon'
    UPDATE_EXE_VOLATILE = 'SOFTWARE\Microsoft\Updates'

    def initialize(registry)
      @reg = registry
    end

    def run
      [cbs_reboot_pending, cbs_in_progress, wu_reboot_required, wu_post_reboot_reporting,
       pending_file_renames, computer_rename, domain_join, sccm_reboot, update_exe_volatile]
    end

    private

    # 1. Component Based Servicing: set when a servicing stack operation
    #    (feature/update install via DISM/TrustedInstaller) needs a restart.
    def cbs_reboot_pending
      hit = @reg.key_exists?("#{CBS}\\RebootPending")
      Finding.new(id: 'cbs_reboot_pending', label: 'Component Based Servicing',
                  pending: hit, source: "HKLM\\#{CBS}\\RebootPending",
                  detail: hit ? 'RebootPending key present' : 'no RebootPending key')
    end

    # 1b. CBS still has an operation mid-flight (rare, usually right after install).
    def cbs_in_progress
      hit = @reg.key_exists?("#{CBS}\\RebootInProgress") || @reg.key_exists?("#{CBS}\\PackagesPending")
      Finding.new(id: 'cbs_in_progress', label: 'CBS packages pending / reboot in progress',
                  pending: hit, source: "HKLM\\#{CBS}\\{RebootInProgress,PackagesPending}",
                  detail: hit ? 'servicing operation not yet finalized' : 'clear')
    end

    # 2. Windows Update Agent: written after it installs an update needing a restart.
    def wu_reboot_required
      hit = @reg.key_exists?("#{WU}\\RebootRequired")
      Finding.new(id: 'wu_reboot_required', label: 'Windows Update',
                  pending: hit, source: "HKLM\\#{WU}\\RebootRequired",
                  detail: hit ? 'RebootRequired key present' : 'no RebootRequired key')
    end

    # 2b. Post-reboot reporting: WU wants to phone home after the *next* restart.
    def wu_post_reboot_reporting
      hit = @reg.key_exists?("#{WU}\\PostRebootReporting")
      Finding.new(id: 'wu_post_reboot_reporting', label: 'Windows Update post-reboot reporting',
                  pending: hit, source: "HKLM\\#{WU}\\PostRebootReporting",
                  detail: hit ? 'PostRebootReporting key present' : 'clear')
    end

    # 3. Session Manager: MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT) queues renames/
    #    deletes of in-use files (DLLs, drivers) that only apply at boot.
    def pending_file_renames
      ops = @reg.value(SESS, 'PendingFileRenameOperations') ||
            @reg.value(SESS, 'PendingFileRenameOperations2')
      entries = Array(ops).reject { |s| s.to_s.strip.empty? }
      # The value is a REG_MULTI_SZ of pairs: source, destination ("" = delete).
      pairs = entries.each_slice(2).map { |src, dst| "#{src.to_s.sub(/\A\\\?\?\\/, '')} -> #{dst.to_s.empty? ? '(delete)' : dst}" }
      Finding.new(id: 'pending_file_rename', label: 'Pending file rename operations',
                  pending: !pairs.empty?, source: "HKLM\\#{SESS}\\PendingFileRenameOperations",
                  detail: pairs.empty? ? 'none queued' : "#{pairs.size} queued: #{pairs.first(3).join(', ')}#{pairs.size > 3 ? ', ...' : ''}")
    end

    # 4. Computer rename: the new name is staged but the active one is still old.
    def computer_rename
      active  = @reg.value(NAME_ACTIVE, 'ComputerName')
      pending = @reg.value(NAME_PENDING, 'ComputerName')
      hit = active && pending && active.casecmp(pending) != 0
      Finding.new(id: 'computer_rename', label: 'Computer rename',
                  pending: !!hit, source: "HKLM\\#{NAME_PENDING} vs ActiveComputerName",
                  detail: hit ? "active '#{active}' != pending '#{pending}'" : (active ? "name '#{active}' is active" : 'no rename staged'))
    end

    # 5. Domain join staged (netlogon writes these until the restart completes it).
    def domain_join
      hit = !@reg.value(DOMAIN_JOIN, 'JoinDomain').nil? || !@reg.value(DOMAIN_JOIN, 'AvoidSpnSet').nil?
      Finding.new(id: 'domain_join', label: 'Pending domain join',
                  pending: hit, source: "HKLM\\#{DOMAIN_JOIN}\\{JoinDomain,AvoidSpnSet}",
                  detail: hit ? 'domain join not finalized' : 'clear')
    end

    # 6. ConfigMgr (SCCM) client: it keeps its own reboot bookkeeping.
    def sccm_reboot
      hit = @reg.key_exists?(SCCM) && @reg.non_empty?(SCCM)
      Finding.new(id: 'sccm_reboot', label: 'ConfigMgr client',
                  pending: hit, source: "HKLM\\#{SCCM}",
                  detail: hit ? 'RebootData present' : (@reg.key_exists?(SCCM) ? 'key present but empty' : 'no ConfigMgr client / clear'))
    end

    # 7. Legacy Update.exe installers flag UpdateExeVolatile != 0.
    def update_exe_volatile
      v = @reg.value(UPDATE_EXE_VOLATILE, 'UpdateExeVolatile').to_i
      Finding.new(id: 'update_exe_volatile', label: 'Legacy Update.exe',
                  pending: v != 0, source: "HKLM\\#{UPDATE_EXE_VOLATILE}\\UpdateExeVolatile",
                  detail: v.zero? ? 'clear' : "UpdateExeVolatile=#{v}")
    end
  end

  # ---------------------------------------------------------------------------
  class Reporter
    def initialize(findings, json: false, quiet: false)
      @findings = findings
      @json = json
      @quiet = quiet
    end

    def pending? = @findings.any?(&:pending)

    def print
      return if @quiet
      return puts(JSON.pretty_generate(to_h)) if @json

      host = ENV['COMPUTERNAME'] || `hostname`.strip
      puts "REBOOT PENDING CHECK  host=#{host}  #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}"
      puts '=' * 76
      @findings.each do |f|
        mark = f.pending ? '[PENDING]' : '[  ok   ]'
        puts format('%s %-42s %s', mark, f.label, f.detail)
      end
      puts '-' * 76
      hits = @findings.select(&:pending)
      if hits.empty?
        puts 'VERDICT: no reboot pending.'
      else
        puts "VERDICT: REBOOT PENDING (#{hits.size} indicator#{'s' if hits.size > 1}: #{hits.map(&:id).join(', ')})"
      end
    end

    def to_h
      { host: ENV['COMPUTERNAME'] || `hostname`.strip, checked_at: Time.now.utc.iso8601,
        reboot_pending: pending?, indicators_tripped: @findings.select(&:pending).map(&:id),
        checks: @findings.map(&:to_h) }
    end
  end

  # ---------------------------------------------------------------------------
  # --self-test: run the detector against fake registries and assert results.
  # This is what we can execute on a Linux CI box; it proves the logic, not the
  # Win32 plumbing.
  # ---------------------------------------------------------------------------
  def self.self_test
    cbs = Detector::CBS
    cases = {
      'clean machine' => [FakeRegistry.new(values: {
        Detector::NAME_ACTIVE => { 'ComputerName' => 'WEB-01' },
        Detector::NAME_PENDING => { 'ComputerName' => 'WEB-01' }
      }), false, []],
      'after cumulative update' => [FakeRegistry.new(keys: ["#{cbs}\\RebootPending", "#{Detector::WU}\\RebootRequired"]),
                                    true, %w[cbs_reboot_pending wu_reboot_required]],
      'driver install queued file replace' => [FakeRegistry.new(values: {
        Detector::SESS => { 'PendingFileRenameOperations' => ['\??\C:\Windows\System32\drivers\nvlddmkm.sys.tmp', '\??\C:\Windows\System32\drivers\nvlddmkm.sys', '\??\C:\Temp\old.dll', ''] }
      }), true, ['pending_file_rename']],
      'hostname changed, not rebooted' => [FakeRegistry.new(values: {
        Detector::NAME_ACTIVE => { 'ComputerName' => 'WIN-8FJ2K1' },
        Detector::NAME_PENDING => { 'ComputerName' => 'WEB-07' }
      }), true, ['computer_rename']],
      'sccm scheduled reboot' => [FakeRegistry.new(values: { Detector::SCCM => { 'RebootBy' => 1_757_030_400 } }),
                                  true, ['sccm_reboot']]
    }
    failures = 0
    puts "self-test: #{cases.size} scenarios against FakeRegistry (#{RUBY_PLATFORM})"
    cases.each do |name, (reg, expect_pending, expect_ids)|
      findings = Detector.new(reg).run
      got_ids = findings.select(&:pending).map(&:id)
      ok = findings.any?(&:pending) == expect_pending && got_ids.sort == expect_ids.sort
      failures += 1 unless ok
      puts format('  %-4s %-38s pending=%-5s tripped=%s', ok ? 'PASS' : 'FAIL', name, expect_pending, got_ids.inspect)
    end
    puts
    puts 'sample report for scenario "after cumulative update":'
    Reporter.new(Detector.new(cases['after cumulative update'][0]).run).print
    puts
    puts failures.zero? ? "self-test: all #{cases.size} passed" : "self-test: #{failures} FAILED"
    exit(failures.zero? ? 0 : 3)
  end

  def self.run(argv = ARGV)
    opts = { json: false, quiet: false, self_test: false }
    OptionParser.new do |o|
      o.banner = 'Usage: win_reboot_pending.rb [--json] [--quiet] [--self-test]'
      o.on('--json', 'Emit JSON') { opts[:json] = true }
      o.on('--quiet', 'No output; exit code only') { opts[:quiet] = true }
      o.on('--self-test', 'Run detection logic against fake registries (works on any OS)') { opts[:self_test] = true }
    end.parse!(argv)

    return self_test if opts[:self_test]

    unless RUBY_PLATFORM =~ /mingw|mswin|cygwin/
      warn 'error: this script reads the Windows registry; on other platforms use --self-test'
      exit 3
    end
    findings = Detector.new(RealRegistry.new).run
    reporter = Reporter.new(findings, json: opts[:json], quiet: opts[:quiet])
    reporter.print
    exit(reporter.pending? ? 1 : 0)
  rescue StandardError => e
    warn "error: #{e.message}"
    exit 3
  end
end

WinRebootPending.run if $PROGRAM_NAME == __FILE__
