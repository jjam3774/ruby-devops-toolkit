#!/usr/bin/env ruby
# frozen_string_literal: true
#
# win_vss_snapshot_audit.rb - Windows Volume Shadow Copy (VSS) audit via WMI
#
# Answers the questions a sysadmin asks after a ransomware scare or a failed
# restore: "Which volumes actually have shadow copies? How old is the newest
# one? Is shadow storage about to hit its cap and silently evict the oldest
# snapshots? Did someone (or something) delete them all?"
#
# Queries Win32_ShadowCopy and Win32_ShadowStorage through WMI using the
# win32ole stdlib (no gems, no vssadmin parsing), then applies simple policy
# thresholds and exits with a monitoring-friendly code:
#
#   0 = OK        every protected volume has a fresh snapshot, storage healthy
#   1 = WARNING   newest snapshot older than --max-age, or storage > --warn-pct used
#   2 = CRITICAL  a --require volume has NO snapshots at all, or storage > --crit-pct
#
# Usage (Windows, elevated prompt recommended):
#   ruby win_vss_snapshot_audit.rb
#   ruby win_vss_snapshot_audit.rb --require C: --require D: --max-age 24
#   ruby win_vss_snapshot_audit.rb --json
#
# Test on any OS with the built-in fixture (no WMI needed):
#   ruby win_vss_snapshot_audit.rb --fixture
#
# Ruby >= 2.7 (RubyInstaller on Windows), stdlib only.

require 'json'
require 'optparse'
require 'time'

module VssAudit
  VERSION = '1.0.0'

  Snapshot = Struct.new(:id, :volume, :created_at, :provider, :persistent, :client_accessible, keyword_init: true)
  Storage  = Struct.new(:volume, :diff_volume, :used_bytes, :allocated_bytes, :max_bytes, keyword_init: true) do
    def pct_used
      return 0.0 if max_bytes.nil? || max_bytes.zero? || max_bytes == 0xFFFFFFFFFFFFFFFF # UNBOUNDED

      (used_bytes.to_f / max_bytes * 100).round(1)
    end
  end

  # ---- WMI source (real) ----------------------------------------------------
  class WmiSource
    def initialize
      require 'win32ole'
      @wmi = WIN32OLE.connect('winmgmts://./root/cimv2')
    end

    def snapshots
      volumes = volume_names # DeviceID -> "C:"
      @wmi.ExecQuery('SELECT ID, VolumeName, InstallDate, ProviderID, Persistent, ClientAccessible FROM Win32_ShadowCopy').map do |s|
        Snapshot.new(
          id: s.ID,
          volume: volumes[s.VolumeName] || s.VolumeName,
          created_at: parse_wmi_time(s.InstallDate),
          provider: s.ProviderID,
          persistent: s.Persistent,
          client_accessible: s.ClientAccessible
        )
      end
    end

    def storage
      volumes = volume_names
      @wmi.ExecQuery('SELECT Volume, DiffVolume, UsedSpace, AllocatedSpace, MaxSpace FROM Win32_ShadowStorage').map do |st|
        Storage.new(
          volume: volumes[ref_device_id(st.Volume)] || st.Volume,
          diff_volume: volumes[ref_device_id(st.DiffVolume)] || st.DiffVolume,
          used_bytes: st.UsedSpace.to_i,
          allocated_bytes: st.AllocatedSpace.to_i,
          max_bytes: st.MaxSpace.to_i
        )
      end
    end

    private

    # Win32_Volume maps the ugly \\?\Volume{GUID}\ DeviceID to a drive letter.
    def volume_names
      @volume_names ||= @wmi.ExecQuery('SELECT DeviceID, DriveLetter FROM Win32_Volume')
                            .each_with_object({}) { |v, h| h[v.DeviceID] = v.DriveLetter || v.DeviceID }
    end

    # Win32_ShadowStorage.Volume is an object reference string like
    #   \\HOST\root\cimv2:Win32_Volume.DeviceID="\\\\?\\Volume{...}\\"
    def ref_device_id(ref)
      ref.to_s[/DeviceID="(.+)"\z/, 1].to_s.gsub('\\\\', '\\')
    end

    # WMI datetime: 20260909031500.000000-000  (CIM_DATETIME)
    def parse_wmi_time(s)
      return nil if s.nil? || s.empty?

      y, mo, d, h, mi, sec = s[0, 4], s[4, 2], s[6, 2], s[8, 2], s[10, 2], s[12, 2]
      offset_min = s[-4..].to_i * (s[-4 - 1] == '-' ? -1 : 1)
      Time.new(y.to_i, mo.to_i, d.to_i, h.to_i, mi.to_i, sec.to_i, offset_min * 60)
    end
  end

  # ---- Fixture source (for tests / non-Windows) -----------------------------
  class FixtureSource
    def initialize(now: Time.now)
      @now = now
    end

    def snapshots
      [
        Snapshot.new(id: '{a1}', volume: 'C:', created_at: @now - 3 * 3600,  provider: '{b5946137-7b9f-4925-af80-51abd60b20d5}', persistent: true, client_accessible: true),
        Snapshot.new(id: '{a2}', volume: 'C:', created_at: @now - 27 * 3600, provider: '{b5946137-7b9f-4925-af80-51abd60b20d5}', persistent: true, client_accessible: true),
        Snapshot.new(id: '{a3}', volume: 'D:', created_at: @now - 40 * 3600, provider: '{b5946137-7b9f-4925-af80-51abd60b20d5}', persistent: true, client_accessible: true)
      ]
    end

    def storage
      gib = 1024**3
      [
        Storage.new(volume: 'C:', diff_volume: 'C:', used_bytes: 18 * gib, allocated_bytes: 19 * gib, max_bytes: 20 * gib),
        Storage.new(volume: 'D:', diff_volume: 'D:', used_bytes: 4 * gib,  allocated_bytes: 5 * gib,  max_bytes: 50 * gib)
      ]
    end
  end

  # ---- Policy -----------------------------------------------------------------
  class Auditor
    def initialize(require_volumes:, max_age_h:, warn_pct:, crit_pct:, now: Time.now)
      @require = require_volumes.map(&:upcase)
      @max_age_h = max_age_h
      @warn_pct = warn_pct
      @crit_pct = crit_pct
      @now = now
    end

    def audit(snapshots, storage)
      findings = []
      by_vol = snapshots.group_by { |s| s.volume.to_s.upcase }

      @require.each do |vol|
        findings << [2, "#{vol} has NO shadow copies"] unless by_vol.key?(vol)
      end

      by_vol.each do |vol, snaps|
        newest = snaps.map(&:created_at).compact.max
        next unless newest

        age_h = ((@now - newest) / 3600).round(1)
        findings << [1, "#{vol} newest snapshot is #{age_h}h old (limit #{@max_age_h}h)"] if age_h > @max_age_h
      end

      storage.each do |st|
        pct = st.pct_used
        if pct >= @crit_pct
          findings << [2, "#{st.volume} shadow storage #{pct}% used (crit #{@crit_pct}%)"]
        elsif pct >= @warn_pct
          findings << [1, "#{st.volume} shadow storage #{pct}% used (warn #{@warn_pct}%)"]
        end
      end

      code = findings.map(&:first).max || 0
      [code, findings]
    end
  end

  # ---- Output -----------------------------------------------------------------
  module Report
    LABEL = %w[OK WARNING CRITICAL].freeze

    def self.human(bytes)
      return 'unbounded' if bytes.nil? || bytes == 0xFFFFFFFFFFFFFFFF

      units = %w[B KiB MiB GiB TiB]
      i = 0
      f = bytes.to_f
      while f >= 1024 && i < units.size - 1
        f /= 1024
        i += 1
      end
      format('%.1f %s', f, units[i])
    end

    def self.text(code, findings, snapshots, storage, now)
      out = ["#{LABEL[code]} - #{findings.empty? ? 'all volumes protected' : findings.map(&:last).join('; ')}", '']
      out << 'SHADOW COPIES'
      snapshots.sort_by { |s| [s.volume.to_s, -s.created_at.to_i] }.each do |s|
        age = ((now - s.created_at) / 3600).round(1)
        out << format('  %-4s %-19s age %6.1fh  %s%s', s.volume, s.created_at.strftime('%Y-%m-%d %H:%M:%S'), age,
                      s.persistent ? 'persistent' : 'temp', s.client_accessible ? ', client-accessible' : '')
      end
      out << '' << 'SHADOW STORAGE'
      storage.each do |st|
        out << format('  %-4s on %-4s used %-10s alloc %-10s max %-10s (%s%%)', st.volume, st.diff_volume,
                      human(st.used_bytes), human(st.allocated_bytes), human(st.max_bytes), st.pct_used)
      end
      out.join("\n")
    end

    def self.json(code, findings, snapshots, storage)
      JSON.pretty_generate(
        status: LABEL[code],
        findings: findings.map { |sev, msg| { severity: LABEL[sev], message: msg } },
        snapshots: snapshots.map { |s| s.to_h.merge(created_at: s.created_at&.iso8601) },
        storage: storage.map { |st| st.to_h.merge(pct_used: st.pct_used) }
      )
    end
  end

  def self.run(argv)
    opts = { require: [], max_age: 24.0, warn: 80.0, crit: 95.0, json: false, fixture: false }
    OptionParser.new do |o|
      o.banner = 'Usage: win_vss_snapshot_audit.rb [--require C:]... [--max-age HOURS] [--warn-pct N] [--crit-pct N] [--json] [--fixture]'
      o.on('--require VOL', 'Volume that MUST have at least one snapshot (repeatable)') { |v| opts[:require] << v }
      o.on('--max-age HOURS', Float) { |v| opts[:max_age] = v }
      o.on('--warn-pct N', Float) { |v| opts[:warn] = v }
      o.on('--crit-pct N', Float) { |v| opts[:crit] = v }
      o.on('--json') { opts[:json] = true }
      o.on('--fixture', 'Use built-in sample data instead of WMI (for testing)') { opts[:fixture] = true }
      o.on('-v', '--version') { puts VERSION; exit }
    end.parse!(argv)

    now = Time.now
    source = if opts[:fixture]
               FixtureSource.new(now: now)
             elsif Gem.win_platform?
               WmiSource.new
             else
               warn 'error: WMI is only available on Windows. Use --fixture to test elsewhere.'
               exit 3
             end

    snapshots = source.snapshots
    storage   = source.storage
    code, findings = Auditor.new(require_volumes: opts[:require], max_age_h: opts[:max_age],
                                 warn_pct: opts[:warn], crit_pct: opts[:crit], now: now)
                            .audit(snapshots, storage)

    puts(opts[:json] ? Report.json(code, findings, snapshots, storage) : Report.text(code, findings, snapshots, storage, now))
    exit code
  rescue StandardError => e
    warn "error: #{e.class}: #{e.message}"
    exit 3
  end
end

VssAudit.run(ARGV) if $PROGRAM_NAME == __FILE__
