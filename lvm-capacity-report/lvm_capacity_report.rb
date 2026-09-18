#!/usr/bin/env ruby
# frozen_string_literal: true
#
# lvm_capacity_report.rb -- LVM capacity, thin-pool and snapshot reporting
#                           with days-to-full projection
#
# THE PROBLEM
# -----------
# `df -h` lies to you about LVM. It tells you how full a *filesystem* is. It
# tells you nothing about:
#
#   * How much unallocated space is left in the volume group -- i.e. whether you
#     can still grow that filesystem at all.
#   * How full the underlying *thin pool* is. A thin LV can report 40% used in
#     df while its pool is at 99%, and when a thin pool fills, writes fail and
#     ext4/XFS remount read-only. Every filesystem on that pool, at once.
#   * Thin pool *metadata* usage, which is a separate, much smaller space that
#     fills faster than you expect and bricks the pool just as hard.
#   * Snapshot fill. A snapshot that reaches 100% is silently invalidated, and
#     the backup you thought you had is gone.
#
# Those four numbers are where LVM outages actually come from, and none of them
# appear in the monitoring most shops have. This script pulls them from LVM's
# own JSON reporting interface, tracks usage between runs in a small state file,
# and projects a days-to-full figure from the observed growth rate.
#
# USAGE
#   sudo ruby lvm_capacity_report.rb
#   sudo ruby lvm_capacity_report.rb --format json
#   ruby lvm_capacity_report.rb --from-fixture fixtures/sample.json   # offline demo
#   sudo ruby lvm_capacity_report.rb --state /var/lib/lvmreport/state.json
#
# EXIT CODES
#   0  everything within thresholds
#   1  at least one WARN
#   2  at least one CRIT (or LVM could not be read)
#
# Requires: Ruby >= 2.7 (stdlib only), lvm2 >= 2.02.107 for --reportformat json.
# Reading LVM metadata requires root.

require 'json'
require 'open3'
require 'optparse'
require 'time'
require 'fileutils'

module LvmCapacityReport
  VERSION = '1.0.0'

  # Thresholds. Metadata gets a tighter threshold than data on purpose: thin
  # pool metadata is typically a few hundred MB against hundreds of GB of data,
  # so it has far less headroom and far less warning time.
  DEFAULTS = {
    vg_free_warn_pct: 20.0,   # warn when LESS than this % of the VG is unallocated
    vg_free_crit_pct: 10.0,
    pool_data_warn: 75.0,
    pool_data_crit: 85.0,
    pool_meta_warn: 50.0,
    pool_meta_crit: 75.0,
    snapshot_warn: 70.0,
    snapshot_crit: 90.0,
    days_warn: 30,            # warn if projected to fill within N days
    days_crit: 7
  }.freeze

  SEVERITY_RANK = { ok: 0, warn: 1, crit: 2 }.freeze

  Finding = Struct.new(:severity, :object, :metric, :value, :message,
                       keyword_init: true)

  # ---------------------------------------------------------------------------
  # Collector -- everything that touches the outside world lives here.
  #
  # The command runner is injected rather than hard-coded. That single decision
  # is what makes this script testable on a machine with no LVM at all: the test
  # harness passes a lambda that returns fixture JSON instead of shelling out.
  # ---------------------------------------------------------------------------
  class Collector
    def initialize(runner: method(:shell))
      @runner = runner
    end

    # LVM's JSON output nests everything under report[0].<entity>. Older lvm2
    # emits a single report object; newer versions can emit several. We flatten
    # across all report entries so both shapes work.
    def fetch(entity, columns)
      cmd = [entity_command(entity), '--reportformat', 'json',
             '--units', 'b', '--nosuffix', '-o', columns.join(',')]
      out, err, ok = @runner.call(cmd)
      raise "#{cmd.first} failed: #{err.to_s.strip}" unless ok

      parsed = JSON.parse(out)
      reports = parsed['report'] || []
      reports.flat_map { |r| r[entity.to_s] || [] }
    rescue JSON::ParserError => e
      raise "could not parse #{entity} JSON: #{e.message}"
    end

    def entity_command(entity)
      { vg: 'vgs', lv: 'lvs', pv: 'pvs' }.fetch(entity)
    end

    # Open3.capture3 raises Errno::ENOENT when the binary is absent, which would
    # otherwise escape as a five-line backtrace on any host without lvm2. A
    # missing tool is an expected operational state, not a crash -- so we turn
    # it into the same [out, err, ok] triple every other failure produces.
    def self.shell(cmd)
      out, err, status = Open3.capture3(*cmd)
      [out, err, status.success?]
    rescue Errno::ENOENT
      ['', "#{cmd.first} not found in PATH -- is lvm2 installed?", false]
    rescue Errno::EACCES => e
      ['', "cannot execute #{cmd.first}: #{e.message}", false]
    end

    def shell(cmd)
      self.class.shell(cmd)
    end
  end

  # ---------------------------------------------------------------------------
  # Fixture-backed collector used by --from-fixture and by the test harness.
  # Same interface, no subprocesses.
  # ---------------------------------------------------------------------------
  class FixtureCollector
    def initialize(path)
      @data = JSON.parse(File.read(path))
    end

    def fetch(entity, _columns)
      @data.fetch(entity.to_s, [])
    end
  end

  # ---------------------------------------------------------------------------
  # State file -- remembers last run's usage so we can compute a growth rate.
  #
  # Without history, "this pool is 82% full" is a snapshot with no urgency
  # attached. With one prior sample, it becomes "82% and gaining 1.4 points a
  # day -- you have 13 days", which is what actually drives a decision.
  # ---------------------------------------------------------------------------
  class State
    def initialize(path)
      @path = path
      @data = load
    end

    attr_reader :data

    def load
      return {} unless @path && File.exist?(@path)
      JSON.parse(File.read(@path))
    rescue JSON::ParserError, SystemCallError
      # A corrupt state file must never break the report. Worst case we lose
      # the projection for one run and rebuild history on the next.
      {}
    end

    def previous(key)
      @data['samples'] && @data['samples'][key]
    end

    def record(key, pct, at)
      @data['samples'] ||= {}
      @data['samples'][key] = { 'pct' => pct, 'at' => at.iso8601 }
    end

    def save(at)
      return unless @path
      @data['updated_at'] = at.iso8601
      FileUtils.mkdir_p(File.dirname(@path))
      File.write(@path, JSON.pretty_generate(@data))
    rescue SystemCallError => e
      warn "warning: could not write state file #{@path}: #{e.message}"
    end

    # Linear projection from two samples. Deliberately simple and deliberately
    # conservative: we only project when growth is positive and the samples are
    # at least an hour apart, because a 5-minute delta amplifies noise into
    # nonsense ("full in 4 hours!") and trains people to ignore the alert.
    def days_to_full(key, current_pct, now)
      prev = previous(key)
      return nil unless prev

      then_at = Time.parse(prev['at'])
      elapsed_days = (now - then_at) / 86_400.0
      return nil if elapsed_days < (1.0 / 24.0)

      delta = current_pct - prev['pct'].to_f
      return nil if delta <= 0.0

      remaining = 100.0 - current_pct
      return 0.0 if remaining <= 0

      (remaining / (delta / elapsed_days)).round(1)
    rescue ArgumentError, TypeError
      nil
    end
  end

  # ---------------------------------------------------------------------------
  # Analyzer
  # ---------------------------------------------------------------------------
  class Analyzer
    VG_COLUMNS = %w[vg_name vg_size vg_free lv_count pv_count].freeze
    LV_COLUMNS = %w[lv_name vg_name lv_size lv_attr data_percent
                    metadata_percent pool_lv origin snap_percent].freeze

    def initialize(collector, state:, thresholds: DEFAULTS, now: Time.now)
      @collector = collector
      @state = state
      @t = thresholds
      @now = now
      @findings = []
      @volume_groups = []
      @pools = []
      @snapshots = []
    end

    attr_reader :findings, :volume_groups, :pools, :snapshots

    def run
      analyze_vgs(@collector.fetch(:vg, VG_COLUMNS))
      analyze_lvs(@collector.fetch(:lv, LV_COLUMNS))
      self
    end

    def worst_severity
      @findings.map(&:severity).max_by { |s| SEVERITY_RANK[s] } || :ok
    end

    private

    # LVM reports bytes as strings when --units b --nosuffix is set, and some
    # versions still append a stray suffix. to_f handles both without raising.
    def bytes(v)
      v.to_s.gsub(/[^0-9.\-]/, '').to_f
    end

    def pct(part, whole)
      return 0.0 if whole.nil? || whole.zero?
      (part / whole * 100.0).round(1)
    end

    def analyze_vgs(rows)
      rows.each do |row|
        name  = row['vg_name']
        size  = bytes(row['vg_size'])
        free  = bytes(row['vg_free'])
        free_pct = pct(free, size)

        @volume_groups << {
          name: name, size_bytes: size, free_bytes: free, free_pct: free_pct,
          lv_count: row['lv_count'].to_i, pv_count: row['pv_count'].to_i
        }

        sev =
          if free_pct < @t[:vg_free_crit_pct] then :crit
          elsif free_pct < @t[:vg_free_warn_pct] then :warn
          else :ok
          end

        next if sev == :ok
        @findings << Finding.new(
          severity: sev, object: "vg/#{name}", metric: 'vg_free_pct',
          value: free_pct,
          message: format('volume group %s has only %s free (%.1f%%) -- ' \
                          'no room to extend LVs or take snapshots',
                          name, human(free), free_pct)
        )
      end
    end

    def analyze_lvs(rows)
      rows.each do |row|
        attr = row['lv_attr'].to_s
        # lv_attr[0] is the volume type character:
        #   t = thin pool, V = thin volume, s = snapshot, - = linear
        case attr[0]
        when 't' then analyze_pool(row)
        when 's' then analyze_snapshot(row)
        end
      end
    end

    def analyze_pool(row)
      key  = "#{row['vg_name']}/#{row['lv_name']}"
      data = row['data_percent'].to_s.empty? ? nil : row['data_percent'].to_f
      meta = row['metadata_percent'].to_s.empty? ? nil : row['metadata_percent'].to_f

      dtf_data = data ? @state.days_to_full("#{key}#data", data, @now) : nil
      dtf_meta = meta ? @state.days_to_full("#{key}#meta", meta, @now) : nil

      @state.record("#{key}#data", data, @now) if data
      @state.record("#{key}#meta", meta, @now) if meta

      @pools << {
        name: key, size_bytes: bytes(row['lv_size']),
        data_pct: data, metadata_pct: meta,
        days_to_full_data: dtf_data, days_to_full_meta: dtf_meta
      }

      check_threshold(key, 'pool_data_pct', data,
                      @t[:pool_data_warn], @t[:pool_data_crit],
                      'thin pool %s data is %.1f%% full -- at 100%% every ' \
                      'filesystem on this pool goes read-only')
      check_threshold(key, 'pool_metadata_pct', meta,
                      @t[:pool_meta_warn], @t[:pool_meta_crit],
                      'thin pool %s METADATA is %.1f%% full -- metadata ' \
                      'exhaustion breaks the pool even with free data space')

      check_projection(key, 'data', dtf_data)
      check_projection(key, 'metadata', dtf_meta)
    end

    def analyze_snapshot(row)
      key  = "#{row['vg_name']}/#{row['lv_name']}"
      used = row['snap_percent'].to_s.empty? ? nil : row['snap_percent'].to_f
      used ||= row['data_percent'].to_s.empty? ? nil : row['data_percent'].to_f

      @snapshots << {
        name: key, origin: row['origin'], used_pct: used,
        size_bytes: bytes(row['lv_size'])
      }

      check_threshold(key, 'snapshot_pct', used,
                      @t[:snapshot_warn], @t[:snapshot_crit],
                      'snapshot %s is %.1f%% full -- at 100%% it is dropped ' \
                      'and any backup depending on it is invalid')
    end

    def check_threshold(obj, metric, value, warn_at, crit_at, fmt)
      return if value.nil?
      sev = if value >= crit_at then :crit
            elsif value >= warn_at then :warn
            else :ok
            end
      return if sev == :ok

      @findings << Finding.new(severity: sev, object: obj, metric: metric,
                               value: value, message: format(fmt, obj, value))
    end

    def check_projection(obj, what, days)
      return if days.nil?
      sev = if days <= @t[:days_crit] then :crit
            elsif days <= @t[:days_warn] then :warn
            else :ok
            end
      return if sev == :ok

      @findings << Finding.new(
        severity: sev, object: obj, metric: "days_to_full_#{what}", value: days,
        message: format('%s %s is projected to reach 100%% in %.1f days at the ' \
                        'current growth rate', obj, what, days)
      )
    end

    def human(b)
      units = %w[B KiB MiB GiB TiB PiB]
      i = 0
      b = b.to_f
      while b >= 1024 && i < units.size - 1
        b /= 1024
        i += 1
      end
      format('%.1f %s', b, units[i])
    end
  end

  # ---------------------------------------------------------------------------
  # Reporting
  # ---------------------------------------------------------------------------
  module Report
    MARK = { ok: '[ OK ]', warn: '[WARN]', crit: '[CRIT]' }.freeze

    def self.human(b)
      units = %w[B KiB MiB GiB TiB PiB]
      i = 0
      b = b.to_f
      while b >= 1024 && i < units.size - 1
        b /= 1024
        i += 1
      end
      format('%.1f %s', b, units[i])
    end

    def self.bar(pct, width = 24)
      return ' ' * width if pct.nil?
      filled = [[(pct / 100.0 * width).round, 0].max, width].min
      ('#' * filled) + ('.' * (width - filled))
    end

    def self.text(analyzer)
      l = []
      l << '=' * 78
      l << 'LVM capacity report'
      l << '=' * 78

      l << ''
      l << 'VOLUME GROUPS'
      l << '-' * 78
      l << format('  %-14s %12s %12s %8s  %s', 'VG', 'SIZE', 'FREE', 'FREE%', 'ALLOCATED')
      analyzer.volume_groups.each do |vg|
        l << format('  %-14s %12s %12s %7.1f%%  %s',
                    vg[:name], human(vg[:size_bytes]), human(vg[:free_bytes]),
                    vg[:free_pct], bar(100.0 - vg[:free_pct]))
      end
      l << '  (none)' if analyzer.volume_groups.empty?

      l << ''
      l << 'THIN POOLS'
      l << '-' * 78
      if analyzer.pools.empty?
        l << '  (none)'
      else
        l << format('  %-22s %8s %8s %10s %10s', 'POOL', 'DATA%', 'META%',
                    'DAYS(DAT)', 'DAYS(MET)')
        analyzer.pools.each do |p|
          l << format('  %-22s %7.1f%% %7.1f%% %10s %10s',
                      p[:name], p[:data_pct] || 0.0, p[:metadata_pct] || 0.0,
                      p[:days_to_full_data] ? p[:days_to_full_data].to_s : '-',
                      p[:days_to_full_meta] ? p[:days_to_full_meta].to_s : '-')
          l << format('  %-22s data %s', '', bar(p[:data_pct]))
          l << format('  %-22s meta %s', '', bar(p[:metadata_pct]))
        end
      end

      unless analyzer.snapshots.empty?
        l << ''
        l << 'SNAPSHOTS'
        l << '-' * 78
        analyzer.snapshots.each do |s|
          l << format('  %-22s origin=%-14s %6.1f%% %s',
                      s[:name], s[:origin].to_s, s[:used_pct] || 0.0,
                      bar(s[:used_pct], 18))
        end
      end

      l << ''
      l << 'FINDINGS'
      l << '-' * 78
      if analyzer.findings.empty?
        l << '  [ OK ] all volume groups, pools and snapshots within thresholds'
      else
        analyzer.findings
                .sort_by { |f| -SEVERITY_RANK[f.severity] }
                .each { |f| l << "  #{MARK[f.severity]} #{f.message}" }
      end

      l << ''
      l << "RESULT: #{analyzer.worst_severity.to_s.upcase}"
      l.join("\n")
    end

    def self.json(analyzer, now)
      JSON.pretty_generate(
        generated_at: now.utc.iso8601,
        version: VERSION,
        status: analyzer.worst_severity,
        volume_groups: analyzer.volume_groups,
        thin_pools: analyzer.pools,
        snapshots: analyzer.snapshots,
        findings: analyzer.findings.map(&:to_h)
      )
    end
  end

  # ---------------------------------------------------------------------------
  # CLI
  # ---------------------------------------------------------------------------
  def self.run(argv)
    opts = { format: 'text', state: '/var/lib/lvm-capacity-report/state.json',
             fixture: nil }

    OptionParser.new do |o|
      o.banner = 'Usage: sudo ruby lvm_capacity_report.rb [options]'
      o.on('--format FMT', %w[text json], 'text (default) or json') { |v| opts[:format] = v }
      o.on('--state PATH', 'State file for growth-rate history') { |v| opts[:state] = v }
      o.on('--no-state', 'Do not read or write history') { opts[:state] = nil }
      o.on('--from-fixture PATH', 'Read LVM data from a JSON fixture') { |v| opts[:fixture] = v }
      o.on('-v', '--version') { puts VERSION; exit 0 }
      o.on('-h', '--help') { puts o; exit 0 }
    end.parse!(argv)

    now = Time.now
    collector = opts[:fixture] ? FixtureCollector.new(opts[:fixture]) : Collector.new
    state = State.new(opts[:state])

    analyzer = Analyzer.new(collector, state: state, now: now).run
    state.save(now)

    puts(opts[:format] == 'json' ? Report.json(analyzer, now) : Report.text(analyzer))

    case analyzer.worst_severity
    when :crit then 2
    when :warn then 1
    else 0
    end
  rescue RuntimeError => e
    warn "error: #{e.message}"
    warn 'hint: reading LVM metadata requires root; try sudo.' if Process.uid != 0
    2
  end
end

exit LvmCapacityReport.run(ARGV) if $PROGRAM_NAME == __FILE__
