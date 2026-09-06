#!/usr/bin/env ruby
# frozen_string_literal: true
#
# smart_disk_health.rb -- S.M.A.R.T. health report for every disk on a Linux box.
#
# Wraps `smartctl --json` (smartmontools >= 7.0) so you get one table, one exit
# code, and one JSON blob you can ship to monitoring -- instead of eyeballing
# forty lines of raw attribute output per drive.
#
# Usage:
#   sudo ruby smart_disk_health.rb                 # scan all disks, print table
#   sudo ruby smart_disk_health.rb --json           # machine-readable output
#   ruby smart_disk_health.rb --fixtures ./fixtures # replay saved smartctl JSON (no root, no disks)
#   sudo ruby smart_disk_health.rb --temp-warn 50 --realloc-warn 1
#
# Exit codes: 0 = all OK, 1 = at least one WARN, 2 = at least one CRIT/FAILED.

require 'json'
require 'open3'
require 'time'
require 'optparse'

module SmartDiskHealth
  # Attribute IDs that predict imminent failure when non-zero (ATA drives).
  # Source: Backblaze failure-correlation study + smartmontools attribute docs.
  CRITICAL_ATTRS = {
    5   => 'Reallocated_Sector_Ct',
    187 => 'Reported_Uncorrect',
    188 => 'Command_Timeout',
    197 => 'Current_Pending_Sector',
    198 => 'Offline_Uncorrectable'
  }.freeze

  Options = Struct.new(:json, :fixtures, :temp_warn, :temp_crit, :realloc_warn,
                       :nvme_pct_used_warn, keyword_init: true)

  # ---------------------------------------------------------------------------
  # Collector: finds disks and pulls raw smartctl JSON for each one.
  # ---------------------------------------------------------------------------
  class Collector
    def initialize(fixtures: nil)
      @fixtures = fixtures
    end

    # Returns [[device_name, parsed_json_hash], ...]
    def collect
      return collect_from_fixtures if @fixtures

      devices.map do |dev|
        out, _err, status = Open3.capture3('smartctl', '--json', '-a', dev)
        # smartctl exit codes are a bitmask; bit 0/1 mean "couldn't talk to the
        # device" and there is nothing useful to parse. Any other bits still
        # come with a full JSON document, so we keep going.
        next [dev, nil] if (status.exitstatus & 0b11) != 0 && out.strip.empty?

        [dev, JSON.parse(out)]
      rescue JSON::ParserError
        [dev, nil]
      end
    end

    private

    def devices
      out, _err, status = Open3.capture3('smartctl', '--json', '--scan')
      raise 'smartctl not found or --scan failed (is smartmontools installed?)' unless status.success?

      JSON.parse(out).fetch('devices', []).map { |d| d['name'] }
    end

    def collect_from_fixtures
      Dir.glob(File.join(@fixtures, '*.json')).sort.map do |path|
        doc = JSON.parse(File.read(path))
        [doc.dig('device', 'name') || File.basename(path, '.json'), doc]
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Analyzer: turns one smartctl JSON document into a normalized verdict.
  # ---------------------------------------------------------------------------
  class Analyzer
    Result = Struct.new(:device, :model, :serial, :type, :temp_c, :hours,
                        :status, :reasons, :critical_attrs, keyword_init: true)

    def initialize(opts)
      @opts = opts
    end

    def analyze(device, doc)
      return unreadable(device) if doc.nil?

      result = Result.new(
        device: device,
        model: doc['model_name'] || doc.dig('nvme_controller', 'model') || 'unknown',
        serial: doc['serial_number'] || 'n/a',
        type: doc.dig('device', 'type') || 'ata',
        temp_c: doc.dig('temperature', 'current'),
        hours: doc.dig('power_on_time', 'hours'),
        status: 'OK', reasons: [], critical_attrs: {}
      )

      check_overall_health(doc, result)
      check_temperature(result)
      if doc.key?('nvme_smart_health_information_log')
        check_nvme(doc['nvme_smart_health_information_log'], result)
      else
        check_ata_attributes(doc, result)
      end
      result
    end

    private

    def unreadable(device)
      Result.new(device: device, model: '?', serial: '?', type: '?', temp_c: nil,
                 hours: nil, status: 'WARN', reasons: ['smartctl could not read device'],
                 critical_attrs: {})
    end

    # `smart_status.passed` is the drive firmware's own verdict. A "false" here
    # means the drive is already telling you it is failing -- CRIT, no debate.
    def check_overall_health(doc, r)
      passed = doc.dig('smart_status', 'passed')
      if passed == false
        escalate(r, 'CRIT', 'SMART overall-health self-assessment: FAILED')
      elsif passed.nil?
        escalate(r, 'WARN', 'SMART status unavailable (SMART disabled?)')
      end
    end

    def check_temperature(r)
      return if r.temp_c.nil?

      if r.temp_c >= @opts.temp_crit
        escalate(r, 'CRIT', "temperature #{r.temp_c}C >= #{@opts.temp_crit}C")
      elsif r.temp_c >= @opts.temp_warn
        escalate(r, 'WARN', "temperature #{r.temp_c}C >= #{@opts.temp_warn}C")
      end
    end

    # ATA/SATA: walk the attribute table and pull out the failure predictors.
    def check_ata_attributes(doc, r)
      table = doc.dig('ata_smart_attributes', 'table') || []
      table.each do |attr|
        id = attr['id']
        next unless CRITICAL_ATTRS.key?(id)

        raw = attr.dig('raw', 'value').to_i
        r.critical_attrs[CRITICAL_ATTRS[id]] = raw
        next if raw.zero?

        # Pending/uncorrectable sectors mean live data is already at risk.
        level = [197, 198].include?(id) ? 'CRIT' : 'WARN'
        level = 'CRIT' if id == 5 && raw >= @opts.realloc_warn * 10
        escalate(r, level, "#{CRITICAL_ATTRS[id]}=#{raw}")
      end
      # Attribute 'when_failed' set by firmware means threshold already crossed.
      failed = table.select { |a| a['when_failed'].to_s != '' }
      failed.each { |a| escalate(r, 'CRIT', "attribute #{a['name']} failed (#{a['when_failed']})") }
    end

    # NVMe exposes a different, simpler health log.
    def check_nvme(log, r)
      pct = log['percentage_used'].to_i
      r.critical_attrs['Percentage_Used'] = pct
      r.critical_attrs['Media_Errors'] = log['media_errors'].to_i
      r.critical_attrs['Unsafe_Shutdowns'] = log['unsafe_shutdowns'].to_i
      r.critical_attrs['Avail_Spare'] = log['available_spare'].to_i

      escalate(r, 'WARN', "NVMe percentage_used=#{pct}%") if pct >= @opts.nvme_pct_used_warn
      escalate(r, 'CRIT', "NVMe media_errors=#{log['media_errors']}") if log['media_errors'].to_i.positive?
      if log['available_spare'] && log['available_spare_threshold'] &&
         log['available_spare'] <= log['available_spare_threshold']
        escalate(r, 'CRIT', "NVMe available_spare #{log['available_spare']}% at/below threshold")
      end
      cw = log['critical_warning'].to_i
      escalate(r, 'CRIT', "NVMe critical_warning bitmask=0x#{cw.to_s(16)}") if cw.positive?
    end

    RANK = { 'OK' => 0, 'WARN' => 1, 'CRIT' => 2 }.freeze
    def escalate(r, level, reason)
      r.reasons << reason
      r.status = level if RANK[level] > RANK[r.status]
    end
  end

  # ---------------------------------------------------------------------------
  # Reporter: human table or JSON, plus the exit code.
  # ---------------------------------------------------------------------------
  class Reporter
    COLOR = { 'OK' => "\e[32m", 'WARN' => "\e[33m", 'CRIT' => "\e[31m" }.freeze

    def initialize(results, json: false)
      @results = results
      @json = json
    end

    def print
      @json ? print_json : print_table
    end

    def exit_code
      return 2 if @results.any? { |r| r.status == 'CRIT' }
      return 1 if @results.any? { |r| r.status == 'WARN' }

      0
    end

    private

    def print_json
      payload = {
        generated_at: Time.now.utc.iso8601,
        host: `hostname`.strip,
        summary: @results.group_by(&:status).transform_values(&:count),
        disks: @results.map(&:to_h)
      }
      puts JSON.pretty_generate(payload)
    end

    def print_table
      tty = $stdout.tty?
      puts format('%-14s %-26s %-6s %5s %8s  %-6s %s',
                  'DEVICE', 'MODEL', 'TYPE', 'TEMP', 'HOURS', 'STATUS', 'REASONS')
      puts '-' * 100
      @results.each do |r|
        status = tty ? "#{COLOR[r.status]}#{r.status}\e[0m" : r.status
        pad = tty ? 6 + 9 : 6 # compensate for escape codes when aligning
        puts format("%-14s %-26.26s %-6s %5s %8s  %-#{pad}s %s",
                    r.device, r.model, r.type,
                    r.temp_c ? "#{r.temp_c}C" : '-',
                    r.hours ? r.hours.to_s : '-',
                    status, r.reasons.empty? ? 'healthy' : r.reasons.join('; '))
      end
      puts
      counts = @results.group_by(&:status).transform_values(&:count)
      puts "#{@results.size} disk(s): #{counts.map { |k, v| "#{v} #{k}" }.join(', ')}"
    end
  end

  def self.parse_options(argv)
    opts = Options.new(json: false, fixtures: nil, temp_warn: 50, temp_crit: 60,
                       realloc_warn: 1, nvme_pct_used_warn: 80)
    OptionParser.new do |o|
      o.banner = 'Usage: smart_disk_health.rb [options]'
      o.on('--json', 'Emit JSON instead of a table') { opts.json = true }
      o.on('--fixtures DIR', 'Read smartctl JSON files from DIR instead of real disks') { |v| opts.fixtures = v }
      o.on('--temp-warn C', Integer, 'Temperature WARN threshold (default 50)') { |v| opts.temp_warn = v }
      o.on('--temp-crit C', Integer, 'Temperature CRIT threshold (default 60)') { |v| opts.temp_crit = v }
      o.on('--realloc-warn N', Integer, 'Reallocated sectors >= N*10 is CRIT (default 1)') { |v| opts.realloc_warn = v }
      o.on('--nvme-used-warn PCT', Integer, 'NVMe percentage_used WARN (default 80)') { |v| opts.nvme_pct_used_warn = v }
    end.parse!(argv)
    opts
  end

  def self.run(argv = ARGV)
    opts = parse_options(argv)
    raw = Collector.new(fixtures: opts.fixtures).collect
    analyzer = Analyzer.new(opts)
    results = raw.map { |dev, doc| analyzer.analyze(dev, doc) }
    reporter = Reporter.new(results, json: opts.json)
    reporter.print
    exit reporter.exit_code
  rescue StandardError => e
    warn "error: #{e.message}"
    exit 3
  end
end

SmartDiskHealth.run if $PROGRAM_NAME == __FILE__
