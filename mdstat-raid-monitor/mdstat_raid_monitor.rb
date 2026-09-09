#!/usr/bin/env ruby
# frozen_string_literal: true
#
# mdstat_raid_monitor.rb - Linux software RAID (md) health monitor
#
# Parses /proc/mdstat (no root, no mdadm binary required), reports every
# array's level, member disks, failed members, and any running
# resync/recovery/check/reshape with progress and ETA. Exits with a
# Nagios/Icinga-compatible code so it can be dropped straight into cron,
# a systemd timer, or a monitoring check:
#
#   0 = OK        all arrays clean
#   1 = WARNING   a rebuild/resync/check is in progress (array still fully readable)
#   2 = CRITICAL  an array is degraded or has failed members / inactive
#   3 = UNKNOWN   /proc/mdstat unreadable or no md arrays found
#
# Usage:
#   ruby mdstat_raid_monitor.rb                 # human-readable report
#   ruby mdstat_raid_monitor.rb --json          # machine-readable JSON
#   ruby mdstat_raid_monitor.rb --file test.txt # parse a saved mdstat (for testing)
#   ruby mdstat_raid_monitor.rb --quiet         # only print when not OK (cron-friendly)
#
# Ruby >= 2.7, stdlib only.

require 'json'
require 'optparse'

module MdstatMonitor
  VERSION = '1.0.0'
  MDSTAT_PATH = '/proc/mdstat'

  # One entry per array found in /proc/mdstat.
  Array_ = Struct.new(
    :name, :active, :level, :members, :failed_members, :spare_members,
    :total_slots, :working_slots, :status_map, :operation, :progress_pct,
    :finish_min, :speed_kbs, :degraded, keyword_init: true
  ) do
    def state
      return 'INACTIVE' unless active
      return 'DEGRADED' if degraded
      return operation.upcase if operation

      'CLEAN'
    end
  end

  # Pure parser: takes the text of /proc/mdstat, returns an Array of Array_.
  class Parser
    # Example header line:
    #   md0 : active raid1 sdb1[1] sda1[0](F) sdc1[2](S)
    HEADER = /\A(md\d+)\s*:\s*(\w+)\s+(?:\((?:auto-)?read-only\)\s+)?(\S+)\s+(.*)\z/.freeze
    MEMBER = /(\S+?)\[(\d+)\]((?:\([A-Z]\))*)/.freeze
    # Example status line:
    #   1953382400 blocks super 1.2 [2/2] [UU]
    STATUS = /\[(\d+)\/(\d+)\]\s+\[([U_]+)\]/.freeze
    # Example progress line:
    #   [=====>...............]  recovery = 27.4% (535938432/1953382400) finish=118.2min speed=199568K/sec
    PROGRESS = /\]\s+(resync|recovery|reshape|check)\s*=\s*([\d.]+)%.*?finish=([\d.]+)min\s+speed=(\d+)K\/sec/.freeze

    def parse(text)
      arrays = []
      current = nil

      text.each_line do |raw|
        line = raw.rstrip
        next if line.empty?

        if (m = HEADER.match(line))
          current = build_array(m)
          arrays << current
          next
        end
        next unless current # skip "Personalities :" and "unused devices:" lines

        if (m = STATUS.match(line))
          current.total_slots   = m[1].to_i
          current.working_slots = m[2].to_i
          current.status_map    = m[3]
          current.degraded      = m[3].include?('_') || m[2].to_i < m[1].to_i
        elsif (m = PROGRESS.match(line))
          current.operation    = m[1]
          current.progress_pct = m[2].to_f
          current.finish_min   = m[3].to_f
          current.speed_kbs    = m[4].to_i
        elsif line =~ /resync=(PENDING|DELAYED)/
          current.operation = "resync-#{Regexp.last_match(1).downcase}"
        end
      end
      arrays
    end

    private

    def build_array(m)
      members = m[4].scan(MEMBER).map { |dev, slot, flags| [dev, slot.to_i, flags] }
      Array_.new(
        name: m[1],
        active: m[2] == 'active',
        level: m[3],
        members: members.map(&:first),
        failed_members: members.select { |_, _, f| f.include?('(F)') }.map(&:first),
        spare_members:  members.select { |_, _, f| f.include?('(S)') }.map(&:first),
        total_slots: 0, working_slots: 0, status_map: '',
        operation: nil, progress_pct: nil, finish_min: nil, speed_kbs: nil,
        degraded: m[2] != 'active'
      )
    end
  end

  # Turns parsed arrays into an exit code + summary line.
  class Evaluator
    OK = 0
    WARNING = 1
    CRITICAL = 2
    UNKNOWN = 3

    def evaluate(arrays)
      return [UNKNOWN, 'UNKNOWN - no md arrays found'] if arrays.empty?

      crit = arrays.select { |a| !a.active || a.degraded || a.failed_members.any? }
      warn = arrays.select { |a| a.operation && !crit.include?(a) }

      if crit.any?
        [CRITICAL, "CRITICAL - #{crit.map { |a| "#{a.name} #{a.state}" }.join(', ')}"]
      elsif warn.any?
        [WARNING, "WARNING - #{warn.map { |a| "#{a.name} #{a.operation} #{a.progress_pct}%" }.join(', ')}"]
      else
        [OK, "OK - #{arrays.size} array(s) clean: #{arrays.map(&:name).join(', ')}"]
      end
    end
  end

  # Rendering helpers.
  class Report
    def self.text(arrays, summary)
      out = [summary, '']
      arrays.each do |a|
        out << format('%-6s %-8s %-9s slots %d/%d %s',
                      a.name, a.level, a.state, a.working_slots, a.total_slots, a.status_map)
        out << "       members : #{a.members.join(' ')}"
        out << "       FAILED  : #{a.failed_members.join(' ')}" if a.failed_members.any?
        out << "       spares  : #{a.spare_members.join(' ')}" if a.spare_members.any?
        if a.progress_pct
          eta = a.finish_min >= 60 ? format('%.1fh', a.finish_min / 60) : format('%.0fmin', a.finish_min)
          out << format('       %-8s: %.1f%%  ETA %s  @ %d MB/s', a.operation, a.progress_pct, eta, a.speed_kbs / 1024)
        end
      end
      out.join("\n")
    end

    def self.json(arrays, code, summary)
      JSON.pretty_generate(
        status: %w[OK WARNING CRITICAL UNKNOWN][code],
        summary: summary,
        checked_at: Time.now.utc.iso8601,
        arrays: arrays.map { |a| a.to_h.merge(state: a.state) }
      )
    end
  end

  def self.run(argv)
    opts = { file: MDSTAT_PATH, json: false, quiet: false }
    OptionParser.new do |o|
      o.banner = 'Usage: mdstat_raid_monitor.rb [--file PATH] [--json] [--quiet]'
      o.on('--file PATH', 'Parse this file instead of /proc/mdstat') { |v| opts[:file] = v }
      o.on('--json', 'Emit JSON') { opts[:json] = true }
      o.on('--quiet', 'Print nothing when status is OK') { opts[:quiet] = true }
      o.on('-v', '--version') { puts VERSION; exit 0 }
    end.parse!(argv)

    text = begin
      File.read(opts[:file])
    rescue Errno::ENOENT, Errno::EACCES => e
      puts "UNKNOWN - cannot read #{opts[:file]}: #{e.message}"
      exit Evaluator::UNKNOWN
    end

    arrays = Parser.new.parse(text)
    code, summary = Evaluator.new.evaluate(arrays)

    if opts[:json]
      puts Report.json(arrays, code, summary)
    elsif !(opts[:quiet] && code == Evaluator::OK)
      puts Report.text(arrays, summary)
    end
    exit code
  end
end

require 'time'
MdstatMonitor.run(ARGV) if $PROGRAM_NAME == __FILE__
