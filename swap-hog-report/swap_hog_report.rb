#!/usr/bin/env ruby
# frozen_string_literal: true
#
# swap_hog_report.rb -- find out WHICH processes are living in swap, not just
# that swap is "80% used".
#
# `free -m` tells you swap is nearly full. It does not tell you that a leaky
# Java heap and a forgotten Redis instance own 90% of it. This script walks
# /proc, reads VmSwap from every /proc/<pid>/status, and prints a ranked
# report with system-wide swap usage, swap devices, and a health verdict with
# a Nagios/systemd-friendly exit code.
#
# Usage:
#   ruby swap_hog_report.rb                  # top 10 swap consumers
#   ruby swap_hog_report.rb --top 25         # top 25
#   ruby swap_hog_report.rb --json           # machine-readable output
#   ruby swap_hog_report.rb --warn 60 --crit 85
#   ruby swap_hog_report.rb --root ./fixture # read a fake /proc tree (tests)
#
# Exit codes: 0 = OK, 1 = WARNING, 2 = CRITICAL, 3 = UNKNOWN (no swap / error)
#
# Requires: Ruby >= 2.7, Linux, stdlib only. Run as root to see every process;
# as a normal user you still see your own processes plus system-wide totals.

require 'optparse'
require 'json'

module SwapHog
  VERSION = '1.0.0'

  # ---------------------------------------------------------------------
  # Options
  # ---------------------------------------------------------------------
  Options = Struct.new(:root, :top, :json, :warn, :crit, :min_kb, keyword_init: true) do
    def self.parse(argv)
      o = new(root: '/', top: 10, json: false, warn: 50.0, crit: 80.0, min_kb: 0)
      OptionParser.new do |p|
        p.banner = 'Usage: swap_hog_report.rb [options]'
        p.on('--root DIR', 'Filesystem root containing /proc (default "/"; use a fixture dir for tests)') { |v| o.root = v }
        p.on('--top N', Integer, 'Show the N biggest swap consumers (default 10)') { |v| o.top = v }
        p.on('--json', 'Emit JSON instead of a human table') { o.json = true }
        p.on('--warn PCT', Float, 'WARNING threshold for swap-used %% (default 50)') { |v| o.warn = v }
        p.on('--crit PCT', Float, 'CRITICAL threshold for swap-used %% (default 80)') { |v| o.crit = v }
        p.on('--min-kb KB', Integer, 'Ignore processes swapping less than KB (default 0)') { |v| o.min_kb = v }
        p.on('-h', '--help') { puts p; exit 0 }
      end.parse!(argv)
      o
    end
  end

  # ---------------------------------------------------------------------
  # /proc readers -- every read is fault tolerant because processes exit
  # between the moment you list /proc and the moment you open their files.
  # ---------------------------------------------------------------------
  class ProcReader
    def initialize(root)
      @root = root
    end

    def path(*parts)
      File.join(@root, 'proc', *parts)
    end

    # /proc/meminfo -> { 'SwapTotal' => kb, 'SwapFree' => kb, ... }
    def meminfo
      out = {}
      File.foreach(path('meminfo')) do |line|
        key, val = line.split(':', 2)
        next unless val
        out[key.strip] = val.to_i # "12345 kB" -> 12345
      end
      out
    rescue Errno::ENOENT
      {}
    end

    # /proc/swaps -> [{ device:, type:, size_kb:, used_kb:, priority: }, ...]
    def swaps
      lines = File.readlines(path('swaps')).drop(1) # header row
      lines.map do |l|
        dev, type, size, used, prio = l.split
        { device: dev, type: type, size_kb: size.to_i, used_kb: used.to_i, priority: prio.to_i }
      end
    rescue Errno::ENOENT
      []
    end

    # Yields one hash per process that has VmSwap > 0.
    def each_process
      entries = begin
        Dir.children(path)
      rescue Errno::ENOENT
        raise ArgumentError, "no /proc under #{@root.inspect} -- is this Linux, or is --root wrong?"
      end
      entries.each do |entry|
        next unless entry.match?(/\A\d+\z/)
        info = process_info(entry)
        yield info if info
      end
    end

    private

    def process_info(pid)
      status = {}
      File.foreach(path(pid, 'status')) do |line|
        key, val = line.split(':', 2)
        status[key] = val.to_s.strip if val
      end
      swap_kb = status['VmSwap'].to_i
      return nil if swap_kb <= 0

      {
        pid: pid.to_i,
        name: status['Name'].to_s,
        uid: status['Uid'].to_s.split.first.to_i,
        swap_kb: swap_kb,
        rss_kb: status['VmRSS'].to_i,
        cmdline: cmdline(pid)
      }
    rescue Errno::ENOENT, Errno::ESRCH, Errno::EACCES
      nil # process vanished or we lack permission -- skip it
    end

    def cmdline(pid)
      raw = File.binread(path(pid, 'cmdline'))
      raw.split("\0").join(' ').strip
    rescue StandardError
      ''
    end
  end

  # ---------------------------------------------------------------------
  # Report model
  # ---------------------------------------------------------------------
  class Report
    attr_reader :total_kb, :free_kb, :used_kb, :swaps, :procs, :status, :opts

    def initialize(opts)
      @opts = opts
      reader = ProcReader.new(opts.root)
      mem = reader.meminfo
      @total_kb = mem.fetch('SwapTotal', 0)
      @free_kb  = mem.fetch('SwapFree', 0)
      @used_kb  = @total_kb - @free_kb
      @swaps    = reader.swaps
      @procs    = []
      reader.each_process { |p| @procs << p if p[:swap_kb] >= opts.min_kb }
      @procs.sort_by! { |p| -p[:swap_kb] }
      @status = verdict
    end

    def used_pct
      return 0.0 if total_kb.zero?
      (used_kb * 100.0 / total_kb).round(1)
    end

    def top
      procs.first(opts.top)
    end

    # How much of the used swap is explained by the top N? Useful to know
    # whether the problem is "one hog" or "death by a thousand daemons".
    def top_share_pct
      return 0.0 if used_kb.zero?
      (top.sum { |p| p[:swap_kb] } * 100.0 / used_kb).round(1)
    end

    def exit_code
      { 'OK' => 0, 'WARNING' => 1, 'CRITICAL' => 2 }.fetch(status, 3)
    end

    def to_h
      {
        status: status,
        swap: { total_kb: total_kb, used_kb: used_kb, free_kb: free_kb, used_pct: used_pct },
        devices: swaps,
        top_share_pct: top_share_pct,
        processes: top
      }
    end

    private

    def verdict
      return 'UNKNOWN' if total_kb.zero?
      return 'CRITICAL' if used_pct >= opts.crit
      return 'WARNING' if used_pct >= opts.warn
      'OK'
    end
  end

  # ---------------------------------------------------------------------
  # Output
  # ---------------------------------------------------------------------
  module Format
    module_function

    def human_kb(kb)
      return format('%.1f GiB', kb / 1024.0 / 1024.0) if kb >= 1024 * 1024
      return format('%.1f MiB', kb / 1024.0) if kb >= 1024
      "#{kb} KiB"
    end

    def table(report)
      io = +''
      io << "swap-hog-report v#{VERSION}  status=#{report.status}\n"
      io << format("swap: %s used of %s (%.1f%%)  free %s\n",
                   human_kb(report.used_kb), human_kb(report.total_kb),
                   report.used_pct, human_kb(report.free_kb))
      report.swaps.each do |s|
        io << format("  %-28s %-9s %10s used / %-10s prio %d\n",
                     s[:device], s[:type], human_kb(s[:used_kb]), human_kb(s[:size_kb]), s[:priority])
      end
      io << "\n"
      if report.procs.empty?
        io << "no processes currently hold swap\n"
        return io
      end
      io << format("%-7s %-6s %-20s %11s %11s  %s\n", 'PID', 'UID', 'NAME', 'SWAP', 'RSS', 'CMD')
      report.top.each do |p|
        cmd = p[:cmdline].empty? ? "[#{p[:name]}]" : p[:cmdline]
        io << format("%-7d %-6d %-20.20s %11s %11s  %.60s\n",
                     p[:pid], p[:uid], p[:name], human_kb(p[:swap_kb]), human_kb(p[:rss_kb]), cmd)
      end
      io << format("\ntop %d processes account for %.1f%% of used swap (%d swapping processes total)\n",
                   report.top.size, report.top_share_pct, report.procs.size)
      io
    end
  end

  def self.run(argv, out: $stdout)
    opts = Options.parse(argv)
    report = Report.new(opts)
    out.puts(opts.json ? JSON.pretty_generate(report.to_h) : Format.table(report))
    report.exit_code
  rescue Errno::EACCES => e
    out.puts "ERROR: #{e.message} (try running as root)"
    3
  rescue ArgumentError => e
    out.puts "UNKNOWN: #{e.message}"
    3
  end
end

exit SwapHog.run(ARGV) if $PROGRAM_NAME == __FILE__
