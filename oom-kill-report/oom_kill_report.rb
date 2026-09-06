#!/usr/bin/env ruby
# frozen_string_literal: true
#
# oom_kill_report.rb -- find out what the Linux OOM killer has been murdering.
#
# Reads kernel messages from `journalctl -k`, `dmesg`, or a saved log file,
# extracts every OOM-killer event, and summarizes: which processes were killed,
# how often, how much memory they held, which cgroup/container was over its
# limit, and a per-day timeline. Optional JSON output for alerting pipelines.
#
# Usage:
#   sudo ruby oom_kill_report.rb                     # journalctl -k --since -7d
#   sudo ruby oom_kill_report.rb --since "-24h"
#   ruby oom_kill_report.rb --file /var/log/kern.log  # or any saved dmesg/journal text
#   ruby oom_kill_report.rb --file kern.log --json
#   ruby oom_kill_report.rb --file kern.log --top 5
#
# Exit codes: 0 = no OOM kills found, 1 = at least one kill found, 3 = error.

require 'json'
require 'open3'
require 'optparse'
require 'time'

module OomKillReport
  # An OOM event is spread over many kernel lines. We anchor on the two lines
  # that always appear, in this order:
  #
  #   <who> invoked oom-killer: gfp_mask=0x..., order=0, oom_score_adj=0
  #   ...
  #   Out of memory: Killed process 4242 (java) total-vm:7891234kB, anon-rss:4123000kB, file-rss:0kB, shmem-rss:0kB, UID:1001 pgtables:9012kB oom_score_adj:0
  #
  # Older kernels (< 5.x) print "Killed process 4242 (java) total-vm:..., anon-rss:..., file-rss:..., shmem-rss:..." without the UID/pgtables.
  # cgroup-triggered kills add:
  #   Memory cgroup out of memory: Killed process ...
  #   memory: usage 524288kB, limit 524288kB, failcnt 1234
  #   oom-kill:constraint=CONSTRAINT_MEMCG,...,task_memcg=/docker/abc123...,task=java,pid=4242,uid=1001
  INVOKED_RE = /(?<invoker>\S+) invoked oom-killer:.*?gfp_mask=(?<gfp>0x[0-9a-f]+).*?order=(?<order>-?\d+)/
  KILLED_RE  = /(?<memcg>Memory cgroup out of memory|Out of memory): Killed process (?<pid>\d+) \((?<comm>[^)]+)\) total-vm:(?<vm>\d+)kB, anon-rss:(?<anon>\d+)kB, file-rss:(?<file>\d+)kB(?:, shmem-rss:(?<shmem>\d+)kB)?(?:, UID:(?<uid>\d+))?/
  CONSTRAINT_RE = /oom-kill:constraint=(?<constraint>\w+).*?task_memcg=(?<task_memcg>\S+?),task=/
  LIMIT_RE   = /memory: usage (?<usage>\d+)kB, limit (?<limit>\d+)kB, failcnt (?<failcnt>\d+)/
  # journalctl / syslog prefix: "Sep 05 12:34:56 host kernel: " or "2026-09-05T12:34:56.123456+00:00 host kernel: "
  TS_RE = /\A(?:(?<iso>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)|(?<syslog>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d))/
  # dmesg -T: "[Fri Sep  5 12:34:56 2026]"
  DMESG_T_RE = /\A\[(?<dm>[A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d \d{4})\]/

  Event = Struct.new(:timestamp, :invoker, :gfp_mask, :order, :pid, :comm,
                     :total_vm_kb, :anon_rss_kb, :file_rss_kb, :shmem_rss_kb, :uid,
                     :cgroup_kill, :constraint, :memcg, :memcg_usage_kb, :memcg_limit_kb,
                     keyword_init: true) do
    def rss_kb = anon_rss_kb.to_i + file_rss_kb.to_i + shmem_rss_kb.to_i
  end

  # ---------------------------------------------------------------------------
  class Source
    def initialize(file: nil, since: '-7d')
      @file = file
      @since = since
    end

    # Yields raw lines; picks the best available kernel-log source.
    def each_line(&blk)
      if @file
        File.foreach(@file, &blk)
      elsif command_exists?('journalctl')
        run(['journalctl', '-k', '--no-pager', '-o', 'short-iso', '--since', @since], &blk)
      else
        run(['dmesg', '-T'], &blk)
      end
    end

    private

    def command_exists?(cmd)
      ENV.fetch('PATH', '').split(File::PATH_SEPARATOR).any? { |d| File.executable?(File.join(d, cmd)) }
    end

    def run(cmd)
      out, err, status = Open3.capture3(*cmd)
      raise "#{cmd.first} failed: #{err.strip}" unless status.success?

      out.each_line { |l| yield l }
    end
  end

  # ---------------------------------------------------------------------------
  # Parser: a tiny state machine. "invoked oom-killer" opens a pending event,
  # the "Killed process" line closes it. Everything between enriches it.
  # ---------------------------------------------------------------------------
  class Parser
    def parse(lines)
      events = []
      pending = nil
      lines.each do |line|
        ts = extract_timestamp(line)
        if (m = INVOKED_RE.match(line))
          pending = Event.new(timestamp: ts, invoker: m[:invoker], gfp_mask: m[:gfp],
                              order: m[:order].to_i, cgroup_kill: false)
        elsif pending && (m = CONSTRAINT_RE.match(line))
          pending.constraint = m[:constraint]
          pending.memcg = m[:task_memcg]
        elsif pending && (m = LIMIT_RE.match(line))
          # Several "memory: usage" lines can appear (hierarchy); keep the first.
          pending.memcg_usage_kb ||= m[:usage].to_i
          pending.memcg_limit_kb ||= m[:limit].to_i
        elsif (m = KILLED_RE.match(line))
          # A kill line with no preceding "invoked" line (truncated log) still counts.
          ev = pending || Event.new(timestamp: ts, invoker: '?', gfp_mask: '?', order: nil)
          ev.timestamp ||= ts
          ev.cgroup_kill = m[:memcg].start_with?('Memory cgroup')
          ev.pid = m[:pid].to_i
          ev.comm = m[:comm]
          ev.total_vm_kb = m[:vm].to_i
          ev.anon_rss_kb = m[:anon].to_i
          ev.file_rss_kb = m[:file].to_i
          ev.shmem_rss_kb = m[:shmem].to_i
          ev.uid = m[:uid]&.to_i
          events << ev
          pending = nil
        end
      end
      events
    end

    private

    def extract_timestamp(line)
      if (m = TS_RE.match(line))
        m[:iso] ? Time.parse(m[:iso]) : Time.parse(m[:syslog])
      elsif (m = DMESG_T_RE.match(line))
        Time.parse(m[:dm])
      end
    rescue ArgumentError
      nil
    end
  end

  # ---------------------------------------------------------------------------
  class Report
    def initialize(events, top: 10)
      @events = events
      @top = top
    end

    def by_process
      @events.group_by(&:comm).map do |comm, evs|
        { comm: comm, kills: evs.size,
          max_rss_mb: (evs.map(&:rss_kb).max / 1024.0).round(1),
          avg_rss_mb: (evs.sum(&:rss_kb) / evs.size / 1024.0).round(1),
          cgroup_kills: evs.count(&:cgroup_kill) }
      end.sort_by { |h| -h[:kills] }.first(@top)
    end

    def by_cgroup
      @events.select(&:memcg).group_by(&:memcg).map do |cg, evs|
        { memcg: cg, kills: evs.size,
          limit_mb: (lim = evs.map(&:memcg_limit_kb).compact.max) ? lim / 1024 : nil }
      end.sort_by { |h| -h[:kills] }
    end

    def timeline
      @events.select(&:timestamp).group_by { |e| e.timestamp.strftime('%Y-%m-%d') }
             .transform_values(&:size).sort.to_h
    end

    def to_h
      { generated_at: Time.now.utc.iso8601, total_kills: @events.size,
        first: @events.map(&:timestamp).compact.min&.iso8601,
        last: @events.map(&:timestamp).compact.max&.iso8601,
        by_process: by_process, by_cgroup: by_cgroup, timeline: timeline,
        events: @events.map { |e| e.to_h.merge(timestamp: e.timestamp&.iso8601, rss_kb: e.rss_kb) } }
    end

    def print_text
      if @events.empty?
        puts 'No OOM-killer events found in the selected window.'
        return
      end
      first = @events.map(&:timestamp).compact.min
      last  = @events.map(&:timestamp).compact.max
      puts "OOM KILL REPORT  #{@events.size} kill(s)  #{first&.strftime('%Y-%m-%d %H:%M')} -> #{last&.strftime('%Y-%m-%d %H:%M')}"
      puts '=' * 78
      puts
      puts format('%-22s %5s %10s %10s %6s', 'PROCESS', 'KILLS', 'MAX RSS', 'AVG RSS', 'CGRP')
      by_process.each do |h|
        puts format('%-22.22s %5d %8.1fMB %8.1fMB %6d', h[:comm], h[:kills], h[:max_rss_mb], h[:avg_rss_mb], h[:cgroup_kills])
      end
      unless by_cgroup.empty?
        puts
        puts format('%-50s %5s %9s', 'CGROUP (memory limit)', 'KILLS', 'LIMIT')
        by_cgroup.each do |h|
          lim = h[:limit_mb] ? "#{h[:limit_mb]}MB" : 'no limit'
          puts format('%-50.50s %5d %9s', h[:memcg], h[:kills], lim)
        end
      end
      puts
      puts 'TIMELINE'
      max = timeline.values.max
      timeline.each { |day, n| puts format('  %s %-30s %d', day, '#' * (n * 30 / max), n) }
      puts
      puts 'MOST RECENT EVENTS'
      @events.last(5).reverse_each do |e|
        who = e.cgroup_kill ? "cgroup #{e.memcg}" : 'system-wide'
        puts format('  %s  pid %-6d %-16.16s rss %6.0fMB  %s  (invoked by %s)',
                    e.timestamp&.strftime('%m-%d %H:%M:%S') || '??-?? ??:??:??',
                    e.pid, e.comm, e.rss_kb / 1024.0, who, e.invoker)
      end
    end
  end

  def self.run(argv = ARGV)
    opts = { file: nil, since: '-7d', json: false, top: 10 }
    OptionParser.new do |o|
      o.banner = 'Usage: oom_kill_report.rb [options]'
      o.on('--file PATH', 'Parse a saved kernel log instead of journalctl/dmesg') { |v| opts[:file] = v }
      o.on('--since WHEN', 'journalctl --since value (default "-7d")') { |v| opts[:since] = v }
      o.on('--json', 'Emit JSON') { opts[:json] = true }
      o.on('--top N', Integer, 'Show top N processes (default 10)') { |v| opts[:top] = v }
    end.parse!(argv)

    lines = []
    Source.new(file: opts[:file], since: opts[:since]).each_line { |l| lines << l }
    events = Parser.new.parse(lines)
    report = Report.new(events, top: opts[:top])
    opts[:json] ? puts(JSON.pretty_generate(report.to_h)) : report.print_text
    exit(events.empty? ? 0 : 1)
  rescue StandardError => e
    warn "error: #{e.message}"
    exit 3
  end
end

OomKillReport.run if $PROGRAM_NAME == __FILE__
