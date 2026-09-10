#!/usr/bin/env ruby
# frozen_string_literal: true
#
# stale_mount_detector.rb -- find hung or stale network mounts (NFS, CIFS/SMB,
# SSHFS, GlusterFS, CephFS) BEFORE `df` hangs your monitoring agent.
#
# A dead NFS server does not produce an error; it produces a process stuck in
# uninterruptible sleep (state "D"). Any tool that innocently stat()s the
# mountpoint -- df, ls, your backup job, your Nagios check -- joins it there.
# This script reads /proc/mounts, keeps only network filesystems, and probes
# each mountpoint in a *separate thread with a hard timeout*, so a hung mount
# is reported as HUNG instead of hanging the reporter.
#
# Usage:
#   ruby stale_mount_detector.rb                 # probe all network mounts
#   ruby stale_mount_detector.rb --timeout 3     # seconds per mount (default 5)
#   ruby stale_mount_detector.rb --json          # machine readable
#   ruby stale_mount_detector.rb --types nfs,nfs4,cifs
#   ruby stale_mount_detector.rb --root ./fixture  # fake /proc/mounts for tests
#
# Exit codes: 0 = all OK, 1 = at least one WARNING (read-only/unknown),
#             2 = at least one HUNG or STALE mount, 3 = could not read mounts
#
# Requires: Ruby >= 2.7, Linux, stdlib only. No root needed.

require 'optparse'
require 'json'

module StaleMount
  VERSION = '1.0.0'
  NETWORK_TYPES = %w[nfs nfs4 cifs smb3 smbfs fuse.sshfs fuse.glusterfs glusterfs ceph fuse.ceph 9p afs].freeze

  Options = Struct.new(:root, :timeout, :json, :types, :all, keyword_init: true) do
    def self.parse(argv)
      o = new(root: '/', timeout: 5.0, json: false, types: NETWORK_TYPES, all: false)
      OptionParser.new do |p|
        p.banner = 'Usage: stale_mount_detector.rb [options]'
        p.on('--root DIR', 'Root containing /proc/mounts and the mountpoints (default "/")') { |v| o.root = v }
        p.on('--timeout SEC', Float, 'Seconds to wait per mount before calling it HUNG (default 5)') { |v| o.timeout = v }
        p.on('--types LIST', Array, 'Comma-separated fs types to probe (default: common network types)') { |v| o.types = v }
        p.on('--all', 'Probe every mount, not just network types') { o.all = true }
        p.on('--json', 'Emit JSON') { o.json = true }
        p.on('-h', '--help') { puts p; exit 0 }
      end.parse!(argv)
      o
    end
  end

  Mount = Struct.new(:device, :point, :type, :options, keyword_init: true) do
    def read_only?
      options.split(',').include?('ro')
    end
  end

  # Parses /proc/mounts. Mountpoints with spaces are octal-escaped (\040) in
  # that file, so we unescape them -- a classic gotcha.
  class MountTable
    def self.load(root)
      file = File.join(root, 'proc', 'mounts')
      File.readlines(file).filter_map do |line|
        dev, point, type, opts = line.split(' ')
        next unless point
        Mount.new(device: unescape(dev), point: unescape(point), type: type, options: opts.to_s)
      end
    end

    def self.unescape(s)
      s.gsub(/\\(\d{3})/) { Regexp.last_match(1).to_i(8).chr }
    end
  end

  # Probes one mountpoint with a hard timeout. We deliberately do NOT use
  # Timeout.timeout: it cannot interrupt a thread stuck in a D-state syscall.
  # Instead we spawn a thread, wait with Thread#join(timeout), and simply
  # abandon the thread if it does not come back. The abandoned thread is
  # cleaned up when the process exits.
  class Prober
    Result = Struct.new(:mount, :state, :latency_ms, :detail, keyword_init: true)

    def initialize(timeout:, root: '/')
      @timeout = timeout
      @root = root
    end

    def probe(mount)
      path = @root == '/' ? mount.point : File.join(@root, mount.point)
      started = clock
      outcome = nil
      worker = begin
        Thread.new { outcome = touch(path) }
      rescue NotImplementedError
        # Platforms without native threads (e.g. ruby.wasm test harness):
        # fall back to a synchronous probe. On real Linux this never runs.
        outcome = touch(path)
        nil
      end
      finished = worker.nil? ? true : !worker.join(@timeout).nil?
      ms = ((clock - started) * 1000).round

      return Result.new(mount: mount, state: 'HUNG', latency_ms: ms,
                        detail: "no response in #{@timeout}s (thread abandoned)") unless finished

      state, detail = outcome
      state = 'WARNING' if state == 'OK' && mount.read_only?
      detail = 'mounted read-only' if state == 'WARNING' && detail.nil?
      Result.new(mount: mount, state: state, latency_ms: ms, detail: detail)
    end

    private

    # Two cheap syscalls: stat() the mountpoint, then list one directory
    # entry. NFS returns ESTALE when the server-side handle is gone.
    def touch(path)
      File.stat(path)
      Dir.each_child(path).first
      ['OK', nil]
    rescue Errno::ESTALE
      ['STALE', 'ESTALE: stale file handle -- server export changed or was rebooted']
    rescue Errno::ENOENT
      ['STALE', 'ENOENT: mountpoint directory missing']
    rescue Errno::EACCES
      ['OK', 'EACCES on listing (mount responsive, permission denied)']
    rescue Errno::EIO, Errno::ENOTCONN, Errno::EHOSTDOWN, Errno::EHOSTUNREACH => e
      ['HUNG', "#{e.class.name.split('::').last}: #{e.message}"]
    rescue SystemCallError => e
      ['WARNING', "#{e.class.name.split('::').last}: #{e.message}"]
    end

    def clock
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end
  end

  class Report
    RANK = { 'OK' => 0, 'WARNING' => 1, 'STALE' => 2, 'HUNG' => 2 }.freeze
    attr_reader :results

    def initialize(results)
      @results = results
    end

    def exit_code
      results.map { |r| RANK.fetch(r.state, 1) }.max || 0
    end

    def summary
      counts = Hash.new(0)
      results.each { |r| counts[r.state] += 1 }
      counts
    end

    def to_h
      {
        status: exit_code.zero? ? 'OK' : (exit_code == 1 ? 'WARNING' : 'CRITICAL'),
        summary: summary,
        mounts: results.map do |r|
          { point: r.mount.point, device: r.mount.device, type: r.mount.type,
            state: r.state, latency_ms: r.latency_ms, detail: r.detail }
        end
      }
    end

    def table
      io = +"stale-mount-detector v#{VERSION}\n"
      if results.empty?
        io << "no network mounts found (use --all to probe everything)\n"
        return io
      end
      io << format("%-8s %8s  %-11s %-28s %-36s %s\n", 'STATE', 'LATENCY', 'TYPE', 'MOUNTPOINT', 'DEVICE', 'DETAIL')
      results.each do |r|
        io << format("%-8s %6dms  %-11s %-28.28s %-36.36s %s\n",
                     r.state, r.latency_ms, r.mount.type, r.mount.point, r.mount.device, r.detail.to_s)
      end
      io << "\n" << summary.map { |k, v| "#{k}=#{v}" }.join('  ') << "\n"
      io
    end
  end

  def self.run(argv, out: $stdout)
    opts = Options.parse(argv)
    mounts = MountTable.load(opts.root)
    mounts = mounts.select { |m| opts.types.include?(m.type) } unless opts.all
    prober = Prober.new(timeout: opts.timeout, root: opts.root)
    report = Report.new(mounts.map { |m| prober.probe(m) })
    out.puts(opts.json ? JSON.pretty_generate(report.to_h) : report.table)
    report.exit_code
  rescue Errno::ENOENT => e
    out.puts "UNKNOWN: cannot read mount table (#{e.message})"
    3
  end
end

exit StaleMount.run(ARGV) if $PROGRAM_NAME == __FILE__
