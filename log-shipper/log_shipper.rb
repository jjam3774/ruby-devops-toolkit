#!/usr/bin/env ruby
# frozen_string_literal: true
#
# log_shipper.rb — tail one or more log files and forward new lines to a
# syslog (RFC 5424 / UDP) and/or HTTP sink in real time, picking up exactly
# where it left off after a restart and coping with log rotation. Pure
# Ruby, no gems (Socket, Net::HTTP, JSON are all stdlib).
#
# Typical uses:
#   ./log_shipper.rb --file /var/log/app.log --http http://collector:9000/ingest --once
#   ./log_shipper.rb --file /var/log/app.log --file /var/log/nginx/error.log \
#       --syslog logs.example.com:514 --follow
#
# State (per file: inode + byte offset) is persisted to --state-file as
# JSON between runs, so `--once` invocations from cron never re-ship or
# drop lines, and a rotated file (new inode at the same path) is detected
# and re-read from byte 0 instead of silently going stale.
#
# Exit codes:
#   0 = every new line shipped to every configured sink
#   1 = some lines failed to ship to at least one sink (partial failure)
#   2 = fatal error (no files found, unreadable/corrupt state file)
#
# Requires: Ruby >= 2.7. No gems.

require 'socket'
require 'net/http'
require 'uri'
require 'json'
require 'optparse'
require 'time'

module LogShipper
  # Tracks (inode, offset) per watched file across runs, so a `--once` cron
  # invocation resumes exactly where the previous one stopped.
  class StateStore
    def initialize(path)
      @path = path
      @state = load
    end

    def offset_for(file_path, current_inode)
      entry = @state[file_path]
      return 0 unless entry
      # A changed inode means the file was rotated (truncated+reused name,
      # or replaced) -- start over from the beginning of the new file.
      entry['inode'] == current_inode ? entry['offset'] : 0
    end

    def update(file_path, inode, offset)
      @state[file_path] = { 'inode' => inode, 'offset' => offset }
    end

    def save
      File.write(@path, JSON.pretty_generate(@state))
    end

    private

    def load
      return {} unless @path && File.exist?(@path)

      JSON.parse(File.read(@path))
    rescue JSON::ParserError => e
      raise "state file #{@path} is corrupt: #{e.message}"
    end
  end

  # Reads new lines appended to a file since the last recorded offset.
  # Returns [lines, new_offset, inode].
  class TailReader
    def read_new_lines(path, state)
      inode = File.stat(path).ino
      start_offset = state.offset_for(path, inode)

      size = File.size(path)
      start_offset = 0 if start_offset > size # file was truncated in place

      lines = []
      File.open(path, 'r') do |f|
        f.seek(start_offset)
        lines = f.each_line.to_a
      end
      new_offset = start_offset + lines.sum(&:bytesize)
      state.update(path, inode, new_offset)
      [lines.map(&:chomp), new_offset, inode]
    end
  end

  # RFC 5424 syslog message formatting + UDP delivery. Isolated behind
  # #send so it can be swapped for a fake in tests without opening a real
  # socket, and so the wire format is unit-testable on its own.
  class SyslogSink
    FACILITY_USER = 1

    def initialize(host, port, app_name: 'log_shipper', udp_socket: nil)
      @host = host
      @port = port
      @app_name = app_name
      @socket = udp_socket || UDPSocket.new
    end

    def self.format_message(text, facility: FACILITY_USER, severity: 6, app_name: 'log_shipper', hostname: nil)
      pri = (facility * 8) + severity
      ts = Time.now.utc.strftime('%Y-%m-%dT%H:%M:%S.%3NZ')
      host = hostname || (Socket.gethostname rescue 'unknown-host')
      "<#{pri}>1 #{ts} #{host} #{app_name} #{Process.pid} - - #{text}"
    end

    def send(line)
      msg = self.class.format_message(line, app_name: @app_name)
      @socket.send(msg, 0, @host, @port)
      true
    rescue StandardError => e
      warn("warning: syslog delivery failed: #{e.message}")
      false
    end
  end

  # Batches lines into a single JSON POST per flush. Isolated behind
  # #send_batch so tests can point it at a real local HTTP stub (see
  # test_log_shipper.rb) rather than mocking Net::HTTP.
  class HttpSink
    def initialize(endpoint_url, source_tag: nil)
      @uri = URI.parse(endpoint_url)
      @source_tag = source_tag
    end

    def send_batch(file_path, lines)
      return true if lines.empty?

      http = Net::HTTP.new(@uri.host, @uri.port)
      http.use_ssl = @uri.scheme == 'https'
      req = Net::HTTP::Post.new(@uri, 'Content-Type' => 'application/json')
      req.body = JSON.generate(source: @source_tag || file_path, lines: lines)
      resp = http.request(req)
      resp.code.to_i < 400
    rescue StandardError => e
      warn("warning: http delivery failed: #{e.message}")
      false
    end
  end

  # Coordinates reading new lines from each watched file and fanning them
  # out to every configured sink, tallying per-file success/failure.
  class Shipper
    def initialize(files:, state:, sinks:, reader: TailReader.new)
      @files = files
      @state = state
      @sinks = sinks
      @reader = reader
    end

    # Returns a summary hash: {file => {shipped: N, failed_sinks: [...]}}
    def run_once
      summary = {}
      @files.each do |path|
        unless File.readable?(path)
          summary[path] = { shipped: 0, error: 'unreadable or missing' }
          next
        end

        lines, = @reader.read_new_lines(path, @state)
        ok_count = 0
        failed_sinks = []

        lines.each do |line|
          next if line.strip.empty?

          line_ok = true
          @sinks.each do |name, sink|
            unless sink_send(sink, path, line)
              failed_sinks << name
              line_ok = false
            end
          end
          ok_count += 1 if line_ok
        end

        summary[path] = { shipped: ok_count, total_new_lines: lines.length, failed_sinks: failed_sinks.uniq }
      end
      @state.save
      summary
    end

    private

    def sink_send(sink, path, line)
      case sink
      when SyslogSink then sink.send(line)
      when HttpSink then sink.send_batch(path, [line])
      else false
      end
    end
  end

  class CLI
    def self.run(argv)
      options = { files: [], once: false, json: false, poll_interval: 2 }
      parser = OptionParser.new do |o|
        o.banner = 'Usage: log_shipper.rb --file PATH [--file PATH ...] [--syslog HOST:PORT] [--http URL] [--once|--follow] [options]'
        o.on('--file PATH', 'Log file to tail (repeatable)') { |f| options[:files] << f }
        o.on('--state-file PATH', 'Where to persist per-file offsets (default: ./.log_shipper_state.json)') { |s| options[:state_file] = s }
        o.on('--syslog HOST:PORT', 'Ship to this syslog server over UDP (RFC 5424)') { |s| options[:syslog] = s }
        o.on('--http URL', 'Ship to this HTTP endpoint as batched JSON POSTs') { |u| options[:http] = u }
        o.on('--once', 'Read to EOF once and exit (cron-friendly)') { options[:once] = true }
        o.on('--follow', 'Keep polling for new lines (like tail -f)') { options[:once] = false }
        o.on('--poll-interval N', Float, 'Seconds between polls in --follow mode (default 2)') { |n| options[:poll_interval] = n }
        o.on('--json', 'Emit a machine-readable JSON summary') { options[:json] = true }
      end
      parser.parse!(argv)

      abort('at least one --file is required') if options[:files].empty?
      missing = options[:files].reject { |f| File.exist?(f) }
      unless missing.empty?
        warn("error: file(s) not found: #{missing.join(', ')}")
        exit 2
      end

      state = begin
        StateStore.new(options[:state_file] || './.log_shipper_state.json')
      rescue StandardError => e
        warn("error: #{e.message}")
        exit 2
      end

      sinks = {}
      if options[:syslog]
        host, port = options[:syslog].split(':')
        sinks[:syslog] = SyslogSink.new(host, port.to_i)
      end
      sinks[:http] = HttpSink.new(options[:http]) if options[:http]

      shipper = Shipper.new(files: options[:files], state: state, sinks: sinks)

      loop do
        summary = shipper.run_once
        if options[:json]
          puts JSON.pretty_generate(summary)
        else
          summary.each do |file, s|
            if s[:error]
              puts "#{file}: ERROR (#{s[:error]})"
            else
              status = s[:failed_sinks].empty? ? 'ok' : "partial (failed: #{s[:failed_sinks].join(',')})"
              puts "#{file}: shipped #{s[:shipped]}/#{s[:total_new_lines]} new lines [#{status}]"
            end
          end
        end

        had_failure = summary.values.any? { |s| s[:error] || !s[:failed_sinks].to_a.empty? }
        break exit(had_failure ? 1 : 0) if options[:once]

        sleep options[:poll_interval]
      end
    end
  end
end

LogShipper::CLI.run(ARGV) if $PROGRAM_NAME == __FILE__
