#!/usr/bin/env ruby
# frozen_string_literal: true
#
# win_rdp_session_manager.rb — audit and clean up Remote Desktop / Terminal
# Services sessions on a Windows host (or RDS farm member) by driving the
# built-in `quser`/`logoff` command-line tools from Ruby. No gems, no WMI —
# just Open3 and careful parsing of quser's fixed-width columns.
#
# Typical uses:
#   ruby win_rdp_session_manager.rb list
#   ruby win_rdp_session_manager.rb report --idle-minutes 120 --disc-minutes 30 --json
#   ruby win_rdp_session_manager.rb logoff 7 --dry-run
#
# Exit codes (for monitoring/cron integration):
#   0 = no session exceeds the configured idle/disconnected thresholds
#   1 = at least one session exceeds a threshold (flagged, not yet acted on)
#   2 = quser could not be reached at all (not on Windows, Terminal Services
#       down, RPC unreachable on a remote --server)
#
# Requires: Ruby >= 2.7, Windows with the Remote Desktop Services role tools
# (quser.exe / logoff.exe ship with every Windows Server and most desktop
# SKUs). No gems.

require 'json'
require 'optparse'

module WinRdpSessionManager
  class QuserUnreachable < StandardError; end

  Session = Struct.new(:username, :session_name, :id, :state, :idle_minutes, :idle_raw,
                        :logon_time, :current, keyword_init: true)

  # Every `quser`/`logoff` invocation goes through this one seam (default:
  # Open3), so the column-offset parsing and threshold logic below can be
  # fully exercised against real captured quser output without a Windows
  # host, exactly like the systemd/win32ole tools elsewhere in this repo.
  class SessionInspector
    def initialize(server: nil, runner: nil)
      @server = server
      @runner = runner || method(:default_runner)
    end

    def list
      cmd = ['quser']
      cmd += ['/server:' + @server] if @server
      out, err, status = @runner.call(cmd)

      # quser exits 1 with "No User exists for *" when nobody is logged on --
      # that's a valid empty result, not a failure to reach the tool at all.
      if !status.success? && !err.to_s.include?('No User exists')
        raise QuserUnreachable, "quser failed: #{err.strip.empty? ? out.strip : err.strip}"
      end

      QuserParser.parse(out)
    end

    def logoff(session_id, dry_run: false)
      cmd = ['logoff', session_id.to_s]
      cmd += ['/server:' + @server] if @server

      return { dry_run: true, command: cmd.join(' ') } if dry_run

      out, err, status = @runner.call(cmd)
      { dry_run: false, command: cmd.join(' '), ok: status.success?, stdout: out.strip, stderr: err.strip }
    end

    private

    def default_runner(cmd)
      require 'open3'
      Open3.capture3(*cmd)
    end
  end

  # quser's columns are fixed-width, not delimiter-separated -- a
  # disconnected session leaves SESSIONNAME blank, which would silently
  # shift every field left if you naively split on whitespace. Instead we
  # find each column's start offset from the header row and slice every
  # data row at those same offsets, which is the standard trick for
  # parsing this particular tool reliably.
  class QuserParser
    COLUMNS = %w[USERNAME SESSIONNAME ID STATE IDLE\ TIME LOGON\ TIME].freeze

    def self.parse(raw)
      lines = raw.each_line.map(&:rstrip).reject(&:empty?)
      return [] if lines.empty?

      header = lines.shift
      offsets = column_offsets(header)
      return [] if offsets.nil? # "No User exists for *" or unrecognized output

      lines.filter_map { |line| parse_row(line, offsets) }
    end

    def self.column_offsets(header)
      positions = COLUMNS.map { |c| [c, header.index(c)] }.to_h
      return nil if positions.values.any?(&:nil?)

      positions
    end
    private_class_method :column_offsets

    def self.parse_row(line, offsets)
      current = line.start_with?('>')
      line = ' ' + line[1..] if current # normalize so column offsets still line up

      username = slice(line, offsets['USERNAME'], offsets['SESSIONNAME']).strip
      session_name = slice(line, offsets['SESSIONNAME'], offsets['ID']).strip
      id = slice(line, offsets['ID'], offsets['STATE']).strip
      state = slice(line, offsets['STATE'], offsets['IDLE TIME']).strip
      idle_raw = slice(line, offsets['IDLE TIME'], offsets['LOGON TIME']).strip
      logon_time = slice(line, offsets['LOGON TIME'], nil).strip

      return nil if username.empty? || id.empty?

      Session.new(
        username: username, session_name: session_name, id: id.to_i,
        state: state.empty? ? 'Active' : state, # quser leaves STATE blank for the active console session
        idle_minutes: IdleTime.to_minutes(idle_raw), idle_raw: idle_raw,
        logon_time: logon_time, current: current
      )
    end
    private_class_method :parse_row

    def self.slice(line, from, to)
      return '' if from.nil? || from >= line.length

      to.nil? ? line[from..] : line[from...[to, line.length].min]
    end
    private_class_method :slice
  end

  # Converts quser's IDLE TIME column ("." / "none" / "23" / "2:15" /
  # "1+02:15") into whole minutes, or nil when there's no meaningful value.
  module IdleTime
    def self.to_minutes(raw)
      case raw
      when '.', ''   then 0
      when 'none'    then nil
      when /\A(\d+)\z/ then Regexp.last_match(1).to_i
      when /\A(\d+):(\d+)\z/ then Regexp.last_match(1).to_i * 60 + Regexp.last_match(2).to_i
      when /\A(\d+)\+(\d+):(\d+)\z/
        d, h, m = Regexp.last_match.captures.map(&:to_i)
        (d * 24 * 60) + (h * 60) + m
      end
    end
  end

  # Flags sessions that have been idle, or disconnected, longer than the
  # configured thresholds. A disconnected session's IDLE TIME keeps
  # counting from whenever the user last had input focus, so it doubles
  # reasonably well as "time since disconnect" for this purpose -- noted
  # in the README, since it's an approximation, not something quser
  # reports directly.
  class ThresholdEvaluator
    def initialize(idle_minutes:, disc_minutes:)
      @idle_minutes = idle_minutes
      @disc_minutes = disc_minutes
    end

    def flag(session)
      return :current if session.current
      return :disconnected_too_long if session.state == 'Disc' && over?(session, @disc_minutes)
      return :idle_too_long if session.state == 'Active' && over?(session, @idle_minutes)

      :ok
    end

    def exit_code_for(flags)
      flags.any? { |f| f != :ok && f != :current } ? 1 : 0
    end

    private

    def over?(session, threshold)
      !threshold.nil? && !session.idle_minutes.nil? && session.idle_minutes >= threshold
    end
  end

  class CLI
    def self.run(argv)
      options = { json: false, idle_minutes: 120, disc_minutes: 60 }
      parser = OptionParser.new do |o|
        o.banner = 'Usage: win_rdp_session_manager.rb <list|report|logoff> [id] [options]'
        o.on('--server NAME', 'Query a remote RDS host instead of the local one') { |s| options[:server] = s }
        o.on('--idle-minutes N', Integer, 'Flag Active sessions idle at least this long (default 120)') { |n| options[:idle_minutes] = n }
        o.on('--disc-minutes N', Integer, 'Flag Disc sessions disconnected at least this long (default 60)') { |n| options[:disc_minutes] = n }
        o.on('--dry-run', 'For logoff: print the command instead of running it') { options[:dry_run] = true }
        o.on('--json', 'Emit machine-readable JSON') { options[:json] = true }
      end
      parser.parse!(argv)

      command = argv.shift
      inspector = SessionInspector.new(server: options[:server])

      case command
      when 'list'
        sessions = with_error_handling { inspector.list }
        emit(sessions.map(&:to_h), options[:json]) { |list| print_list(list) }
        exit 0

      when 'report'
        sessions = with_error_handling { inspector.list }
        evaluator = ThresholdEvaluator.new(idle_minutes: options[:idle_minutes], disc_minutes: options[:disc_minutes])
        flags = sessions.map { |s| evaluator.flag(s) }
        report = sessions.zip(flags).map { |s, f| s.to_h.merge(flag: f.to_s) }
        emit(report, options[:json]) { |list| print_report(list) }
        exit evaluator.exit_code_for(flags)

      when 'logoff'
        id = argv.first
        abort('usage: logoff <session-id> [--dry-run] [--server NAME]') unless id

        result = with_error_handling { inspector.logoff(id, dry_run: options[:dry_run]) }
        emit(result, options[:json]) { |r| print_logoff(r) }
        exit(result[:ok] == false ? 1 : 0)

      else
        puts parser
        exit(command.nil? ? 0 : 1)
      end
    end

    def self.with_error_handling
      yield
    rescue QuserUnreachable => e
      warn("error: #{e.message}")
      exit 2
    rescue Errno::ENOENT => e
      warn("error: quser/logoff not found on PATH (#{e.message}) — this tool only runs on Windows")
      exit 2
    end

    def self.emit(data, json)
      if json
        puts JSON.pretty_generate(data)
      else
        yield data
      end
    end

    def self.print_list(list)
      list.each do |s|
        marker = s[:current] ? '*' : ' '
        puts "#{marker}#{s[:username].ljust(20)} id=#{s[:id]}  #{s[:state].ljust(6)} idle=#{s[:idle_raw].to_s.ljust(8)} logon=#{s[:logon_time]}"
      end
    end

    def self.print_report(list)
      list.each do |s|
        marker = { 'ok' => 'OK', 'current' => 'OK', 'idle_too_long' => 'WARN', 'disconnected_too_long' => 'WARN' }[s[:flag]] || '?'
        puts "[#{marker}] #{s[:username]} (id=#{s[:id]}, #{s[:state]}, idle=#{s[:idle_raw]}) — #{s[:flag]}"
      end
    end

    def self.print_logoff(result)
      if result[:dry_run]
        puts "DRY RUN: would execute `#{result[:command]}`"
      else
        puts result[:ok] ? "OK: #{result[:command]}" : "FAILED: #{result[:command]} — #{result[:stderr]}"
      end
    end
  end
end

WinRdpSessionManager::CLI.run(ARGV) if $PROGRAM_NAME == __FILE__
