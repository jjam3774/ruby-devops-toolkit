#!/usr/bin/env ruby
# frozen_string_literal: true
#
# path_env_audit.rb -- audit the PATH environment variable for privilege-
# escalation and hygiene problems, on Windows and Unix.
#
# PATH is a classic, overlooked attack surface: if a directory that any user
# can write to appears on PATH *ahead of* the real system directories, an
# attacker drops a malicious `python.exe` / `ls` there and it runs instead of
# the real one. Unquoted or relative entries and duplicates cause their own
# bugs. This audits the live PATH (or one you pass in) and ranks the findings.
#
#   ruby path_env_audit.rb                       # audit this process's PATH
#   ruby path_env_audit.rb --path "$SOMEPATH"    # audit a specific value
#   ruby path_env_audit.rb --json
#
# Stdlib only: json, optparse, etc. No gems. The classification is pure and is
# exercised by path_env_audit_test.rb on any platform. Exit codes: 0/1/2.

require 'json'
require 'optparse'

module PathAudit
  module_function

  WORLD_WRITABLE_HINT = /\A(\/tmp|\/var\/tmp|\/dev\/shm|C:\\Users\\Public|C:\\Temp|C:\\Windows\\Temp)/i.freeze

  # entries: array of raw PATH strings, in order. writable: ->(dir){bool} lets
  # the caller inject a real writability probe (or a stub for tests).
  def classify(entries, windows:, writable: nil)
    sep = windows ? '\\' : '/'
    findings = []
    seen = {}
    system_seen = false

    entries.each_with_index do |raw, idx|
      entry = raw.to_s
      if entry.strip.empty?
        findings << ['WARN', 'empty-entry', idx, 'empty PATH element (implicitly means current directory)']
        next
      end
      # A relative entry means "current working directory dependent" -- unsafe.
      absolute = windows ? entry =~ /\A([a-zA-Z]:\\|\\\\)/ : entry.start_with?('/')
      findings << ['WARN', 'relative-entry', idx, "relative directory on PATH: #{entry}"] unless absolute

      # Duplicates: waste and can mask ordering intent.
      key = windows ? entry.downcase : entry
      if seen[key]
        findings << ['INFO', 'duplicate-entry', idx, "#{entry} already appears at position #{seen[key]}"]
      else
        seen[key] = idx
      end

      # Unquoted-looking Windows entry with spaces (only meaningful when the
      # PATH was reconstructed from an unsplit string; flagged as hygiene).
      if windows && entry.include?(' ') && entry.include?('"')
        findings << ['WARN', 'embedded-quote', idx, "PATH entry contains a quote: #{entry}"]
      end

      user_writable =
        if writable
          begin writable.call(entry) rescue false end
        else
          entry =~ WORLD_WRITABLE_HINT ? true : false
        end

      is_system = system_dir?(entry, windows)
      system_seen ||= is_system

      if user_writable && !system_seen
        findings << ['CRIT', 'writable-before-system', idx,
                     "user-writable dir #{entry} precedes the system directories on PATH"]
      elsif user_writable
        findings << ['WARN', 'writable-entry', idx, "user-writable dir on PATH: #{entry}"]
      end
    end

    findings.map { |sev, code, pos, detail| { severity: sev, code: code, position: pos, detail: detail } }
  end

  def system_dir?(entry, windows)
    if windows
      entry =~ /\AC:\\Windows(\\System32|\\SysWOW64)?\\?\z/i ? true : false
    else
      %w[/usr/bin /bin /usr/sbin /sbin /usr/local/bin].include?(entry)
    end
  end
end

if __FILE__ == $PROGRAM_NAME
  options = { json: false, path: nil }
  OptionParser.new do |o|
    o.banner = 'Usage: ruby path_env_audit.rb [options]'
    o.on('--path VALUE', 'audit this PATH string instead of the live one') { |v| options[:path] = v }
    o.on('--json', 'JSON output') { options[:json] = true }
  end.parse!

  windows = RUBY_PLATFORM =~ /mswin|mingw|cygwin/ ? true : false
  sep = windows ? ';' : ':'
  raw = options[:path] || ENV['PATH'].to_s
  entries = raw.split(sep, -1)

  # Real writability probe: directory exists and is writable by us.
  probe = lambda { |dir| File.directory?(dir) && File.writable?(dir) }
  findings = PathAudit.classify(entries, windows: windows, writable: probe)

  rank = { 'CRIT' => 0, 'WARN' => 1, 'INFO' => 2 }
  findings.sort_by! { |f| [rank[f[:severity]], f[:position]] }
  crit = findings.count { |f| f[:severity] == 'CRIT' }
  warn = findings.count { |f| f[:severity] == 'WARN' }

  if options[:json]
    puts JSON.pretty_generate('platform' => windows ? 'windows' : 'unix',
                              'entries' => entries.size,
                              'findings' => findings.map { |f| f.transform_keys(&:to_s) },
                              'summary' => { 'crit' => crit, 'warn' => warn,
                                             'info' => findings.size - crit - warn })
  else
    puts "PATH audit -- #{entries.size} entries (#{windows ? 'windows' : 'unix'})"
    puts
    if findings.empty?
      puts 'no findings -- clean.'
    else
      findings.each { |f| puts format('%-5s %-24s #%-3d %s', f[:severity], f[:code], f[:position], f[:detail]) }
      puts
      puts "#{crit} critical, #{warn} warning, #{findings.size - crit - warn} info"
    end
  end
  exit(crit.positive? ? 2 : warn.positive? ? 1 : 0)
end
