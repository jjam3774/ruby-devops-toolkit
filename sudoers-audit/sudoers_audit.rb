#!/usr/bin/env ruby
# frozen_string_literal: true
#
# sudoers_audit.rb
#
# Parses /etc/sudoers (plus any #include / #includedir files it pulls
# in, exactly like real sudo does) and flags the handful of privilege
# grants that repeatedly show up in real-world escalation writeups:
# NOPASSWD root shells, wildcard command paths (which let a "restricted"
# sudo rule run arbitrary binaries), and sudoers files that are
# world-writable. It also shells out to `visudo -c` to catch outright
# syntax errors before they lock someone out of sudo entirely.
#
# No gems required -- `optparse`, `json`, and `open3` are stdlib.
#
# Usage:
#   sudo ruby sudoers_audit.rb                      # audit /etc/sudoers (needs root to read it)
#   ruby sudoers_audit.rb --file ./my_sudoers        # audit any sudoers-format file (testing/CI)
#   ruby sudoers_audit.rb --file ./my_sudoers --json
#   ruby sudoers_audit.rb --file ./my_sudoers --skip-visudo   # if visudo isn't installed
#
# Exit codes (cron/CI friendly):
#   0 = no risky entries found
#   1 = WARN-level findings
#   2 = CRIT-level findings, a visudo syntax error, or the file couldn't be read

require 'optparse'
require 'json'
require 'open3'

# ---------------------------------------------------------------------------
# Parsing
#
# This is a lightweight, line-oriented parser -- NOT a full sudoers
# grammar implementation. It does not resolve User_Alias/Cmnd_Alias
# definitions, and it splits multiple cmndspecs on the top-level commas
# sudoers uses between them. That's enough to catch the risk patterns
# this script looks for; anything using heavy aliasing should also be
# read by a human, not just this script. See README Troubleshooting.
# ---------------------------------------------------------------------------

SudoersEntry = Struct.new(:file, :line_no, :raw, :who, :host, :runas, :tags_and_cmnds, keyword_init: true)

# Reads one sudoers-format file, following #include/#includedir
# directives it finds (the same mechanism real sudo uses to pull in
# /etc/sudoers.d/*), and returns [entries, included_files, errors].
def parse_sudoers(path, seen = [])
  entries = []
  included = []
  errors = []

  unless File.readable?(path)
    errors << "cannot read #{path} (permission denied?)"
    return [entries, included, errors]
  end
  return [entries, included, errors] if seen.include?(File.expand_path(path))

  seen << File.expand_path(path)
  buffer = nil

  File.readlines(path).each_with_index do |raw_line, idx|
    line_no = idx + 1
    line = raw_line.chomp

    # Line continuations: a trailing backslash joins with the next line.
    if buffer
      line = buffer + line.sub(/^\s*/, ' ')
      buffer = nil
    end
    if line.end_with?('\\')
      buffer = line.sub(/\\\z/, '')
      next
    end

    stripped = line.strip
    next if stripped.empty?

    if stripped.start_with?('#include ')
      inc_path = stripped.sub('#include ', '').strip
      included << inc_path
      sub_entries, sub_included, sub_errors = parse_sudoers(inc_path, seen)
      entries.concat(sub_entries)
      included.concat(sub_included)
      errors.concat(sub_errors)
      next
    end

    if stripped.start_with?('#includedir ')
      dir = stripped.sub('#includedir ', '').strip
      if Dir.exist?(dir)
        Dir.children(dir).sort.each do |fname|
          next if fname.start_with?('.') || fname.end_with?('~') || fname.include?('.rpmsave') || fname.include?('.rpmnew')

          sub_path = File.join(dir, fname)
          included << sub_path
          sub_entries, sub_included, sub_errors = parse_sudoers(sub_path, seen)
          entries.concat(sub_entries)
          included.concat(sub_included)
          errors.concat(sub_errors)
        end
      else
        errors << "#includedir target #{dir} does not exist"
      end
      next
    end

    next if stripped.start_with?('#') # plain comment
    next if stripped.match?(/^(Defaults|User_Alias|Host_Alias|Cmnd_Alias|Runas_Alias)\b/)

    m = stripped.match(/\A(\S+)\s+(\S+)\s*=\s*(?:\(([^)]*)\)\s*)?(.+)\z/)
    next unless m # not a user-spec line we recognize; ignore rather than false-flag

    entries << SudoersEntry.new(
      file: path, line_no: line_no, raw: stripped,
      who: m[1], host: m[2], runas: m[3], tags_and_cmnds: m[4]
    )
  end

  [entries, included, errors]
end

# ---------------------------------------------------------------------------
# Risk logic -- pure function over parsed entries, no file I/O.
# ---------------------------------------------------------------------------
WILDCARD_CMND = /[*?]/.freeze

def classify_entry(entry)
  findings = []
  cmndspecs = entry.tags_and_cmnds.split(/,(?![^(]*\))/).map(&:strip)

  cmndspecs.each do |spec|
    nopasswd = spec.match?(/\bNOPASSWD\s*:/)
    cmnd = spec.sub(/\A(?:NOPASSWD|PASSWD|NOEXEC|EXEC|SETENV|NOSETENV|LOG_INPUT|NOLOG_INPUT|LOG_OUTPUT|NOLOG_OUTPUT)\s*:\s*/i, '').strip
    is_all_cmnd = cmnd == 'ALL'
    has_wildcard = cmnd.match?(WILDCARD_CMND)
    broad_who = %w[ALL].include?(entry.who) || entry.who.start_with?('%')

    if entry.who == 'ALL' && (is_all_cmnd || nopasswd)
      findings << { severity: 'CRIT', reason: "who=ALL (every local account) granted '#{cmnd}'#{nopasswd ? ' with NOPASSWD' : ''}" }
    elsif nopasswd && is_all_cmnd
      findings << { severity: 'CRIT', reason: "NOPASSWD: ALL -- passwordless full-root grant for '#{entry.who}'" }
    elsif nopasswd && has_wildcard
      findings << { severity: 'CRIT', reason: "NOPASSWD with a wildcard command ('#{cmnd}') -- wildcards can usually be abused to run arbitrary binaries" }
    elsif nopasswd
      findings << { severity: 'WARN', reason: "NOPASSWD grant for '#{entry.who}' on '#{cmnd}' -- passwordless, review if still needed" }
    elsif has_wildcard
      findings << { severity: 'WARN', reason: "wildcard command spec '#{cmnd}' -- verify it can't be pointed at an unintended binary" }
    elsif is_all_cmnd && broad_who
      findings << { severity: 'WARN', reason: "'#{entry.who}' can run ALL commands (password required) -- confirm this group is meant to be full sudoers" }
    end
  end

  findings
end

def check_file_permissions(path)
  return [] unless File.exist?(path)

  stat = File.stat(path)
  findings = []
  findings << { severity: 'CRIT', reason: "#{path} is world-writable (mode #{format('%o', stat.mode & 0o777)}) -- any local user could edit sudo policy" } if stat.mode & 0o002 != 0
  findings << { severity: 'WARN', reason: "#{path} is group-writable (mode #{format('%o', stat.mode & 0o777)}) -- confirm the group is trusted" } if stat.mode & 0o020 != 0
  findings
end

def run_visudo(path)
  out, status = Open3.capture2e('visudo', '-c', '-f', path)
  { ok: status.success?, output: out.strip }
rescue Errno::ENOENT
  { ok: nil, output: 'visudo not found on PATH' }
end

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  options = { file: '/etc/sudoers', json: false, skip_visudo: false }
  parser = OptionParser.new do |opts|
    opts.banner = 'Usage: sudoers_audit.rb [--file PATH] [options]'
    opts.on('--file PATH', 'Sudoers file to audit (default: /etc/sudoers)') { |v| options[:file] = v }
    opts.on('--json', 'Emit machine-readable JSON instead of text') { options[:json] = true }
    opts.on('--skip-visudo', 'Skip the visudo -c syntax check') { options[:skip_visudo] = true }
    opts.on('-h', '--help', 'Show this help') { puts opts; exit 0 }
  end
  parser.parse!

  entries, included_files, parse_errors = parse_sudoers(options[:file])

  if entries.empty? && parse_errors.any?
    warn "sudoers_audit: #{parse_errors.join('; ')}"
    exit 2
  end

  findings = []
  findings.concat(check_file_permissions(options[:file]).map { |f| f.merge(file: options[:file], line: nil) })
  included_files.each { |f| findings.concat(check_file_permissions(f).map { |x| x.merge(file: f, line: nil) }) }

  entries.each do |entry|
    classify_entry(entry).each { |f| findings << f.merge(file: entry.file, line: entry.line_no, raw: entry.raw) }
  end

  visudo_result = options[:skip_visudo] ? nil : run_visudo(options[:file])
  if visudo_result && visudo_result[:ok] == false
    findings << { severity: 'CRIT', reason: "visudo -c reported a syntax error: #{visudo_result[:output]}", file: options[:file], line: nil }
  end

  if options[:json]
    puts JSON.pretty_generate(
      file: options[:file],
      included_files: included_files,
      entries_checked: entries.size,
      visudo: visudo_result,
      findings: findings
    )
  else
    if findings.empty?
      puts "sudoers_audit: #{entries.size} entries across #{1 + included_files.size} file(s) checked, no risky grants found"
    else
      findings.sort_by { |f| f[:severity] == 'CRIT' ? 0 : 1 }.each do |f|
        loc = f[:line] ? "#{f[:file]}:#{f[:line]}" : f[:file]
        puts "[#{f[:severity]}] #{loc}"
        puts "        #{f[:reason]}"
        puts "        > #{f[:raw]}" if f[:raw]
      end
      crit = findings.count { |f| f[:severity] == 'CRIT' }
      warn_n = findings.count { |f| f[:severity] == 'WARN' }
      puts "\n#{entries.size} entries checked, #{crit} CRIT, #{warn_n} WARN"
    end
    if visudo_result
      status_label = visudo_result[:ok].nil? ? 'SKIPPED (visudo not found)' : (visudo_result[:ok] ? 'PASSED' : 'FAILED')
      puts "visudo -c: #{status_label}"
    end
  end

  exit_code =
    if findings.any? { |f| f[:severity] == 'CRIT' }
      2
    elsif findings.any? { |f| f[:severity] == 'WARN' }
      1
    else
      0
    end
  exit exit_code
end
