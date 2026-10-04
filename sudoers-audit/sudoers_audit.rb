#!/usr/bin/env ruby
# frozen_string_literal: true
# sudoers_audit.rb - static audit of /etc/sudoers and its includes. Linux. Ruby 2.7+, stdlib only.
# Read-only: it never calls visudo or sudo. Run as root to read /etc/sudoers (mode 0440).
# Exit 0 = no findings above INFO, 1 = HIGH/MEDIUM findings.
require 'optparse'
require 'json'

Finding = Struct.new(:severity, :file, :line, :rule, :detail, keyword_init: true)

class SudoersAudit
  attr_reader :findings

  def initialize(root_file, admin_groups: %w[root %sudo %wheel %admin])
    @root_file = root_file
    @admins = admin_groups
    @findings = []
    @seen = {}
  end

  def run
    walk(@root_file)
    @findings
  end

  private

  def add(sev, file, line, rule, detail)
    @findings << Finding.new(severity: sev, file: file, line: line, rule: rule, detail: detail)
  end

  # Recursively follow #include / @include / #includedir / @includedir
  def walk(path, depth = 0)
    return add('MEDIUM', path, 0, 'include-depth', 'include nesting > 10') if depth > 10
    return if @seen[path]

    @seen[path] = true
    check_file_perms(path)
    logical_lines(path).each do |num, text|
      case text
      when /\A[#@]include(dir)?\s+(\S+)/
        target = Regexp.last_match(2)
        if Regexp.last_match(1)
          Dir.glob(File.join(target, '*')).sort.each do |f|
            base = File.basename(f)
            next if base.include?('.') || base.end_with?('~') # sudo ignores these

            walk(f, depth + 1)
          end
        else
          walk(target, depth + 1)
        end
      when /\A#/, ''
        next
      else
        check_rule(path, num, text)
      end
    end
  end

  # Join backslash-continued lines; strip trailing comments.
  def logical_lines(path)
    out = []
    buf = +''
    start = 1
    File.foreach(path).with_index(1) do |raw, n|
      line = raw.chomp
      start = n if buf.empty?
      if line.end_with?('\\')
        buf << line.chomp('\\') << ' '
        next
      end
      buf << line
      out << [start, buf.sub(/(?<!^)\s+#.*\z/, '').strip]
      buf = +''
    end
    out
  end

  def check_file_perms(path)
    st = File.stat(path)
    add('HIGH', path, 0, 'bad-owner', "owned by uid #{st.uid}, must be root") unless st.uid.zero?
    add('HIGH', path, 0, 'world-writable', format('mode %04o', st.mode & 0o7777)) if (st.mode & 0o002) != 0
    add('MEDIUM', path, 0, 'group-writable', format('mode %04o', st.mode & 0o7777)) if (st.mode & 0o020) != 0
  rescue SystemCallError => e
    add('INFO', path, 0, 'unreadable', e.message)
  end

  def check_rule(file, num, text)
    return if text =~ /\A(User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias)\b/

    who = text.split(/\s+/, 2).first
    if text =~ /\bDefaults.*!authenticate/
      add('HIGH', file, num, 'no-authenticate', 'Defaults !authenticate disables passwords globally')
    end
    if text =~ /\bDefaults.*!(use_pty|requiretty)|\bDefaults.*env_keep.*(LD_|PYTHON|RUBY)/
      add('MEDIUM', file, num, 'weak-defaults', text)
    end
    return unless text =~ /=/ && text !~ /\ADefaults/

    nopasswd = text.include?('NOPASSWD')
    all_cmds = text =~ /(?:\)|:|=|,)\s*(?:NOPASSWD:\s*)?ALL\s*\z/
    is_admin = @admins.include?(who)
    add('HIGH', file, num, 'nopasswd-all', "#{who}: passwordless ALL") if nopasswd && all_cmds
    add('MEDIUM', file, num, 'nopasswd', "#{who}: NOPASSWD rule") if nopasswd && !all_cmds
    add('MEDIUM', file, num, 'unexpected-all', "#{who}: full ALL access") if all_cmds && !is_admin && who != 'root'
    add('HIGH', file, num, 'wildcard-cmd', "#{who}: wildcard in command (arg injection risk)") if text =~ /\/\S*\*/
    if text =~ %r{/(vi|vim|nano|less|more|man|find|awk|python\d?|perl|ruby|bash|sh|zsh|tar|env)\b}
      add('HIGH', file, num, 'shell-escape', "#{who}: #{Regexp.last_match(1)} allows shell escape to root")
    end
  end
end

if $PROGRAM_NAME == __FILE__
  opts = { file: '/etc/sudoers', json: false }
  OptionParser.new do |o|
    o.on('-f', '--file PATH', 'root sudoers file (default /etc/sudoers)') { |v| opts[:file] = v }
    o.on('-j', '--json') { opts[:json] = true }
  end.parse!
  abort "cannot read #{opts[:file]} (run as root?)" unless File.readable?(opts[:file])

  order = { 'HIGH' => 0, 'MEDIUM' => 1, 'INFO' => 2 }
  fs = SudoersAudit.new(opts[:file]).run.sort_by { |f| [order[f.severity], f.file, f.line] }
  if opts[:json]
    puts JSON.pretty_generate(fs.map(&:to_h))
  elsif fs.empty?
    puts 'No findings.'
  else
    fs.each { |f| puts format('%-6s %-16s %s:%d  %s', f.severity, f.rule, f.file, f.line, f.detail) }
    puts "\n#{fs.count { |f| f.severity == 'HIGH' }} high, #{fs.count { |f| f.severity == 'MEDIUM' }} medium"
  end
  exit(fs.any? { |f| %w[HIGH MEDIUM].include?(f.severity) } ? 1 : 0)
end
