#!/usr/bin/env ruby
# frozen_string_literal: true
# config_lint.rb - lint a directory of JSON / YAML / INI-style config files before deploy.
# Usage: ruby config_lint.rb DIR [--require-keys db.host,db.port] [--json]
require 'json'
require 'yaml'
require 'optparse'

Issue = Struct.new(:file, :severity, :message)

def dig_path(obj, path)
  path.split('.').reduce(obj) { |o, k| o.is_a?(Hash) ? o[k] : (return nil) }
end

def lint_text(path, text, issues)
  issues << Issue.new(path, :low, 'no trailing newline') unless text.end_with?("\n") || text.empty?
  issues << Issue.new(path, :low, 'mixed CRLF and LF line endings') if text.include?("\r\n") && text.gsub("\r\n", '').include?("\n")
  text.each_line.with_index(1) do |l, n|
    issues << Issue.new(path, :low, "line #{n}: trailing whitespace") if l.chomp =~ /[ \t]+$/
  end
end

def lint_json(path, text, issues, required)
  data = JSON.parse(text)
  required.each { |k| issues << Issue.new(path, :high, "missing required key #{k}") if dig_path(data, k).nil? }
rescue JSON::ParserError => e
  issues << Issue.new(path, :high, "invalid JSON: #{e.message.lines.first.strip[0, 90]}")
end

def lint_yaml(path, text, issues, required)
  text.each_line.with_index(1) do |l, n|
    issues << Issue.new(path, :high, "line #{n}: tab character used for indentation") if l =~ /\A\t/
  end
  data = YAML.safe_load(text, aliases: true)
  required.each { |k| issues << Issue.new(path, :high, "missing required key #{k}") if dig_path(data, k).nil? } if data.is_a?(Hash)
rescue Psych::Exception => e
  issues << Issue.new(path, :high, "invalid YAML: #{e.message[0, 90]}")
end

def lint_ini(path, text, issues)
  seen = Hash.new { |h, k| h[k] = {} }
  section = '(global)'
  text.each_line.with_index(1) do |l, n|
    s = l.strip
    next if s.empty? || s.start_with?('#', ';')
    if s =~ /\A\[(.+)\]\z/ then section = Regexp.last_match(1)
    elsif s.include?('=')
      key = s.split('=', 2).first.strip
      issues << Issue.new(path, :medium, "line #{n}: duplicate key '#{key}' in [#{section}] (first on line #{seen[section][key]})") if seen[section].key?(key)
      seen[section][key] ||= n
    else
      issues << Issue.new(path, :high, "line #{n}: not a section, comment or key=value")
    end
  end
end

opts = { required: [], json: false }
OptionParser.new do |o|
  o.on('--require-keys LIST') { |v| opts[:required] = v.split(',') }
  o.on('--json') { opts[:json] = true }
end.parse!
dir = ARGV.shift or abort 'usage: config_lint.rb DIR'

issues = []
files = Dir.glob(File.join(dir, '**', '*.{json,yml,yaml,ini,conf,cfg}')).sort
files.each do |f|
  text = File.read(f)
  issues << Issue.new(f, :medium, format('world-writable (mode %o)', File.stat(f).mode & 0o777)) if File.stat(f).mode & 0o002 != 0
  lint_text(f, text, issues)
  case File.extname(f)
  when '.json' then lint_json(f, text, issues, opts[:required])
  when '.yml', '.yaml' then lint_yaml(f, text, issues, opts[:required])
  else lint_ini(f, text, issues)
  end
end

if opts[:json]
  puts JSON.pretty_generate(files: files.size, issues: issues.map(&:to_h))
else
  puts "Checked #{files.size} file(s)"
  issues.each { |i| puts "[#{i.severity.to_s.upcase}] #{i.file}: #{i.message}" }
  puts 'OK: all configs clean' if issues.empty?
end
exit(issues.any? { |i| i.severity == :high } ? 2 : (issues.empty? ? 0 : 1))
