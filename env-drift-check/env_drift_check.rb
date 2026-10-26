#!/usr/bin/env ruby
# frozen_string_literal: true
# env_drift_check.rb - compare .env files against a .env.example template.
# Reports MISSING keys, EXTRA keys, EMPTY values, PLACEHOLDER values left in,
# and DUPLICATE keys. Never prints secret values.
# Usage: ruby env_drift_check.rb TEMPLATE ENV_FILE [ENV_FILE...] [--json]
# Exit: 0 clean, 1 drift (warnings), 2 missing required keys.
require 'json'

PLACEHOLDER = /\A(changeme|change_me|your[-_].*|xxx+|todo|<.*>|\*+)\z/i

# Parse KEY=VALUE lines (handles `export`, quotes, comments, blank lines).
# Returns [ {key=>value}, [duplicate keys] ]
def parse_env(text)
  h = {}
  dups = []
  text.each_line do |line|
    line = line.strip
    next if line.empty? || line.start_with?('#')
    m = line.match(/\A(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\z/)
    next unless m
    k = m[1]
    v = m[2].sub(/\s+#.*\z/, '').strip.sub(/\A(["'])(.*)\1\z/, '\2')
    dups << k if h.key?(k)
    h[k] = v
  end
  [h, dups.uniq]
end

def compare(template, actual, dups)
  {
    missing:     template.keys - actual.keys,
    extra:       actual.keys - template.keys,
    empty:       (actual.keys & template.keys).select { |k| actual[k].empty? && !template[k].empty? },
    placeholder: actual.select { |_, v| v =~ PLACEHOLDER }.keys,
    duplicate:   dups
  }
end

if $PROGRAM_NAME == __FILE__
  json = ARGV.delete('--json')
  tpl_path, *files = ARGV
  abort "usage: #{$PROGRAM_NAME} TEMPLATE ENV_FILE... [--json]" if files.empty?
  tpl, = parse_env(File.read(tpl_path))
  report = files.to_h do |f|
    act, dups = parse_env(File.read(f))
    [f, compare(tpl, act, dups)]
  end
  if json
    puts JSON.pretty_generate(report)
  else
    report.each do |f, r|
      puts "== #{f}"
      if r.values.all?(&:empty?) then puts '  OK: matches template'
      else r.each { |k, v| puts format('  %-12s %s', k.to_s.upcase, v.join(', ')) unless v.empty? } end
    end
  end
  worst = report.values.map { |r| r[:missing].any? ? 2 : (r.values.any?(&:any?) ? 1 : 0) }.max
  exit worst
end
