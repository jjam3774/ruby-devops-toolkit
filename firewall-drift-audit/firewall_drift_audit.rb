#!/usr/bin/env ruby
# frozen_string_literal: true
#
# firewall_drift_audit.rb -- parse an iptables-save (or nft, via the same
# legacy-compatible text format) ruleset and flag drift against a JSON
# security baseline: chains whose default policy went from DROP to ACCEPT,
# ports opened wider than the baseline allows, and baseline ports that
# quietly disappeared.
#
# Usage:
#   sudo iptables-save | ruby firewall_drift_audit.rb --baseline baseline.json
#   ruby firewall_drift_audit.rb --input snapshot.txt --baseline baseline.json --json
#
# Exit status:
#   0   no CRIT findings
#   1   at least one CRIT finding
#   2   usage / input error
#
# Requires: Ruby 3.x, stdlib only (json, optparse). Reads iptables-save's
# plain-text output -- no `iptables` gem, no native extension, and no root
# privileges of its own (only whatever produced the snapshot needed root).

require 'json'
require 'optparse'

Rule = Struct.new(:chain, :protocol, :dport, :source, :jump, :raw, keyword_init: true)
Finding = Struct.new(:severity, :reason, keyword_init: true)

# ---------------------------------------------------------------------------
# Parses the *filter table block of an iptables-save snapshot into chain
# policies and individual rules. Deliberately tolerant: unrecognized lines
# (custom chains, other tables, comments) are ignored rather than raising,
# since a real fleet's rulesets are messier than any single fixture.
# ---------------------------------------------------------------------------
def parse_iptables_save(text)
  policies = {}
  rules = []
  in_filter = false

  text.each_line do |line|
    line = line.strip
    next if line.empty? || line.start_with?('#')

    in_filter = true if line == '*filter'
    in_filter = false if line == 'COMMIT' || (line.start_with?('*') && line != '*filter')
    next unless in_filter

    if line.start_with?(':')
      # ":INPUT DROP [0:0]"
      name, policy, = line[1..].split(/\s+/)
      policies[name] = policy
    elsif line.start_with?('-A ')
      chain = line.split(/\s+/)[1]
      proto = line[/-p\s+(\S+)/, 1]
      dport = line[/--dport\s+(\d+)/, 1]&.to_i
      source = line[/-s\s+(\S+)/, 1]
      jump = line[/-j\s+(\S+)/, 1]
      rules << Rule.new(chain: chain, protocol: proto, dport: dport, source: source, jump: jump, raw: line)
    end
  end

  { policies: policies, rules: rules }
end

# ---------------------------------------------------------------------------
# Pure classification against a baseline hash (already-parsed JSON). No
# file or process I/O in here -- makes it trivial to unit test with
# hand-built policies/rules instead of a live parse.
# ---------------------------------------------------------------------------
def classify(parsed, baseline)
  findings = []
  policies = parsed[:policies]
  rules = parsed[:rules]

  (baseline['default_policies'] || {}).each do |chain, expected|
    actual = policies[chain]
    next if actual.nil? # chain not present in this snapshot at all; not this script's concern here
    next if actual == expected

    if expected == 'DROP' && actual == 'ACCEPT'
      findings << Finding.new(severity: :crit, reason: "chain #{chain} default policy is ACCEPT, baseline requires DROP")
    else
      findings << Finding.new(severity: :warn, reason: "chain #{chain} default policy is #{actual}, baseline expects #{expected}")
    end
  end

  allowed = { 'tcp' => (baseline['allowed_tcp_ports'] || []), 'udp' => (baseline['allowed_udp_ports'] || []) }
  open_ports = Hash.new { |h, k| h[k] = [] } # proto => [ports actually open]

  rules.each do |r|
    next unless r.jump == 'ACCEPT' && r.dport && %w[tcp udp].include?(r.protocol)

    open_ports[r.protocol] << r.dport
    next if allowed[r.protocol].include?(r.dport)

    wide_open = r.source.nil? || r.source == '0.0.0.0/0'
    if wide_open
      findings << Finding.new(severity: :crit, reason: "#{r.protocol}/#{r.dport} accepts from anywhere but is not in the baseline allowlist (#{r.raw})")
    else
      findings << Finding.new(severity: :warn, reason: "#{r.protocol}/#{r.dport} is open to #{r.source} (not in baseline) -- verify this is intentional")
    end
  end

  allowed.each do |proto, ports|
    ports.each do |port|
      next if open_ports[proto].include?(port)

      findings << Finding.new(severity: :warn, reason: "baseline expects #{proto}/#{port} to be open, but no matching ACCEPT rule was found")
    end
  end

  overall = if findings.any? { |f| f.severity == :crit }
              :crit
            elsif findings.any? { |f| f.severity == :warn }
              :warn
            else
              :ok
            end

  { severity: overall, findings: findings, open_ports: open_ports }
end

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
options = { baseline_path: nil, input_path: nil, json: false }
parser = OptionParser.new do |opts|
  opts.banner = "Usage: firewall_drift_audit.rb --baseline baseline.json [--input snapshot.txt | < iptables-save output]"
  opts.on('--baseline FILE', 'JSON security baseline (required)') { |v| options[:baseline_path] = v }
  opts.on('--input FILE', 'Read an iptables-save snapshot from a file instead of stdin') { |v| options[:input_path] = v }
  opts.on('--json', 'Emit a JSON report instead of text') { options[:json] = true }
  opts.on('-h', '--help', 'Show this help') { puts opts; exit 0 }
end
parser.parse!(ARGV)

unless options[:baseline_path]
  warn 'error: --baseline FILE is required'
  warn parser
  exit 2
end

begin
  baseline = JSON.parse(File.read(options[:baseline_path]))
rescue StandardError => e
  warn "error: could not read/parse baseline: #{e.class}: #{e.message}"
  exit 2
end

raw_text =
  if options[:input_path]
    File.read(options[:input_path])
  elsif !$stdin.tty?
    $stdin.read
  else
    warn 'error: no input -- pass --input FILE or pipe `iptables-save` output on stdin (requires root on a live host)'
    exit 2
  end

parsed = parse_iptables_save(raw_text)
result = classify(parsed, baseline)

if options[:json]
  puts JSON.pretty_generate(
    severity: result[:severity],
    open_ports: result[:open_ports],
    findings: result[:findings].map { |f| { severity: f.severity, reason: f.reason } }
  )
else
  tag = { crit: '[CRIT]', warn: '[WARN]', ok: '[ ok ]' }[result[:severity]]
  puts "#{tag} overall firewall drift status: #{result[:severity]}"
  result[:findings].each do |f|
    line_tag = { crit: '[CRIT]', warn: '[WARN]', info: '[info]' }[f.severity]
    puts "  #{line_tag} #{f.reason}"
  end
  puts '---'
  puts "#{result[:findings].count { |f| f.severity == :crit }} CRIT, #{result[:findings].count { |f| f.severity == :warn }} WARN"
end

exit(result[:severity] == :crit ? 1 : 0)
