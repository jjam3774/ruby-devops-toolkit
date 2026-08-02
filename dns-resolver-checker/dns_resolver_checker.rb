#!/usr/bin/env ruby
# frozen_string_literal: true
#
# dns_resolver_checker.rb
#
# Queries one or more DNS record types for a domain against a *fleet* of
# resolvers concurrently, and flags disagreement between resolvers
# (propagation lag, split-brain internal/external DNS), records that
# fail to resolve, and records that don't match an expected value.
#
# No gems required: `resolv`, `socket`, `optparse`, `json`, `timeout`,
# and `thread` (Queue) are all in the Ruby standard library.
#
# Usage:
#   ruby dns_resolver_checker.rb example.com
#   ruby dns_resolver_checker.rb example.com --types A,MX,TXT --resolvers 8.8.8.8,1.1.1.1,9.9.9.9
#   ruby dns_resolver_checker.rb example.com --types A --expect 93.184.216.34
#   ruby dns_resolver_checker.rb example.com --json
#
# Exit codes (cron/monitoring friendly):
#   0 = every record type resolves consistently everywhere (and matches --expect, if given)
#   1 = WARN -- resolvers disagree, or some (not all) resolvers failed to answer
#   2 = CRIT -- a record failed to resolve on every resolver, or didn't match --expect anywhere

require 'resolv'
require 'optparse'
require 'json'
require 'timeout'

RESOURCE_CLASSES = {
  'A' => Resolv::DNS::Resource::IN::A,
  'AAAA' => Resolv::DNS::Resource::IN::AAAA,
  'CNAME' => Resolv::DNS::Resource::IN::CNAME,
  'MX' => Resolv::DNS::Resource::IN::MX,
  'TXT' => Resolv::DNS::Resource::IN::TXT,
  'NS' => Resolv::DNS::Resource::IN::NS
}.freeze

# Pulls the human-readable value out of whichever Resolv::DNS::Resource
# subclass a query returned -- each record type stores its payload under
# a different accessor (address/name/exchange/strings).
def resource_value(type, resource)
  case type
  when 'A', 'AAAA' then resource.address.to_s
  when 'CNAME', 'NS' then resource.name.to_s
  when 'MX' then "#{resource.preference} #{resource.exchange}"
  when 'TXT' then resource.strings.join
  else resource.to_s
  end
end

# ---------------------------------------------------------------------------
# fetch_record: one resolver, one record type, one domain. Never raises --
# any failure comes back as {status: 'error', error: '...'} so a single
# flaky resolver can't kill the whole run.
# ---------------------------------------------------------------------------
def fetch_record(resolver, type, domain, timeout)
  host, port_str = resolver.split(':', 2)
  port = port_str ? port_str.to_i : 53

  Timeout.timeout(timeout) do
    dns = Resolv::DNS.new(nameserver_port: [[host, port]])
    begin
      resources = dns.getresources(domain, RESOURCE_CLASSES.fetch(type))
      { status: 'ok', values: resources.map { |r| resource_value(type, r) }.sort }
    ensure
      dns.close
    end
  end
rescue StandardError => e
  { status: 'error', error: "#{e.class}: #{e.message}" }
end

# ---------------------------------------------------------------------------
# Bounded concurrency across every (type, resolver) pair -- same
# queue-of-jobs / fixed-worker-pool shape as this toolkit's other
# network checkers, so no more sockets are open at once than --concurrency.
# ---------------------------------------------------------------------------
def run_checks(domain, types, resolvers, options)
  jobs = types.product(resolvers)
  queue = Queue.new
  jobs.each { |j| queue << j }
  results = Queue.new

  workers = Array.new([options[:concurrency], jobs.size].min) do
    Thread.new do
      loop do
        type, resolver = begin
          queue.pop(true)
        rescue ThreadError
          break
        end
        results << [type, resolver, fetch_record(resolver, type, domain, options[:timeout])]
      end
    end
  end
  workers.each(&:join)

  out = Hash.new { |h, k| h[k] = {} }
  Array.new(results.size) { results.pop }.each { |type, resolver, res| out[type][resolver] = res }
  out
end

# ---------------------------------------------------------------------------
# evaluate_type: pure function, no sockets involved -- takes the
# {resolver => {status:, values:/error:}} hash for ONE record type and
# classifies it. Kept separate from run_checks/fetch_record so the test
# suite can exercise every branch with hand-built hashes.
# ---------------------------------------------------------------------------
def evaluate_type(type, resolver_results, expect)
  errored = resolver_results.select { |_, r| r[:status] == 'error' }
  ok = resolver_results.reject { |k, _| errored.key?(k) }

  if ok.empty?
    return { severity: 'CRIT', reasons: ["#{type}: every resolver failed to answer"] }
  end

  distinct_sets = ok.values.map { |r| r[:values] }.uniq

  reasons = []
  severity = 'OK'

  if expect
    unless ok.values.any? { |r| r[:values].include?(expect) }
      severity = 'CRIT'
      reasons << "#{type}: expected value #{expect.inspect} not returned by any resolver"
    end
  end

  if distinct_sets.size > 1
    severity = 'WARN' if severity == 'OK'
    summary = ok.map { |name, r| "#{name}=#{r[:values].empty? ? 'EMPTY' : r[:values].join('|')}" }.join(', ')
    reasons << "#{type}: resolvers disagree (#{summary})"
  end

  unless errored.empty?
    severity = 'WARN' if severity == 'OK'
    reasons << "#{type}: #{errored.size}/#{resolver_results.size} resolver(s) failed to answer (#{errored.keys.join(', ')})"
  end

  reasons << "#{type}: consistent across #{ok.size} resolver(s)" if reasons.empty?
  { severity: severity, reasons: reasons }
end

# ---------------------------------------------------------------------------
# Run -- only when executed directly, not when required by the test suite
# (see firewall-audit/firewall_audit.rb in this repo for the same pattern).
# ---------------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  options = {
    types: ['A'],
    resolvers: ['8.8.8.8', '1.1.1.1', '9.9.9.9'],
    timeout: 3,
    concurrency: 8,
    json: false,
    expect: nil
  }

  parser = OptionParser.new do |opts|
    opts.banner = 'Usage: dns_resolver_checker.rb DOMAIN [options]'
    opts.on('--types LIST', Array, 'Comma-separated record types to check (default: A)') { |v| options[:types] = v.map(&:upcase) }
    opts.on('--resolvers LIST', Array, 'Comma-separated resolver host[:port] list') { |v| options[:resolvers] = v }
    opts.on('--expect VALUE', 'Fail with CRIT if no resolver returns this value for the (single) record type checked') { |v| options[:expect] = v }
    opts.on('--timeout SECONDS', Integer, 'Per-query timeout (default: 3)') { |v| options[:timeout] = v }
    opts.on('--concurrency N', Integer, 'Max concurrent queries (default: 8)') { |v| options[:concurrency] = v }
    opts.on('--json', 'Emit machine-readable JSON instead of text') { options[:json] = true }
    opts.on('-h', '--help', 'Show this help') { puts opts; exit 0 }
  end
  parser.parse!

  domain = ARGV.first
  if domain.nil?
    warn parser.banner
    exit 2
  end

  raw = run_checks(domain, options[:types], options[:resolvers], options)
  findings = raw.map { |type, resolver_results| [type, evaluate_type(type, resolver_results, options[:types].size == 1 ? options[:expect] : nil)] }

  if options[:json]
    puts JSON.pretty_generate(
      domain: domain,
      results: raw,
      findings: findings.to_h
    )
  else
    findings.each do |type, v|
      puts "[#{v[:severity].ljust(4)}] #{domain} #{type}"
      v[:reasons].each { |r| puts "        #{r}" }
    end
    crit = findings.count { |_, v| v[:severity] == 'CRIT' }
    warn_n = findings.count { |_, v| v[:severity] == 'WARN' }
    puts "\n#{findings.size} record type(s) checked across #{options[:resolvers].size} resolver(s), #{crit} CRIT, #{warn_n} WARN"
  end

  exit_code =
    if findings.any? { |_, v| v[:severity] == 'CRIT' }
      2
    elsif findings.any? { |_, v| v[:severity] == 'WARN' }
      1
    else
      0
    end
  exit exit_code
end
