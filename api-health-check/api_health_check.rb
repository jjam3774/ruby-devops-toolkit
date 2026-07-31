#!/usr/bin/env ruby
# frozen_string_literal: true
#
# api_health_check.rb
#
# Concurrently polls a list of HTTP(S) endpoints, checks status code /
# latency / an optional response-body pattern, retries failures with
# exponential backoff, and reports pass/fail per endpoint. Built entirely on
# Ruby's stdlib (Net::HTTP + Thread) -- no gems, so it drops onto any box
# with Ruby installed and works from cron, CI, or a Nagios-style check.
#
# Endpoints are described in a small JSON config, e.g.:
#
#   [
#     { "name": "web-app",  "url": "https://example.com/healthz", "expect_status": 200 },
#     { "name": "internal", "url": "http://10.0.0.5:9000/status", "expect_status": 200,
#       "expect_body": "\"ok\":\\s*true", "timeout": 3 }
#   ]
#
# Usage:
#   ruby api_health_check.rb --config endpoints.json
#   ruby api_health_check.rb --config endpoints.json --json
#   ruby api_health_check.rb --config endpoints.json --retries 3 --concurrency 10
#   ruby api_health_check.rb --url https://example.com/healthz   # quick one-off check
#
# Exit codes (cron/CI friendly):
#   0 - all endpoints healthy
#   1 - at least one endpoint degraded (succeeded only after retrying)
#   2 - at least one endpoint down (failed all retries)

require 'net/http'
require 'uri'
require 'json'
require 'optparse'
require 'timeout'
require 'time'

CheckResult = Struct.new(:name, :url, :status, :ok, :latency_ms, :attempts, :error, keyword_init: true) do
  def to_h
    {
      name: name, url: url, status: status, ok: ok,
      latency_ms: latency_ms, attempts: attempts, error: error
    }
  end
end

class EndpointChecker
  def initialize(endpoint, retries:, backoff_base:)
    @endpoint = endpoint
    @retries = retries
    @backoff_base = backoff_base
  end

  # Performs the check, retrying on failure with exponential backoff
  # (backoff_base * 2**attempt seconds). Returns a CheckResult.
  def call
    name = @endpoint['name'] || @endpoint['url']
    url = @endpoint['url']
    expect_status = @endpoint['expect_status'] || 200
    expect_body = @endpoint['expect_body']
    timeout = @endpoint['timeout'] || 5

    attempts = 0
    last_error = nil

    (@retries + 1).times do |i|
      attempts += 1
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

      begin
        status, body = perform_request(url, timeout)
        latency_ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round(1)

        if status == expect_status && (expect_body.nil? || body =~ Regexp.new(expect_body))
          return CheckResult.new(
            name: name, url: url, status: status, ok: true,
            latency_ms: latency_ms, attempts: attempts, error: nil
          )
        end

        last_error = "expected status #{expect_status}" \
                     "#{expect_body ? " and body matching /#{expect_body}/" : ''}, got status #{status}"
      rescue StandardError => e
        last_error = "#{e.class}: #{e.message}"
      end

      sleep(@backoff_base * (2**i)) if i < @retries
    end

    CheckResult.new(
      name: name, url: url, status: nil, ok: false,
      latency_ms: nil, attempts: attempts, error: last_error
    )
  end

  private

  def perform_request(url_string, timeout)
    uri = URI.parse(url_string)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = (uri.scheme == 'https')
    http.open_timeout = timeout
    http.read_timeout = timeout

    request = Net::HTTP::Get.new(uri.request_uri.empty? ? '/' : uri.request_uri)
    response = http.request(request)
    [response.code.to_i, response.body.to_s]
  end
end

def parse_options(argv)
  opts = {
    config: nil, url: nil, retries: 2, backoff_base: 0.5,
    concurrency: 8, json: false
  }
  parser = OptionParser.new do |o|
    o.banner = 'Usage: ruby api_health_check.rb [options]'
    o.on('--config FILE', 'JSON file describing endpoints to check') { |v| opts[:config] = v }
    o.on('--url URL', 'Quick one-off check of a single URL (expects HTTP 200)') { |v| opts[:url] = v }
    o.on('--retries N', Integer, 'Retries per endpoint before marking down (default: 2)') { |v| opts[:retries] = v }
    o.on('--backoff SECONDS', Float, 'Base backoff in seconds; doubles each retry (default: 0.5)') { |v| opts[:backoff_base] = v }
    o.on('--concurrency N', Integer, 'Max endpoints checked in parallel (default: 8)') { |v| opts[:concurrency] = v }
    o.on('--json', 'Emit machine-readable JSON instead of text') { opts[:json] = true }
    o.on('-h', '--help', 'Show this help') do
      puts o
      exit 0
    end
  end
  parser.parse!(argv)
  opts
end

def load_endpoints(opts)
  return [{ 'name' => opts[:url], 'url' => opts[:url] }] if opts[:url]

  raise ArgumentError, 'Provide --config FILE or --url URL' unless opts[:config]
  raise ArgumentError, "Config not found: #{opts[:config]}" unless File.readable?(opts[:config])

  JSON.parse(File.read(opts[:config]))
end

# Runs checks concurrently using a bounded thread pool (a simple work queue
# fed to N worker threads), so a config with 200 endpoints doesn't spawn 200
# live sockets at once.
def run_checks(endpoints, opts)
  queue = Queue.new
  endpoints.each { |e| queue << e }
  results = Queue.new

  workers = Array.new([opts[:concurrency], endpoints.size].min.clamp(1, Float::INFINITY).to_i) do
    Thread.new do
      until queue.empty?
        endpoint = begin
          queue.pop(true)
        rescue ThreadError
          nil
        end
        next unless endpoint

        checker = EndpointChecker.new(endpoint, retries: opts[:retries], backoff_base: opts[:backoff_base])
        results << checker.call
      end
    end
  end
  workers.each(&:join)

  out = []
  out << results.pop until results.empty?
  out
end

def print_text_report(results)
  puts "api_health_check: #{results.size} endpoint(s) checked"
  puts '-' * 72
  results.each do |r|
    icon = r.ok ? 'OK  ' : 'DOWN'
    detail = r.ok ? "status=#{r.status} latency=#{r.latency_ms}ms attempts=#{r.attempts}" : "error=#{r.error} attempts=#{r.attempts}"
    puts "[#{icon}] #{r.name.ljust(20)} #{detail}"
  end
end

if __FILE__ == $PROGRAM_NAME
  begin
    options = parse_options(ARGV)
    endpoints = load_endpoints(options)
  rescue ArgumentError, JSON::ParserError => e
    warn "Error: #{e.message}"
    exit 3
  end

  results = run_checks(endpoints, options)

  if options[:json]
    puts JSON.pretty_generate(
      checked_at: Time.now.utc.iso8601,
      endpoint_count: results.size,
      results: results.map(&:to_h)
    )
  else
    print_text_report(results)
  end

  down = results.count { |r| !r.ok }
  degraded = results.count { |r| r.ok && r.attempts > 1 }

  exit(down.positive? ? 2 : degraded.positive? ? 1 : 0)
end
