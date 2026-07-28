#!/usr/bin/env ruby
# frozen_string_literal: true
#
# prometheus_exporter.rb
#
# A minimal Prometheus "node exporter" written in pure Ruby: it reads system
# stats straight from /proc, serves them as an HTTP /metrics endpoint in the
# Prometheus text exposition format, and needs nothing but the standard
# library -- no `prometheus-client` gem, no Sinatra, no WEBrick.
#
# Why this exists: every monitoring stack eventually needs "just one more
# metric" from a box that doesn't have an exporter for it -- a custom queue
# depth, an app-specific counter, a stat some vendor exporter doesn't expose.
# Reaching for a full framework for that is overkill. This script shows the
# whole exporter pattern (registry -> collectors -> HTTP handler -> text
# format) in ~150 lines you can read in one sitting and bolt custom metrics
# onto directly.
#
# Usage:
#   ruby prometheus_exporter.rb --port 9200
#   curl http://localhost:9200/metrics
#
# Then point Prometheus at it with a scrape config:
#   scrape_configs:
#     - job_name: 'ruby_node_exporter'
#       static_configs:
#         - targets: ['localhost:9200']
#
# Requires: Ruby >= 2.7 (stdlib only: socket, optparse). Reads /proc, so the
# system-stat collectors below are Linux-specific; the HTTP server and
# metrics registry are portable to any OS (see the Windows note in
# Troubleshooting for how to swap in WMI-backed collectors there).

require 'socket'
require 'optparse'

# --- Metric registry --------------------------------------------------------
#
# A tiny stand-in for what `prometheus-client` gives you: named metrics with
# help text and a type, rendered in the Prometheus text exposition format.
# Real Prometheus metric types (counter, gauge) are represented here just
# well enough to be correct for scraping -- this is deliberately not a full
# client library.
class MetricsRegistry
  Metric = Struct.new(:name, :help, :type, :value_fn)

  def initialize
    @metrics = []
  end

  # Registers a gauge: a value that can go up or down (e.g. current memory
  # used). `value_fn` is called fresh on every scrape so the exporter always
  # reports live data, not a stale snapshot from startup.
  def gauge(name, help, &value_fn)
    @metrics << Metric.new(name, help, 'gauge', value_fn)
  end

  # Registers a counter: a value that only increases (e.g. total requests
  # served). Prometheus counters are rendered identically to gauges on the
  # wire -- the distinction is purely about how consumers should interpret
  # resets -- but we track the type for the HELP/TYPE header lines.
  def counter(name, help, &value_fn)
    @metrics << Metric.new(name, help, 'counter', value_fn)
  end

  # Renders every registered metric in the Prometheus text exposition
  # format: https://prometheus.io/docs/instrumenting/exposition_formats/
  def render
    lines = []
    @metrics.each do |m|
      value = m.value_fn.call
      next if value.nil? # collector unavailable on this platform -- skip silently

      lines << "# HELP #{m.name} #{m.help}"
      lines << "# TYPE #{m.name} #{m.type}"
      lines << "#{m.name} #{format_value(value)}"
    end
    "#{lines.join("\n")}\n"
  end

  private

  def format_value(v)
    v.is_a?(Float) ? format('%.4f', v) : v.to_s
  end
end

# --- /proc collectors (Linux) -----------------------------------------------
#
# Each method returns nil (rather than raising) when the expected /proc file
# isn't present, so the registry can skip that metric gracefully on
# non-Linux platforms instead of crashing the whole exporter.
module ProcStats
  module_function

  def load_average_1m
    File.read('/proc/loadavg').split(' ').first.to_f
  rescue Errno::ENOENT
    nil
  end

  def memory_total_bytes
    meminfo['MemTotal']
  end

  def memory_available_bytes
    meminfo['MemAvailable']
  end

  def uptime_seconds
    File.read('/proc/uptime').split(' ').first.to_f
  rescue Errno::ENOENT
    nil
  end

  def meminfo
    return {} unless File.exist?('/proc/meminfo')

    File.readlines('/proc/meminfo').each_with_object({}) do |line, acc|
      # Lines look like "MemTotal:       16384000 kB"
      key, rest = line.split(':', 2)
      next unless rest

      kb = rest.strip.split(' ').first.to_i
      acc[key] = kb * 1024 # normalize to bytes, Prometheus convention
    end
  end
end

# --- HTTP server -------------------------------------------------------------
#
# A deliberately tiny HTTP/1.1 server built directly on TCPServer. It only
# understands enough of HTTP to (a) read a request line, (b) drain any
# request headers, and (c) write a well-formed response -- exactly what a
# scrape endpoint needs and nothing more. Each connection is handled on its
# own thread so a slow/stalled scraper client can't block others.
class Exporter
  def initialize(registry, port:, request_counter: nil)
    @registry = registry
    @port = port
    @request_counter = request_counter
  end

  def start
    server = TCPServer.new(@port)
    puts "prometheus_exporter listening on :#{@port} (GET /metrics)"

    loop do
      client = server.accept
      Thread.new(client) { |c| handle(c) }
    end
  ensure
    server&.close
  end

  private

  def handle(client)
    request_line = client.gets
    return unless request_line

    # Drain headers until the blank line that ends an HTTP request; we
    # don't need their contents for this read-only endpoint.
    while (line = client.gets)
      break if line == "\r\n" || line == "\n"
    end

    method, path, = request_line.split(' ')

    if method == 'GET' && path == '/metrics'
      @request_counter&.call
      body = @registry.render
      respond(client, 200, 'OK', 'text/plain; version=0.0.4', body)
    else
      respond(client, 404, 'Not Found', 'text/plain', "not found: #{path}\n")
    end
  rescue StandardError => e
    warn "request error: #{e.message}"
  ensure
    client.close
  end

  def respond(client, code, reason, content_type, body)
    client.write("HTTP/1.1 #{code} #{reason}\r\n")
    client.write("Content-Type: #{content_type}\r\n")
    client.write("Content-Length: #{body.bytesize}\r\n")
    client.write("Connection: close\r\n\r\n")
    client.write(body)
  end
end

# --- CLI entry point ---------------------------------------------------------
if $PROGRAM_NAME == __FILE__
  options = { port: 9200 }
  OptionParser.new do |opts|
    opts.banner = 'Usage: prometheus_exporter.rb [options]'
    opts.on('--port N', Integer, 'Port to listen on (default 9200)') { |v| options[:port] = v }
  end.parse!

  registry = MetricsRegistry.new
  scrape_count = 0

  registry.gauge('node_load1', 'Load average over the last minute') { ProcStats.load_average_1m }
  registry.gauge('node_memory_total_bytes', 'Total physical memory in bytes') { ProcStats.memory_total_bytes }
  registry.gauge('node_memory_available_bytes', 'Available physical memory in bytes') { ProcStats.memory_available_bytes }
  registry.gauge('node_uptime_seconds', 'Seconds since boot') { ProcStats.uptime_seconds }
  registry.gauge('ruby_exporter_process_uptime_seconds', 'Seconds since this exporter process started') do
    (Process.clock_gettime(Process::CLOCK_MONOTONIC) - $exporter_start).round(4)
  end
  # Example custom counter: total number of times this exporter itself has
  # been scraped. This is the pattern you'd copy for an app-specific metric.
  registry.counter('ruby_exporter_scrapes_total', 'Total number of /metrics scrapes served') { scrape_count }

  $exporter_start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  exporter = Exporter.new(registry, port: options[:port], request_counter: -> { scrape_count += 1 })

  trap('INT') do
    puts "\nShutting down."
    exit
  end

  exporter.start
end
