#!/usr/bin/env ruby
# frozen_string_literal: true
#
# docker_health_audit.rb -- talk directly to the Docker Engine API (no
# `docker` CLI, no docker-api gem) to inventory every container on a host,
# then flag the specific things that bite people in production: crash-loop
# restarts, containers that mount the Docker socket into themselves (a
# well-known container-escape vector), and containers running --privileged.
#
# Usage:
#   ruby docker_health_audit.rb                              # talks to /var/run/docker.sock
#   ruby docker_health_audit.rb --socket /custom/docker.sock
#   ruby docker_health_audit.rb --host tcp://127.0.0.1:2375   # remote/TCP daemon, or a test double
#   ruby docker_health_audit.rb --json --restart-threshold 3
#
# Exit status:
#   0   no CRIT findings
#   1   at least one CRIT finding
#   2   usage / connection error
#
# Requires: Ruby 3.x, stdlib only (socket, json, optparse, uri, net/http for
# the --host tcp:// path). No gems -- this script speaks the Docker Engine
# API's HTTP-over-Unix-socket protocol directly, the same way the real
# `docker` CLI does under the hood.

require 'socket'
require 'json'
require 'optparse'
require 'uri'
require 'net/http'

# ---------------------------------------------------------------------------
# Minimal HTTP/1.1 GET over a Unix domain socket. Net::HTTP has no built-in
# support for connecting over a UNIXSocket, so for the (default, and most
# common in production) socket transport this hand-rolls just enough of the
# protocol to issue a GET and parse a Content-Length or chunked response.
# This is genuinely how the Docker CLI and most Docker client libraries
# talk to dockerd -- there is no TCP involved unless you've explicitly
# opted the daemon into it.
# ---------------------------------------------------------------------------
def http_get_over_unix_socket(socket_path, path)
  sock = UNIXSocket.new(socket_path)
  begin
    sock.write("GET #{path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\n\r\n")
    raw = sock.read
  ensure
    sock.close
  end

  head, body = raw.split("\r\n\r\n", 2)
  status_line, *header_lines = head.split("\r\n")
  status = status_line.split(' ')[1].to_i
  headers = header_lines.each_with_object({}) do |line, h|
    k, v = line.split(':', 2)
    h[k.strip.downcase] = v.strip if k && v
  end

  if headers['transfer-encoding'].to_s.include?('chunked')
    body = dechunk(body)
  end

  [status, body]
end

def dechunk(body)
  out = +''
  rest = body
  loop do
    size_line, rest = rest.split("\r\n", 2)
    break if size_line.nil?

    size = size_line.strip.to_i(16)
    break if size.zero?

    out << rest[0...size]
    rest = rest[(size + 2)..] # skip the chunk's trailing \r\n
  end
  out
end

# ---------------------------------------------------------------------------
# Thin client abstraction: same #get(path) interface whether we're talking
# to a Unix socket or a tcp:// host (real remote daemon, or a test double
# started with `docker daemon -H tcp://...`-style config, or -- as used to
# verify this script -- a plain HTTP/Unix-socket stub server).
# ---------------------------------------------------------------------------
class DockerClient
  def initialize(socket_path: nil, host: nil)
    @socket_path = socket_path
    @host = host
  end

  def get(path)
    if @host
      uri = URI.parse("#{@host}#{path}")
      res = Net::HTTP.start(uri.hostname, uri.port) { |http| http.request(Net::HTTP::Get.new(uri)) }
      [res.code.to_i, res.body]
    else
      http_get_over_unix_socket(@socket_path, path)
    end
  end

  def get_json(path)
    status, body = get(path)
    parsed = body.to_s.empty? ? nil : (JSON.parse(body) rescue nil)
    [status, parsed]
  end
end

Finding = Struct.new(:severity, :reason, keyword_init: true)

# ---------------------------------------------------------------------------
# Pure classification of one container's /containers/:id/json inspect
# payload. No socket/HTTP in here -- this is what gets exercised directly
# against hand-built fixtures.
# ---------------------------------------------------------------------------
def classify_container(inspect, restart_threshold:)
  findings = []
  name = inspect['Name'].to_s.sub(%r{^/}, '')
  state = inspect.dig('State', 'Status')
  restart_count = inspect['RestartCount'].to_i
  exit_code = inspect.dig('State', 'ExitCode')
  privileged = inspect.dig('HostConfig', 'Privileged')
  binds = inspect.dig('HostConfig', 'Binds') || []

  if restart_count >= restart_threshold && %w[running restarting].include?(state)
    findings << Finding.new(severity: :crit, reason: "restarted #{restart_count} times and is still #{state} -- likely crash-looping")
  end

  if state == 'exited' && exit_code.to_i != 0
    findings << Finding.new(severity: :warn, reason: "exited with non-zero status #{exit_code}")
  end

  if privileged
    findings << Finding.new(severity: :crit, reason: 'running with --privileged (full host device/capability access)')
  end

  if binds.any? { |b| b.include?('docker.sock') }
    findings << Finding.new(severity: :crit, reason: 'mounts the Docker socket into the container -- typically equivalent to root on the host')
  end

  binds.each do |b|
    src = b.split(':').first
    if %w[/ /etc /root].include?(src)
      findings << Finding.new(severity: :warn, reason: "bind-mounts sensitive host path #{src} into the container")
    end
  end

  overall = if findings.any? { |f| f.severity == :crit }
              :crit
            elsif findings.any? { |f| f.severity == :warn }
              :warn
            else
              :ok
            end

  { name: name, state: state, severity: overall, findings: findings }
end

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
options = { socket: '/var/run/docker.sock', host: nil, json: false, restart_threshold: 5 }
parser = OptionParser.new do |opts|
  opts.banner = 'Usage: docker_health_audit.rb [options]'
  opts.on('--socket PATH', "Docker Unix socket path (default: #{options[:socket]})") { |v| options[:socket] = v }
  opts.on('--host URL', 'Connect to a tcp:// Docker host instead of the Unix socket') { |v| options[:host] = v }
  opts.on('--restart-threshold N', Integer, "Flag CRIT at this many restarts (default: #{options[:restart_threshold]})") { |v| options[:restart_threshold] = v }
  opts.on('--json', 'Emit a JSON report instead of text') { options[:json] = true }
  opts.on('-h', '--help', 'Show this help') { puts opts; exit 0 }
end
parser.parse!(ARGV)

client = DockerClient.new(socket_path: options[:socket], host: options[:host])

begin
  status, containers = client.get_json('/containers/json?all=1')
  raise "GET /containers/json -> HTTP #{status}" unless status == 200
rescue StandardError => e
  warn "error: could not reach the Docker API (#{options[:host] || options[:socket]}): #{e.class}: #{e.message}"
  warn 'Is dockerd running, and does this user have permission to access the socket (usually needs the `docker` group)?'
  exit 2
end

reports = containers.map do |c|
  status, inspect = client.get_json("/containers/#{c['Id']}/json")
  if status != 200 || inspect.nil?
    { name: c['Names']&.first.to_s.sub(%r{^/}, ''), state: c['State'], severity: :warn,
      findings: [Finding.new(severity: :warn, reason: "could not inspect container (HTTP #{status})")] }
  else
    classify_container(inspect, restart_threshold: options[:restart_threshold])
  end
end

crit_count = reports.count { |r| r[:severity] == :crit }
warn_count = reports.count { |r| r[:severity] == :warn }

if options[:json]
  puts JSON.pretty_generate(
    total: reports.size, crit: crit_count, warn: warn_count,
    containers: reports.map do |r|
      { name: r[:name], state: r[:state], severity: r[:severity],
        findings: r[:findings].map { |f| { severity: f.severity, reason: f.reason } } }
    end
  )
else
  reports.each do |r|
    tag = { crit: '[CRIT]', warn: '[WARN]', ok: '[ ok ]' }[r[:severity]]
    puts "#{tag} #{r[:name]}  (#{r[:state]})"
    r[:findings].each { |f| puts "        - #{f.reason}" }
  end
  puts '---'
  puts "#{reports.size} containers audited, #{crit_count} CRIT, #{warn_count} WARN"
end

exit(crit_count.positive? ? 1 : 0)
