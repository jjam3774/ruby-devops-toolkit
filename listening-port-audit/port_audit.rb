#!/usr/bin/env ruby
# frozen_string_literal: true
#
# port_audit.rb -- Listening-port baseline auditor for Linux
#
# Enumerates every TCP/UDP socket the host is listening on, compares the live
# picture against a declarative YAML baseline, and reports four classes of
# finding:
#
#   OK          listener matches the baseline (right port, right proto, right scope)
#   UNEXPECTED  something is listening that the baseline never authorised
#   EXPOSED     an authorised service is bound world-wide when the baseline
#               said it should be loopback-only
#   MISSING     the baseline expects a listener that is not currently up
#
# The socket enumeration has two backends. It prefers iproute2's `ss`, because
# that is the only source that reliably gives you the owning process name. If
# `ss` is absent (minimal containers, distroless images, locked-down appliances)
# it falls back to parsing /proc/net/{tcp,tcp6,udp,udp6} directly in pure Ruby
# with no external binaries at all.
#
# Exit codes are designed for cron / Nagios / systemd OnFailure use:
#   0  clean
#   1  drift found (UNEXPECTED / EXPOSED / MISSING)
#   2  the audit itself failed to run
#
# Usage:
#   ruby port_audit.rb --baseline baseline.yml
#   ruby port_audit.rb --baseline baseline.yml --json
#   ruby port_audit.rb --discover > baseline.yml   # bootstrap from a known-good host
#
# Ruby >= 2.7, stdlib only.

require 'yaml'
require 'json'
require 'optparse'
require 'set'

module PortAudit
  VERSION = '1.0.0'

  # ---------------------------------------------------------------------------
  # A single listening socket, normalised so both backends produce the same shape.
  # ---------------------------------------------------------------------------
  Listener = Struct.new(:proto, :addr, :port, :process, :pid, keyword_init: true) do
    # "Scope" is the security-relevant question: who can reach this socket?
    #   :loopback  127.0.0.0/8 or ::1        -- local processes only
    #   :any       0.0.0.0 or ::             -- every interface, incl. the internet
    #   :specific  a particular NIC address  -- one network only
    def scope
      case addr
      when '127.0.0.1', '::1' then :loopback
      when '0.0.0.0', '::', '*' then :any
      else
        addr.start_with?('127.') ? :loopback : :specific
      end
    end

    def key
      "#{proto}/#{port}"
    end

    def to_s
      "#{proto}/#{port} on #{addr} (#{process || 'unknown'})"
    end
  end

  # ---------------------------------------------------------------------------
  # Backend 1: iproute2 `ss`. Gives us the process name, which /proc/net cannot
  # without walking every /proc/*/fd symlink as root.
  # ---------------------------------------------------------------------------
  class SsBackend
    # -t tcp, -u udp, -l listening only, -p show process, -n numeric (no DNS),
    # -H suppress the header row so we do not have to skip it.
    COMMAND = 'ss -tulpnH 2>/dev/null'

    def self.available?
      system('command -v ss > /dev/null 2>&1')
    end

    def name = 'ss'

    def listeners
      out = `#{COMMAND}`
      return [] unless $?.success?

      out.each_line.filter_map { |line| parse_line(line) }
    end

    private

    # A typical line looks like:
    #   tcp   LISTEN 0  4096  127.0.0.1:5432  0.0.0.0:*  users:(("postgres",pid=812,fd=5))
    # UDP lines say UNCONN instead of LISTEN, which is normal for a bound UDP socket.
    def parse_line(line)
      f = line.split
      return nil if f.size < 5

      proto = f[0]
      state = f[1]
      return nil unless %w[LISTEN UNCONN].include?(state)

      local = f[4]
      addr, port = split_endpoint(local)
      return nil if port.nil?

      process, pid = parse_users(line)

      Listener.new(proto: proto.sub(/\d$/, ''), addr: addr, port: port.to_i,
                   process: process, pid: pid)
    end

    # IPv6 endpoints are written [::1]:8080, IPv4 as 127.0.0.1:8080, and a
    # wildcard v6 bind shows up as *:8080. Split on the LAST colon so the v6
    # address itself survives intact.
    def split_endpoint(endpoint)
      idx = endpoint.rindex(':')
      return [nil, nil] unless idx

      addr = endpoint[0...idx].delete('[]')
      port = endpoint[(idx + 1)..]
      addr = '::' if addr == '*'
      [addr, port]
    end

    def parse_users(line)
      m = line.match(/users:\(\("([^"]+)",pid=(\d+)/)
      m ? [m[1], m[2].to_i] : [nil, nil]
    end
  end

  # ---------------------------------------------------------------------------
  # Backend 2: pure-Ruby /proc/net parsing. No shelling out, works in a
  # scratch container. Addresses are little-endian hex, which is the only
  # genuinely fiddly part.
  # ---------------------------------------------------------------------------
  class ProcNetBackend
    # st == 0A is TCP_LISTEN. UDP sockets have no listen state; a bound UDP
    # socket sits in st 07 (TCP_CLOSE reused as "unconnected").
    TCP_LISTEN = '0A'
    UDP_UNCONN = '07'

    SOURCES = {
      '/proc/net/tcp'  => %w[tcp  4],
      '/proc/net/tcp6' => %w[tcp6 6],
      '/proc/net/udp'  => %w[udp  4],
      '/proc/net/udp6' => %w[udp6 6]
    }.freeze

    def self.available? = File.readable?('/proc/net/tcp')

    def name = '/proc/net'

    def listeners
      SOURCES.flat_map do |path, (proto, family)|
        next [] unless File.readable?(path)

        wanted = proto.start_with?('tcp') ? TCP_LISTEN : UDP_UNCONN
        parse_file(path, proto, family.to_i, wanted)
      end
    end

    private

    def parse_file(path, proto, family, wanted_state)
      File.readlines(path).drop(1).filter_map do |line|
        f = line.split
        next nil if f.size < 4
        next nil unless f[3].upcase == wanted_state

        addr_hex, port_hex = f[1].split(':')
        addr = family == 4 ? decode_v4(addr_hex) : decode_v6(addr_hex)
        next nil if addr.nil?

        Listener.new(proto: proto.sub(/6$/, ''), addr: addr,
                     port: port_hex.to_i(16), process: nil, pid: nil)
      end
    end

    # /proc/net/tcp writes IPv4 as a single little-endian 32-bit hex word, so
    # 0100007F is 127.0.0.1 -- read the byte pairs back to front.
    def decode_v4(hex)
      return nil unless hex&.length == 8

      hex.scan(/../).reverse.map { |b| b.to_i(16) }.join('.')
    end

    # IPv6 is four little-endian 32-bit words. Reverse the bytes inside each
    # word, then join, then compress the longest run of zero groups.
    def decode_v6(hex)
      return nil unless hex&.length == 32

      bytes = hex.scan(/.{8}/).flat_map { |word| word.scan(/../).reverse }
      groups = bytes.each_slice(2).map { |hi, lo| (hi + lo).sub(/\A0+(?=.)/, '') }
      compress_v6(groups)
    end

    def compress_v6(groups)
      joined = groups.join(':')
      return '::' if groups.all? { |g| g == '0' }
      return '::1' if groups[0..6].all? { |g| g == '0' } && groups[7] == '1'

      # Collapse the longest run of >=2 zero groups into "::" per RFC 5952.
      best = joined.scan(/(?:\A|:)0(?::0)+(?=:|\z)/).max_by(&:length)
      best ? joined.sub(best, '::').sub(/:::+/, '::') : joined
    end
  end

  # ---------------------------------------------------------------------------
  # The baseline: a declarative description of what SHOULD be listening.
  # ---------------------------------------------------------------------------
  #   allowed:
  #     - port: 22
  #       proto: tcp
  #       scope: any          # any | loopback | specific
  #       process: sshd       # optional; warns on mismatch
  #       required: true      # if absent from the host, report MISSING
  #       note: "fleet SSH"
  #   ignore_ports: [0]       # ports never reported (e.g. ephemeral test rigs)
  class Baseline
    Rule = Struct.new(:port, :proto, :scope, :process, :required, :note,
                      keyword_init: true)

    attr_reader :rules, :ignored

    def initialize(data)
      @ignored = Array(data['ignore_ports']).map(&:to_i).to_set
      @rules = Array(data['allowed']).map do |r|
        Rule.new(
          port: r['port'].to_i,
          proto: (r['proto'] || 'tcp').downcase,
          scope: (r['scope'] || 'any').downcase.to_sym,
          process: r['process'],
          required: r.fetch('required', false),
          note: r['note']
        )
      end
    end

    def self.load(path)
      raise ArgumentError, "baseline not found: #{path}" unless File.exist?(path)

      new(YAML.safe_load(File.read(path)) || {})
    end

    def rule_for(listener)
      @rules.find { |r| r.port == listener.port && r.proto == listener.proto }
    end

    def ignored?(listener) = @ignored.include?(listener.port)
  end

  # ---------------------------------------------------------------------------
  # The comparison engine.
  # ---------------------------------------------------------------------------
  Finding = Struct.new(:status, :severity, :proto, :port, :addr, :process,
                       :detail, keyword_init: true)

  class Auditor
    SEVERITY = { 'UNEXPECTED' => 'high', 'EXPOSED' => 'high',
                 'MISSING' => 'medium', 'DRIFT' => 'low', 'OK' => 'info' }.freeze

    def initialize(baseline) = @baseline = baseline

    def run(listeners)
      findings = listeners.reject { |l| @baseline.ignored?(l) }
                          .map { |l| classify(l) }
      findings + missing_findings(listeners)
    end

    private

    def classify(listener)
      rule = @baseline.rule_for(listener)
      return finding('UNEXPECTED', listener,
                     'no baseline rule authorises this listener') if rule.nil?

      if rule.scope == :loopback && listener.scope != :loopback
        return finding('EXPOSED', listener,
                       "baseline says loopback-only, bound to #{listener.addr}")
      end

      if rule.process && listener.process && rule.process != listener.process
        return finding('DRIFT', listener,
                       "expected process #{rule.process}, found #{listener.process}")
      end

      finding('OK', listener, rule.note || 'matches baseline')
    end

    # A required listener that never showed up in the live scan.
    def missing_findings(listeners)
      live = listeners.map(&:key).to_set
      @baseline.rules.select(&:required).reject { |r| live.include?("#{r.proto}/#{r.port}") }
               .map do |r|
        Finding.new(status: 'MISSING', severity: SEVERITY['MISSING'],
                    proto: r.proto, port: r.port, addr: '-', process: r.process,
                    detail: 'required listener is not running')
      end
    end

    def finding(status, listener, detail)
      Finding.new(status: status, severity: SEVERITY[status], proto: listener.proto,
                  port: listener.port, addr: listener.addr,
                  process: listener.process, detail: detail)
    end
  end

  # ---------------------------------------------------------------------------
  # Output
  # ---------------------------------------------------------------------------
  class Report
    MARK = { 'OK' => '[ OK ]', 'UNEXPECTED' => '[FAIL]', 'EXPOSED' => '[FAIL]',
             'MISSING' => '[WARN]', 'DRIFT' => '[WARN]' }.freeze

    def initialize(findings, source) = (@findings = findings; @source = source)

    def text
      lines = []
      lines << '=' * 74
      lines << "  LISTENING PORT AUDIT   source=#{@source}   #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}"
      lines << '=' * 74
      lines << format('  %-7s %-6s %-6s %-22s %s', 'STATUS', 'PROTO', 'PORT', 'ADDRESS', 'PROCESS')
      lines << '-' * 74

      sorted.each do |f|
        lines << format('  %-7s %-6s %-6s %-22s %s', MARK[f.status], f.proto,
                        f.port, f.addr.to_s[0, 22], f.process || '-')
        lines << "          -> #{f.detail}" unless f.status == 'OK'
      end

      lines << '-' * 74
      lines << "  #{summary_line}"
      lines << '=' * 74
      lines.join("\n")
    end

    def json
      JSON.pretty_generate(
        generated_at: Time.now.utc.iso8601_safe,
        source: @source,
        summary: counts,
        findings: @findings.map(&:to_h)
      )
    end

    def counts
      @findings.group_by(&:status).transform_values(&:size)
    end

    # Anything that is not OK is drift the operator must look at.
    def drift? = @findings.any? { |f| f.status != 'OK' }

    private

    ORDER = %w[UNEXPECTED EXPOSED MISSING DRIFT OK].freeze

    def sorted
      @findings.sort_by { |f| [ORDER.index(f.status) || 9, f.port] }
    end

    def summary_line
      c = counts
      "#{@findings.size} listeners checked | " +
        ORDER.map { |s| "#{s.downcase}=#{c.fetch(s, 0)}" }.join(' ')
    end
  end

  # Small shim so the script works without requiring 'time' on old rubies.
  module TimeShim
    def iso8601_safe = strftime('%Y-%m-%dT%H:%M:%SZ')
  end

  # ---------------------------------------------------------------------------
  # Discovery mode: dump the current state as a baseline you can commit to git.
  # ---------------------------------------------------------------------------
  def self.discover(listeners)
    seen = {}
    listeners.each do |l|
      key = "#{l.proto}/#{l.port}"
      # Prefer the widest scope we saw for a given port, since that is the
      # one that actually determines exposure.
      next if seen[key] && seen[key].scope == :any

      seen[key] = l
    end

    allowed = seen.values.sort_by { |l| [l.proto, l.port] }.map do |l|
      { 'port' => l.port, 'proto' => l.proto, 'scope' => l.scope.to_s,
        'process' => l.process, 'required' => false,
        'note' => 'discovered automatically -- review me' }.compact
    end

    { 'ignore_ports' => [], 'allowed' => allowed }.to_yaml
  end

  def self.backend
    if SsBackend.available?
      SsBackend.new
    elsif ProcNetBackend.available?
      ProcNetBackend.new
    else
      raise 'no usable socket source: neither ss nor /proc/net is available'
    end
  end
end

Time.include(PortAudit::TimeShim)

# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  opts = { baseline: 'baseline.yml', format: :text }

  OptionParser.new do |o|
    o.banner = 'Usage: port_audit.rb [options]'
    o.on('-b', '--baseline PATH', 'YAML baseline file')  { |v| opts[:baseline] = v }
    o.on('-j', '--json', 'emit JSON instead of a table') { opts[:format] = :json }
    o.on('-d', '--discover', 'print a baseline from current state') { opts[:discover] = true }
    o.on('--force-proc', 'skip ss, use the /proc/net parser')       { opts[:force_proc] = true }
    o.on('-v', '--version') { puts "port_audit #{PortAudit::VERSION}"; exit 0 }
    o.on('-h', '--help')    { puts o; exit 0 }
  end.parse!

  begin
    backend = opts[:force_proc] ? PortAudit::ProcNetBackend.new : PortAudit.backend
    listeners = backend.listeners

    if opts[:discover]
      puts PortAudit.discover(listeners)
      exit 0
    end

    baseline = PortAudit::Baseline.load(opts[:baseline])
    findings = PortAudit::Auditor.new(baseline).run(listeners)
    report   = PortAudit::Report.new(findings, backend.name)

    puts opts[:format] == :json ? report.json : report.text
    exit(report.drift? ? 1 : 0)
  rescue StandardError => e
    warn "port_audit: #{e.class}: #{e.message}"
    exit 2
  end
end
