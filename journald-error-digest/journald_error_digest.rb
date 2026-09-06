#!/usr/bin/env ruby
# frozen_string_literal: true
#
# journald_error_digest.rb - Turn a wall of journalctl noise into a ranked,
# de-duplicated digest of what actually went wrong on a Linux box.
#
# The script shells out to `journalctl -o json` (one JSON object per line),
# keeps entries at or above a priority threshold (default: err), collapses
# near-identical messages into "signatures" (numbers, PIDs, hex IDs and
# paths are normalised away), then ranks them by unit and by frequency.
#
# Usage:
#   ruby journald_error_digest.rb                 # last 24h, priority <= err
#   ruby journald_error_digest.rb --since "2 hours ago" --priority warning
#   ruby journald_error_digest.rb --boot           # current boot only
#   ruby journald_error_digest.rb --json > digest.json
#   journalctl -o json --since yesterday | ruby journald_error_digest.rb --stdin
#
# Exit codes: 0 = nothing above threshold, 1 = errors found, 2 = usage/runtime error.
#
# Tested with Ruby 3.0+ on Ubuntu 22.04 (systemd 249). Only stdlib is used.

require 'json'
require 'optparse'
require 'open3'
require 'time'

PRIORITIES = {
  'emerg' => 0, 'alert' => 1, 'crit' => 2, 'err' => 3,
  'warning' => 4, 'notice' => 5, 'info' => 6, 'debug' => 7
}.freeze
PRIORITY_NAMES = PRIORITIES.invert.freeze

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
options = {
  since: '24 hours ago',
  priority: 'err',
  boot: false,
  stdin: false,
  json: false,
  top: 15,
  unit: nil
}

OptionParser.new do |o|
  o.banner = 'Usage: journald_error_digest.rb [options]'
  o.on('--since WHEN', 'journalctl --since expression (default: "24 hours ago")') { |v| options[:since] = v }
  o.on('--priority LEVEL', PRIORITIES.keys, "Highest numeric priority to keep (#{PRIORITIES.keys.join('|')})") { |v| options[:priority] = v }
  o.on('--boot', 'Restrict to the current boot') { options[:boot] = true }
  o.on('--unit UNIT', 'Only this systemd unit (e.g. nginx.service)') { |v| options[:unit] = v }
  o.on('--top N', Integer, 'Show the N most frequent signatures (default 15)') { |v| options[:top] = v }
  o.on('--stdin', 'Read journalctl -o json output from STDIN instead of running journalctl') { options[:stdin] = true }
  o.on('--json', 'Emit the digest as JSON for downstream tooling') { options[:json] = true }
  o.on('-h', '--help') { puts o; exit 0 }
end.parse!

# ---------------------------------------------------------------------------
# Collecting entries
# ---------------------------------------------------------------------------
def build_journalctl_cmd(opts)
  cmd = %w[journalctl -o json --no-pager -q]
  cmd += ['-p', opts[:priority]]              # journalctl filters 0..N for us
  cmd += ['--since', opts[:since]] unless opts[:boot]
  cmd << '-b' if opts[:boot]
  cmd += ['-u', opts[:unit]] if opts[:unit]
  cmd
end

def read_entries(opts)
  raw = if opts[:stdin]
          $stdin.read
        else
          out, err, status = Open3.capture3(*build_journalctl_cmd(opts))
          unless status.success?
            warn "journalctl failed (exit #{status.exitstatus}): #{err.strip}"
            exit 2
          end
          out
        end

  raw.each_line.filter_map do |line|
    line = line.strip
    next if line.empty?
    JSON.parse(line)
  rescue JSON::ParserError
    nil # journald can emit binary/blob fields; skip anything unparseable
  end
end

# ---------------------------------------------------------------------------
# Normalising a message into a signature
# ---------------------------------------------------------------------------
# Two log lines that differ only by a PID, an IP, a timestamp or a hex ID are
# the same *problem*. Collapsing them is what makes the digest readable.
def signature_for(message)
  sig = message.dup
  sig = sig.gsub(/\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b/, '<ip>')          # IPv4[:port]
  sig = sig.gsub(/\b0x[0-9a-f]+\b/i, '<hex>')                               # hex addresses
  sig = sig.gsub(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i, '<uuid>')
  sig = sig.gsub(%r{(/[\w.\-]+){2,}}, '<path>')                             # filesystem paths
  sig = sig.gsub(/\b\d+(?:\.\d+)?(?:ms|s|MB|KB|GB|%)?\b/, '<n>')            # bare numbers / durations
  sig.squeeze(' ').strip[0, 160]
end

def field(entry, *names)
  names.each do |n|
    v = entry[n]
    return v if v.is_a?(String) && !v.empty?
  end
  nil
end

def entry_time(entry)
  usec = entry['__REALTIME_TIMESTAMP'].to_i
  usec.zero? ? nil : Time.at(usec / 1_000_000.0)
end

# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------
def aggregate(entries, max_priority)
  by_sig = Hash.new { |h, k| h[k] = { count: 0, first: nil, last: nil, priority: 7, unit: nil, sample: nil } }
  by_unit = Hash.new(0)
  by_priority = Hash.new(0)

  entries.each do |e|
    prio = e['PRIORITY'].to_i
    next if prio > max_priority

    msg = field(e, 'MESSAGE') || '(no MESSAGE field)'
    unit = field(e, '_SYSTEMD_UNIT', 'UNIT', 'SYSLOG_IDENTIFIER', '_COMM') || 'kernel'
    ts = entry_time(e)
    key = [unit, signature_for(msg)]

    s = by_sig[key]
    s[:count] += 1
    s[:unit] = unit
    s[:sample] ||= msg
    s[:priority] = [s[:priority], prio].min
    s[:first] = ts if ts && (s[:first].nil? || ts < s[:first])
    s[:last] = ts if ts && (s[:last].nil? || ts > s[:last])

    by_unit[unit] += 1
    by_priority[PRIORITY_NAMES[prio] || prio.to_s] += 1
  end

  {
    signatures: by_sig.map { |(unit, sig), v| v.merge(unit: unit, signature: sig) }
                      .sort_by { |v| [v[:priority], -v[:count]] },
    units: by_unit.sort_by { |_, c| -c },
    priorities: by_priority.sort_by { |name, _| PRIORITIES[name] || 99 },
    total: by_sig.values.sum { |v| v[:count] }
  }
end

# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
def fmt_time(t)
  t ? t.strftime('%m-%d %H:%M:%S') : '--'
end

def render_text(digest, opts)
  puts "journald error digest  (since: #{opts[:boot] ? 'this boot' : opts[:since]}, priority <= #{opts[:priority]})"
  puts '=' * 78
  if digest[:total].zero?
    puts 'No journal entries at or above the requested priority. Nice.'
    return
  end

  puts "Total entries: #{digest[:total]}   Distinct problems: #{digest[:signatures].size}"
  puts
  puts 'By priority:'
  digest[:priorities].each { |name, c| puts format('  %-8s %6d', name, c) }
  puts
  puts 'Noisiest units:'
  digest[:units].first(8).each { |unit, c| puts format('  %-40s %6d', unit[0, 40], c) }
  puts
  puts "Top #{opts[:top]} problems (ranked by severity, then frequency):"
  puts format('  %-5s %-7s %-26s %-19s %s', 'COUNT', 'PRIO', 'UNIT', 'LAST SEEN', 'MESSAGE (sample)')
  digest[:signatures].first(opts[:top]).each do |s|
    puts format('  %-5d %-7s %-26s %-19s %s',
                s[:count], PRIORITY_NAMES[s[:priority]], s[:unit][0, 26],
                fmt_time(s[:last]), s[:sample][0, 70])
  end
end

def render_json(digest, opts)
  out = {
    generated_at: Time.now.iso8601,
    since: opts[:boot] ? 'boot' : opts[:since],
    max_priority: opts[:priority],
    total: digest[:total],
    by_priority: digest[:priorities].to_h,
    by_unit: digest[:units].to_h,
    problems: digest[:signatures].first(opts[:top]).map do |s|
      s.merge(priority: PRIORITY_NAMES[s[:priority]],
              first: s[:first]&.iso8601, last: s[:last]&.iso8601)
    end
  }
  puts JSON.pretty_generate(out)
end

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
entries = read_entries(options)
digest = aggregate(entries, PRIORITIES[options[:priority]])
options[:json] ? render_json(digest, options) : render_text(digest, options)
exit(digest[:total].zero? ? 0 : 1)
