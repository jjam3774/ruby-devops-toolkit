#!/usr/bin/env ruby
# frozen_string_literal: true
# win_service_recovery_audit.rb - audit Windows service failure/recovery actions
# via `sc.exe qfailure`, so critical services actually restart after a crash.
# Usage: ruby win_service_recovery_audit.rb [--services A,B] [--fixture DIR] [--json]
# Exit: 0 all OK, 1 warnings, 2 critical.
require 'optparse'
require 'json'
require 'open3'

DEFAULT_SERVICES = %w[W32Time Spooler EventLog Dnscache LanmanServer WinRM].freeze

Result = Struct.new(:service, :sev, :issues, :actions, :reset_secs)

# Parse `sc qfailure` text into { reset_secs:, actions: [[type, delay_ms], ...] }
def parse_qfailure(text)
  reset = text[/RESET_PERIOD.*?:\s*(\d+|INFINITE)/i, 1]
  reset = reset.to_s.upcase == 'INFINITE' ? :infinite : reset&.to_i
  actions = text.scan(/(RESTART|REBOOT|RUN PROCESS|NONE)\s*--\s*Delay\s*=\s*(\d+)\s*milliseconds/i)
                .map { |t, d| [t.upcase, d.to_i] }
  { reset_secs: reset, actions: actions }
end

def evaluate(name, parsed)
  issues = []
  acts = parsed[:actions]
  sev = 'OK'
  if acts.empty? || acts.all? { |t, _| t == 'NONE' }
    issues << 'no recovery actions configured: a crash leaves the service down'
    sev = 'CRIT'
  else
    issues << 'first failure has no action' if acts.first[0] == 'NONE'
    issues << 'REBOOT as first action is aggressive' if acts.first[0] == 'REBOOT'
    issues << 'restart delay under 1s can cause a crash loop' if acts.any? { |t, d| t == 'RESTART' && d < 1000 }
    issues << 'RESTART delay over 5 min' if acts.any? { |t, d| t == 'RESTART' && d > 300_000 }
    sev = 'WARN' unless issues.empty?
  end
  if parsed[:reset_secs].nil? || parsed[:reset_secs] == :infinite
    issues << 'failure counter never resets (RESET_PERIOD infinite/missing)'
    sev = 'WARN' if sev == 'OK'
  end
  Result.new(name, sev, issues, acts, parsed[:reset_secs])
end

def query(name, fixture_dir)
  if fixture_dir
    f = File.join(fixture_dir, "#{name}.txt")
    return File.exist?(f) ? File.read(f) : nil
  end
  out, _err, st = Open3.capture3('sc.exe', 'qfailure', name)
  st.success? ? out : nil
rescue Errno::ENOENT
  warn 'sc.exe not found: run on Windows or use --fixture'
  exit 3
end

if $PROGRAM_NAME == __FILE__
  o = { services: DEFAULT_SERVICES }
  OptionParser.new do |p|
    p.on('--services LIST') { |v| o[:services] = v.split(',') }
    p.on('--fixture DIR') { |v| o[:fixture] = v }
    p.on('--json') { o[:json] = true }
  end.parse!
  results = o[:services].map do |s|
    text = query(s, o[:fixture])
    text ? evaluate(s, parse_qfailure(text)) : Result.new(s, 'WARN', ['service not found / query failed'], [], nil)
  end
  if o[:json]
    puts JSON.pretty_generate(results.map(&:to_h))
  else
    results.each do |r|
      puts format('[%-4s] %-12s %s', r.sev, r.service, r.actions.map { |t, d| "#{t}(#{d / 1000}s)" }.join(' > '))
      r.issues.each { |i| puts "         - #{i}" }
    end
  end
  exit(results.any? { |r| r.sev == 'CRIT' } ? 2 : (results.any? { |r| r.sev == 'WARN' } ? 1 : 0))
end
