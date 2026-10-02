#!/usr/bin/env ruby
# frozen_string_literal: true
#
# failed_units.rb - turn `systemctl --failed` into a triage report: WHY did it fail, and what did it log?
# Ruby 3.0+, stdlib only, systemd 250+ (for --output=json). Usage:
#   ruby failed_units.rb [--lines 3] [--json] [--input units.json] [--user]
#   --input   read a saved `systemctl list-units --failed --output=json` instead of running it
require 'open3'
require 'json'
require 'optparse'

# Result= values from `systemctl show` and what an operator should do about each.
ADVICE = {
  'exit-code'      => 'Process exited non-zero. Read the log lines; run ExecStart by hand as the unit user.',
  'signal'         => 'Killed by a signal (segfault/abort). Check coredumpctl.',
  'core-dump'      => 'Crashed with a core dump. Run: coredumpctl info <unit>.',
  'timeout'        => 'Start/stop timed out. Raise TimeoutStartSec= or fix a hanging dependency.',
  'oom-kill'       => 'Out-of-memory kill. Raise MemoryMax= or fix the leak.',
  'start-limit-hit'=> 'Restarted too fast. Fix the crash, then `systemctl reset-failed`.',
  'resources'      => 'Could not fork/allocate. Check limits, cgroups and free memory.',
  'dependency'     => 'A required unit failed first; fix that one.',
  'protocol'       => 'Service violated its Type= protocol (e.g. never sent READY).'
}.freeze

def sh(*cmd)
  out, _err, st = Open3.capture3(*cmd)
  st.success? ? out : ''
end

def failed_units(opts)
  if opts[:input]
    JSON.parse(File.read(opts[:input]))
  else
    args = ['systemctl', *(opts[:user] ? ['--user'] : []), 'list-units', '--failed', '--all', '--output=json', '--no-pager']
    JSON.parse(sh(*args).then { |o| o.empty? ? '[]' : o })
  end
end

def details(unit, opts)
  return {} if opts[:input] && !opts[:live]
  show = sh('systemctl', *(opts[:user] ? ['--user'] : []), 'show', unit, '-p', 'Result,ExecMainStatus,ActiveEnterTimestamp,NRestarts')
  show.lines.to_h { |l| l.chomp.split('=', 2) }
end

def recent_log(unit, opts)
  return [] if opts[:input] && !opts[:live]
  sh('journalctl', *(opts[:user] ? ['--user'] : []), '-u', unit, '-n', opts[:lines].to_s, '--no-pager', '-o', 'cat').lines.map(&:chomp)
end

opts = { lines: 3, json: false }
OptionParser.new do |o|
  o.on('--lines N', Integer) { |v| opts[:lines] = v }
  o.on('--json') { opts[:json] = true }
  o.on('--input FILE') { |v| opts[:input] = v }
  o.on('--live', 'with --input, still query systemctl/journalctl per unit') { opts[:live] = true }
  o.on('--user') { opts[:user] = true }
end.parse!

report = failed_units(opts).map do |u|
  name = u['unit']
  d = details(name, opts)
  result = d['Result'] || u['sub']
  { unit: name, description: u['description'], active: u['active'], sub: u['sub'],
    result: result, exit_status: d['ExecMainStatus'], restarts: d['NRestarts'],
    advice: ADVICE.fetch(result, 'See `systemctl status` and the journal.'), log: recent_log(name, opts) }
end

if opts[:json]
  puts JSON.pretty_generate(report)
else
  puts report.empty? ? 'No failed units. All good.' : "#{report.size} failed unit(s)"
  report.each do |r|
    puts "\n#{r[:unit]}  [#{r[:result]}#{r[:exit_status] ? ", status=#{r[:exit_status]}" : ''}]  #{r[:description]}"
    puts "  advice: #{r[:advice]}"
    r[:log].each { |l| puts "  log: #{l}" }
  end
end
exit(report.empty? ? 0 : 2)
