#!/usr/bin/env ruby
# frozen_string_literal: true
# win_time_service_audit.rb - audit the Windows Time service (w32tm) for the
# misconfigurations that silently break Kerberos (5-minute skew limit).
# Runs `w32tm /query /status` and `/query /configuration` and grades them.
# Usage (Windows):  ruby win_time_service_audit.rb [--json] [--max-sync-hours 24]
#       (anywhere):  ruby win_time_service_audit.rb --fixture DIR   # status.txt + config.txt
# Exit: 0 PASS, 1 WARN, 2 FAIL.  Stdlib only.
require 'optparse'
require 'json'
require 'open3'
require 'time'

opts = { json: false, max_sync_hours: 24, fixture: nil, domain_joined: true }
OptionParser.new do |o|
  o.on('--json') { opts[:json] = true }
  o.on('--max-sync-hours N', Float) { |v| opts[:max_sync_hours] = v }
  o.on('--fixture DIR', 'read status.txt/config.txt instead of running w32tm') { |v| opts[:fixture] = v }
  o.on('--standalone', 'host is not domain joined (expects Type NTP)') { opts[:domain_joined] = false }
end.parse!

def w32tm(args, fixture, fname)
  return File.read(File.join(fixture, fname)) if fixture
  out, err, st = Open3.capture3('w32tm', *args)
  raise "w32tm #{args.join(' ')} failed: #{err.strip.empty? ? out.strip : err.strip}" unless st.success?
  out
end

# "Key: value" lines -> hash. Keys repeat across [sections] in /configuration,
# so we track the current section and namespace keys as "Section/Key".
def parse_kv(text)
  section = nil
  text.each_line.with_object({}) do |line, h|
    line = line.strip
    if line =~ /\A\[(.+)\]\z/ then section = Regexp.last_match(1); next end
    next unless line =~ /\A([^:]+):\s*(.*?)\s*(\(Local\)|\(Policy\))?\z/
    key = Regexp.last_match(1).strip
    key = "#{section}/#{key}" if section
    h[key] = Regexp.last_match(2)
  end
end

# Locale-dependent timestamp; return nil rather than guess if we can't parse it.
def parse_time(s)
  Time.strptime(s, '%m/%d/%Y %I:%M:%S %p')
rescue ArgumentError
  (Time.parse(s) rescue nil)
end

Finding = Struct.new(:sev, :check, :detail)

def evaluate(status, config, opts, now: Time.now)
  f = []
  src = status['Source'].to_s
  if src.empty? || src =~ /Local CMOS Clock|Free-running/i
    f << Finding.new('FAIL', 'source', "clock is free-running (Source: #{src.empty? ? 'none' : src}); nothing is disciplining it")
  else
    f << Finding.new('PASS', 'source', "syncing from #{src}")
  end

  last = parse_time(status['Last Successful Sync Time'].to_s)
  if last.nil?
    f << Finding.new('WARN', 'last-sync', "unparseable/absent: #{status['Last Successful Sync Time'].inspect}")
  else
    hrs = (now - last) / 3600.0
    sev = hrs > opts[:max_sync_hours] * 2 ? 'FAIL' : hrs > opts[:max_sync_hours] ? 'WARN' : 'PASS'
    f << Finding.new(sev, 'last-sync', format('%.1f h ago (limit %g h)', hrs, opts[:max_sync_hours]))
  end

  stratum = status['Stratum'].to_s[/\d+/].to_i
  f << Finding.new(stratum.zero? || stratum > 5 ? 'WARN' : 'PASS', 'stratum', "stratum #{stratum}")

  type = config['NtpClient/Type'].to_s.split.first
  want = opts[:domain_joined] ? 'NT5DS' : 'NTP'
  if type == want || (type == 'AllSync' && !opts[:domain_joined])
    f << Finding.new('PASS', 'client-type', "Type=#{type}")
  else
    f << Finding.new('WARN', 'client-type', "Type=#{type.inspect}, expected #{want} for this host role")
  end

  if config['NtpClient/Enabled'].to_s.split.first == '0'
    f << Finding.new('FAIL', 'ntpclient', 'NtpClient provider is disabled')
  end

  pos = config['Config/MaxPosPhaseCorrection'].to_i
  neg = config['Config/MaxNegPhaseCorrection'].to_i
  if pos > 172_800 || neg > 172_800 # 48 h: the accidental "accept anything" setting
    f << Finding.new('WARN', 'phase-correction', "MaxPos/NegPhaseCorrection #{pos}/#{neg}s lets a bad source step the clock by days")
  end
  f
end

begin
  status = parse_kv(w32tm(%w[/query /status], opts[:fixture], 'status.txt'))
  config = parse_kv(w32tm(%w[/query /configuration], opts[:fixture], 'config.txt'))
rescue StandardError => e
  warn "ERROR: #{e.message}"; exit 2
end

findings = evaluate(status, config, opts)
worst = findings.map(&:sev).include?('FAIL') ? 'FAIL' : findings.map(&:sev).include?('WARN') ? 'WARN' : 'PASS'
if opts[:json]
  puts JSON.pretty_generate(overall: worst, findings: findings.map(&:to_h))
else
  puts "win-time-service-audit: #{worst}"
  findings.each { |x| puts format('  [%-4s] %-16s %s', x.sev, x.check, x.detail) }
end
exit({ 'PASS' => 0, 'WARN' => 1, 'FAIL' => 2 }[worst])
