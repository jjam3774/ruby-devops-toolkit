#!/usr/bin/env ruby
# frozen_string_literal: true
# firewall_audit.rb - audit Windows Firewall inbound-allow rules. Ruby 2.7+, stdlib only.
# Live:    ruby firewall_audit.rb            (runs `netsh advfirewall`, needs an English-locale Windows)
# Offline: ruby firewall_audit.rb --rules rules.txt --profiles profiles.txt
require 'optparse'
require 'json'

RISKY_PORTS = { '21' => 'FTP', '23' => 'Telnet', '135' => 'RPC', '445' => 'SMB',
                '3389' => 'RDP', '5985' => 'WinRM-HTTP', '5986' => 'WinRM-HTTPS' }.freeze

# Parse `netsh advfirewall firewall show rule name=all verbose` into an array of hashes.
# Each rule is a block of "Key:      Value" lines separated by a line of dashes.
def parse_rules(text)
  text.split(/^-{20,}\s*$/).filter_map do |block|
    rule = {}
    block.each_line do |l|
      k, v = l.strip.split(/:\s+/, 2)
      rule[k] = v if k && v && !k.empty?
    end
    rule if rule['Rule Name']
  end
end

# Parse `netsh advfirewall show allprofiles state` -> { "Domain" => "ON", ... }
def parse_profiles(text)
  prof = nil
  text.each_line.with_object({}) do |l, h|
    prof = Regexp.last_match(1) if l =~ /^(\w+) Profile Settings/
    h[prof] = Regexp.last_match(1).upcase if prof && l =~ /^State\s+(\w+)/
  end
end

def audit(rules, profiles)
  out = []
  profiles.each { |p, s| out << ['HIGH', "#{p} profile", 'firewall-off', 'profile state is OFF'] if s == 'OFF' }
  rules.each do |r|
    next unless r['Enabled'] == 'Yes' && r['Direction'] == 'In' && r['Action'] == 'Allow'

    name = r['Rule Name']
    remote_any = r['RemoteIP'].to_s.casecmp('Any').zero?
    ports = r['LocalPort'].to_s.split(',').map(&:strip)
    public_prof = r['Profiles'].to_s =~ /Public|Any|All/i
    risky = ports.select { |pt| RISKY_PORTS.key?(pt) }

    risky.each do |pt|
      sev = remote_any ? 'HIGH' : 'MEDIUM'
      out << [sev, name, 'risky-port', "#{RISKY_PORTS[pt]} (#{pt}) open to #{r['RemoteIP']} on #{r['Profiles']}"]
    end
    if remote_any && public_prof && r['Program'].to_s.casecmp('Any').zero? && r['LocalPort'].to_s.casecmp('Any').zero?
      out << ['HIGH', name, 'wide-open', 'any program, any port, any remote, Public profile']
    end
    if remote_any && r['Program'].to_s =~ /\\(Temp|Downloads|AppData|Users)\\/i
      out << ['MEDIUM', name, 'odd-program-path', "allows inbound for #{r['Program']}"]
    end
  end
  out.sort_by { |s, *| s == 'HIGH' ? 0 : 1 }
end

if $PROGRAM_NAME == __FILE__
  o = {}
  OptionParser.new do |p|
    p.on('--rules FILE') { |v| o[:rules] = v }
    p.on('--profiles FILE') { |v| o[:profiles] = v }
    p.on('-j', '--json') { o[:json] = true }
  end.parse!
  rt = o[:rules] ? File.read(o[:rules]) : `netsh advfirewall firewall show rule name=all verbose`
  pt = o[:profiles] ? File.read(o[:profiles]) : `netsh advfirewall show allprofiles state`
  rules = parse_rules(rt)
  findings = audit(rules, parse_profiles(pt))
  if o[:json]
    puts JSON.pretty_generate(findings.map { |s, n, k, d| { severity: s, rule: n, check: k, detail: d } })
  else
    puts "Parsed #{rules.size} rules"
    findings.each { |s, n, k, d| puts format('%-6s %-14s %-28s %s', s, k, n, d) }
    puts findings.empty? ? 'No findings.' : "#{findings.count { |f| f[0] == 'HIGH' }} high / #{findings.size} total"
  end
  exit(findings.any? { |f| f[0] == 'HIGH' } ? 1 : 0)
end
