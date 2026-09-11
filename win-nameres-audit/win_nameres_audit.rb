#!/usr/bin/env ruby
# frozen_string_literal: true
#
# win_nameres_audit.rb — audit a Windows host for the name-resolution and SMB
# settings that make credential-relay attacks (Responder, ntlmrelayx) work.
#
# When DNS fails to resolve a name, Windows falls back to asking the local
# network: LLMNR, NetBIOS-NS and mDNS broadcasts, plus a WPAD lookup for a proxy.
# Anyone on the same segment can answer "that's me", collect an NTLMv2 hash or
# relay the authentication, and be a domain user before lunch. Every one of
# these fallbacks can be turned off; this script checks whether they were.
#
# Checks (severity):
#   [CRIT] LLMNR          EnableMulticast policy missing or != 0
#   [CRIT] NETBIOS        NetBIOS over TCP/IP enabled on an IP-enabled adapter
#   [CRIT] SMB1_ENABLED   SMB1 server component present / not disabled
#   [WARN] SMB_SIGN_SRV   LanmanServer RequireSecuritySignature != 1
#   [WARN] SMB_SIGN_CLI   LanmanWorkstation RequireSecuritySignature != 1
#   [WARN] MDNS           EnableMDNS != 0 (Windows 10 1703+ answers mDNS by default)
#   [WARN] WPAD_AUTO      proxy auto-detect on, or WinHttpAutoProxySvc not disabled
#   [WARN] NETBT_NODE     NodeType != 2 (P-node) so NetBIOS still broadcasts
#   [INFO] WINS           a WINS server is configured (legacy, but not exploitable by itself)
#   [INFO] DNS_NOT_LOCAL  adapter DNS servers are not RFC1918/link-local (public resolvers on a domain host)
#
# Usage:  ruby win_nameres_audit.rb [--json]      (run elevated for HKLM policy keys)
# Exit:   0 clean, 1 warnings only, 2 any CRIT
#
# Requirements: Ruby 3.x on Windows; win32ole (stdlib) and win32-registry (default gem).
# The analysis layer takes plain Hashes/Arrays, so it is unit-tested on Linux with
# fixtures — see test_win_nameres_audit.rb.

require 'optparse'
require 'json'

# --------------------------------------------------------------------------
# Data sources — the only code that touches Windows.
# --------------------------------------------------------------------------
class WindowsSources
  def initialize
    require 'win32ole'
    require 'win32/registry'
    @wmi = WIN32OLE.connect('winmgmts:\\\\.\\root\\cimv2')
  end

  # One Hash per IP-enabled adapter (WMI Win32_NetworkAdapterConfiguration).
  def adapters
    q = 'SELECT Description, IPEnabled, IPAddress, DHCPEnabled, DNSServerSearchOrder, TcpipNetbiosOptions, WINSPrimaryServer FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE'
    @wmi.ExecQuery(q).map do |a|
      { description: a.Description.to_s, ip: Array(a.IPAddress).map(&:to_s), dhcp: a.DHCPEnabled ? true : false,
        dns: Array(a.DNSServerSearchOrder).map(&:to_s), netbios: a.TcpipNetbiosOptions.to_i, wins: a.WINSPrimaryServer.to_s }
    end
  end

  # SMB1 feature state via WMI Win32_OptionalFeature (InstallState 1 = enabled, 2 = disabled)
  def smb1_feature_state
    @wmi.ExecQuery("SELECT InstallState FROM Win32_OptionalFeature WHERE Name = 'SMB1Protocol-Server'").map { |f| f.InstallState.to_i }.first
  rescue WIN32OLERuntimeError
    nil
  end

  # Registry values as a flat Hash of "HIVE\\path\\value" => data (nil when absent).
  REG_VALUES = {
    'llmnr'       => ['HKLM', 'SOFTWARE\Policies\Microsoft\Windows NT\DNSClient', 'EnableMulticast'],
    'mdns'        => ['HKLM', 'SYSTEM\CurrentControlSet\Services\Dnscache\Parameters', 'EnableMDNS'],
    'nodetype'    => ['HKLM', 'SYSTEM\CurrentControlSet\Services\NetBT\Parameters', 'NodeType'],
    'smb1'        => ['HKLM', 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters', 'SMB1'],
    'sign_srv'    => ['HKLM', 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters', 'RequireSecuritySignature'],
    'sign_cli'    => ['HKLM', 'SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters', 'RequireSecuritySignature'],
    'wpad_svc'    => ['HKLM', 'SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc', 'Start'],
    'wpad_policy' => ['HKLM', 'SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings', 'EnableAutoProxyResultCache'],
    'wpad_user'   => ['HKCU', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections', 'DefaultConnectionSettings']
  }.freeze

  def registry
    REG_VALUES.transform_values do |hive, path, name|
      root = hive == 'HKLM' ? Win32::Registry::HKEY_LOCAL_MACHINE : Win32::Registry::HKEY_CURRENT_USER
      root.open(path, Win32::Registry::KEY_READ | 0x0100) { |k| k[name] }
    rescue Win32::Registry::Error
      nil
    end
  end
end

# --------------------------------------------------------------------------
# Analysis — pure Ruby. adapters is an Array of Hashes, reg a Hash of the
# keys above, smb1_state an Integer or nil.
# --------------------------------------------------------------------------
module Analyzer
  Check = Struct.new(:severity, :code, :status, :detail, :fix, keyword_init: true)

  PRIVATE_DNS = [/\A10\./, /\A192\.168\./, /\A172\.(1[6-9]|2\d|3[01])\./, /\A127\./, /\A169\.254\./, /\Afe80:/i, /\Afd/i, /\A::1\z/].freeze

  def self.run(adapters, reg, smb1_state)
    c = []

    # LLMNR: policy value 0 disables. Absent = enabled (the default).
    llmnr = reg['llmnr']
    c << Check.new(severity: 'CRIT', code: 'LLMNR', status: llmnr.to_i.zero? && !llmnr.nil? ? 'PASS' : 'FAIL',
                   detail: llmnr.nil? ? 'EnableMulticast policy not set (LLMNR on by default)' : "EnableMulticast=#{llmnr}",
                   fix: 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f')

    # NetBIOS over TCP/IP per adapter: 0 = via DHCP (usually on), 1 = on, 2 = off
    nb_on = adapters.select { |a| a[:netbios] != 2 }
    c << Check.new(severity: 'CRIT', code: 'NETBIOS', status: nb_on.empty? ? 'PASS' : 'FAIL',
                   detail: nb_on.empty? ? 'disabled on all IP-enabled adapters' : nb_on.map { |a| "#{a[:description]} (TcpipNetbiosOptions=#{a[:netbios]})" }.join('; '),
                   fix: 'wmic nicconfig where IPEnabled=true call SetTcpipNetbios 2   (or Set-NetAdapterBinding / DHCP option 001)')

    # mDNS: EnableMDNS 0 disables; absent = enabled on Win10 1703+
    md = reg['mdns']
    c << Check.new(severity: 'WARN', code: 'MDNS', status: !md.nil? && md.to_i.zero? ? 'PASS' : 'FAIL',
                   detail: md.nil? ? 'EnableMDNS not set (mDNS responder on by default)' : "EnableMDNS=#{md}",
                   fix: 'reg add HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters /v EnableMDNS /t REG_DWORD /d 0 /f')

    # NetBT node type: 2 = P-node (WINS only, no broadcast). 1 B, 4 M, 8 H.
    nt = reg['nodetype']
    c << Check.new(severity: 'WARN', code: 'NETBT_NODE', status: nt.to_i == 2 ? 'PASS' : 'FAIL',
                   detail: nt.nil? ? 'NodeType not set (H-node when WINS configured, else B-node broadcasts)' : "NodeType=#{nt}",
                   fix: 'reg add HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters /v NodeType /t REG_DWORD /d 2 /f')

    # SMB1: feature disabled (InstallState 2) or SMB1=0 in LanmanServer
    smb1 = reg['smb1']
    smb1_off = (smb1_state == 2) || (!smb1.nil? && smb1.to_i.zero?)
    c << Check.new(severity: 'CRIT', code: 'SMB1_ENABLED', status: smb1_off ? 'PASS' : 'FAIL',
                   detail: "SMB1Protocol-Server InstallState=#{smb1_state.inspect}, LanmanServer\\SMB1=#{smb1.inspect}",
                   fix: 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol  /  Set-SmbServerConfiguration -EnableSMB1Protocol $false')

    # SMB signing
    c << Check.new(severity: 'WARN', code: 'SMB_SIGN_SRV', status: reg['sign_srv'].to_i == 1 ? 'PASS' : 'FAIL',
                   detail: "LanmanServer RequireSecuritySignature=#{reg['sign_srv'].inspect}",
                   fix: 'Set-SmbServerConfiguration -RequireSecuritySignature $true')
    c << Check.new(severity: 'WARN', code: 'SMB_SIGN_CLI', status: reg['sign_cli'].to_i == 1 ? 'PASS' : 'FAIL',
                   detail: "LanmanWorkstation RequireSecuritySignature=#{reg['sign_cli'].inspect}",
                   fix: 'Set-SmbClientConfiguration -RequireSecuritySignature $true')

    # WPAD: service Start 4 = disabled. DefaultConnectionSettings byte 8 bit 0x08 = auto-detect on.
    svc_disabled = reg['wpad_svc'].to_i == 4
    dcs = reg['wpad_user']
    autodetect = dcs.is_a?(String) && dcs.bytesize > 8 ? (dcs.getbyte(8) & 0x08) != 0 : nil
    wpad_fail = !svc_disabled || autodetect == true
    c << Check.new(severity: 'WARN', code: 'WPAD_AUTO', status: wpad_fail ? 'FAIL' : 'PASS',
                   detail: "WinHttpAutoProxySvc Start=#{reg['wpad_svc'].inspect}#{autodetect.nil? ? '' : ", IE auto-detect=#{autodetect}"}",
                   fix: 'sc config WinHttpAutoProxySvc start= disabled; untick "Automatically detect settings"; add a wpad DNS record pointing at a sinkhole')

    # WINS / DNS hygiene (informational)
    wins = adapters.select { |a| !a[:wins].empty? }
    c << Check.new(severity: 'INFO', code: 'WINS', status: wins.empty? ? 'PASS' : 'FAIL',
                   detail: wins.empty? ? 'no WINS servers' : wins.map { |a| "#{a[:description]} -> #{a[:wins]}" }.join('; '), fix: 'remove WINS once NetBIOS is off')
    pub = adapters.flat_map { |a| a[:dns].reject { |d| PRIVATE_DNS.any? { |re| d =~ re } }.map { |d| "#{a[:description]} -> #{d}" } }
    c << Check.new(severity: 'INFO', code: 'DNS_NOT_LOCAL', status: pub.empty? ? 'PASS' : 'FAIL',
                   detail: pub.empty? ? 'all adapter DNS servers are private/link-local' : pub.join('; '), fix: 'point domain members at internal resolvers only')
    c
  end
end

def summarize(checks)
  fails = checks.reject { |k| k.status == 'PASS' }
  crit = fails.count { |k| k.severity == 'CRIT' }
  warn = fails.count { |k| k.severity == 'WARN' }
  [crit.positive? ? 'CRIT' : (warn.positive? ? 'WARN' : 'OK'), crit, warn]
end

def print_text(adapters, checks)
  status, crit, warn = summarize(checks)
  puts "win_nameres_audit  #{Time.now.strftime('%Y-%m-%d %H:%M')}  #{adapters.size} IP-enabled adapter(s)"
  puts '-' * 100
  adapters.each do |a|
    puts format('  %-40s ip=%-16s dhcp=%-5s netbios=%-1s dns=%s', a[:description][0, 40], a[:ip].first, a[:dhcp], a[:netbios], a[:dns].join(','))
  end
  puts
  puts format('%-6s %-14s %-5s %s', 'SEV', 'CHECK', 'RESULT', 'DETAIL')
  checks.each do |k|
    puts format('%-6s %-14s %-5s %s', k.severity, k.code, k.status, k.detail)
    puts format('%-6s %-14s %-5s fix: %s', '', '', '', k.fix) if k.status == 'FAIL' && k.severity != 'INFO'
  end
  puts
  puts "#{status}: #{crit} critical, #{warn} warning(s) — #{checks.count { |k| k.status == 'PASS' }}/#{checks.size} checks pass"
end

if __FILE__ == $PROGRAM_NAME
  opts = { json: false }
  OptionParser.new do |o|
    o.banner = 'Usage: win_nameres_audit.rb [--json]'
    o.on('--json', 'JSON output') { opts[:json] = true }
  end.parse!
  abort 'win_nameres_audit.rb only runs on Windows (needs win32ole + win32/registry)' unless RUBY_PLATFORM =~ /mingw|mswin|cygwin/

  src = WindowsSources.new
  adapters = src.adapters
  checks = Analyzer.run(adapters, src.registry, src.smb1_feature_state)
  status, crit, warn = summarize(checks)
  if opts[:json]
    puts JSON.pretty_generate(status: status, critical: crit, warnings: warn, adapters: adapters, checks: checks.map(&:to_h))
  else
    print_text(adapters, checks)
  end
  exit(crit.positive? ? 2 : (warn.positive? ? 1 : 0))
end
