# test_win_nameres_audit.rb — stub harness: feeds Analyzer realistic fixtures
# (what WMI and the registry would return) so the scoring runs on any OS.
require_relative 'win_nameres_audit'

# A typical domain-joined workstation that nobody has hardened.
adapters = [
  { description: 'Intel(R) Ethernet Connection I219-LM', ip: ['10.20.5.41', 'fe80::1c2a:3b4c:5d6e:7f80'], dhcp: true,
    dns: ['10.20.0.10', '10.20.0.11'], netbios: 0, wins: '' },
  { description: 'Intel(R) Wi-Fi 6 AX201 160MHz', ip: ['192.168.1.57'], dhcp: true,
    dns: ['8.8.8.8', '1.1.1.1'], netbios: 0, wins: '' },
  { description: 'Hyper-V Virtual Ethernet Adapter', ip: ['172.28.0.1'], dhcp: false,
    dns: [], netbios: 2, wins: '' }
]
# IE DefaultConnectionSettings blob: byte 8 = 0x09 -> direct (0x01) + auto-detect (0x08)
dcs = [0x46, 0, 0, 0, 0x2a, 0, 0, 0, 0x09, 0, 0, 0].pack('C*')
reg_unhardened = { 'llmnr' => nil, 'mdns' => nil, 'nodetype' => nil, 'smb1' => nil, 'sign_srv' => 0, 'sign_cli' => 0,
                   'wpad_svc' => 3, 'wpad_policy' => nil, 'wpad_user' => dcs }
checks = Analyzer.run(adapters, reg_unhardened, 1)
print_text(adapters, checks)
status, crit, warn = summarize(checks)
raise "expected CRIT, got #{status}" unless status == 'CRIT'
raise 'LLMNR should fail when policy absent' unless checks.find { |c| c.code == 'LLMNR' }.status == 'FAIL'
raise 'NETBIOS should list two adapters' unless checks.find { |c| c.code == 'NETBIOS' }.detail.scan('TcpipNetbiosOptions').size == 2
raise 'WPAD should detect auto-detect bit' unless checks.find { |c| c.code == 'WPAD_AUTO' }.detail.include?('auto-detect=true')
raise 'public DNS should be reported' unless checks.find { |c| c.code == 'DNS_NOT_LOCAL' }.detail.include?('8.8.8.8')

puts
puts '=== after hardening (GPO applied, SMB1 removed, NetBIOS off) ==='
hardened = adapters.map { |a| a.merge(netbios: 2, dns: a[:dns].map { |d| d.start_with?('10.') ? d : '10.20.0.10' }) }
reg_hardened = { 'llmnr' => 0, 'mdns' => 0, 'nodetype' => 2, 'smb1' => 0, 'sign_srv' => 1, 'sign_cli' => 1,
                 'wpad_svc' => 4, 'wpad_policy' => nil, 'wpad_user' => [0x46, 0, 0, 0, 0x2b, 0, 0, 0, 0x01, 0, 0, 0].pack('C*') }
checks2 = Analyzer.run(hardened, reg_hardened, 2)
print_text(hardened, checks2)
status2, = summarize(checks2)
raise "expected OK after hardening, got #{status2}" unless status2 == 'OK'
puts 'assertions: 6/6 passed'
exit(crit.positive? ? 2 : (warn.positive? ? 1 : 0))
