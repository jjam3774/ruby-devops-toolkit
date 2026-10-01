#!/usr/bin/env ruby
# frozen_string_literal: true
# win_uac_audit.rb - grade User Account Control settings read from
#   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
# On Windows it reads the live registry (win32/registry, stdlib). Anywhere else
# use --fixture values.json. --self-test runs built-in fixtures on any OS.
# Exit: 0 all PASS, 1 WARN, 2 FAIL
require 'json'
require 'optparse'

KEY = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'

# name => [good-test lambda, severity if bad, why, fix]
RULES = {
  'EnableLUA' => [->(v) { v == 1 }, 'FAIL', 'UAC is switched off entirely', 'Set EnableLUA=1 and reboot'],
  'ConsentPromptBehaviorAdmin' => [->(v) { [2, 5].include?(v) }, 'FAIL',
                                   'admins elevate with no prompt (0) or without secure desktop (1,3,4)',
                                   'Set to 2 (always prompt) or 5 (default)'],
  'ConsentPromptBehaviorUser' => [->(v) { [0, 1, 3].include?(v) }, 'WARN',
                                  'unexpected value - standard users should get a credential prompt (3, default, 1) or be denied (0)',
                                  'Set to 3 (default), 1, or 0'],
  'PromptOnSecureDesktop' => [->(v) { v == 1 }, 'FAIL',
                              'prompts render on the user desktop where malware can click them',
                              'Set PromptOnSecureDesktop=1'],
  'FilterAdministratorToken' => [->(v) { v == 1 }, 'WARN',
                                 'built-in Administrator (RID 500) is exempt from Admin Approval Mode',
                                 'Set FilterAdministratorToken=1'],
  'EnableInstallerDetection' => [->(v) { v == 1 }, 'WARN', 'installers do not trigger elevation prompts',
                                 'Set EnableInstallerDetection=1'],
  'EnableVirtualization' => [->(v) { v == 1 }, 'WARN', 'legacy apps write straight to protected locations',
                             'Set EnableVirtualization=1'],
  'LocalAccountTokenFilterPolicy' => [->(v) { v.nil? || v.zero? }, 'FAIL',
                                      'remote local-admin logons get a full token (pass-the-hash lateral movement)',
                                      'Delete the value or set it to 0']
}.freeze

# Missing values fall back to Windows defaults before judging.
DEFAULTS = { 'EnableLUA' => 1, 'ConsentPromptBehaviorAdmin' => 5, 'ConsentPromptBehaviorUser' => 3,
             'PromptOnSecureDesktop' => 1, 'FilterAdministratorToken' => 0, 'EnableInstallerDetection' => 1,
             'EnableVirtualization' => 1, 'LocalAccountTokenFilterPolicy' => nil }.freeze

def read_registry
  require 'win32/registry'
  Win32::Registry::HKEY_LOCAL_MACHINE.open(KEY) do |reg|
    RULES.keys.to_h do |name|
      [name, (reg[name] rescue nil)]
    end
  end
end

def evaluate(values)
  RULES.map do |name, (ok, sev, why, fix)|
    v = values.key?(name) && !values[name].nil? ? values[name] : DEFAULTS[name]
    pass = ok.call(v)
    { setting: name, value: v, status: pass ? 'PASS' : sev, why: pass ? nil : why, fix: pass ? nil : fix }
  end
end

def exit_code(results)
  return 2 if results.any? { |r| r[:status] == 'FAIL' }
  results.any? { |r| r[:status] == 'WARN' } ? 1 : 0
end

def report(results, json)
  if json
    puts JSON.pretty_generate(results)
  else
    results.each do |r|
      puts format('%-5s %-31s = %s', r[:status], r[:setting], r[:value].inspect)
      puts "        why: #{r[:why]}\n        fix: #{r[:fix]}" if r[:why]
    end
  end
end

def self_test
  good = DEFAULTS.merge('ConsentPromptBehaviorAdmin' => 2, 'FilterAdministratorToken' => 1)
  bad  = good.merge('EnableLUA' => 0, 'ConsentPromptBehaviorAdmin' => 0, 'LocalAccountTokenFilterPolicy' => 1)
  raise 'good fixture should pass' unless exit_code(evaluate(good)).zero?
  raise 'bad fixture should fail' unless exit_code(evaluate(bad)) == 2
  fails = evaluate(bad).count { |r| r[:status] == 'FAIL' }
  raise "expected 3 FAILs, got #{fails}" unless fails == 3
  puts 'self-test OK (3 assertions)'
end

if $PROGRAM_NAME == __FILE__
  o = {}
  OptionParser.new do |op|
    op.on('--fixture F') { |v| o[:fixture] = v }
    op.on('--json') { o[:json] = true }
    op.on('--self-test') { o[:self] = true }
  end.parse!
  (self_test; exit 0) if o[:self]
  values = o[:fixture] ? JSON.parse(File.read(o[:fixture])) : read_registry
  results = evaluate(values)
  report(results, o[:json])
  exit exit_code(results)
end
