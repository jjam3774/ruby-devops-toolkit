#!/usr/bin/env ruby
# frozen_string_literal: true
#
# power_plan_enforcer.rb
#
# Idempotent Windows power-policy enforcement across a fleet: makes sure
# each box is on the right power plan (WMI), has Fast Startup set the way
# you want it (registry), and has hibernation on or off as policy demands
# (powercfg.exe). Three different automation surfaces in one small script,
# which is exactly the kind of glue Ruby is good at on Windows -- the
# alternative is three separate PowerShell one-liners nobody remembers to
# run together.
#
# Why this matters operationally: a server that silently drifts onto
# "Balanced" power policy throttles CPU under light load (surprising perf
# regressions that look like application bugs), and a server with Fast
# Startup enabled skips full driver re-init on "shutdown", which is a
# classic cause of stale-state bugs after a maintenance reboot. Both are
# one WMI/registry write away from fixed -- if you remember to check.
#
# Only standard library plus win32ole on Windows: win32ole, win32/registry
# (both Windows-only, required lazily), optparse, yaml, open3.
#
# Everything that actually talks to Windows (WMI, the registry, powercfg)
# is behind a small injectable interface so the reconciliation logic
# (PowerPolicyEnforcer#plan / #apply!) can be fully unit-tested on any
# platform, including this one -- see power_plan_enforcer_test.rb, which
# runs entirely off fixtures.

require 'optparse'
require 'yaml'

# --------------------------------------------------------------------------
# Talks to the root\cimv2\power WMI namespace for power-plan enumeration
# and activation. Only instantiated on a real run; tests inject a fake
# with the same three methods instead.
# --------------------------------------------------------------------------
class WmiPowerPlans
  def initialize
    require 'win32ole'
    @wmi = WIN32OLE.connect('winmgmts:\\\\.\\root\\cimv2\\power')
  end

  # Returns an Array of { name:, is_active:, instance_id: } hashes.
  def list
    @wmi.ExecQuery('SELECT * FROM Win32_PowerPlan').to_enum.map do |plan|
      { name: plan.ElementName, is_active: plan.IsActive, instance_id: plan.InstanceID }
    end
  end

  def activate(instance_id)
    plan = @wmi.ExecQuery(
      "SELECT * FROM Win32_PowerPlan WHERE InstanceID = '#{instance_id.gsub("'", "''")}'"
    ).to_enum.first
    raise "power plan #{instance_id} vanished before activation" unless plan

    plan.Activate
  end
end

# --------------------------------------------------------------------------
# Fast Startup lives entirely in the registry (HiberbootEnabled). Real
# implementation uses Win32::Registry; tests inject an in-memory Hash.
# --------------------------------------------------------------------------
class WindowsRegistry
  KEY_PATH = 'SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power'
  VALUE = 'HiberbootEnabled'

  def read_hiberboot_enabled
    require 'win32/registry'
    Win32::Registry::HKEY_LOCAL_MACHINE.open(KEY_PATH) do |reg|
      reg[VALUE, Win32::Registry::REG_DWORD]
    end
  rescue Win32::Registry::Error
    nil # value not present -- Windows treats this as "unset", not an error
  end

  def write_hiberboot_enabled(value)
    require 'win32/registry'
    Win32::Registry::HKEY_LOCAL_MACHINE.open(KEY_PATH, Win32::Registry::KEY_WRITE) do |reg|
      reg.write(VALUE, Win32::Registry::REG_DWORD, value)
    end
  end
end

# --------------------------------------------------------------------------
# Hibernation on/off isn't a simple registry flag -- turning it on/off
# through the supported path allocates/frees hiberfil.sys, which only
# powercfg.exe does correctly. Real implementation shells out; tests
# inject a fake runner (same Open3-wrapping pattern used elsewhere in this
# repo, e.g. deploy_webhook_orchestrator's RetryingHttpClient).
# --------------------------------------------------------------------------
class PowercfgControl
  Result = Struct.new(:success, :stdout, :stderr, keyword_init: true)

  def hibernation_enabled?
    require 'win32/registry'
    Win32::Registry::HKEY_LOCAL_MACHINE.open('SYSTEM\\CurrentControlSet\\Control\\Power') do |reg|
      reg['HibernateEnabled', Win32::Registry::REG_DWORD] == 1
    end
  rescue Win32::Registry::Error
    false
  end

  def set_hibernation(enabled)
    require 'open3'
    stdout, stderr, status = Open3.capture3('powercfg.exe', '/hibernate', enabled ? 'on' : 'off')
    Result.new(success: status.success?, stdout: stdout, stderr: stderr)
  end
end

# --------------------------------------------------------------------------
# Core reconciler. Depends only on the three small interfaces above (each
# with #list/#activate, #read_/#write_hiberboot_enabled, and
# #hibernation_enabled?/#set_hibernation) -- never on WIN32OLE or
# Win32::Registry directly, which is what makes it testable off Windows.
# --------------------------------------------------------------------------
class PowerPolicyEnforcer
  Action = Struct.new(:kind, :detail, :payload, keyword_init: true) do
    def describe = "#{kind.to_s.upcase.ljust(20)} #{detail}"
  end

  def initialize(policy, power_plans:, registry:, powercfg:, logger: method(:puts))
    @policy = policy
    @power_plans = power_plans
    @registry = registry
    @powercfg = powercfg
    @logger = logger
  end

  def plan
    actions = []
    actions.concat(plan_power_plan)
    actions.concat(plan_fast_startup)
    actions.concat(plan_hibernation)
    actions
  end

  def apply!(actions, dry_run: true)
    actions.each do |action|
      @logger.call((dry_run ? '[dry-run] ' : '[apply]   ') + action.describe)
      next if dry_run

      execute(action)
    end
  end

  private

  def plan_power_plan
    return [] unless @policy['active_plan']

    plans = @power_plans.list
    target = plans.find { |p| p[:name].casecmp?(@policy['active_plan']) }
    unless target
      @logger.call("WARNING: power plan #{@policy['active_plan'].inspect} not found on this system; skipping")
      return []
    end
    return [] if target[:is_active]

    currently_active = plans.find { |p| p[:is_active] }
    [Action.new(kind: :activate_power_plan,
                detail: "#{currently_active && currently_active[:name]} -> #{target[:name]} (#{target[:instance_id]})",
                payload: target[:instance_id])]
  end

  def plan_fast_startup
    return [] unless @policy.key?('fast_startup_enabled')

    wanted = @policy['fast_startup_enabled'] ? 1 : 0
    current = @registry.read_hiberboot_enabled
    return [] if current == wanted

    [Action.new(kind: :set_fast_startup, detail: "HiberbootEnabled #{current.inspect} -> #{wanted}", payload: wanted)]
  end

  def plan_hibernation
    return [] unless @policy.key?('hibernation_enabled')

    wanted = @policy['hibernation_enabled']
    current = @powercfg.hibernation_enabled?
    return [] if current == wanted

    [Action.new(kind: :set_hibernation, detail: "hibernation #{current} -> #{wanted}", payload: wanted)]
  end

  def execute(action)
    case action.kind
    when :activate_power_plan
      @power_plans.activate(action.payload)
    when :set_fast_startup
      @registry.write_hiberboot_enabled(action.payload)
    when :set_hibernation
      result = @powercfg.set_hibernation(action.payload)
      unless result.success
        @logger.call("  -> FAILED: powercfg /hibernate #{action.payload ? 'on' : 'off'}: #{result.stderr}")
      end
    else
      raise "unknown action kind #{action.kind}"
    end
  end
end

# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  options = { apply: false }
  OptionParser.new do |opts|
    opts.banner = 'Usage: power_plan_enforcer.rb --policy policy.yml [--apply]'
    opts.on('--policy PATH', 'YAML policy describing the desired power state (required)') { |v| options[:policy] = v }
    opts.on('--apply', 'Actually make the changes (default: dry-run only)') { options[:apply] = true }
    opts.on('-h', '--help', 'Show this help') { puts opts; exit 0 }
  end.parse!(ARGV)

  unless options[:policy]
    warn 'error: --policy is required'
    exit 4
  end

  unless RUBY_PLATFORM =~ /mswin|mingw|cygwin/
    warn 'This script talks to WMI and the Windows registry and can only run for real on Windows.'
    warn 'Run power_plan_enforcer_test.rb instead to exercise its logic on this platform.'
    exit 4
  end

  policy = YAML.safe_load_file(options[:policy])
  enforcer = PowerPolicyEnforcer.new(
    policy,
    power_plans: WmiPowerPlans.new,
    registry: WindowsRegistry.new,
    powercfg: PowercfgControl.new
  )
  actions = enforcer.plan

  if actions.empty?
    puts 'No drift detected -- power policy already matches spec.'
    exit 0
  end

  puts "#{actions.size} change(s) needed:"
  enforcer.apply!(actions, dry_run: !options[:apply])
  puts "\nDry run only -- re-run with --apply to make these changes." unless options[:apply]
  exit 0
end
