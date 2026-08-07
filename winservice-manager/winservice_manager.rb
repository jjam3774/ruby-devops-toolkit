#!/usr/bin/env ruby
# frozen_string_literal: true
#
# winservice_manager.rb -- declarative Windows service management via WMI.
#
# Problem it solves:
#   "Make sure the Spooler service is running and set to Automatic startup
#   on all 40 print servers" is a one-line requirement that sysadmins end
#   up re-solving by hand with services.msc, or with a pile of ad-hoc
#   PowerShell one-liners that don't record *what* they changed. This
#   script takes a small YAML file describing the desired state of a set
#   of services (running/stopped, startup type) and reconciles reality to
#   match it -- Chef/Puppet-style, but ~250 lines of stdlib Ruby talking
#   straight to WMI's Win32_Service class. It only touches a service when
#   it's actually out of the desired state, and it tells you exactly what
#   it changed (or would change, with --dry-run).
#
# Prerequisites:
#   - Ruby with win32ole (ships with any Windows Ruby install, e.g. RubyInstaller)
#   - Administrator privileges (starting/stopping services and changing
#     startup type requires elevation)
#   - Run locally, or against a remote host with WMI/DCOM reachable and
#     appropriate credentials (see --host)
#
# Usage:
#   ruby winservice_manager.rb --config services.yml
#   ruby winservice_manager.rb --config services.yml --dry-run
#   ruby winservice_manager.rb --config services.yml --json
#
# services.yml:
#   Spooler:
#     state: running
#     start_mode: automatic
#   Fax:
#     state: stopped
#     start_mode: disabled
#   wuauserv:
#     state: running
#
# Exit codes (cron/monitoring friendly):
#   0 = everything already matched desired state (no changes needed)
#   1 = drift found and successfully reconciled (or would be, in --dry-run)
#   2 = one or more services missing or a WMI call failed
#
# No gems required -- win32ole, yaml, json, optparse are all stdlib.

require "optparse"
require "json"
require "yaml"

class WinServiceManager
  # WMI Win32_Service StartMode strings, normalized to short symbols so the
  # YAML config can say `automatic` / `manual` / `disabled` without the
  # caller needing to know WMI's exact casing.
  START_MODE_TO_WMI = {
    automatic: "Automatic",
    manual: "Manual",
    disabled: "Disabled"
  }.freeze

  # Common WMI Win32_Service method return codes worth naming explicitly --
  # the rest are just reported as "WMI error <code>". Source: MSDN
  # Win32_Service.StartService / ChangeStartMode documentation.
  WMI_RETURN_CODES = {
    0 => "Success",
    1 => "Not Supported",
    2 => "Access Denied",
    3 => "Dependent Services Running",
    4 => "Invalid Service Control",
    5 => "Service Cannot Accept Control",
    6 => "Service Not Active",
    7 => "Service Request Timeout",
    8 => "Unknown Failure",
    9 => "Path Not Found",
    10 => "Service Already Running",
    11 => "Service Database Locked",
    12 => "Service Dependency Deleted",
    13 => "Service Dependency Failure",
    14 => "Service Disabled",
    15 => "Service Logon Failed",
    16 => "Service Marked For Deletion",
    17 => "Service No Thread",
    18 => "Status Circular Dependency",
    19 => "Status Duplicate Name",
    20 => "Status Invalid Name",
    21 => "Status Invalid Parameter",
    22 => "Status Invalid Service Account",
    23 => "Status Service Exists",
    24 => "Service Already Paused"
  }.freeze

  Result = Struct.new(:service, :status, :actions, :error, keyword_init: true) do
    def to_h
      { service: service, status: status, actions: actions, error: error }.compact
    end
  end

  # wmi: an object responding to #exec_query(wql) -- injected so this class
  # can be unit-tested on any platform without a real Windows host or WIN32OLE.
  # In production, WinServiceManager.connect(host) builds the real WMI adapter.
  def initialize(wmi:, dry_run: false)
    @wmi = wmi
    @dry_run = dry_run
  end

  # Connects to WMI on `host` ("." for local machine) via WIN32OLE and
  # returns a ready-to-use WinServiceManager. Only callable on Windows.
  def self.connect(host: ".", dry_run: false)
    require "win32ole"
    swbem = WIN32OLE.connect("winmgmts:{impersonationLevel=impersonate}!//#{host}/root/cimv2")
    new(wmi: RealWmiAdapter.new(swbem), dry_run: dry_run)
  end

  # Thin wrapper around the real WIN32OLE SWbemServices object so the
  # reconciliation logic below only ever talks to the small #exec_query
  # interface, never to WIN32OLE directly.
  class RealWmiAdapter
    def initialize(swbem)
      @swbem = swbem
    end

    def exec_query(wql)
      @swbem.ExecQuery(wql).to_enum(:each).to_a
    end
  end

  # desired: Hash of { "ServiceName" => { state: :running|:stopped, start_mode: :automatic|:manual|:disabled } }
  # Returns an Array of Result, one per service in `desired`.
  def reconcile(desired)
    desired.map { |name, spec| reconcile_one(name, spec) }
  end

  private

  def reconcile_one(name, spec)
    svc = find_service(name)
    return Result.new(service: name, status: :missing, actions: [], error: "no such service") unless svc

    actions = []

    if spec[:start_mode]
      wmi_mode = START_MODE_TO_WMI.fetch(spec[:start_mode]) { raise ArgumentError, "unknown start_mode #{spec[:start_mode]}" }
      if svc.StartMode != wmi_mode
        actions << change_start_mode(svc, name, wmi_mode)
      end
    end

    if spec[:state]
      current_running = (svc.State == "Running")
      want_running = (spec[:state].to_sym == :running)
      if want_running && !current_running
        actions << start_service(svc, name)
      elsif !want_running && current_running
        actions << stop_service(svc, name)
      end
    end

    failed = actions.any? { |a| a[:ok] == false }
    status = actions.empty? ? :ok : (failed ? :error : :changed)
    error = failed ? actions.find { |a| a[:ok] == false }[:detail] : nil
    Result.new(service: name, status: status, actions: actions, error: error)
  rescue StandardError => e
    Result.new(service: name, status: :error, actions: actions || [], error: "#{e.class}: #{e.message}")
  end

  def find_service(name)
    escaped = name.gsub("'", "''")
    rows = @wmi.exec_query("SELECT * FROM Win32_Service WHERE Name='#{escaped}'")
    rows.first
  end

  def change_start_mode(svc, name, wmi_mode)
    if @dry_run
      return { op: "set_start_mode", target: wmi_mode, ok: true, detail: "DRY-RUN: would change #{name} start mode -> #{wmi_mode}" }
    end
    rc = svc.ChangeStartMode(wmi_mode)
    describe_result("set_start_mode", wmi_mode, rc)
  end

  def start_service(svc, _name)
    return { op: "start", target: "Running", ok: true, detail: "DRY-RUN: would start service" } if @dry_run

    rc = svc.StartService
    describe_result("start", "Running", rc)
  end

  def stop_service(svc, _name)
    return { op: "stop", target: "Stopped", ok: true, detail: "DRY-RUN: would stop service" } if @dry_run

    rc = svc.StopService
    describe_result("stop", "Stopped", rc)
  end

  def describe_result(op, target, return_code)
    code = return_code.to_i
    label = WMI_RETURN_CODES.fetch(code, "WMI error #{code}")
    { op: op, target: target, ok: code.zero?, detail: "#{label} (code #{code})" }
  end
end

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  options = { host: ".", dry_run: false, json: false }

  OptionParser.new do |opts|
    opts.banner = "Usage: winservice_manager.rb --config services.yml [options]"
    opts.on("--config PATH", "YAML file describing desired service state (required)") { |v| options[:config] = v }
    opts.on("--host HOST", "Target host for WMI (default: . = local machine)") { |v| options[:host] = v }
    opts.on("--dry-run", "Report drift without changing anything") { options[:dry_run] = true }
    opts.on("--json", "Emit machine-readable JSON instead of text") { options[:json] = true }
    opts.on("-h", "--help", "Show this help") { puts opts; exit 0 }
  end.parse!

  abort "ERROR: --config is required" unless options[:config]
  abort "ERROR: config file not found: #{options[:config]}" unless File.exist?(options[:config])

  raw = YAML.safe_load(File.read(options[:config]), symbolize_names: true)
  desired = raw.each_with_object({}) do |(name, spec), h|
    h[name.to_s] = {
      state: spec[:state]&.to_sym,
      start_mode: spec[:start_mode]&.to_sym
    }
  end

  manager = WinServiceManager.connect(host: options[:host], dry_run: options[:dry_run])
  results = manager.reconcile(desired)

  if options[:json]
    puts JSON.pretty_generate(results.map(&:to_h))
  else
    results.each do |r|
      case r.status
      when :ok
        puts "OK      #{r.service}: already in desired state"
      when :changed
        puts "CHANGED #{r.service}:"
        r.actions.each { |a| puts "          - #{a[:op]} -> #{a[:target]}: #{a[:detail]}" }
      when :missing
        puts "MISSING #{r.service}: #{r.error}"
      when :error
        puts "ERROR   #{r.service}: #{r.error}"
        r.actions.each { |a| puts "          - #{a[:op]} -> #{a[:target]}: #{a[:detail]}" unless a[:ok] }
      end
    end
  end

  exit_code =
    if results.any? { |r| r.status == :missing || r.status == :error }
      2
    elsif results.any? { |r| r.status == :changed }
      1
    else
      0
    end
  exit exit_code
end
