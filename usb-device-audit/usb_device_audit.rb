#!/usr/bin/env ruby
# frozen_string_literal: true
#
# usb_device_audit.rb — Audit USB mass-storage devices (currently connected
# AND historically connected) on a Windows host via WMI + the registry, and
# flag any device whose vendor ID / product ID / serial number is not on a
# YAML allow-list.
#
# Problem this solves:
#   Data-loss-prevention and SOC 2 / ISO 27001 reviews all eventually ask the
#   same question: "has anyone plugged in a USB drive that isn't ours?" The
#   honest answer at most shops is "we have no idea" -- Windows will happily
#   let a device come and go without anyone noticing, and once it's
#   unplugged there's no live signal left. But Windows *keeps a receipt*:
#   every USB mass-storage device that has ever been attached leaves an
#   entry under the registry's USBSTOR enumeration key, even long after it's
#   unplugged. This script combines that historical record with a live WMI
#   snapshot of what's plugged in right now, and flags anything -- past or
#   present -- whose vendor/product/serial triplet isn't on a per-host YAML
#   allow-list of company-issued devices.
#
# Data sources:
#   - Win32_PnPEntity   (WHERE PNPDeviceID LIKE 'USBSTOR%') -- currently
#     enumerated USB mass-storage devices.
#   - Win32_DiskDrive   (WHERE InterfaceType='USB')          -- cross-check /
#     fills in a friendly model description for the same live devices.
#   - Win32_USBHub      (WHERE PNPDeviceID LIKE 'USBSTOR%')  -- some storage
#     devices only surface their disk-class ID at the hub-enumeration level;
#     this catches those without double-counting (records are de-duplicated
#     by PNPDeviceID).
#   - HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR (via the WMI StdRegProv
#     registry provider, so it works locally OR against a remote host over
#     the same WMI/DCOM channel as everything else) -- every USB
#     mass-storage device Windows has EVER seen, connected or not. This is
#     the well-known "USBSTOR forensic" registry location: one subkey per
#     device model (Disk&Ven_...&Prod_...&Rev_...), and one subkey per
#     serial number underneath that, holding a FriendlyName value.
#
# Prerequisites:
#   - Ruby with the `win32ole` stdlib (bundled with all Windows Ruby builds,
#     e.g. RubyInstaller -- nothing extra to gem-install)
#   - Run from a Windows host (locally, or a jump box reaching a remote host
#     over WMI/DCOM: TCP 135 + dynamic RPC ports)
#   - Run elevated: reading other users' USBSTOR history and some
#     Win32_DiskDrive properties requires admin rights for complete results
#   - An account with permission to query WMI (root\cimv2 and root\default)
#     on the target host
#
# Usage:
#   ruby usb_device_audit.rb --host localhost --allowlist allowlist.yml
#   ruby usb_device_audit.rb --inventory hosts.txt --allowlist allowlist.yml --out report.json
#
# allowlist.yml format (mirrors this repo's local-admin-audit convention):
#   default:                       # applies to any host without a specific entry
#     - vendor: "0781"             # SanDisk
#       product: "5567"
#       serial: "4C531001271208117537"
#       label: "IT-issued SanDisk Ultra, asset #4021"
#     - vendor: "0951"             # Kingston
#       product: "1666"
#       serial: "*"                # "*" allows ANY serial of this vendor/product
#       label: "Approved Kingston DataTraveler model (any unit)"
#   overrides:
#     KIOSK01:
#       - vendor: "0951"
#         product: "1666"
#         serial: "*"
#         label: "Public kiosk -- any approved-model stick permitted"
#
# Severity:
#   A device NOT on the allow-list is CRIT if it is currently connected
#   (active policy violation right now) and WARN if it is only present in
#   the historical USBSTOR record (it was plugged in at some point, but
#   isn't attached now -- still worth investigating, just less urgent).
#
# Exit codes:
#   0  every device (connected + historical) on every host is on the allow-list
#   1  at least one unauthorized device was found
#   2  usage / connection error
#
# --- Testing note (read this before filing a bug) --------------------------
# WMI, win32ole, and the Windows registry only exist on Windows, so the
# collection step (`WmiUsbSource`) cannot execute in a Linux CI sandbox. The
# parsing and comparison logic that actually decides "unauthorized" vs.
# "allowed" -- the part with real bugs to catch -- is isolated in the
# `UsbId` and `UsbAudit` modules below, which take plain Ruby data in and
# return plain Ruby data out. Those have zero WMI/registry dependency and
# are exercised directly by the included test harness
# (`test_usb_device_audit.rb`) using a `StubUsbSource` in place of the real
# WMI + registry queries. See the tutorial's "output" tab, this repo's
# test_output.txt, and the README's Troubleshooting section for exactly what
# that does and does not prove.

require 'optparse'
require 'yaml'
require 'json'
require 'time'

# ---------------------------------------------------------------------------
# WMI + registry collection (Windows-only; requires win32ole)
# ---------------------------------------------------------------------------
class WmiUsbSource
  HKEY_LOCAL_MACHINE = 0x80000002
  USBSTOR_KEY = 'SYSTEM\\CurrentControlSet\\Enum\\USBSTOR'

  # Returns an Array of device Hashes for everything currently plugged into
  # `host`: { pnp_device_id:, description:, friendly_name:, status: :connected }
  def connected_devices_for(host)
    require 'win32ole' # deferred require: only needed on the real code path
    locator = WIN32OLE.new('WbemScripting.SWbemLocator')
    conn = locator.ConnectServer(host, 'root\\cimv2')
    conn.Security_.ImpersonationLevel = 3 # impersonate

    devices = {}

    # Live USB mass-storage entries as Windows' PnP manager currently sees them.
    conn.ExecQuery("SELECT * FROM Win32_PnPEntity WHERE PNPDeviceID LIKE 'USBSTOR%'").each do |pnp|
      devices[pnp.PNPDeviceID] = device_record(pnp.PNPDeviceID, pnp.Description, nil, :connected)
    end

    # Win32_DiskDrive often carries a friendlier Model/Caption string and a
    # real SerialNumber property for the same physical disk; merge it in
    # where we can match by device path, add it standalone otherwise.
    conn.ExecQuery("SELECT * FROM Win32_DiskDrive WHERE InterfaceType='USB'").each do |disk|
      pnp_id = disk.PNPDeviceID
      next unless pnp_id

      if devices[pnp_id]
        devices[pnp_id][:friendly_name] ||= disk.Caption
      else
        devices[pnp_id] = device_record(pnp_id, disk.Caption, disk.Caption, :connected)
      end
    end

    # Some composite storage devices only enumerate their disk-class PNP ID
    # at the hub level rather than under Win32_PnPEntity's default view;
    # this is a belt-and-suspenders pass, de-duplicated by PNPDeviceID above.
    conn.ExecQuery("SELECT * FROM Win32_USBHub WHERE PNPDeviceID LIKE 'USBSTOR%'").each do |hub|
      devices[hub.PNPDeviceID] ||= device_record(hub.PNPDeviceID, hub.Description, nil, :connected)
    end

    devices.values
  rescue LoadError
    raise_no_win32ole
  rescue StandardError => e
    raise "WMI query failed for host #{host}: #{e.message}"
  end

  # Returns an Array of device Hashes for every USB mass-storage device
  # Windows has EVER recorded on `host`, from the USBSTOR registry key --
  # regardless of whether it's plugged in right now. Read via the WMI
  # StdRegProv provider so this works against a remote host the same way
  # the rest of the script does (no need for a separate remote-registry
  # transport).
  def historical_devices_for(host)
    require 'win32ole'
    locator = WIN32OLE.new('WbemScripting.SWbemLocator')
    conn = locator.ConnectServer(host, 'root\\default')
    reg = conn.Get('StdRegProv')

    devices = []

    # EnumKey's [out] "sNames" parameter comes back as the second element of
    # the return array in win32ole; the first element is the method's own
    # numeric return code (0 == success).
    _rc, device_classes = reg.EnumKey(HKEY_LOCAL_MACHINE, USBSTOR_KEY)
    Array(device_classes).each do |device_class|
      # e.g. "Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_1100"
      class_path = "#{USBSTOR_KEY}\\#{device_class}"
      _rc, serials = reg.EnumKey(HKEY_LOCAL_MACHINE, class_path)

      Array(serials).each do |serial|
        instance_path = "#{class_path}\\#{serial}"
        _rc, friendly_name = reg.GetStringValue(HKEY_LOCAL_MACHINE, instance_path, 'FriendlyName')
        pnp_style_id = "USBSTOR\\#{device_class}\\#{serial}"
        devices << device_record(pnp_style_id, friendly_name, friendly_name, :historical)
      end
    end

    devices
  rescue LoadError
    raise_no_win32ole
  rescue StandardError => e
    raise "USBSTOR registry read failed for host #{host}: #{e.message}"
  end

  private

  def device_record(pnp_device_id, description, friendly_name, status)
    { pnp_device_id: pnp_device_id, description: description, friendly_name: friendly_name, status: status }
  end

  def raise_no_win32ole
    # win32ole isn't available on this platform (e.g. developing/testing on
    # macOS or Linux). Surface a clear, actionable error instead of a raw
    # Ruby backtrace -- this is the expected failure mode off Windows.
    raise 'win32ole is not available on this platform (this script\'s WMI/registry ' \
          'collection step only runs on Windows). Use --host with a stub source for ' \
          'local testing (see test_usb_device_audit.rb), or run this on a Windows host.'
  end
end

# A drop-in replacement for WmiUsbSource used by the test harness (and
# usable for local testing on non-Windows machines). Takes fixture data
# shaped as { host => { connected: [...], historical: [...] } } and just
# looks values up -- zero WMI, zero registry, zero win32ole.
class StubUsbSource
  def initialize(fixture)
    @fixture = fixture
  end

  def connected_devices_for(host)
    host_fixture(host)[:connected] || []
  end

  def historical_devices_for(host)
    host_fixture(host)[:historical] || []
  end

  private

  def host_fixture(host)
    @fixture.fetch(host) { raise "no fixture data for host #{host}" }
  end
end

# ---------------------------------------------------------------------------
# Pure parsing logic -- no WMI, no I/O, fully unit-testable
# ---------------------------------------------------------------------------
module UsbId
  # Parses a PNPDeviceID (live, from Win32_PnPEntity/Win32_DiskDrive/
  # Win32_USBHub) or the equivalent registry-derived ID this script
  # synthesizes for historical devices, e.g.:
  #
  #   USB\VID_0951&PID_1666&REV_0100\070F5A3B2C1D0000&0
  #   USBSTOR\DISK&VEN_KINGSTON&PROD_DATATRAVELER_3.0&REV_1100\070F5A3B2C1D0000&0
  #
  # Returns { vendor:, product:, serial: } with each value upcased, or nil
  # for any component that couldn't be found.
  def self.parse(pnp_device_id)
    parts = pnp_device_id.to_s.split('\\')
    ids_segment = parts[1].to_s        # "VID_.../PID_..." or "DISK&VEN_...&PROD_..."
    raw_serial  = parts[2].to_s        # may be absent for malformed/partial IDs

    vendor  = ids_segment[/(?:VID|VEN)_([0-9A-Za-z]+)/, 1]
    product = ids_segment[/(?:PID|PROD)_([0-9A-Za-z._-]+?)(?:&|\z)/, 1]

    # Multi-LUN mass-storage devices append "&<lun-number>" to the serial
    # (e.g. "...&0"); strip it so one physical drive maps to a single
    # allow-list entry regardless of which logical unit Windows enumerates.
    serial = raw_serial.sub(/&\d+\z/, '')

    {
      vendor: vendor&.upcase,
      product: product&.upcase,
      serial: serial.empty? ? nil : serial.upcase
    }
  end
end

# ---------------------------------------------------------------------------
# Pure comparison logic -- no WMI, no I/O, fully unit-testable
# ---------------------------------------------------------------------------
module UsbAudit
  # devices:   Array<Hash> with :pnp_device_id, :description, :friendly_name, :status (:connected/:historical)
  # allowlist: Array<Hash> with 'vendor', 'product', 'serial' (serial may be "*" for any serial)
  # Returns a Hash: { findings: [...], unauthorized: [...], ok: [...] }
  def self.evaluate(devices, allowlist)
    findings = devices.map do |device|
      ids = UsbId.parse(device[:pnp_device_id])
      is_allowed = allowed?(ids, allowlist)

      {
        pnp_device_id: device[:pnp_device_id],
        description: device[:description],
        friendly_name: device[:friendly_name],
        status: device[:status],
        vendor_id: ids[:vendor],
        product_id: ids[:product],
        serial_number: ids[:serial],
        allowed: is_allowed,
        severity: severity_for(is_allowed, device[:status])
      }
    end

    {
      findings: findings,
      unauthorized: findings.reject { |f| f[:allowed] },
      ok: findings.select { |f| f[:allowed] }
    }
  end

  def self.allowed?(ids, allowlist)
    allowlist.any? do |entry|
      vendor_match  = match?(entry['vendor'], ids[:vendor])
      product_match = match?(entry['product'], ids[:product])
      serial_match  = entry['serial'].to_s == '*' || match?(entry['serial'], ids[:serial])
      vendor_match && product_match && serial_match
    end
  end

  def self.severity_for(is_allowed, status)
    return nil if is_allowed

    status == :connected ? 'CRIT' : 'WARN'
  end

  def self.match?(allowlist_value, actual_value)
    return false if allowlist_value.nil? || actual_value.nil?

    allowlist_value.to_s.strip.upcase == actual_value.to_s.strip.upcase
  end
end

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def load_allowlist(path, host)
  data = YAML.safe_load(File.read(path)) || {}
  overrides = data['overrides'] || {}
  overrides[host] || data['default'] || []
end

def audit_host(host, allowlist_path, source)
  connected  = source.connected_devices_for(host)
  historical = source.historical_devices_for(host)

  # A device seen live is the authoritative record; drop the historical
  # duplicate of the same PNPDeviceID so it isn't counted (and reported)
  # twice with two different statuses.
  connected_ids = connected.map { |d| d[:pnp_device_id] }
  historical = historical.reject { |d| connected_ids.include?(d[:pnp_device_id]) }

  allowlist = load_allowlist(allowlist_path, host)
  UsbAudit.evaluate(connected + historical, allowlist)
end

def run(options)
  hosts =
    if options[:inventory]
      File.readlines(options[:inventory]).map(&:strip).reject(&:empty?).reject { |l| l.start_with?('#') }
    else
      [options[:host]]
    end

  source = options[:source] || WmiUsbSource.new
  report = { generated_at: Time.now.utc.iso8601, hosts: {} }
  any_findings = false

  hosts.each do |host|
    print "Auditing #{host}... "
    begin
      result = audit_host(host, options[:allowlist], source)
      status = result[:unauthorized].empty? ? 'OK' : 'FINDINGS'
      any_findings ||= status == 'FINDINGS'
      puts status

      report[:hosts][host] = { status: status }.merge(result)
    rescue StandardError => e
      puts "ERROR (#{e.message})"
      any_findings = true
      report[:hosts][host] = { status: 'ERROR', error: e.message }
    end
  end

  puts "\n--- Summary ---"
  report[:hosts].each do |host, r|
    next if r[:status] == 'OK'

    puts "#{host}: #{r[:status]}"
    if r[:status] == 'ERROR'
      puts "    ERROR: #{r[:error]}"
      next
    end
    Array(r[:unauthorized]).each do |f|
      label = f[:friendly_name] || f[:description] || f[:pnp_device_id]
      ids = "VID=#{f[:vendor_id] || '?'} PID=#{f[:product_id] || '?'} SERIAL=#{f[:serial_number] || '?'}"
      puts "    [#{f[:severity]}] #{f[:status].upcase} #{label} (#{ids})"
    end
  end
  puts 'All devices on the allow-list. Clean.' unless any_findings

  if options[:out]
    File.write(options[:out], JSON.pretty_generate(report))
    puts "\nFull report written to #{options[:out]}"
  end

  any_findings ? 1 : 0
end

if $PROGRAM_NAME == __FILE__
  options = {}
  OptionParser.new do |o|
    o.banner = 'Usage: usb_device_audit.rb (--inventory FILE | --host NAME) --allowlist FILE [--out FILE]'
    o.on('--inventory FILE', 'File with one hostname per line') { |v| options[:inventory] = v }
    o.on('--host NAME', 'Single hostname to audit (use "localhost" for the local machine)') { |v| options[:host] = v }
    o.on('--allowlist FILE', 'YAML allow-list (see header comment for format)') { |v| options[:allowlist] = v }
    o.on('--out FILE', 'Write full JSON report to FILE') { |v| options[:out] = v }
  end.parse!

  if !options[:inventory] && !options[:host]
    warn 'ERROR: must pass --inventory or --host'
    exit 2
  end
  unless options[:allowlist]
    warn 'ERROR: must pass --allowlist'
    exit 2
  end

  exit run(options)
end
