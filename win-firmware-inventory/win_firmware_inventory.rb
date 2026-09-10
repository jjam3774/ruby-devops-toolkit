#!/usr/bin/env ruby
# frozen_string_literal: true
#
# win_firmware_inventory.rb -- Windows hardware + firmware readiness inventory
# via WMI (win32ole) and the registry.
#
# Answers the questions a fleet admin gets asked every quarter:
#   * What BIOS/UEFI version is this box on, and how old is it?
#   * Is there a TPM, is it 2.0, is it enabled/activated?
#   * Is Secure Boot actually ON (not just "supported")?
#   * Are there free DIMM slots before we order RAM?
#   * Serial numbers / model / CPU for the asset register
#
# Output is a readable summary plus optional JSON or a one-line CSV row that
# you can append across a fleet (see --csv). Findings are graded so the exit
# code can drive a scheduled task or an RMM alert.
#
# Usage (on Windows, elevated PowerShell/cmd recommended for TPM data):
#   ruby win_firmware_inventory.rb
#   ruby win_firmware_inventory.rb --json
#   ruby win_firmware_inventory.rb --csv >> fleet.csv
#   ruby win_firmware_inventory.rb --max-bios-age 3
#   ruby win_firmware_inventory.rb --mock fixture.json   # test with fake WMI data
#
# Exit codes: 0 = OK, 1 = WARN (findings), 2 = FAIL (Secure Boot off / no TPM 2.0)
#
# Requires: Ruby >= 2.7 on Windows (RubyInstaller) -- win32ole and win32/registry
# ship with it, no gems. --mock mode works anywhere (no Windows APIs touched).

require 'optparse'
require 'json'
require 'date'

module FirmwareInventory
  VERSION = '1.0.0'

  Options = Struct.new(:json, :csv, :mock, :max_bios_age, keyword_init: true) do
    def self.parse(argv)
      o = new(json: false, csv: false, mock: nil, max_bios_age: 4)
      OptionParser.new do |p|
        p.banner = 'Usage: win_firmware_inventory.rb [options]'
        p.on('--json', 'Emit JSON') { o.json = true }
        p.on('--csv', 'Emit a single CSV row (header printed if stdout is a TTY)') { o.csv = true }
        p.on('--max-bios-age YEARS', Integer, 'Warn when BIOS release date is older (default 4)') { |v| o.max_bios_age = v }
        p.on('--mock FILE', 'Read WMI/registry data from a JSON fixture instead of Windows') { |v| o.mock = v }
        p.on('-h', '--help') { puts p; exit 0 }
      end.parse!(argv)
      o
    end
  end

  # -------------------------------------------------------------------
  # Data sources. Both expose the same two methods so the rest of the
  # script never knows whether it is talking to real WMI or a fixture.
  #   query(namespace, wql) -> Array<Hash{String=>value}>
  #   registry_dword(path, name) -> Integer or nil
  # -------------------------------------------------------------------
  class WmiSource
    def initialize
      require 'win32ole'
      require 'win32/registry'
      @locator = WIN32OLE.new('WbemScripting.SWbemLocator')
      @services = {}
    end

    def query(namespace, wql)
      svc = (@services[namespace] ||= @locator.ConnectServer('.', namespace))
      svc.ExecQuery(wql).each_with_object([]) do |obj, rows|
        row = {}
        obj.Properties_.each { |prop| row[prop.Name] = prop.Value }
        rows << row
      end
    rescue WIN32OLERuntimeError => e
      warn "WMI query failed in #{namespace}: #{wql} (#{e.message.lines.first.strip})"
      []
    end

    def registry_dword(path, name)
      Win32::Registry::HKEY_LOCAL_MACHINE.open(path) { |k| k[name] }
    rescue Win32::Registry::Error
      nil
    end
  end

  class MockSource
    def initialize(file)
      @data = JSON.parse(File.read(file))
    end

    # Fixture format: { "queries": { "root\\cimv2|SELECT ... FROM Win32_BIOS": [ {...} ] },
    #                   "registry": { "PATH|Name": 1 } }
    def query(namespace, wql)
      key = "#{namespace}|#{wql}"
      @data.fetch('queries').fetch(key) { raise KeyError, "mock has no data for #{key}" }
    end

    def registry_dword(path, name)
      @data.fetch('registry', {})["#{path}|#{name}"]
    end
  end

  # -------------------------------------------------------------------
  # Collector -- turns raw WMI rows into one tidy inventory hash.
  # -------------------------------------------------------------------
  class Collector
    CIMV2 = 'root\\cimv2'
    TPM_NS = 'root\\cimv2\\Security\\MicrosoftTpm'
    SECUREBOOT_KEY = 'SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State'

    def initialize(source)
      @src = source
    end

    def collect
      cs   = first(CIMV2, 'SELECT Manufacturer, Model, TotalPhysicalMemory, SystemType FROM Win32_ComputerSystem')
      bios = first(CIMV2, 'SELECT SMBIOSBIOSVersion, ReleaseDate, SerialNumber, Manufacturer FROM Win32_BIOS')
      cpu  = first(CIMV2, 'SELECT Name, NumberOfCores, NumberOfLogicalProcessors FROM Win32_Processor')
      board = first(CIMV2, 'SELECT Product, SerialNumber FROM Win32_BaseBoard')
      dimms = @src.query(CIMV2, 'SELECT Capacity, Speed, DeviceLocator FROM Win32_PhysicalMemory')
      slots = first(CIMV2, 'SELECT MemoryDevices FROM Win32_PhysicalMemoryArray')
      disks = @src.query(CIMV2, 'SELECT Model, Size, MediaType, InterfaceType FROM Win32_DiskDrive')
      tpm  = first(TPM_NS, 'SELECT IsEnabled_InitialValue, IsActivated_InitialValue, SpecVersion, ManufacturerVersion FROM Win32_Tpm')
      sb   = @src.registry_dword(SECUREBOOT_KEY, 'UEFISecureBootEnabled')

      {
        system: {
          manufacturer: cs['Manufacturer'], model: cs['Model'], system_type: cs['SystemType'],
          board: board['Product'], board_serial: board['SerialNumber'],
          bios_serial: bios['SerialNumber']
        },
        bios: {
          vendor: bios['Manufacturer'], version: bios['SMBIOSBIOSVersion'],
          release_date: parse_wmi_date(bios['ReleaseDate']),
          age_years: age_years(parse_wmi_date(bios['ReleaseDate']))
        },
        cpu: { name: cpu['Name'].to_s.squeeze(' ').strip, cores: cpu['NumberOfCores'], threads: cpu['NumberOfLogicalProcessors'] },
        memory: {
          total_gb: gb(cs['TotalPhysicalMemory']),
          dimms: dimms.map { |d| { slot: d['DeviceLocator'], gb: gb(d['Capacity']), mhz: d['Speed'] } },
          slots_total: slots['MemoryDevices'], slots_free: slots['MemoryDevices'] ? slots['MemoryDevices'] - dimms.size : nil
        },
        disks: disks.map { |d| { model: d['Model'], gb: gb(d['Size']), media: d['MediaType'], bus: d['InterfaceType'] } },
        tpm: {
          present: !tpm.empty?,
          spec: tpm['SpecVersion'].to_s.split(',').first.to_s.strip,
          enabled: tpm['IsEnabled_InitialValue'], activated: tpm['IsActivated_InitialValue']
        },
        secure_boot: sb.nil? ? nil : sb == 1
      }
    end

    private

    def first(ns, wql)
      @src.query(ns, wql).first || {}
    end

    # WMI dates look like "20220815000000.000000+000": yyyymmddHHMMSS.ffffff+zzz
    def parse_wmi_date(s)
      return nil if s.nil? || s.to_s.empty?
      Date.strptime(s.to_s[0, 8], '%Y%m%d').iso8601
    rescue ArgumentError
      nil
    end

    def age_years(iso)
      return nil unless iso
      ((Date.today - Date.parse(iso)) / 365.25).floor
    end

    def gb(bytes)
      return nil if bytes.nil?
      (bytes.to_i / 1024.0**3).round(1)
    end
  end

  # -------------------------------------------------------------------
  # Grader -- converts inventory facts into findings + an exit code.
  # -------------------------------------------------------------------
  class Grader
    Finding = Struct.new(:level, :text)

    def initialize(inv, max_bios_age)
      @inv = inv
      @max = max_bios_age
    end

    def findings
      f = []
      f << Finding.new('FAIL', 'Secure Boot is OFF') if @inv[:secure_boot] == false
      f << Finding.new('WARN', 'Secure Boot state unknown (legacy BIOS boot or registry key missing)') if @inv[:secure_boot].nil?
      if !@inv[:tpm][:present]
        f << Finding.new('FAIL', 'No TPM reported (Win32_Tpm empty -- run elevated, or TPM disabled in firmware)')
      elsif @inv[:tpm][:spec].to_f < 2.0
        f << Finding.new('FAIL', "TPM spec #{@inv[:tpm][:spec]} < 2.0 (Windows 11 / BitLocker best practice needs 2.0)")
      elsif @inv[:tpm][:enabled] == false || @inv[:tpm][:activated] == false
        f << Finding.new('WARN', 'TPM present but not enabled/activated in firmware')
      end
      age = @inv[:bios][:age_years]
      f << Finding.new('WARN', "BIOS is #{age} years old (#{@inv[:bios][:release_date]}) -- check vendor for firmware updates") if age && age >= @max
      f << Finding.new('INFO', "#{@inv[:memory][:slots_free]} free DIMM slot(s)") if @inv[:memory][:slots_free].to_i.positive?
      f
    end

    def exit_code
      levels = findings.map(&:level)
      return 2 if levels.include?('FAIL')
      return 1 if levels.include?('WARN')
      0
    end
  end

  # -------------------------------------------------------------------
  # Output formats
  # -------------------------------------------------------------------
  module Format
    module_function

    def text(inv, grader)
      s  = inv[:system]; b = inv[:bios]; m = inv[:memory]; t = inv[:tpm]
      io = +"win-firmware-inventory v#{VERSION}\n"
      io << "System   : #{s[:manufacturer]} #{s[:model]} (#{s[:system_type]})  serial #{s[:bios_serial]}\n"
      io << "Board    : #{s[:board]}  serial #{s[:board_serial]}\n"
      io << "BIOS     : #{b[:vendor]} #{b[:version]}  released #{b[:release_date]} (#{b[:age_years]}y old)\n"
      io << "CPU      : #{inv[:cpu][:name]}  #{inv[:cpu][:cores]}C/#{inv[:cpu][:threads]}T\n"
      io << "Memory   : #{m[:total_gb]} GB in #{m[:dimms].size}/#{m[:slots_total]} slots"
      io << "  [" << m[:dimms].map { |d| "#{d[:slot]}=#{d[:gb]}GB@#{d[:mhz]}" }.join(', ') << "]\n"
      inv[:disks].each { |d| io << "Disk     : #{d[:model]}  #{d[:gb]} GB  #{d[:media]} (#{d[:bus]})\n" }
      io << "TPM      : #{t[:present] ? "spec #{t[:spec]} enabled=#{t[:enabled]} activated=#{t[:activated]}" : 'NOT PRESENT'}\n"
      io << "SecureBoot: #{inv[:secure_boot].nil? ? 'unknown' : (inv[:secure_boot] ? 'ON' : 'OFF')}\n\n"
      fs = grader.findings
      io << (fs.empty? ? "findings: none -- all checks passed\n" : "findings:\n")
      fs.each { |f| io << format("  [%-4s] %s\n", f.level, f.text) }
      io << "\nresult: #{%w[OK WARN FAIL][grader.exit_code]}\n"
      io
    end

    CSV_COLS = %w[hostname manufacturer model serial bios_version bios_date bios_age_y tpm_spec secure_boot ram_gb free_slots result].freeze

    def csv(inv, grader, hostname)
      row = [hostname, inv[:system][:manufacturer], inv[:system][:model], inv[:system][:bios_serial],
             inv[:bios][:version], inv[:bios][:release_date], inv[:bios][:age_years], inv[:tpm][:spec],
             inv[:secure_boot], inv[:memory][:total_gb], inv[:memory][:slots_free], %w[OK WARN FAIL][grader.exit_code]]
      row.map { |v| v.to_s.include?(',') ? "\"#{v}\"" : v.to_s }.join(',') + "\n"
    end
  end

  def self.run(argv, out: $stdout, hostname: ENV.fetch('COMPUTERNAME', 'localhost'))
    opts = Options.parse(argv)
    source = opts.mock ? MockSource.new(opts.mock) : WmiSource.new
    inv = Collector.new(source).collect
    grader = Grader.new(inv, opts.max_bios_age)
    if opts.json
      out.puts JSON.pretty_generate(inv.merge(findings: grader.findings.map(&:to_h), result: %w[OK WARN FAIL][grader.exit_code]))
    elsif opts.csv
      out.print Format::CSV_COLS.join(',') + "\n" if out.respond_to?(:tty?) && out.tty?
      out.print Format.csv(inv, grader, hostname)
    else
      out.print Format.text(inv, grader)
    end
    grader.exit_code
  rescue LoadError => e
    out.puts "ERROR: #{e.message} -- this script needs Windows Ruby (win32ole), or use --mock FILE"
    3
  end
end

exit FirmwareInventory.run(ARGV) if $PROGRAM_NAME == __FILE__
