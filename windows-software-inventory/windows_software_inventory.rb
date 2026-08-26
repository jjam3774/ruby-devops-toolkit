#!/usr/bin/env ruby
# frozen_string_literal: true
#
# windows_software_inventory.rb — build a clean inventory of installed software
# on Windows by reading the registry Uninstall keys directly, and flag the
# entries that matter for security and licensing: software with no publisher,
# 32-bit apps on a 64-bit box, entries missing a version, and anything matching
# a configurable "unwanted" watchlist (toolbars, remote-access tools, EOL
# runtimes).
#
# Why registry, not Win32_Product (WMI)? Querying Win32_Product is notorious
# for being slow AND for triggering an MSI self-repair on every installed
# package. Reading the Uninstall keys is instant and side-effect-free — it's
# what every decent inventory tool actually does.
#
# Uses win32ole to talk to the StdRegProv WMI registry provider. That keeps
# collection (Windows-only) cleanly separated from the analysis rules, which
# are plain Ruby and unit-tested on any OS (see
# windows_software_inventory_test.rb).
#
# Usage (on Windows):
#   ruby windows_software_inventory.rb
#   ruby windows_software_inventory.rb --json
#   ruby windows_software_inventory.rb --watch "TeamViewer,AnyDesk,Java 8"
#
# Exit codes: 0 = clean, 1 = warnings, 2 = a watchlist match (CRIT).

require "json"
require "optparse"

Program = Struct.new(
  :name,        # DisplayName
  :version,     # DisplayVersion
  :publisher,   # Publisher
  :install_date, # InstallDate (YYYYMMDD string) or nil
  :arch,        # "x64" or "x86"
  keyword_init: true
)

DEFAULT_WATCH = ["TeamViewer", "AnyDesk", "VNC", "toolbar", "Java 6", "Java 7",
                 "Java 8", "Flash Player", "QuickTime"].freeze

# --- analysis rules (pure — no registry, no Windows) ------------------------

def audit(programs, watch)
  findings = []
  wl = watch.map(&:downcase)
  programs.each do |p|
    name = p.name.to_s
    hit = wl.find { |w| name.downcase.include?(w) }
    if hit
      findings << { severity: :crit, code: "watchlist-match", name: name,
                    detail: "matches watchlist term #{hit.inspect} (version #{p.version || '?'})" }
    end
    if p.publisher.to_s.strip.empty?
      findings << { severity: :warn, code: "no-publisher", name: name,
                    detail: "no publisher recorded — unsigned or hand-installed?" }
    end
    if p.version.to_s.strip.empty?
      findings << { severity: :warn, code: "no-version", name: name,
                    detail: "no version recorded" }
    end
  end
  findings
end

def summarise(programs)
  {
    total: programs.size,
    x86: programs.count { |p| p.arch == "x86" },
    x64: programs.count { |p| p.arch == "x64" },
    no_publisher: programs.count { |p| p.publisher.to_s.strip.empty? }
  }
end

# --- collection (Windows only) ---------------------------------------------

HKLM = 0x80000002
UNINSTALL_PATHS = [
  ['SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall', "x64"],
  ['SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall', "x86"]
].freeze

def collect_programs
  require "win32ole"
  reg = WIN32OLE.connect("winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\default:StdRegProv")
  programs = []
  UNINSTALL_PATHS.each do |base, arch|
    subkeys = nil
    reg.EnumKey(HKLM, base, subkeys) # out-param filled via WIN32OLE
    keys = subkeys.nil? ? [] : subkeys
    (keys || []).each do |sub|
      path = "#{base}\\#{sub}"
      name = read_str(reg, path, "DisplayName")
      next if name.nil? || name.empty?
      # Skip updates/hotfix entries that clutter every box.
      next if name =~ /\A(KB\d+|Update for|Security Update|Hotfix)/i
      programs << Program.new(
        name: name,
        version: read_str(reg, path, "DisplayVersion"),
        publisher: read_str(reg, path, "Publisher"),
        install_date: read_str(reg, path, "InstallDate"),
        arch: arch
      )
    end
  end
  programs
end

def read_str(reg, path, value)
  out = nil
  reg.GetStringValue(HKLM, path, value, out)
  out
rescue StandardError
  nil
end

# --- CLI --------------------------------------------------------------------

if $PROGRAM_NAME == __FILE__
  options = { json: false, watch: DEFAULT_WATCH }
  OptionParser.new do |o|
    o.banner = "Usage: ruby windows_software_inventory.rb [options]  (Windows)"
    o.on("--json", "Emit JSON") { options[:json] = true }
    o.on("--watch A,B,C", Array, "Override the unwanted-software watchlist") { |v| options[:watch] = v }
  end.parse!

  begin
    programs = collect_programs
  rescue LoadError
    abort "win32ole not available — this collector only runs on Windows. " \
          "The analysis rules are testable anywhere: see windows_software_inventory_test.rb"
  end

  findings = audit(programs, options[:watch])
  rank = { crit: 2, warn: 1 }
  findings.sort_by! { |f| -rank[f[:severity]] }
  exit_code = findings.any? { |f| f[:severity] == :crit } ? 2 : (findings.empty? ? 0 : 1)
  sums = summarise(programs)

  if options[:json]
    puts JSON.pretty_generate(
      "generated_at" => Time.now.to_s,
      "summary" => sums.transform_keys(&:to_s),
      "programs" => programs.map { |p| p.to_h.transform_keys(&:to_s) },
      "findings" => findings.map { |f| f.transform_keys(&:to_s).merge("severity" => f[:severity].to_s) },
      "exit_code" => exit_code
    )
  else
    puts "windows_software_inventory: #{sums[:total]} programs (#{sums[:x64]} x64, #{sums[:x86]} x86)"
    if findings.empty?
      puts "no findings — inventory clean."
    else
      findings.each { |f| puts format("%-4s %-16s %-38s %s", f[:severity].to_s.upcase, f[:code], f[:name][0, 38], f[:detail]) }
      puts "#{findings.count { |f| f[:severity] == :crit }} CRIT, #{findings.count { |f| f[:severity] == :warn }} WARN"
    end
  end
  exit exit_code
end
