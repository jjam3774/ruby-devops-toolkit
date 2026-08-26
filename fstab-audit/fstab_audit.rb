#!/usr/bin/env ruby
# frozen_string_literal: true
#
# fstab_audit.rb — audit /etc/fstab for the mistakes that turn a reboot into
# an outage or a security finding: duplicate mount points, references to
# devices that no longer exist, missing hardening options (nodev/nosuid/noexec)
# on the mounts that need them, and fstab entries that aren't actually mounted.
#
# fstab errors are uniquely nasty because nothing complains until the next
# boot — and then the box drops to an emergency shell. This catches them while
# the machine is still up.
#
# Reads /etc/fstab directly and cross-checks against /proc/mounts and the block
# devices under /dev. Stdlib only. Point --fstab / --mounts at copied files to
# audit an image offline.
#
# Usage:
#   ruby fstab_audit.rb                       # audit the live system
#   sudo ruby fstab_audit.rb --json           # for pipelines
#   ruby fstab_audit.rb --fstab ./fstab.copy --mounts ./mounts.copy
#
# Exit codes: 0 = clean, 1 = warnings, 2 = at least one CRIT.

require "json"
require "optparse"

options = { fstab: "/etc/fstab", mounts: "/proc/mounts", dev: "/dev", json: false }

OptionParser.new do |o|
  o.banner = "Usage: ruby fstab_audit.rb [options]"
  o.on("--fstab FILE", "fstab file to audit (default /etc/fstab)") { |v| options[:fstab] = v }
  o.on("--mounts FILE", "mounts file to cross-check (default /proc/mounts)") { |v| options[:mounts] = v }
  o.on("--dev DIR", "device directory for existence checks (default /dev)") { |v| options[:dev] = v }
  o.on("--json", "Emit JSON instead of text") { options[:json] = true }
end.parse!

# Data mounts that hold user-controlled files should carry these hardening
# options; a missing one is not fatal but is worth a warning.
HARDENING = {
  "/tmp"      => %w[nodev nosuid noexec],
  "/var/tmp"  => %w[nodev nosuid noexec],
  "/dev/shm"  => %w[nodev nosuid noexec],
  "/home"     => %w[nodev nosuid],
  "/boot"     => %w[nodev nosuid]
}.freeze

PSEUDO_FS = %w[proc sysfs tmpfs devtmpfs devpts cgroup cgroup2 mqueue debugfs
               tracefs securityfs pstore bpf configfs swap none overlay squashfs
               autofs nfs nfs4 cifs fuse fuse.gvfsd-fuse].freeze

findings = []
def add(findings, sev, code, where, detail)
  findings << { severity: sev, code: code, where: where, detail: detail }
end

# --- parse fstab ------------------------------------------------------------
abort "cannot read #{options[:fstab]}" unless File.readable?(options[:fstab])

entries = []
File.readlines(options[:fstab]).each_with_index do |line, i|
  raw = line.sub(/#.*/, "").strip
  next if raw.empty?
  f = raw.split(/\s+/)
  # spec, file, vfstype, [mntops, [freq, [passno]]]
  if f.size < 3
    add(findings, :warn, "malformed-line", "line #{i + 1}", "fewer than 3 fields: #{raw.inspect}")
    next
  end
  entries << {
    line: i + 1,
    spec: f[0],           # what to mount (device / UUID= / LABEL=)
    mount: f[1],          # where
    type: f[2],
    opts: (f[3] || "defaults").split(","),
    passno: f[5].to_i
  }
end

# --- parse mounts -----------------------------------------------------------
mounted = {}
if File.readable?(options[:mounts])
  File.readlines(options[:mounts]).each do |line|
    f = line.split(/\s+/)
    mounted[f[1]] = f[0] if f.size >= 2
  end
else
  add(findings, :warn, "no-mounts", options[:mounts], "mounts file unreadable — 'not mounted' checks skipped")
end

# --- checks -----------------------------------------------------------------

# 1. Two entries for the same mount point: the second silently shadows the
#    first, and which one wins depends on mount order.
entries.group_by { |e| e[:mount] }.each do |mnt, group|
  next if group.size < 2 || mnt == "none" || mnt == "swap"
  lines = group.map { |e| e[:line] }.join(", ")
  add(findings, :crit, "duplicate-mount", mnt, "mount point declared #{group.size} times (lines #{lines})")
end

entries.each do |e|
  spec = e[:spec]
  # 2. The device the entry names must resolve to something. UUID=/LABEL= are
  #    checked against /dev/disk/by-* ; bare paths against the filesystem.
  #    Pseudo filesystems (tmpfs, proc, ...) have no backing device, so we
  #    skip only the device-existence check for them — hardening and mount
  #    checks below still apply.
  is_pseudo = PSEUDO_FS.include?(e[:type]) && !spec.start_with?("/")
  unless is_pseudo
    resolved =
      if spec.start_with?("UUID=")
        File.exist?(File.join(options[:dev], "disk/by-uuid", spec.delete_prefix("UUID=")))
      elsif spec.start_with?("LABEL=")
        File.exist?(File.join(options[:dev], "disk/by-label", spec.delete_prefix("LABEL=")))
      elsif spec.start_with?("/")
        File.exist?(spec)
      else
        true # PARTUUID=, network specs, etc — don't guess
      end
    unless resolved
      # If it's currently mounted, the device clearly exists (by-uuid link may
      # just be absent in a container) — downgrade to warn.
      sev = mounted.key?(e[:mount]) ? :warn : :crit
      add(findings, sev, "missing-device", "line #{e[:line]}", "#{spec} for #{e[:mount]} not found under #{options[:dev]}")
    end
  end

  # 3. Hardening options on the mounts that hold untrusted files.
  if (need = HARDENING[e[:mount]])
    miss = need - e[:opts]
    add(findings, :warn, "missing-hardening", e[:mount], "missing #{miss.join(', ')} (has: #{e[:opts].join(',')})") unless miss.empty?
  end

  # 4. Declared in fstab but not actually mounted (and not swap/none): a reboot
  #    landmine, since the entry will be attempted at boot.
  if !mounted.empty? && e[:mount].start_with?("/") && !mounted.key?(e[:mount])
    sev = e[:passno].positive? ? :warn : :warn
    add(findings, sev, "not-mounted", e[:mount], "fstab entry (line #{e[:line]}) is not currently mounted")
  end
end

# --- output -----------------------------------------------------------------
rank = { crit: 2, warn: 1 }
findings.sort_by! { |f| [-rank[f[:severity]], f[:code]] }
exit_code = findings.any? { |f| f[:severity] == :crit } ? 2 : (findings.empty? ? 0 : 1)

if options[:json]
  puts JSON.pretty_generate(
    "fstab" => options[:fstab],
    "entries" => entries.size,
    "findings" => findings.map { |f| f.transform_keys(&:to_s).merge("severity" => f[:severity].to_s) },
    "exit_code" => exit_code
  )
else
  puts "fstab_audit: #{entries.size} entries in #{options[:fstab]}"
  if findings.empty?
    puts "no findings — clean."
  else
    findings.each { |f| puts format("%-4s %-18s %-22s %s", f[:severity].to_s.upcase, f[:code], f[:where], f[:detail]) }
    puts "#{findings.count { |f| f[:severity] == :crit }} CRIT, #{findings.count { |f| f[:severity] == :warn }} WARN"
  end
end

exit exit_code
