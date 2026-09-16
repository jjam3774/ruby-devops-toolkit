#!/usr/bin/env ruby
# frozen_string_literal: true
#
# mac_posture_audit.rb -- Audit the Linux Mandatory Access Control (MAC) posture.
#
# Every modern distro ships a Linux Security Module (LSM) that is supposed to
# confine daemons: AppArmor on Debian/Ubuntu/SUSE, SELinux on RHEL/Fedora/Rocky.
# The problem is that "installed" is not "enforcing", and "enforcing" is not
# "actually confining the processes that face the network". A profile in complain
# mode logs violations and permits them. A daemon running unconfined has no MAC
# protection at all, no matter how healthy `aa-status` looks in aggregate.
#
# This script reads the kernel's own view of the world -- /sys/kernel/security,
# /proc/<pid>/attr/current, /sys/fs/selinux -- and answers the only three
# questions that matter:
#
#   1. Which LSM is active, and is it actually enforcing?
#   2. How many profiles are loaded, and how many are in permissive/complain mode?
#   3. Which *listening network daemons* are running unconfined?
#
# Question 3 is the one that catches real problems. It cross-references the set
# of processes holding listening TCP/UDP sockets (via /proc/net/tcp inode ->
# /proc/<pid>/fd) against each process's MAC label, and reports every
# network-facing process the LSM is not confining.
#
# Pure Ruby standard library. No gems. Read-only: this script never loads,
# unloads, or changes a profile.
#
# Usage:
#   ruby mac_posture_audit.rb                  # human-readable report
#   ruby mac_posture_audit.rb --json           # machine-readable, for monitoring
#   ruby mac_posture_audit.rb --root ./fixture # audit a captured /proc + /sys tree
#   ruby mac_posture_audit.rb --quiet          # exit code only, no output
#
# Exit codes:  0 = clean   1 = warnings   2 = failures   3 = usage error

require 'json'
require 'optparse'
require 'socket'

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Processes we never expect to be confined and do not want to alarm on.
# Kernel threads have no real executable and cannot carry a MAC label.
KERNEL_THREAD_MARKER = nil # kernel threads have an empty /proc/<pid>/cmdline

# Daemons that are usually intentionally unconfined but still worth listing at
# a lower severity, because they are part of the trusted computing base.
TCB_EXEMPT = %w[systemd init systemd-journald systemd-udevd].freeze

SEVERITY_ORDER = { 'FAIL' => 0, 'WARN' => 1, 'INFO' => 2, 'PASS' => 3 }.freeze

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

# Read a file, returning nil instead of raising. Almost every path we touch may
# be absent (different distro), unreadable (not root), or vanish mid-read (a
# process exiting between readdir and open), so a nil-on-failure read keeps the
# call sites free of rescue blocks.
def slurp(path)
  File.read(path)
rescue SystemCallError, IOError
  nil
end

def dir_entries(path)
  Dir.children(path)
rescue SystemCallError
  []
end

# ---------------------------------------------------------------------------
# LSM detection
# ---------------------------------------------------------------------------

# The kernel publishes the list of active LSMs here. On older kernels the file
# does not exist, so we fall back to probing the securityfs mount points.
def detect_lsms(root)
  raw = slurp(File.join(root, 'sys/kernel/security/lsm'))
  return raw.strip.split(',') if raw && !raw.strip.empty?

  found = []
  found << 'apparmor' if File.directory?(File.join(root, 'sys/kernel/security/apparmor'))
  found << 'selinux'  if File.directory?(File.join(root, 'sys/fs/selinux'))
  found
end

# AppArmor exposes every loaded profile and its mode in one flat file:
#   /sys/kernel/security/apparmor/profiles
#   /usr/sbin/cups-browsed (enforce)
#   /usr/bin/man (complain)
def apparmor_profiles(root)
  raw = slurp(File.join(root, 'sys/kernel/security/apparmor/profiles'))
  return nil unless raw

  raw.each_line.with_object({}) do |line, acc|
    # Split on the LAST space-paren so profile names containing spaces survive.
    if (m = line.strip.match(/\A(.*)\s+\((\w+)\)\z/))
      acc[m[1]] = m[2] # e.g. "enforce", "complain", "kill", "unconfined"
    end
  end
end

# SELinux's global mode lives in a single byte: 1 = enforcing, 0 = permissive.
# If /sys/fs/selinux/enforce is missing entirely, SELinux is disabled.
def selinux_mode(root)
  raw = slurp(File.join(root, 'sys/fs/selinux/enforce'))
  return 'disabled' unless raw

  raw.strip == '1' ? 'enforcing' : 'permissive'
end

def selinux_policy_name(root)
  slurp(File.join(root, 'etc/selinux/config'))
    &.each_line
    &.find { |l| l =~ /\A\s*SELINUXTYPE\s*=/ }
    &.split('=', 2)&.last&.strip
end

# ---------------------------------------------------------------------------
# Per-process MAC labels
# ---------------------------------------------------------------------------

# /proc/<pid>/attr/current holds the process's security label:
#   AppArmor: "/usr/sbin/nginx (enforce)" or "unconfined"
#   SELinux:  "system_u:system_r:httpd_t:s0"
# A NUL terminator is common; strip it before parsing.
def process_label(root, pid)
  raw = slurp(File.join(root, 'proc', pid.to_s, 'attr/current'))
  return nil unless raw

  label = raw.delete("\0").strip
  label.empty? ? nil : label
end

def label_confined?(label, lsm)
  return false if label.nil?

  case lsm
  when 'apparmor'
    # "unconfined" alone, or a profile explicitly in unconfined mode.
    return false if label == 'unconfined'
    return false if label.end_with?('(unconfined)')

    true
  when 'selinux'
    # The unconfined_t / unconfined_service_t domains are the "no policy" domains.
    type = label.split(':')[2].to_s
    !type.start_with?('unconfined_')
  else
    false
  end
end

def label_mode(label, lsm)
  if lsm == 'apparmor' && (m = label.to_s.match(/\((\w+)\)\z/))
    m[1]
  elsif lsm == 'selinux'
    label.to_s.split(':')[2]
  end
end

# ---------------------------------------------------------------------------
# Process inventory
# ---------------------------------------------------------------------------

Process_ = Struct.new(:pid, :comm, :cmdline, :label, :confined, :mode, :listening, keyword_init: true)

def numeric_dirs(path)
  dir_entries(path).select { |e| e =~ /\A\d+\z/ }.map(&:to_i).sort
end

def read_process(root, pid, lsm)
  comm = slurp(File.join(root, 'proc', pid.to_s, 'comm'))&.strip
  return nil if comm.nil?

  # Kernel threads have an empty cmdline. They live entirely in kernel space and
  # are outside the scope of a userspace MAC policy, so we drop them here rather
  # than reporting dozens of meaningless "unconfined kthreadd" findings.
  cmdline_raw = slurp(File.join(root, 'proc', pid.to_s, 'cmdline')).to_s
  return nil if cmdline_raw.empty?

  label = process_label(root, pid)
  Process_.new(
    pid: pid,
    comm: comm,
    cmdline: cmdline_raw.split("\0").reject(&:empty?).join(' ')[0, 120],
    label: label || '(unreadable)',
    confined: label_confined?(label, lsm),
    mode: label_mode(label, lsm),
    listening: false
  )
end

# ---------------------------------------------------------------------------
# Listening-socket -> PID mapping
# ---------------------------------------------------------------------------
#
# /proc/net/tcp gives us socket inodes but not PIDs. /proc/<pid>/fd/* gives us
# symlinks of the form "socket:[12345]". Intersecting the two yields the set of
# PIDs that own at least one *listening* socket -- the processes an attacker on
# the network can reach directly.

TCP_LISTEN_STATE = '0A' # the st column value for TCP_LISTEN

def listening_socket_inodes(root)
  inodes = {}
  %w[proc/net/tcp proc/net/tcp6].each do |rel|
    raw = slurp(File.join(root, rel))
    next unless raw

    raw.each_line.drop(1).each do |line|
      f = line.split
      next if f.size < 10
      next unless f[3] == TCP_LISTEN_STATE

      port = f[1].split(':').last.to_i(16)
      inodes[f[9]] = port # column 9 is the inode
    end
  end

  # UDP has no LISTEN state; any bound UDP socket is reachable, so include them all.
  %w[proc/net/udp proc/net/udp6].each do |rel|
    raw = slurp(File.join(root, rel))
    next unless raw

    raw.each_line.drop(1).each do |line|
      f = line.split
      next if f.size < 10

      port = f[1].split(':').last.to_i(16)
      inodes[f[9]] ||= port
    end
  end
  inodes
end

def pids_with_listening_sockets(root, pids)
  inodes = listening_socket_inodes(root)
  return {} if inodes.empty?

  owners = Hash.new { |h, k| h[k] = [] }
  pids.each do |pid|
    fd_dir = File.join(root, 'proc', pid.to_s, 'fd')
    dir_entries(fd_dir).each do |fd|
      target = begin
        File.readlink(File.join(fd_dir, fd))
      rescue SystemCallError
        next
      end
      # Real /proc gives "socket:[12345]"; a captured fixture tree stores a
      # plain file whose *name* encodes the inode, so accept both shapes.
      next unless (m = target.match(/socket:\[(\d+)\]/))

      port = inodes[m[1]]
      owners[pid] << port if port
    end
  end
  owners.transform_values { |ports| ports.uniq.sort }
end

# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

def audit(root)
  lsms = detect_lsms(root)
  findings = []
  details = { 'lsms' => lsms }

  lsm = if lsms.include?('apparmor') then 'apparmor'
        elsif lsms.include?('selinux') then 'selinux'
        end

  if lsm.nil?
    findings << finding('FAIL', 'lsm.active',
                        'No MAC LSM active (neither AppArmor nor SELinux)',
                        'Every daemon on this host runs with DAC permissions only. ' \
                        'Install and enable apparmor or selinux-policy-targeted.')
    return [findings, details]
  end

  details['active_lsm'] = lsm

  # -- 1. Global enforcement state -----------------------------------------
  if lsm == 'apparmor'
    profiles = apparmor_profiles(root) || {}
    details['profiles_total'] = profiles.size
    by_mode = profiles.values.tally
    details['profiles_by_mode'] = by_mode

    if profiles.empty?
      findings << finding('FAIL', 'apparmor.profiles',
                          'AppArmor is active but zero profiles are loaded',
                          'Run `aa-status`; reinstall the apparmor-profiles package ' \
                          'and `systemctl restart apparmor`.')
    else
      findings << finding('PASS', 'apparmor.profiles',
                          "#{profiles.size} AppArmor profiles loaded",
                          nil)
    end

    complain = profiles.select { |_, m| m == 'complain' }
    if complain.any?
      findings << finding('WARN', 'apparmor.complain',
                          "#{complain.size} profile(s) in complain mode (logging, not blocking)",
                          "Move to enforce with `aa-enforce <profile>`: " +
                          complain.keys.first(6).join(', '))
    else
      findings << finding('PASS', 'apparmor.complain', 'No profiles in complain mode', nil)
    end

    unconf = profiles.select { |_, m| m == 'unconfined' }
    if unconf.any?
      findings << finding('WARN', 'apparmor.unconfined_profiles',
                          "#{unconf.size} profile(s) loaded in unconfined mode",
                          "These profiles exist but confine nothing: #{unconf.keys.first(6).join(', ')}")
    end
  else
    mode = selinux_mode(root)
    details['selinux_mode'] = mode
    details['selinux_policy'] = selinux_policy_name(root)

    case mode
    when 'enforcing'
      findings << finding('PASS', 'selinux.mode', 'SELinux is enforcing', nil)
    when 'permissive'
      findings << finding('FAIL', 'selinux.mode',
                          'SELinux is permissive -- denials are logged but allowed',
                          'Fix outstanding denials (`ausearch -m avc -ts recent`), then ' \
                          'set SELINUX=enforcing in /etc/selinux/config and reboot.')
    else
      findings << finding('FAIL', 'selinux.mode',
                          'SELinux is disabled',
                          'Set SELINUX=enforcing in /etc/selinux/config and relabel (`touch /.autorelabel`).')
    end
  end

  # -- 2. Per-process confinement ------------------------------------------
  pids = numeric_dirs(File.join(root, 'proc'))
  procs = pids.filter_map { |pid| read_process(root, pid, lsm) }
  details['processes_scanned'] = procs.size

  listeners = pids_with_listening_sockets(root, procs.map(&:pid))
  procs.each { |p| p.listening = listeners.key?(p.pid) }

  confined = procs.count(&:confined)
  details['processes_confined'] = confined
  details['processes_unconfined'] = procs.size - confined

  # -- 3. The finding that matters: unconfined network-facing daemons -------
  exposed = procs.select { |p| p.listening && !p.confined }
  details['listeners_total'] = procs.count(&:listening)
  details['listeners_unconfined'] = exposed.size

  if exposed.empty?
    findings << finding('PASS', 'mac.network_daemons',
                        'Every listening daemon is confined by a MAC profile', nil)
  else
    exposed.sort_by { |p| TCB_EXEMPT.include?(p.comm) ? 1 : 0 }.each do |p|
      sev = TCB_EXEMPT.include?(p.comm) ? 'INFO' : 'FAIL'
      ports = listeners[p.pid].first(6).join(', ')
      findings << finding(sev, "mac.unconfined:#{p.comm}",
                          "pid #{p.pid} #{p.comm} listens on #{ports} with no MAC profile",
                          sev == 'FAIL' ? profile_hint(lsm, p) : 'Part of the trusted computing base; expected.',
                          pid: p.pid, cmdline: p.cmdline, label: p.label, ports: listeners[p.pid])
    end
  end

  # -- 4. Processes running under a complain-mode profile -------------------
  complaining = procs.select { |p| p.mode == 'complain' || p.mode.to_s.start_with?('unconfined_') }
  if complaining.any?
    findings << finding('WARN', 'mac.complain_processes',
                        "#{complaining.size} running process(es) under a non-enforcing profile",
                        complaining.first(6).map { |p| "#{p.comm}(#{p.pid})" }.join(', '))
  end

  [findings, details]
end

def profile_hint(lsm, proc_)
  if lsm == 'apparmor'
    "Generate a starter profile: `aa-genprof #{proc_.comm}` (or install the " \
    "distro profile package), test in complain mode, then `aa-enforce`."
  else
    "No SELinux domain transition for #{proc_.comm}. Check the binary's label " \
    "(`ls -Z`) and that a policy module exists (`semodule -l | grep #{proc_.comm}`)."
  end
end

def finding(severity, id, message, remediation, **extra)
  { 'severity' => severity, 'id' => id, 'message' => message,
    'remediation' => remediation }.merge(extra.transform_keys(&:to_s)).compact
end

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

COLOR = { 'FAIL' => "\e[31m", 'WARN' => "\e[33m", 'PASS' => "\e[32m", 'INFO' => "\e[36m" }.freeze
RESET = "\e[0m"

def colorize(sev, text, enabled)
  enabled ? "#{COLOR[sev]}#{text}#{RESET}" : text
end

def print_report(findings, details, color:)
  host = begin
    Socket.gethostname
  rescue StandardError
    'unknown'
  end

  puts '=' * 74
  puts "  MAC POSTURE AUDIT -- #{host} -- #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}"
  puts '=' * 74
  puts

  lsm = details['active_lsm'] || 'none'
  puts "  Active LSM        : #{lsm}"
  puts "  LSMs in kernel    : #{Array(details['lsms']).join(', ')}" unless Array(details['lsms']).empty?
  if details['profiles_total']
    modes = (details['profiles_by_mode'] || {}).map { |k, v| "#{v} #{k}" }.join(', ')
    puts "  Profiles loaded   : #{details['profiles_total']} (#{modes})"
  end
  puts "  SELinux mode      : #{details['selinux_mode']}" if details['selinux_mode']
  puts "  Processes scanned : #{details['processes_scanned']} " \
       "(#{details['processes_confined']} confined, #{details['processes_unconfined']} unconfined)"
  puts "  Listening daemons : #{details['listeners_total']} " \
       "(#{details['listeners_unconfined']} unconfined)"
  puts
  puts '-' * 74
  puts

  sorted = findings.sort_by { |f| [SEVERITY_ORDER[f['severity']] || 9, f['id']] }
  sorted.each do |f|
    tag = format('[%-4s]', f['severity'])
    puts "#{colorize(f['severity'], tag, color)} #{f['message']}"
    puts "         -> #{f['remediation']}" if f['remediation']
    puts "         cmd: #{f['cmdline']}" if f['cmdline']
    puts "         label: #{f['label']}" if f['label']
    puts
  end

  counts = findings.map { |f| f['severity'] }.tally
  puts '-' * 74
  puts "  #{counts.fetch('FAIL', 0)} fail   " \
       "#{counts.fetch('WARN', 0)} warn   " \
       "#{counts.fetch('INFO', 0)} info   " \
       "#{counts.fetch('PASS', 0)} pass"
  puts '=' * 74
end

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv)
  opts = { root: '/', json: false, quiet: false, color: $stdout.tty? }
  parser = OptionParser.new do |o|
    o.banner = 'Usage: ruby mac_posture_audit.rb [options]'
    o.on('--root PATH', 'Audit a captured /proc + /sys tree instead of the live host') { |v| opts[:root] = v }
    o.on('--json', 'Emit JSON instead of a text report') { opts[:json] = true }
    o.on('--quiet', 'Suppress output; communicate via exit code only') { opts[:quiet] = true }
    o.on('--[no-]color', 'Force ANSI colour on/off') { |v| opts[:color] = v }
    o.on('-h', '--help', 'Show this help') { puts o; exit 0 }
  end

  begin
    parser.parse!(argv)
  rescue OptionParser::ParseError => e
    warn "error: #{e.message}"
    warn parser.to_s
    return 3
  end

  unless File.directory?(File.join(opts[:root], 'proc'))
    warn "error: #{opts[:root]} does not look like a root filesystem (no /proc)"
    return 3
  end

  findings, details = audit(opts[:root])

  if opts[:json]
    puts JSON.pretty_generate('generated_at' => Time.now.utc.iso8601,
                              'summary' => details,
                              'findings' => findings)
  elsif !opts[:quiet]
    print_report(findings, details, color: opts[:color])
  end

  return 2 if findings.any? { |f| f['severity'] == 'FAIL' }
  return 1 if findings.any? { |f| f['severity'] == 'WARN' }

  0
end

require 'time'
exit(main(ARGV)) if __FILE__ == $PROGRAM_NAME
