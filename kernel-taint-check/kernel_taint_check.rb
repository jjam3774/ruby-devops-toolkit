#!/usr/bin/env ruby
# frozen_string_literal: true
#
# kernel_taint_check.rb - Decode /proc/sys/kernel/tainted into human-readable flags.
#
# A tainted kernel is one that has done something that makes upstream bug
# reports less trustworthy (proprietary/out-of-tree module, forced module load,
# machine check, oops, warning...). The value is a bitmask; this script decodes
# it, classifies each flag by operational concern, and lists out-of-tree modules
# from /sys/module/*/taint.
#
# Usage: ruby kernel_taint_check.rb [--value N] [--json]
# Exit:  0 = clean or informational only, 1 = concerning flags set
require 'json'
require 'optparse'

# bit => [letter, description, concern]  (see Documentation/admin-guide/tainted-kernels.rst)
FLAGS = {
  0  => ['P', 'proprietary module loaded',            :info],
  1  => ['F', 'module force-loaded',                  :warn],
  2  => ['S', 'SMP kernel on unsupported CPU',        :warn],
  3  => ['R', 'module force-unloaded',                :warn],
  4  => ['M', 'machine check exception occurred',     :crit],
  5  => ['B', 'bad page referenced',                  :crit],
  6  => ['U', 'taint requested by userspace',         :info],
  7  => ['D', 'kernel died recently (OOPS or BUG)',   :crit],
  8  => ['A', 'ACPI table overridden',                :warn],
  9  => ['W', 'kernel issued a WARN',                 :warn],
  10 => ['C', 'staging driver loaded',                :info],
  11 => ['I', 'workaround for platform firmware bug', :info],
  12 => ['O', 'out-of-tree module loaded',            :info],
  13 => ['E', 'unsigned module loaded',               :warn],
  14 => ['L', 'soft lockup occurred',                 :crit],
  15 => ['K', 'kernel live-patched',                  :info]
}.freeze

def decode(value)
  FLAGS.filter_map do |bit, (letter, desc, concern)|
    next unless value[bit] == 1
    { bit: bit, letter: letter, description: desc, concern: concern }
  end
end

# Modules that taint the kernel expose /sys/module/<name>/taint (e.g. "PO")
def tainting_modules(root = '/sys/module')
  Dir.glob(File.join(root, '*', 'taint')).filter_map do |f|
    t = File.read(f).strip
    [File.basename(File.dirname(f)), t] unless t.empty?
  end.sort
rescue SystemCallError
  []
end

opts = { json: false, value: nil }
OptionParser.new do |o|
  o.on('--value N', Integer, 'decode this number instead of /proc') { |v| opts[:value] = v }
  o.on('--json') { opts[:json] = true }
end.parse!

value = opts[:value] || Integer(File.read('/proc/sys/kernel/tainted').strip)
flags = decode(value)
mods  = opts[:value] ? [] : tainting_modules
bad   = flags.any? { |f| %i[warn crit].include?(f[:concern]) }

if opts[:json]
  puts JSON.pretty_generate(tainted: value, flags: flags, modules: mods.to_h)
else
  puts "tainted = #{value} (#{value.zero? ? 'clean' : 'TAINTED'})"
  flags.each { |f| puts format('  [%-4s] bit %-2d %s (%s)', f[:concern].to_s.upcase, f[:bit], f[:letter], f[:description]) }
  mods.each { |n, t| puts "  module #{n} taints: #{t}" }
end
exit(bad ? 1 : 0)
