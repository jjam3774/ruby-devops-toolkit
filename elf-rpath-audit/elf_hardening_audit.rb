#!/usr/bin/env ruby
# frozen_string_literal: true
#
# elf_hardening_audit.rb -- Audit ELF binaries for RPATH hijacking and missing
#                           compiler hardening, in pure Ruby. No gems, no
#                           readelf, no objdump, no checksec.
#
# THE PROBLEM
# -----------
# A binary's RPATH/RUNPATH is a list of directories the dynamic linker searches
# for shared libraries *before* the system paths. If one of those directories is
# writable by a non-root user -- or is a relative path, which resolves against
# whatever the current working directory happens to be -- then anyone who can
# write there can drop a malicious .so and have it loaded into the process. When
# the binary is also SUID root, that is a straight local root.
#
# This is not a hypothetical. It is one of the most common findings in any
# serious build-pipeline review, and it is almost always introduced accidentally
# by a `-Wl,-rpath,./lib` or a build system that bakes in a temp build directory.
#
# Meanwhile the same ELF headers tell you whether the binary was compiled with
# the mitigations every distro has shipped by default for a decade: RELRO, a
# non-executable stack, and PIE. Vendor-shipped binaries and anything built by
# an in-house pipeline routinely miss them.
#
# WHAT THIS SCRIPT DOES
# ---------------------
# It parses the ELF headers itself -- program headers, PT_DYNAMIC, the dynamic
# string table -- and reports, per binary:
#
#   * RPATH / RUNPATH entries that are relative, missing, world/group-writable,
#     or owned by a non-root user          (severity scales with SUID + writability)
#   * NEEDED libraries that cannot be resolved on this host
#   * Executable stack        (PT_GNU_STACK carrying the X flag)
#   * No RELRO / Partial RELRO (PT_GNU_RELRO and DT_BIND_NOW / DF_BIND_NOW)
#   * Non-PIE executables      (ET_EXEC rather than ET_DYN + PT_INTERP)
#
# Read-only. It opens files, reads a few hundred bytes of headers, and never
# writes, patches or executes anything it scans.
#
# Usage:
#   ruby elf_hardening_audit.rb /usr/bin /usr/local/bin
#   ruby elf_hardening_audit.rb --json /opt/vendor-app
#   ruby elf_hardening_audit.rb --min-severity FAIL /usr/bin
#   ruby elf_hardening_audit.rb --suid-only /                 # scan the whole box
#
# Exit codes:  0 = clean   1 = warnings   2 = failures   3 = usage error

require 'json'
require 'optparse'
require 'time'

# ===========================================================================
# ELF parsing
# ===========================================================================

class ElfError < StandardError; end

# A deliberately small ELF reader. It only understands what this audit needs:
# the identification bytes, the program header table, PT_DYNAMIC, and the
# dynamic string table. That is roughly 150 lines instead of a 5,000-line
# general-purpose library, and it depends on nothing outside the stdlib.
class ElfFile
  # --- e_type ---
  ET_EXEC = 2
  ET_DYN  = 3

  # --- p_type ---
  PT_LOAD      = 1
  PT_DYNAMIC   = 2
  PT_INTERP    = 3
  PT_GNU_STACK = 0x6474e551
  PT_GNU_RELRO = 0x6474e552

  # --- d_tag ---
  DT_NULL     = 0
  DT_NEEDED   = 1
  DT_STRTAB   = 5
  DT_STRSZ    = 10
  DT_SONAME   = 14
  DT_RPATH    = 15
  DT_BIND_NOW = 24
  DT_RUNPATH  = 29
  DT_FLAGS    = 30
  DT_FLAGS_1  = 0x6ffffffb

  DF_BIND_NOW = 0x08
  DF_1_NOW    = 0x00000001
  DF_1_PIE    = 0x08000000

  attr_reader :path, :bits, :type, :needed, :rpath, :runpath, :soname,
              :interp, :exec_stack, :relro, :bind_now, :pie

  def initialize(path)
    @path = path
    @needed = []
    @rpath = []
    @runpath = []
    File.open(path, 'rb') { |io| parse(io) }
  end

  # Cheap pre-filter: read four bytes and decide whether this file is worth
  # opening properly. Scanning /usr/bin means touching thousands of shell
  # scripts, and we do not want to pay full-parse cost to reject them.
  def self.elf?(path)
    return false unless File.file?(path) && File.size(path) > 64

    File.open(path, 'rb') { |io| io.read(4) } == "\x7FELF".b
  rescue SystemCallError
    false
  end

  private

  def parse(io)
    ident = io.read(16)
    raise ElfError, 'not an ELF file' unless ident && ident[0, 4] == "\x7FELF".b

    @bits = case ident.getbyte(4)
            when 1 then 32
            when 2 then 64
            else raise ElfError, "unknown EI_CLASS #{ident.getbyte(4)}"
            end
    # EI_DATA: 1 = little-endian, 2 = big-endian. Nearly everything is LE, but
    # honouring the byte is two lines and makes the parser correct on s390x.
    @little = ident.getbyte(5) == 1
    raise ElfError, "unknown EI_DATA #{ident.getbyte(5)}" unless [1, 2].include?(ident.getbyte(5))

    # e_type (2) e_machine (2) e_version (4) e_entry e_phoff e_shoff ...
    @type = u16(io.read(2))
    io.read(2)                       # e_machine
    io.read(4)                       # e_version
    io.read(addr_size)               # e_entry
    phoff = uaddr(io.read(addr_size))
    io.read(addr_size)               # e_shoff
    io.read(4)                       # e_flags
    io.read(2)                       # e_ehsize
    phentsize = u16(io.read(2))
    phnum = u16(io.read(2))

    raise ElfError, 'no program headers' if phnum.zero? || phoff.zero?
    raise ElfError, "absurd phnum #{phnum}" if phnum > 128

    phdrs = read_program_headers(io, phoff, phentsize, phnum)
    @loads = phdrs.select { |p| p[:type] == PT_LOAD }

    gnu_stack = phdrs.find { |p| p[:type] == PT_GNU_STACK }
    # p_flags bit 0 is PF_X. A missing PT_GNU_STACK is itself a red flag on
    # Linux: the kernel then falls back to an executable stack.
    @exec_stack = gnu_stack.nil? || (gnu_stack[:flags] & 0x1) == 1

    @relro = phdrs.any? { |p| p[:type] == PT_GNU_RELRO }

    interp_hdr = phdrs.find { |p| p[:type] == PT_INTERP }
    if interp_hdr
      io.seek(interp_hdr[:offset])
      @interp = io.read(interp_hdr[:filesz].to_i).to_s.split("\0").first
    end

    dyn_hdr = phdrs.find { |p| p[:type] == PT_DYNAMIC }
    parse_dynamic(io, dyn_hdr) if dyn_hdr

    # A PIE is ET_DYN *with* an interpreter. A plain shared library is also
    # ET_DYN but has no PT_INTERP, and "is this .so a PIE" is a meaningless
    # question -- so report PIE as nil for libraries and skip the check.
    @pie = if @interp.nil? && @type == ET_DYN
             nil # shared library
           else
             @type == ET_DYN
           end
  end

  def read_program_headers(io, phoff, phentsize, phnum)
    io.seek(phoff)
    raw = io.read(phentsize * phnum).to_s
    raise ElfError, 'truncated program header table' if raw.bytesize < phentsize * phnum

    (0...phnum).map do |i|
      e = raw.byteslice(i * phentsize, phentsize)
      if @bits == 64
        # 64-bit: p_type(4) p_flags(4) p_offset(8) p_vaddr(8) p_paddr(8) p_filesz(8) ...
        { type: u32(e.byteslice(0, 4)), flags: u32(e.byteslice(4, 4)),
          offset: u64(e.byteslice(8, 8)), vaddr: u64(e.byteslice(16, 8)),
          filesz: u64(e.byteslice(32, 8)) }
      else
        # 32-bit: p_type(4) p_offset(4) p_vaddr(4) p_paddr(4) p_filesz(4) p_memsz(4) p_flags(4)
        { type: u32(e.byteslice(0, 4)), offset: u32(e.byteslice(4, 4)),
          vaddr: u32(e.byteslice(8, 4)), filesz: u32(e.byteslice(16, 4)),
          flags: u32(e.byteslice(24, 4)) }
      end
    end
  end

  def parse_dynamic(io, hdr)
    io.seek(hdr[:offset])
    raw = io.read(hdr[:filesz].to_i).to_s
    step = addr_size * 2
    entries = []
    offset = 0
    while offset + step <= raw.bytesize
      tag = uaddr(raw.byteslice(offset, addr_size))
      val = uaddr(raw.byteslice(offset + addr_size, addr_size))
      break if tag == DT_NULL

      entries << [tag, val]
      offset += step
    end

    strtab_vaddr = entries.find { |t, _| t == DT_STRTAB }&.last
    strsz = entries.find { |t, _| t == DT_STRSZ }&.last.to_i
    strtab = read_strtab(io, strtab_vaddr, strsz)

    flags   = entries.find { |t, _| t == DT_FLAGS }&.last.to_i
    flags_1 = entries.find { |t, _| t == DT_FLAGS_1 }&.last.to_i
    @bind_now = entries.any? { |t, _| t == DT_BIND_NOW } ||
                (flags & DF_BIND_NOW) != 0 ||
                (flags_1 & DF_1_NOW) != 0

    entries.each do |tag, val|
      case tag
      when DT_NEEDED  then @needed  << str_at(strtab, val)
      when DT_SONAME  then @soname   = str_at(strtab, val)
      when DT_RPATH   then @rpath   += split_paths(str_at(strtab, val))
      when DT_RUNPATH then @runpath += split_paths(str_at(strtab, val))
      end
    end
    @needed.compact!
  end

  # DT_STRTAB is a virtual address. Translate it to a file offset by finding the
  # PT_LOAD segment that contains it -- offset = p_offset + (vaddr - p_vaddr).
  def read_strtab(io, vaddr, size)
    return nil if vaddr.nil?

    seg = @loads.find { |l| vaddr >= l[:vaddr] && vaddr < l[:vaddr] + l[:filesz] }
    return nil unless seg

    file_off = seg[:offset] + (vaddr - seg[:vaddr])
    size = 1 << 20 if size <= 0 || size > (1 << 20) # sanity clamp
    io.seek(file_off)
    io.read(size)
  end

  def str_at(strtab, offset)
    return nil if strtab.nil? || offset >= strtab.bytesize

    strtab.byteslice(offset..-1).split("\0").first
  end

  def split_paths(str)
    str.to_s.split(':').reject(&:empty?)
  end

  def addr_size = @bits == 64 ? 8 : 4

  def u16(b) = @little ? b.unpack1('v') : b.unpack1('n')
  def u32(b) = @little ? b.unpack1('V') : b.unpack1('N')
  def u64(b) = @little ? b.unpack1('Q<') : b.unpack1('Q>')
  def uaddr(b) = @bits == 64 ? u64(b) : u32(b)
end

# ===========================================================================
# Library resolution
# ===========================================================================

# Mirrors (a useful subset of) the dynamic linker's search order so we can tell
# whether a DT_NEEDED entry would actually resolve at runtime.
class LibraryResolver
  DEFAULT_DIRS = %w[
    /lib /lib64 /usr/lib /usr/lib64 /usr/local/lib /usr/local/lib64
  ].freeze

  def initialize(root: '/')
    @root = root
    @dirs = build_search_path
    @cache = {}
  end

  attr_reader :dirs

  def resolve(soname, rpath: [], runpath: [], origin: nil)
    key = [soname, rpath, runpath, origin]
    return @cache[key] if @cache.key?(key)

    # Real linker order: DT_RPATH (only when DT_RUNPATH is absent), then
    # LD_LIBRARY_PATH, then DT_RUNPATH, then the cache and default dirs.
    search = []
    search += expand(rpath, origin) if runpath.empty?
    search += expand(runpath, origin)
    search += @dirs

    hit = search.find { |d| File.exist?(File.join(d, soname)) }
    @cache[key] = hit && File.join(hit, soname)
  end

  private

  # $ORIGIN expands to the directory holding the binary. $LIB and $PLATFORM are
  # expanded approximately; getting them exactly right needs the loader's own
  # notion of the platform string, which is not worth replicating here.
  def expand(paths, origin)
    paths.map do |p|
      p.gsub('$ORIGIN', origin.to_s).gsub('${ORIGIN}', origin.to_s)
       .gsub('$LIB', 'lib64').gsub('${LIB}', 'lib64')
    end
  end

  def build_search_path
    dirs = DEFAULT_DIRS.map { |d| File.join(@root, d) }
    # Multiarch dirs (/usr/lib/x86_64-linux-gnu) are where Debian keeps almost
    # everything, and they are not in the hardcoded list above.
    Dir.glob(File.join(@root, 'usr/lib/*-linux-gnu*')).each { |d| dirs << d }
    Dir.glob(File.join(@root, 'lib/*-linux-gnu*')).each { |d| dirs << d }
    dirs += ld_so_conf_dirs
    dirs.select { |d| File.directory?(d) }.uniq
  end

  def ld_so_conf_dirs
    files = [File.join(@root, 'etc/ld.so.conf')] +
            Dir.glob(File.join(@root, 'etc/ld.so.conf.d/*.conf'))
    files.flat_map do |f|
      File.readlines(f, chomp: true).filter_map do |line|
        line = line.sub(/#.*/, '').strip
        next if line.empty? || line.start_with?('include')

        File.join(@root, line)
      end
    rescue SystemCallError
      []
    end
  end
end

# ===========================================================================
# Directory security classification
# ===========================================================================

DirRisk = Struct.new(:state, :detail, keyword_init: true)

# Decide how dangerous a single RPATH/RUNPATH directory is.
def classify_dir(dir, origin)
  return DirRisk.new(state: :relative, detail: 'relative path -- resolves against the CWD of whoever runs the binary') \
    if !dir.start_with?('/') && !dir.include?('$ORIGIN')

  resolved = dir.gsub('$ORIGIN', origin.to_s).gsub('${ORIGIN}', origin.to_s)
  return DirRisk.new(state: :unresolvable, detail: 'contains a loader variable we cannot expand') \
    if resolved.include?('$')

  st = begin
    File.stat(resolved)
  rescue SystemCallError
    return DirRisk.new(state: :missing, detail: 'directory does not exist (a future attacker can create it)')
  end

  return DirRisk.new(state: :notdir, detail: 'exists but is not a directory') unless st.directory?

  mode = st.mode
  if (mode & 0o002) != 0
    DirRisk.new(state: :world_writable, detail: format('world-writable (mode %04o)', mode & 0o7777))
  elsif (mode & 0o020) != 0 && st.gid != 0
    DirRisk.new(state: :group_writable, detail: format('group-writable by gid %d (mode %04o)', st.gid, mode & 0o7777))
  elsif st.uid != 0
    DirRisk.new(state: :nonroot_owner, detail: "owned by uid #{st.uid}, not root")
  else
    DirRisk.new(state: :ok, detail: format('root-owned, mode %04o', mode & 0o7777))
  end
end

# ===========================================================================
# Audit
# ===========================================================================

SEVERITY_ORDER = { 'FAIL' => 0, 'WARN' => 1, 'INFO' => 2 }.freeze

def finding(sev, path, check, message, remediation)
  { 'severity' => sev, 'path' => path, 'check' => check,
    'message' => message, 'remediation' => remediation }
end

def audit_binary(path, resolver, opts)
  elf = begin
    ElfFile.new(path)
  rescue ElfError, SystemCallError => e
    return [finding('INFO', path, 'parse', "skipped: #{e.message}", nil)] if opts[:verbose]

    return []
  end

  st = File.stat(path)
  suid = (st.mode & 0o4000) != 0
  sgid = (st.mode & 0o2000) != 0
  privileged = suid || sgid
  origin = File.dirname(File.realpath(path))
  out = []

  return [] if opts[:suid_only] && !privileged

  # --- 1. RPATH / RUNPATH -------------------------------------------------
  { 'RPATH' => elf.rpath, 'RUNPATH' => elf.runpath }.each do |kind, dirs|
    dirs.each do |dir|
      risk = classify_dir(dir, origin)
      next if risk.state == :ok || risk.state == :notdir

      sev = case risk.state
            when :world_writable, :relative then privileged ? 'FAIL' : 'FAIL'
            when :group_writable, :nonroot_owner then privileged ? 'FAIL' : 'WARN'
            when :missing then privileged ? 'FAIL' : 'WARN'
            else 'WARN'
            end
      tag = privileged ? (suid ? ' [SUID]' : ' [SGID]') : ''
      out << finding(sev, path, "#{kind.downcase}.#{risk.state}",
                     "#{kind} '#{dir}'#{tag}: #{risk.detail}",
                     rpath_fix(kind, dir, risk, privileged))
    end
  end

  # RPATH (as opposed to RUNPATH) cannot be overridden by LD_LIBRARY_PATH and is
  # deprecated; even a safe RPATH is worth flagging on a privileged binary.
  if elf.rpath.any? && elf.runpath.empty?
    out << finding(privileged ? 'WARN' : 'INFO', path, 'rpath.deprecated',
                   "uses legacy DT_RPATH (#{elf.rpath.join(':')}) instead of DT_RUNPATH",
                   'Rebuild with `-Wl,--enable-new-dtags` so the entry becomes DT_RUNPATH.')
  end

  # --- 2. Unresolvable NEEDED libraries -----------------------------------
  elf.needed.each do |lib|
    next if resolver.resolve(lib, rpath: elf.rpath, runpath: elf.runpath, origin: origin)

    out << finding('WARN', path, 'needed.missing',
                   "NEEDED library '#{lib}' does not resolve on this host",
                   'The binary will fail at exec time. Install the providing package ' \
                   "or fix the search path (`ldd #{path}`).")
  end

  # --- 3. Compiler hardening ---------------------------------------------
  if elf.exec_stack
    out << finding('FAIL', path, 'hardening.exec_stack',
                   'executable stack (PT_GNU_STACK carries PF_X, or is absent)',
                   'Rebuild with `-z noexecstack`; usually caused by a hand-written .S ' \
                   'file missing a .note.GNU-stack section.')
  end

  unless elf.relro
    out << finding(privileged ? 'FAIL' : 'WARN', path, 'hardening.no_relro',
                   'no RELRO -- the GOT stays writable for the life of the process',
                   'Rebuild with `-Wl,-z,relro -Wl,-z,now` for full RELRO.')
  end

  if elf.relro && !elf.bind_now
    out << finding('WARN', path, 'hardening.partial_relro',
                   'partial RELRO only (lazy binding leaves the GOT writable)',
                   'Add `-Wl,-z,now` to get full RELRO.')
  end

  if elf.pie == false
    out << finding(privileged ? 'FAIL' : 'WARN', path, 'hardening.no_pie',
                   'not a PIE -- the executable loads at a fixed address, defeating ASLR',
                   'Rebuild with `-fPIE -pie`.')
  end

  out
end

def rpath_fix(kind, dir, risk, privileged)
  case risk.state
  when :world_writable, :group_writable
    "Anyone who can write to #{dir} can preload code into this process" +
      (privileged ? ' AT ELEVATED PRIVILEGE. Treat as a live local-privilege-escalation path. ' : '. ') +
      "Fix the directory permissions (`chmod go-w #{dir}`) or strip the entry with `patchelf --remove-rpath`."
  when :relative
    'A relative search path resolves against the caller\'s working directory. ' \
    'Rebuild without it, or rewrite it as $ORIGIN-relative with ' \
    "`patchelf --set-rpath '$ORIGIN/../lib'`."
  when :missing
    "#{dir} does not exist today, so the entry is inert -- until somebody with " \
    'write access to its parent creates it. Remove the stale entry.'
  when :nonroot_owner
    "#{dir} is not root-owned; its owner can replace libraries loaded by this binary."
  else
    'Review this search-path entry.'
  end
end

# ===========================================================================
# Scanning
# ===========================================================================

SKIP_DIRS = %w[/proc /sys /dev /run /snap].freeze

def collect_candidates(roots, recursive:)
  files = []
  roots.each do |root|
    if File.file?(root)
      files << root
      next
    end

    pattern = recursive ? File.join(root, '**', '*') : File.join(root, '*')
    Dir.glob(pattern, File::FNM_DOTMATCH).each do |p|
      next if SKIP_DIRS.any? { |s| p.start_with?(s) }
      next if File.symlink?(p) # follow-once: the real file is scanned separately
      next unless File.file?(p)

      files << p
    end
  end
  files.uniq
end

# ===========================================================================
# Reporting
# ===========================================================================

COLOR = { 'FAIL' => "\e[31m", 'WARN' => "\e[33m", 'INFO' => "\e[36m" }.freeze
RESET = "\e[0m"

def print_report(findings, stats, color:)
  puts '=' * 78
  puts "  ELF HARDENING & RPATH AUDIT -- #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}"
  puts '=' * 78
  puts
  puts "  Files examined    : #{stats[:examined]}"
  puts "  ELF objects       : #{stats[:elf]}  (#{stats[:suid]} SUID/SGID)"
  puts "  Findings          : #{findings.size}"
  puts
  puts '-' * 78

  findings.group_by { |f| f['path'] }
          .sort_by { |_, fs| fs.map { |f| SEVERITY_ORDER[f['severity']] }.min }
          .each do |path, fs|
    puts
    puts "  #{path}"
    fs.sort_by { |f| SEVERITY_ORDER[f['severity']] }.each do |f|
      tag = format('[%-4s]', f['severity'])
      tag = "#{COLOR[f['severity']]}#{tag}#{RESET}" if color
      puts "    #{tag} #{f['message']}"
      puts "           -> #{f['remediation']}" if f['remediation']
    end
  end

  counts = findings.map { |f| f['severity'] }.tally
  puts
  puts '-' * 78
  puts "  #{counts.fetch('FAIL', 0)} fail   #{counts.fetch('WARN', 0)} warn   #{counts.fetch('INFO', 0)} info"
  puts '=' * 78
end

# ===========================================================================
# Entry point
# ===========================================================================

def main(argv)
  opts = { json: false, recursive: true, suid_only: false, verbose: false,
           min_severity: 'INFO', color: $stdout.tty?, root: '/' }

  parser = OptionParser.new do |o|
    o.banner = 'Usage: ruby elf_hardening_audit.rb [options] PATH [PATH...]'
    o.on('--json', 'Emit JSON instead of a text report') { opts[:json] = true }
    o.on('--[no-]recursive', 'Recurse into subdirectories (default: yes)') { |v| opts[:recursive] = v }
    o.on('--suid-only', 'Only report on SUID/SGID binaries') { opts[:suid_only] = true }
    o.on('--min-severity SEV', %w[FAIL WARN INFO], 'FAIL, WARN or INFO') { |v| opts[:min_severity] = v }
    o.on('--root PATH', 'Treat PATH as / when resolving libraries') { |v| opts[:root] = v }
    o.on('--verbose', 'Report files that could not be parsed') { opts[:verbose] = true }
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

  if argv.empty?
    warn 'error: no paths given'
    warn parser.to_s
    return 3
  end

  missing = argv.reject { |p| File.exist?(p) }
  unless missing.empty?
    warn "error: no such path: #{missing.join(', ')}"
    return 3
  end

  resolver = LibraryResolver.new(root: opts[:root])
  candidates = collect_candidates(argv, recursive: opts[:recursive])

  stats = { examined: candidates.size, elf: 0, suid: 0 }
  findings = []

  candidates.each do |path|
    next unless ElfFile.elf?(path)

    stats[:elf] += 1
    begin
      stats[:suid] += 1 if (File.stat(path).mode & 0o6000) != 0
    rescue SystemCallError
      next
    end
    findings.concat(audit_binary(path, resolver, opts))
  end

  threshold = SEVERITY_ORDER[opts[:min_severity]]
  findings.select! { |f| SEVERITY_ORDER[f['severity']] <= threshold }

  if opts[:json]
    puts JSON.pretty_generate('generated_at' => Time.now.utc.iso8601,
                              'search_path' => resolver.dirs,
                              'summary' => stats,
                              'findings' => findings)
  else
    print_report(findings, stats, color: opts[:color])
  end

  return 2 if findings.any? { |f| f['severity'] == 'FAIL' }
  return 1 if findings.any? { |f| f['severity'] == 'WARN' }

  0
end

exit(main(ARGV)) if __FILE__ == $PROGRAM_NAME
