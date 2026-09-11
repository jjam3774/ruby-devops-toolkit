#!/usr/bin/env ruby
# frozen_string_literal: true
#
# nfs_exports_audit.rb — audit /etc/exports (and the live exportfs table) for
# the NFS misconfigurations that turn a file server into a root shell.
#
# Findings (severity in brackets):
#   [CRIT] WORLD_RW         export is rw to '*' / everyone
#   [CRIT] NO_ROOT_SQUASH   remote root == local root (rw). WARN when ro.
#   [CRIT] INSECURE         'insecure' lets any unprivileged client port mount it
#   [CRIT] SENSITIVE_PATH   /, /etc, /root, /usr, /var, /home, /boot exported rw
#   [WARN] WORLD_RO         readable by everyone (still a data leak)
#   [WARN] BROAD_CLIENT     CIDR shorter than /16 or a *.wildcard hostname
#   [WARN] ASYNC            'async' — acknowledged writes can be lost on a crash
#   [WARN] SEC_SYS_ONLY     AUTH_SYS on a broad client (uid/gid are client-asserted)
#   [WARN] NESTED_WIDER     a sub-directory is exported more openly than its parent
#   [WARN] MISSING_PATH     the exported directory does not exist on this host
#   [WARN] NO_SUBTREE_OPT   subtree_check left implicit (exportfs warns about this too)
#
# Usage:
#   ruby nfs_exports_audit.rb                        # /etc/exports + /etc/exports.d/*.exports
#   ruby nfs_exports_audit.rb --exports ./exports    # audit a captured file
#   ruby nfs_exports_audit.rb --live                 # parse "exportfs -v" (what the kernel
#                                                    # actually serves, incl. defaults)
#   ruby nfs_exports_audit.rb --json
#
# Exit codes: 0 clean, 1 warnings only, 2 any CRIT.   Stdlib only.

require 'optparse'
require 'json'
require 'open3'

SENSITIVE = %w[/ /etc /root /usr /var /home /boot /bin /sbin /lib /lib64 /opt].freeze
NFS_DEFAULTS = %w[ro sync wdelay hide root_squash no_all_squash secure subtree_check_unset].freeze

Export = Struct.new(:path, :client, :options, :source, :line, keyword_init: true) do
  def opts
    @opts ||= options.to_s.split(',').map(&:strip).reject(&:empty?)
  end

  def rw?           = opts.include?('rw')
  def world?        = client == '*' || client == '<world>' || client.empty? # exportfs -v prints <world> for *
  def root_squash?  = !opts.include?('no_root_squash')
  def sec           = (opts.find { |o| o.start_with?('sec=') } || 'sec=sys').sub('sec=', '')
end

# ---------------------------------------------------------------------------
# Parsing /etc/exports
#   /srv/share   10.0.0.0/24(rw,sync,no_subtree_check)  *.corp.example.com(ro)
#   "/path with spaces" host(rw)
#   /srv/pub  *        # a bare client with no (options) uses the defaults
#   line continuations with trailing backslash are honoured
# ---------------------------------------------------------------------------
def parse_exports(text, source: '/etc/exports')
  logical = []
  buf = +''
  text.each_line.with_index(1) do |raw, n|
    line = raw.sub(/#.*/, '').rstrip
    if line.end_with?('\\')
      buf << line.chomp('\\') << ' '
      next
    end
    buf << line
    logical << [buf.strip, n] unless buf.strip.empty?
    buf = +''
  end

  logical.flat_map do |line, n|
    # path is either "quoted" or the first whitespace-free token
    if line.start_with?('"')
      path = line[/\A"([^"]+)"/, 1]
      rest = line.sub(/\A"[^"]+"\s*/, '')
    else
      path, rest = line.split(/\s+/, 2)
    end
    rest ||= ''
    # each client spec: host, host(opts). Options never contain whitespace.
    specs = rest.scan(/(\S+?)\(([^)]*)\)|(\S+)/).map { |h1, o, h2| h1 ? [h1, o] : [h2, ''] }
    specs = [['*', '']] if specs.empty? # "/path" alone == everyone, defaults
    specs.map { |client, o| Export.new(path: path, client: client, options: o, source: source, line: n) }
  end
end

# "exportfs -v" prints one export per line with the *effective* option set:
#   /srv/share  10.0.0.0/24(sync,wdelay,hide,no_subtree_check,sec=sys,rw,secure,root_squash,no_all_squash)
# Long paths wrap onto the next line — join a bare path line with its successor.
def parse_exportfs(text)
  lines = text.lines.map(&:rstrip).reject(&:empty?)
  joined = []
  lines.each do |l|
    if l =~ /\A\S+\z/ && !l.include?('(') # bare path, continuation follows
      joined << l
    elsif joined.last && !joined.last.include?('(')
      joined[-1] = "#{joined.last} #{l.strip}"
    else
      joined << l
    end
  end
  joined.flat_map { |l| parse_exports(l, source: 'exportfs -v') }
end

def read_exports_tree(main = '/etc/exports', dir = '/etc/exports.d')
  files = [main] + Dir.glob(File.join(dir, '*.exports')).sort
  files.select { |f| File.exist?(f) }.flat_map { |f| parse_exports(File.read(f), source: f) }
end

# ---------------------------------------------------------------------------
# Client-spec classification
# ---------------------------------------------------------------------------
def broad_client?(client)
  return true if client == '*' || client == '<world>' || client.empty?
  return true if client.start_with?('*') || client.include?('?')       # *.example.com
  if client =~ %r{\A[\d.]+/(\d+)\z} || client =~ %r{\A[0-9a-f:]+/(\d+)\z}i
    bits = Regexp.last_match(1).to_i
    v6 = client.include?(':')
    return v6 ? bits < 48 : bits < 16
  end
  if client =~ %r{\A[\d.]+/([\d.]+)\z} # dotted netmask form 10.0.0.0/255.0.0.0
    mask = Regexp.last_match(1).split('.').map(&:to_i).sum { |octet| octet.to_s(2).count('1') }
    return mask < 16
  end
  false
end

# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------
Finding = Struct.new(:severity, :code, :path, :client, :detail, keyword_init: true)

def audit(exports, check_paths: true)
  f = []
  add = ->(sev, code, e, detail) { f << Finding.new(severity: sev, code: code, path: e.path, client: e.client, detail: detail) }

  exports.each do |e|
    if e.world?
      e.rw? ? add.('CRIT', 'WORLD_RW', e, 'writable by every host that can reach the server')
            : add.('WARN', 'WORLD_RO', e, 'readable by every host that can reach the server')
    end
    unless e.root_squash?
      add.(e.rw? ? 'CRIT' : 'WARN', 'NO_ROOT_SQUASH', e, "remote root is local root#{e.rw? ? ' with write access' : ''} — add root_squash")
    end
    add.('CRIT', 'INSECURE', e, "'insecure' accepts mounts from unprivileged source ports (any user on the client)") if e.opts.include?('insecure')
    if e.rw? && SENSITIVE.include?(e.path.chomp('/').empty? ? '/' : e.path.chomp('/'))
      add.('CRIT', 'SENSITIVE_PATH', e, "#{e.path} exported read-write")
    end
    add.('WARN', 'BROAD_CLIENT', e, 'client spec matches a very large set of hosts') if broad_client?(e.client) && !e.world?
    add.('WARN', 'ASYNC', e, "'async' acknowledges writes before they hit disk") if e.opts.include?('async')
    if e.sec == 'sys' && broad_client?(e.client) && !e.world? # world exports are already CRIT/WARN above
      add.('WARN', 'SEC_SYS_ONLY', e, 'AUTH_SYS trusts the uid/gid the client asserts; consider sec=krb5p')
    end
    unless e.opts.include?('subtree_check') || e.opts.include?('no_subtree_check') || e.source == 'exportfs -v'
      add.('WARN', 'NO_SUBTREE_OPT', e, 'neither subtree_check nor no_subtree_check given; exportfs will default to no_subtree_check and warn')
    end
    if check_paths && e.source != 'exportfs -v' && !File.directory?(e.path)
      add.('WARN', 'MISSING_PATH', e, 'exported path does not exist on this host')
    end
  end

  # Nested exports: /srv (ro, 10.0.0.0/24) and /srv/data (rw, *) — the child
  # undoes whatever restriction the parent expressed.
  exports.each do |child|
    exports.each do |parent|
      next if child.equal?(parent) || parent.path == child.path
      next unless child.path.start_with?(parent.path.chomp('/') + '/')
      wider_client = (child.world? && !parent.world?) || (broad_client?(child.client) && !broad_client?(parent.client))
      wider_mode   = child.rw? && !parent.rw?
      if wider_client || wider_mode
        add.('WARN', 'NESTED_WIDER', child, "exported more openly than parent #{parent.path} (#{parent.client}#{parent.rw? ? ',rw' : ',ro'})")
      end
    end
  end
  f.uniq { |x| [x.code, x.path, x.client] }
end

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
opts = { exports: nil, live: false, exportfs_file: nil, json: false, check_paths: true }
OptionParser.new do |o|
  o.banner = 'Usage: nfs_exports_audit.rb [options]'
  o.on('--exports FILE', 'audit this exports file instead of /etc/exports (+ exports.d)') { |v| opts[:exports] = v }
  o.on('--live', 'audit the running export table via "exportfs -v"') { opts[:live] = true }
  o.on('--exportfs FILE', 'audit a captured "exportfs -v" output') { |v| opts[:exportfs_file] = v }
  o.on('--no-path-check', 'do not verify exported directories exist') { opts[:check_paths] = false }
  o.on('--json', 'JSON output') { opts[:json] = true }
end.parse!

exports =
  if opts[:exportfs_file]
    parse_exportfs(File.read(opts[:exportfs_file]))
  elsif opts[:live]
    out, st = Open3.capture2e('exportfs', '-v')
    abort "exportfs -v failed: #{out.strip}" unless st.success?
    parse_exportfs(out)
  elsif opts[:exports]
    parse_exports(File.read(opts[:exports]), source: opts[:exports])
  else
    read_exports_tree
  end

findings = audit(exports, check_paths: opts[:check_paths])
crit = findings.count { |x| x.severity == 'CRIT' }
warn = findings.count { |x| x.severity == 'WARN' }
status = crit.positive? ? 'CRIT' : (warn.positive? ? 'WARN' : 'OK')

if opts[:json]
  puts JSON.pretty_generate(status: status, exports: exports.map(&:to_h), critical: crit, warnings: warn,
                            findings: findings.map(&:to_h))
else
  puts "nfs_exports_audit  #{exports.size} export entr#{exports.size == 1 ? 'y' : 'ies'} from #{exports.map(&:source).uniq.join(', ')}"
  puts '-' * 92
  puts format('%-28s %-24s %-4s %-10s %s', 'PATH', 'CLIENT', 'MODE', 'ROOT', 'OPTIONS')
  exports.each do |e|
    puts format('%-28s %-24s %-4s %-10s %s', e.path[0, 28], e.client[0, 24], e.rw? ? 'rw' : 'ro', e.root_squash? ? 'squashed' : 'NOT SQUASH', e.options[0, 40])
  end
  puts
  if findings.empty?
    puts 'no findings'
  else
    findings.sort_by { |x| [x.severity == 'CRIT' ? 0 : 1, x.path] }.each do |x|
      puts format('[%-4s] %-15s %-24s %-18s %s', x.severity, x.code, x.path[0, 24], x.client[0, 18], x.detail)
    end
  end
  puts
  puts "#{status}: #{crit} critical, #{warn} warning(s)"
end
exit(crit.positive? ? 2 : (warn.positive? ? 1 : 0))
