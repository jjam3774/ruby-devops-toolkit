#!/usr/bin/env ruby
# frozen_string_literal: true
#
# repo_trust_audit.rb - audit the software repositories a Linux host trusts,
# and the signing keys behind them.
#
# Every package on this box arrived from a URL in one of these files, validated
# by a key in one of these keyrings. That is the shortest supply chain an
# attacker has to compromise, and almost nobody audits it. This script finds:
#
#   * repositories with signature verification switched OFF
#     ([trusted=yes] on apt, gpgcheck=0 on dnf/yum) - the single worst finding
#   * the legacy apt trust model, where ANY key in /etc/apt/trusted.gpg.d can
#     sign ANY repository, instead of a per-repo Signed-By
#   * signing keys that have expired or are about to
#   * third-party repos pinned above the distribution's own packages, which
#     lets a vendor repo silently replace OS packages
#   * suite/codename mismatches - the "FrankenDebian" that breaks on upgrade
#
# Supports apt one-line (.list), apt deb822 (.sources) and dnf/yum (.repo).
# Ruby standard library only; key expiry uses the system `gpg` when present.
#
# Usage:
#   ruby repo_trust_audit.rb                      # audit this host
#   ruby repo_trust_audit.rb --root ./fixtures    # audit a captured tree
#   ruby repo_trust_audit.rb --json
#   ruby repo_trust_audit.rb --expiry-warn 180    # warn this far before expiry
#   ruby repo_trust_audit.rb --no-keys            # skip key inspection
#
# Exit codes: 0 = clean, 1 = WARN findings, 2 = at least one CRIT.

require 'optparse'
require 'json'
require 'time'

module RepoTrustAudit
  VERSION = '1.0.0'

  Repo = Struct.new(:id, :kind, :enabled, :uris, :suites, :components, :options,
                    :file, :line, :signed_by, keyword_init: true)
  Key = Struct.new(:keyid, :uid, :created, :expires, :validity, :file, keyword_init: true)
  Finding = Struct.new(:severity, :code, :subject, :detail, :evidence, keyword_init: true)

  # Hosts that ship the distribution itself. Anything else is third-party and
  # gets a closer look - not because third-party is wrong, but because you
  # should be able to name every one of them from memory.
  DISTRO_HOSTS = %w[
    archive.ubuntu.com security.ubuntu.com ports.ubuntu.com
    deb.debian.org security.debian.org ftp.debian.org
    mirrors.kernel.org archive.canonical.com
    mirror.centos.org vault.centos.org dl.fedoraproject.org
    download.fedoraproject.org mirrors.fedoraproject.org cdn.redhat.com
  ].freeze

  # ---------------------------------------------------------------------------
  # Source discovery + parsing
  # ---------------------------------------------------------------------------
  class Collector
    attr_reader :repos, :errors

    def initialize(root: '')
      @root = root.to_s.chomp('/')
      @repos = []
      @errors = []
    end

    def path(p)
      @root.empty? ? p : File.join(@root, p)
    end

    def display(p)
      @root.empty? ? p : p.sub(/\A#{Regexp.escape(@root)}/, '')
    end

    def collect
      read_apt_list(path('/etc/apt/sources.list'))
      Dir.glob(File.join(path('/etc/apt/sources.list.d'), '*.list')).sort.each { |f| read_apt_list(f) }
      Dir.glob(File.join(path('/etc/apt/sources.list.d'), '*.sources')).sort.each { |f| read_deb822(f) }
      Dir.glob(File.join(path('/etc/yum.repos.d'), '*.repo')).sort.each { |f| read_yum(f) }
      self
    end

    private

    # One-line format:  deb [opt=val opt=val] URI suite component...
    def read_apt_list(file)
      return unless File.file?(file) && File.readable?(file)

      File.readlines(file).each_with_index do |raw, idx|
        line = raw.strip
        next if line.empty?

        enabled = true
        if line.start_with?('#')
          # A commented-out repo is still worth reporting as disabled, but only
          # if it actually looks like a repo line and not prose.
          body = line.sub(/\A#+\s*/, '')
          next unless body =~ /\Adeb(-src)?\s/

          line = body
          enabled = false
        end
        next unless line =~ /\Adeb(-src)?\s/

        type = line.split(/\s+/, 2).first
        rest = line.sub(/\Adeb(-src)?\s+/, '')
        options = {}
        if rest.start_with?('[')
          close = rest.index(']')
          if close.nil?
            @errors << { file: display(file), line: idx + 1, error: 'unterminated [options]' }
            next
          end
          rest[1...close].split(/\s+/).each do |kv|
            k, v = kv.split('=', 2)
            options[k.to_s.downcase] = v.to_s
          end
          rest = rest[(close + 1)..].to_s.strip
        end
        parts = rest.split(/\s+/)
        uri = parts.shift
        suite = parts.shift
        next if uri.nil? || suite.nil?

        @repos << Repo.new(
          id: "#{type} #{uri} #{suite}", kind: :apt, enabled: enabled,
          uris: [uri], suites: [suite], components: parts, options: options,
          file: display(file), line: idx + 1, signed_by: options['signed-by']
        )
      end
    end

    # deb822 format (.sources): RFC822-style stanzas, blank-line separated.
    def read_deb822(file)
      return unless File.file?(file) && File.readable?(file)

      stanza = {}
      start_line = 1
      flush = lambda do
        unless stanza.empty?
          types = (stanza['types'] || 'deb').split(/\s+/)
          enabled = (stanza['enabled'] || 'yes').downcase != 'no'
          opts = {}
          opts['trusted'] = stanza['trusted'] if stanza['trusted']
          opts['allow-insecure'] = stanza['allow-insecure'] if stanza['allow-insecure']
          @repos << Repo.new(
            id: "#{types.join('/')} #{stanza['uris']} #{stanza['suites']}",
            kind: :apt, enabled: enabled,
            uris: stanza['uris'].to_s.split(/\s+/),
            suites: stanza['suites'].to_s.split(/\s+/),
            components: stanza['components'].to_s.split(/\s+/),
            options: opts, file: display(file), line: start_line,
            signed_by: stanza['signed-by']
          )
        end
        stanza = {}
      end

      File.readlines(file).each_with_index do |raw, idx|
        line = raw.rstrip
        if line.strip.empty?
          flush.call
          start_line = idx + 2
          next
        end
        next if line.strip.start_with?('#')

        if line =~ /\A\s/ && !stanza.empty?
          # Continuation line for a multi-line field (Signed-By pastes a whole
          # armoured key this way).
          stanza[stanza.keys.last] = "#{stanza[stanza.keys.last]} #{line.strip}"
          next
        end
        k, v = line.split(':', 2)
        next if v.nil?

        start_line = idx + 1 if stanza.empty?
        stanza[k.strip.downcase] = v.strip
      end
      flush.call
    end

    # dnf/yum .repo files are INI: [section] then key=value.
    def read_yum(file)
      return unless File.file?(file) && File.readable?(file)

      section = nil
      attrs = {}
      line_no = 0
      flush = lambda do
        return if section.nil?

        @repos << Repo.new(
          id: section, kind: :yum,
          enabled: (attrs['enabled'] || '1').to_s.strip != '0',
          uris: [attrs['baseurl'], attrs['metalink'], attrs['mirrorlist']].compact,
          suites: [], components: [], options: attrs,
          file: display(file), line: attrs['__line'].to_i, signed_by: attrs['gpgkey']
        )
        attrs = {}
      end

      File.readlines(file).each_with_index do |raw, idx|
        line_no = idx + 1
        line = raw.strip
        next if line.empty? || line.start_with?('#', ';')

        if line =~ /\A\[(.+)\]\z/
          flush.call
          section = Regexp.last_match(1)
          attrs = { '__line' => line_no.to_s }
        elsif section && line.include?('=')
          k, v = line.split('=', 2)
          attrs[k.strip.downcase] = v.strip
        end
      end
      flush.call
    end
  end

  # ---------------------------------------------------------------------------
  # Keyring inspection
  #
  # Parsing OpenPGP packets by hand is a project in its own right, so this
  # shells out to the gpg already installed on any host that has apt or dnf and
  # reads the machine-readable --with-colons output. If gpg is missing, key
  # checks are skipped and the report says so rather than quietly passing.
  # ---------------------------------------------------------------------------
  class KeyInspector
    DIRS = ['/etc/apt/trusted.gpg.d', '/etc/apt/keyrings', '/usr/share/keyrings',
            '/etc/pki/rpm-gpg'].freeze

    attr_reader :keys, :available, :legacy_keyring

    def initialize(root: '')
      @root = root.to_s.chomp('/')
      @keys = []
      @available = !`which gpg 2>/dev/null`.strip.empty?
      @legacy_keyring = false
    end

    def inspect_all
      return self unless @available

      legacy = File.join(@root, '/etc/apt/trusted.gpg')
      @legacy_keyring = File.file?(legacy) && File.size(legacy) > 0

      DIRS.each do |dir|
        Dir.glob(File.join(@root.empty? ? dir : File.join(@root, dir), '*')).sort.each do |f|
          next unless File.file?(f)
          # gpg writes a ~ backup when a keyring is edited; auditing it produces
          # duplicate, stale findings.
          next if f.end_with?('~')
          next unless f =~ /\.(gpg|asc|pgp|key)\z/i || File.basename(f).start_with?('RPM-GPG-KEY')

          parse_keyring(f)
        end
      end
      self
    end

    private

    def parse_keyring(file)
      out = `gpg --no-default-keyring --batch --quiet --with-colons --show-keys #{quote(file)} 2>/dev/null`
      return if out.strip.empty?

      current = nil
      out.each_line do |line|
        fields = line.chomp.split(':', -1)
        case fields[0]
        when 'pub'
          # 2=validity 5=keyid 6=created 7=expires (epoch seconds, or blank)
          current = Key.new(keyid: fields[4], validity: fields[1],
                            created: epoch(fields[5]), expires: epoch(fields[6]),
                            uid: nil, file: display(file))
          @keys << current
        when 'uid'
          current.uid ||= unescape(fields[9]) if current
        end
      end
    rescue StandardError => e
      warn "repo_trust_audit: gpg failed on #{file}: #{e.message}"
    end

    def epoch(v)
      return nil if v.nil? || v.strip.empty?

      Time.at(v.to_i)
    rescue StandardError
      nil
    end

    def unescape(s)
      s.to_s.gsub(/\\x([0-9a-fA-F]{2})/) { [Regexp.last_match(1).hex].pack('C') }
    end

    def display(p)
      @root.empty? ? p : p.sub(/\A#{Regexp.escape(@root)}/, '')
    end

    def quote(s)
      "'#{s.gsub("'", "'\\\\''")}'"
    end
  end

  # ---------------------------------------------------------------------------
  # Pin priorities - /etc/apt/preferences.d
  # ---------------------------------------------------------------------------
  class PinReader
    Pin = Struct.new(:package, :pin, :priority, :file, :line, keyword_init: true)

    def self.read(root)
      out = []
      base = root.to_s.empty? ? '/etc/apt/preferences.d' : File.join(root.chomp('/'), '/etc/apt/preferences.d')
      files = Dir.glob(File.join(base, '*')).sort
      main = root.to_s.empty? ? '/etc/apt/preferences' : File.join(root.chomp('/'), '/etc/apt/preferences')
      files.unshift(main) if File.file?(main)
      files.each do |f|
        next unless File.file?(f) && File.readable?(f)

        cur = {}
        start = 1
        File.readlines(f).each_with_index do |raw, idx|
          line = raw.strip
          if line.empty?
            out << build(cur, f, start, root) unless cur.empty?
            cur = {}
            next
          end
          next if line.start_with?('#')

          k, v = line.split(':', 2)
          next if v.nil?

          start = idx + 1 if cur.empty?
          cur[k.strip.downcase] = v.strip
        end
        out << build(cur, f, start, root) unless cur.empty?
      end
      out.compact
    end

    def self.build(h, file, line, root)
      return nil unless h['pin-priority']

      disp = root.to_s.empty? ? file : file.sub(/\A#{Regexp.escape(root.chomp('/'))}/, '')
      Pin.new(package: h['package'], pin: h['pin'], priority: h['pin-priority'].to_i,
              file: disp, line: line)
    end
  end

  # ---------------------------------------------------------------------------
  # Auditor
  # ---------------------------------------------------------------------------
  class Auditor
    def initialize(repos:, keys:, pins:, codename:, expiry_warn_days:, keys_available:,
                   legacy_keyring:, now: Time.now)
      @repos = repos
      @keys = keys
      @pins = pins
      @codename = codename
      @expiry_warn = expiry_warn_days
      @keys_available = keys_available
      @legacy_keyring = legacy_keyring
      @now = now
    end

    def findings
      out = []
      @repos.each { |r| out.concat(repo_findings(r)) }
      out.concat(key_findings)
      out.concat(pin_findings)
      out.concat(duplicate_findings)
      out.sort_by { |f| [{ 'CRIT' => 0, 'WARN' => 1, 'INFO' => 2 }.fetch(f.severity, 3), f.code, f.subject.to_s] }
    end

    private

    def repo_findings(r)
      out = []
      loc = "#{r.file}:#{r.line}"
      unless r.enabled
        return [Finding.new(severity: 'INFO', code: 'DISABLED', subject: r.id,
                            detail: 'repository is present but disabled', evidence: loc)]
      end

      if r.kind == :apt
        if r.options['trusted'].to_s.downcase == 'yes'
          out << Finding.new(severity: 'CRIT', code: 'SIGNATURE_CHECK_OFF', subject: r.id,
                             detail: 'trusted=yes disables signature verification entirely. ' \
                                     'Anyone who can answer for this URL - or sit on the path when ' \
                                     'it is plain HTTP - can install packages as root.',
                             evidence: loc)
        end
        if r.options['allow-insecure'].to_s.downcase == 'yes'
          out << Finding.new(severity: 'CRIT', code: 'ALLOW_INSECURE', subject: r.id,
                             detail: 'allow-insecure=yes accepts an unsigned or broken Release file.',
                             evidence: loc)
        end
        # Only worth flagging for third-party repos. The distribution's own
        # archives are validated by the distro keyring package, which is the
        # intended design; a vendor repo riding on that same global keyring is
        # the actual problem.
        if r.signed_by.to_s.strip.empty? && r.uris.compact.any? { |u| third_party?(u) }
          out << Finding.new(severity: 'WARN', code: 'NO_SIGNED_BY', subject: r.id,
                             detail: 'third-party repo with no Signed-By, so it is validated against ' \
                                     'every key in the global apt keyring - and every other repo is ' \
                                     'validated against its key. Pin it: ' \
                                     'Signed-By: /usr/share/keyrings/<vendor>.gpg.',
                             evidence: loc)
        end
      else
        if r.options['gpgcheck'].to_s.strip == '0'
          out << Finding.new(severity: 'CRIT', code: 'SIGNATURE_CHECK_OFF', subject: r.id,
                             detail: 'gpgcheck=0 disables package signature verification for this repo.',
                             evidence: loc)
        end
        if r.options['sslverify'].to_s.strip == '0'
          out << Finding.new(severity: 'CRIT', code: 'SSL_VERIFY_OFF', subject: r.id,
                             detail: 'sslverify=0 accepts any TLS certificate for this repository.',
                             evidence: loc)
        end
        if r.options['repo_gpgcheck'].to_s.strip != '1'
          out << Finding.new(severity: 'INFO', code: 'NO_REPO_GPGCHECK', subject: r.id,
                             detail: 'repo_gpgcheck is not 1, so repository metadata itself is not ' \
                                     'signature-checked (only the packages are).',
                             evidence: loc)
        end
        if r.options['gpgkey'].to_s.strip.empty? && r.options['gpgcheck'].to_s.strip != '0'
          out << Finding.new(severity: 'WARN', code: 'NO_GPGKEY', subject: r.id,
                             detail: 'gpgcheck is on but no gpgkey is declared; the repo relies on a ' \
                                     'key already imported into the RPM database.',
                             evidence: loc)
        end
      end

      r.uris.compact.each do |uri|
        host = uri_host(uri)
        if uri.start_with?('http://')
          sev = r.options['trusted'].to_s.downcase == 'yes' ? 'CRIT' : 'WARN'
          out << Finding.new(severity: sev, code: 'PLAINTEXT_TRANSPORT', subject: r.id,
                             detail: "#{uri} is plain HTTP. Signatures still protect package contents, " \
                                     'but the package list you fetch - and therefore what you are told ' \
                                     'to install - is visible and modifiable in transit.',
                             evidence: loc)
        end
        if third_party?(uri)
          out << Finding.new(severity: 'INFO', code: 'THIRD_PARTY', subject: r.id,
                             detail: "third-party origin #{host} - confirm you still need it and that " \
                                     'someone owns keeping it patched.',
                             evidence: loc)
        end
      end

      if @codename && r.kind == :apt
        r.suites.each do |suite|
          base = suite.split('-').first
          next if base.nil? || base.empty?
          next if %w[stable testing unstable oldstable stable-security].include?(base)
          next if base == @codename
          next unless known_codename?(base)

          out << Finding.new(severity: 'WARN', code: 'SUITE_MISMATCH', subject: r.id,
                             detail: "suite #{suite} does not match this host's codename #{@codename}. " \
                                     'Mixing releases ("FrankenDebian") breaks on the next dist-upgrade.',
                             evidence: loc)
        end
      end

      out
    end

    # Only flag a suite as a mismatch when it is recognisably another release
    # name; vendor repos legitimately use suites like "stable", "main" or "any".
    KNOWN = %w[buster bullseye bookworm trixie sid
               bionic focal jammy noble oracular plucky xenial trusty].freeze
    def known_codename?(name)
      KNOWN.include?(name)
    end

    def key_findings
      unless @keys_available
        return [Finding.new(severity: 'INFO', code: 'KEYS_NOT_CHECKED', subject: 'keyrings',
                            detail: 'gpg is not installed, so signing-key expiry was not checked.',
                            evidence: nil)]
      end

      out = []
      if @legacy_keyring
        out << Finding.new(severity: 'WARN', code: 'LEGACY_TRUSTED_GPG', subject: '/etc/apt/trusted.gpg',
                           detail: 'the legacy monolithic keyring exists and is non-empty. Keys added ' \
                                   'by the deprecated apt-key live here and can sign for every ' \
                                   'repository on the host. Migrate them to per-repo Signed-By keyrings.',
                           evidence: '/etc/apt/trusted.gpg')
      end

      @keys.each do |k|
        label = "#{k.keyid} #{k.uid}".strip
        if k.validity == 'e' || (k.expires && k.expires < @now)
          out << Finding.new(severity: 'CRIT', code: 'KEY_EXPIRED', subject: label,
                             detail: "signing key expired #{k.expires ? k.expires.utc.strftime('%Y-%m-%d') : '(date unknown)'}. " \
                                     'Updates from the repo it signs will start failing, and the usual ' \
                                     '"fix" people reach for is trusted=yes.',
                             evidence: k.file)
        elsif k.expires && k.expires < @now + (@expiry_warn * 86_400)
          days = ((k.expires - @now) / 86_400).round
          out << Finding.new(severity: 'WARN', code: 'KEY_EXPIRING', subject: label,
                             detail: "signing key expires in #{days} days (#{k.expires.utc.strftime('%Y-%m-%d')}).",
                             evidence: k.file)
        elsif k.validity == 'r'
          out << Finding.new(severity: 'CRIT', code: 'KEY_REVOKED', subject: label,
                             detail: 'signing key is revoked but still present in a trusted keyring.',
                             evidence: k.file)
        end
      end
      out
    end

    def pin_findings
      third_party_hosts = @repos.flat_map { |r| r.uris.compact.map { |u| uri_host(u) } }
                                .compact.uniq.reject { |h| DISTRO_HOSTS.include?(h) }
      @pins.select { |p| p.priority > 500 }.map do |p|
        sev = p.package.to_s.strip == '*' ? 'CRIT' : 'WARN'
        Finding.new(
          severity: sev, code: 'PIN_ABOVE_DISTRO', subject: "#{p.package} <- #{p.pin}",
          detail: "Pin-Priority #{p.priority} is above the distribution's 500, so this source can " \
                  "replace OS packages#{p.package.to_s.strip == '*' ? ' - and it applies to every package' : ''}. " \
                  "Third-party origins present: #{third_party_hosts.first(4).join(', ')}.",
          evidence: "#{p.file}:#{p.line}"
        )
      end
    end

    def duplicate_findings
      seen = Hash.new { |h, k| h[k] = [] }
      @repos.select(&:enabled).each do |r|
        comps = r.components.sort.join(',')
        r.uris.compact.each { |u| r.suites.each { |s| seen[[u, s, comps]] << "#{r.file}:#{r.line}" } }
      end
      seen.select { |_, v| v.size > 1 }.map do |(uri, suite, _comps), locs|
        Finding.new(severity: 'INFO', code: 'DUPLICATE_SOURCE', subject: "#{uri} #{suite}",
                    detail: "defined #{locs.size} times; apt will fetch it repeatedly and warn on every update.",
                    evidence: locs.join(', '))
      end
    end

    # "Third party" means: not one of the distribution's own archive hosts, and
    # not a local file/cdrom source.
    def third_party?(uri)
      return false if uri.to_s.start_with?('file:', 'cdrom:')

      host = uri_host(uri)
      return false if host.nil?
      return false if DISTRO_HOSTS.include?(host)
      return false if host.end_with?('.archive.ubuntu.com', '.debian.org', '.ubuntu.com')

      true
    end

    def uri_host(uri)
      m = %r{\A[a-z+\-.]+://([^/@]*@)?([^/:]+)}i.match(uri.to_s)
      m && m[2].downcase
    end
  end

  # ---------------------------------------------------------------------------
  # Reporters
  # ---------------------------------------------------------------------------
  class TextReporter
    COLORS = { 'CRIT' => "\e[31m", 'WARN' => "\e[33m", 'INFO' => "\e[36m" }.freeze
    RESET = "\e[0m"

    def initialize(io, color:)
      @io = io
      @color = color
    end

    def report(repos:, keys:, findings:, codename:, errors:)
      enabled = repos.count(&:enabled)
      @io.puts "repository trust audit  -  #{enabled} enabled repo(s), " \
               "#{repos.size - enabled} disabled, #{keys.size} signing key(s)"
      @io.puts "host codename: #{codename || 'unknown'}"
      @io.puts '=' * 78
      @io.puts
      @io.puts 'repositories'
      @io.puts '-' * 78
      repos.each do |r|
        mark = r.enabled ? ' ' : '#'
        @io.puts format('  %s %-46s %s', mark, truncate(r.uris.compact.first.to_s, 46),
                        "#{r.file}:#{r.line}")
        extra = []
        extra << "suite=#{r.suites.join(',')}" unless r.suites.empty?
        extra << "signed-by=#{File.basename(r.signed_by.to_s)}" unless r.signed_by.to_s.strip.empty?
        extra << 'TRUSTED=YES' if r.options['trusted'].to_s.downcase == 'yes'
        extra << 'gpgcheck=0' if r.options['gpgcheck'].to_s.strip == '0'
        @io.puts "      #{extra.join('  ')}" unless extra.empty?
      end

      findings.group_by { |f| [f.severity, f.code] }.each do |(sev, code), group|
        @io.puts
        @io.puts "#{paint(sev)}  #{code}   (#{group.size})"
        @io.puts '-' * 78
        group.each do |f|
          @io.puts "    #{f.subject}"
          @io.puts "      #{wrap(f.detail, 72)}"
          @io.puts "      at #{f.evidence}" if f.evidence
        end
      end

      unless errors.empty?
        @io.puts
        @io.puts 'parse problems'
        @io.puts '-' * 78
        errors.each { |e| @io.puts "  #{e[:file]}:#{e[:line]}  #{e[:error]}" }
      end

      counts = findings.group_by(&:severity).transform_values(&:size)
      @io.puts
      @io.puts '=' * 78
      @io.puts format('summary  CRIT=%d  WARN=%d  INFO=%d',
                      counts.fetch('CRIT', 0), counts.fetch('WARN', 0), counts.fetch('INFO', 0))
    end

    private

    def paint(sev)
      return sev.ljust(4) unless @color

      "#{COLORS.fetch(sev, '')}#{sev.ljust(4)}#{RESET}"
    end

    def truncate(s, n)
      s.length > n ? "#{s[0, n - 3]}..." : s
    end

    def wrap(s, width)
      out = []
      line = ''
      s.split(/\s+/).each do |w|
        if line.length + w.length + 1 > width
          out << line
          line = w
        else
          line = line.empty? ? w : "#{line} #{w}"
        end
      end
      out << line
      out.join("\n      ")
    end
  end

  class JsonReporter
    def initialize(io)
      @io = io
    end

    def report(repos:, keys:, findings:, codename:, errors:)
      @io.puts JSON.pretty_generate(
        codename: codename,
        repositories: repos.map do |r|
          { id: r.id, kind: r.kind, enabled: r.enabled, uris: r.uris, suites: r.suites,
            components: r.components, signed_by: r.signed_by, options: r.options.reject { |k, _| k == '__line' },
            file: r.file, line: r.line }
        end,
        keys: keys.map do |k|
          { keyid: k.keyid, uid: k.uid, validity: k.validity,
            created: k.created&.iso8601, expires: k.expires&.iso8601, keyring: k.file }
        end,
        findings: findings.map do |f|
          { severity: f.severity, code: f.code, subject: f.subject, detail: f.detail, evidence: f.evidence }
        end,
        parse_errors: errors
      )
    end
  end

  # ---------------------------------------------------------------------------
  # CLI
  # ---------------------------------------------------------------------------
  class CLI
    def self.run(argv, io = $stdout)
      opts = { root: '', json: false, color: io.tty?, expiry_warn: 90, keys: true, at: nil }
      OptionParser.new do |o|
        o.banner = 'Usage: repo_trust_audit.rb [options]'
        o.on('--root DIR', 'Treat DIR as / (for fixtures or a captured tree)') { |v| opts[:root] = v }
        o.on('--expiry-warn DAYS', Integer, 'Warn this many days before key expiry (default 90)') do |v|
          opts[:expiry_warn] = v
        end
        o.on('--no-keys', 'Skip signing-key inspection') { opts[:keys] = false }
        o.on('--at TIME', 'Pin "now" (testing)') { |v| opts[:at] = v }
        o.on('--json', 'Emit JSON') { opts[:json] = true }
        o.on('--[no-]color', 'Force colour on/off') { |v| opts[:color] = v }
        o.on('-v', '--version') { io.puts VERSION; exit 0 }
        o.on('-h', '--help') { io.puts o; exit 0 }
      end.parse!(argv)

      now = opts[:at] ? Time.parse(opts[:at]) : Time.now
      collector = Collector.new(root: opts[:root]).collect
      inspector = KeyInspector.new(root: opts[:root])
      inspector.inspect_all if opts[:keys]

      findings = Auditor.new(
        repos: collector.repos, keys: inspector.keys, pins: PinReader.read(opts[:root]),
        codename: codename(opts[:root]), expiry_warn_days: opts[:expiry_warn],
        keys_available: opts[:keys] && inspector.available,
        legacy_keyring: inspector.legacy_keyring, now: now
      ).findings

      reporter = opts[:json] ? JsonReporter.new(io) : TextReporter.new(io, color: opts[:color])
      reporter.report(repos: collector.repos, keys: inspector.keys, findings: findings,
                      codename: codename(opts[:root]), errors: collector.errors)

      return 2 if findings.any? { |f| f.severity == 'CRIT' }
      return 1 if findings.any? { |f| f.severity == 'WARN' }

      0
    end

    def self.codename(root)
      path = root.to_s.empty? ? '/etc/os-release' : File.join(root.chomp('/'), '/etc/os-release')
      return nil unless File.readable?(path)

      File.readlines(path).each do |line|
        return Regexp.last_match(1).delete('"') if line =~ /\AVERSION_CODENAME=(.+)/
        return Regexp.last_match(1).delete('"') if line =~ /\AUBUNTU_CODENAME=(.+)/
      end
      nil
    end
  end
end

exit RepoTrustAudit::CLI.run(ARGV) if $PROGRAM_NAME == __FILE__
