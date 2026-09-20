#!/usr/bin/env ruby
# frozen_string_literal: true
#
# sshd_config_audit.rb - audit an OpenSSH server config the way sshd actually
# reads it: first value wins, Include files are spliced in place, and Match
# blocks are evaluated as separate overlays.
#
# Most "SSH hardening checkers" grep the file for a keyword and report the last
# line they find. That is wrong twice over. OpenSSH takes the FIRST obtained
# value for almost every keyword, and a Match block further down can hand back
# everything the global section just locked away - which is how a host passes a
# grep-based audit while still accepting root logins with a password from the
# office subnet.
#
# Ruby standard library only. No gems.
#
# Usage:
#   ruby sshd_config_audit.rb                          # audit /etc/ssh/sshd_config
#   ruby sshd_config_audit.rb --config ./sshd_config   # audit a specific file
#   ruby sshd_config_audit.rb --root ./fixtures        # treat ./fixtures as /
#   ruby sshd_config_audit.rb --json
#   ruby sshd_config_audit.rb --show-effective         # dump the resolved config
#
# Exit codes: 0 = clean, 1 = WARN findings, 2 = at least one CRIT.

require 'optparse'
require 'json'

module SshdConfigAudit
  VERSION = '1.0.0'

  Directive = Struct.new(:keyword, :value, :file, :line, :match_index, keyword_init: true)
  MatchBlock = Struct.new(:index, :criteria, :file, :line, keyword_init: true)
  Finding = Struct.new(:severity, :code, :scope, :detail, :evidence, keyword_init: true)

  # ---------------------------------------------------------------------------
  # Parser
  #
  # Produces a flat, ordered list of Directives. match_index 0 means "global";
  # 1..n identify Match blocks in the order they appear. Include files are
  # spliced in at the point of inclusion, which is exactly what sshd does - and
  # is why an Include at the TOP of the file (as Fedora and Ubuntu 24.04 ship it)
  # can override everything below it.
  # ---------------------------------------------------------------------------
  class Parser
    MAX_INCLUDE_DEPTH = 8

    attr_reader :directives, :matches, :errors, :files_read

    def initialize(root: '/')
      @root = root.to_s.chomp('/')
      @directives = []
      @matches = []
      @errors = []
      @files_read = []
      @match_index = 0
    end

    def parse(path)
      read_file(path, 0)
      self
    end

    private

    def real(path)
      return path if @root.empty?
      return File.join(@root, path) if path.start_with?('/')

      path
    end

    def display(path)
      return path if @root.empty?

      path.sub(/\A#{Regexp.escape(@root)}/, '')
    end

    def read_file(path, depth)
      if depth > MAX_INCLUDE_DEPTH
        @errors << { file: display(path), line: 0, error: 'Include nesting too deep' }
        return
      end
      unless File.readable?(path)
        @errors << { file: display(path), line: 0, error: 'not readable' }
        return
      end

      @files_read << display(path)
      File.readlines(path).each_with_index do |raw, idx|
        line_no = idx + 1
        line = raw.sub(/\A\xEF\xBB\xBF/, '').strip
        next if line.empty? || line.start_with?('#')

        # sshd accepts "Keyword value" and "Keyword=value".
        keyword, value = line.split(/[\s=]+/, 2)
        keyword = keyword.to_s
        value = value.to_s.strip

        case keyword.downcase
        when 'include'
          expand_include(value, path, line_no, depth)
        when 'match'
          @match_index += 1
          @matches << MatchBlock.new(index: @match_index, criteria: value,
                                     file: display(path), line: line_no)
        else
          @directives << Directive.new(keyword: keyword, value: value,
                                       file: display(path), line: line_no,
                                       match_index: @match_index)
        end
      end
    end

    # Include takes glob patterns, and relative patterns resolve against
    # /etc/ssh. Matches are read in lexical order, which is why everyone names
    # drop-ins 10-, 20-, 50-.
    def expand_include(pattern, parent, line_no, depth)
      pattern.split(/\s+/).each do |pat|
        base = pat.start_with?('/') ? real(pat) : File.join(File.dirname(parent), pat)
        found = Dir.glob(base).select { |f| File.file?(f) }.sort
        if found.empty?
          @errors << { file: display(parent), line: line_no,
                       error: "Include #{pat} matched no files" }
        end
        found.each { |f| read_file(f, depth + 1) }
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Resolver - applies OpenSSH's first-wins rule.
  # ---------------------------------------------------------------------------
  class Resolver
    # The handful of keywords that legitimately accumulate instead of being
    # overridden. Everything else is first-wins.
    MULTI = %w[hostkey port listenaddress acceptenv subsystem setenv
               permitlisten permitopen include].freeze

    def initialize(directives)
      @directives = directives
    end

    # Effective config for a given scope. Global scope is match_index 0. A Match
    # block's effective config is the global config with that block's directives
    # taking precedence - because sshd re-reads the file per connection and the
    # Match directives are simply "obtained first" for a matching client.
    def effective(match_index: 0)
      out = {}
      order = match_index.zero? ? [0] : [match_index, 0]
      order.each do |scope|
        @directives.select { |d| d.match_index == scope }.each do |d|
          key = d.keyword.downcase
          if MULTI.include?(key)
            (out[key] ||= []) << d
          elsif !out.key?(key)
            out[key] = d
          end
        end
      end
      out
    end

    def value(effective, keyword, default = nil)
      d = effective[keyword.downcase]
      return default if d.nil?
      return d.map(&:value) if d.is_a?(Array)

      d.value
    end

    def source(effective, keyword)
      d = effective[keyword.downcase]
      return nil if d.nil?

      d = d.first if d.is_a?(Array)
      "#{d.file}:#{d.line}"
    end
  end

  # ---------------------------------------------------------------------------
  # Checks
  # ---------------------------------------------------------------------------
  class Auditor
    # Algorithms OpenSSH still accepts if you ask for them, and should not be.
    WEAK_CIPHERS = %w[3des-cbc aes128-cbc aes192-cbc aes256-cbc arcfour arcfour128
                      arcfour256 blowfish-cbc cast128-cbc rijndael-cbc@lysator.liu.se].freeze
    WEAK_MACS = %w[hmac-md5 hmac-md5-96 hmac-md5-etm@openssh.com
                   hmac-md5-96-etm@openssh.com hmac-sha1 hmac-sha1-96
                   hmac-sha1-etm@openssh.com hmac-sha1-96-etm@openssh.com
                   umac-64@openssh.com umac-64-etm@openssh.com
                   hmac-ripemd160 hmac-ripemd160@openssh.com].freeze
    WEAK_KEX = %w[diffie-hellman-group1-sha1 diffie-hellman-group14-sha1
                  diffie-hellman-group-exchange-sha1 gss-gex-sha1- gss-group1-sha1-
                  gss-group14-sha1-].freeze
    WEAK_HOSTKEY_ALGS = %w[ssh-dss ssh-dss-cert-v01@openssh.com ssh-rsa
                           ssh-rsa-cert-v01@openssh.com].freeze

    # keyword, bad-value test, severity, code, explanation
    BOOL_CHECKS = [
      ['PermitRootLogin', 'prohibit-password',
       ->(v) { %w[yes].include?(v.to_s.downcase) }, 'CRIT', 'ROOT_LOGIN',
       'root can log in directly; an attacker only has to guess one password, and the audit trail loses who it was'],
      ['PermitEmptyPasswords', 'no',
       ->(v) { v.to_s.downcase == 'yes' }, 'CRIT', 'EMPTY_PASSWORDS',
       'accounts with an empty password hash can log in over the network'],
      ['PasswordAuthentication', 'no',
       ->(v) { v.to_s.downcase == 'yes' }, 'WARN', 'PASSWORD_AUTH',
       'password auth is on, so this host is brute-forceable; keys or certificates are the fix'],
      ['HostbasedAuthentication', 'no',
       ->(v) { v.to_s.downcase == 'yes' }, 'CRIT', 'HOSTBASED_AUTH',
       'trust is delegated to the client host, so one compromised box logs into all of them'],
      ['IgnoreRhosts', 'yes',
       ->(v) { v.to_s.downcase == 'no' }, 'CRIT', 'RHOSTS',
       '.rhosts and .shosts files are honoured - 1980s trust model, still exploitable'],
      ['PermitUserEnvironment', 'no',
       ->(v) { !%w[no].include?(v.to_s.downcase) }, 'WARN', 'USER_ENVIRONMENT',
       'a user can set environment variables (LD_PRELOAD among them) via authorized_keys'],
      ['X11Forwarding', 'no',
       ->(v) { v.to_s.downcase == 'yes' }, 'WARN', 'X11_FORWARDING',
       'X11 forwarding is on; on a server with no GUI it is pure attack surface'],
      ['StrictModes', 'yes',
       ->(v) { v.to_s.downcase == 'no' }, 'WARN', 'STRICT_MODES',
       'sshd will accept world-writable home directories and key files'],
      ['GSSAPIAuthentication', 'no',
       ->(v) { v.to_s.downcase == 'yes' }, 'WARN', 'GSSAPI',
       'GSSAPI auth is on; unless this host is Kerberised it is unused code in the pre-auth path'],
      ['UsePAM', 'yes',
       ->(v) { v.to_s.downcase == 'no' }, 'WARN', 'NO_PAM',
       'PAM is off, so account expiry, faillock and pam_pwquality are all bypassed']
    ].freeze

    def initialize(parser, resolver)
      @parser = parser
      @resolver = resolver
    end

    def findings
      out = []
      out.concat(scope_findings(0, 'global'))
      @parser.matches.each do |m|
        label = "Match #{m.criteria} (#{m.file}:#{m.line})"
        out.concat(scope_findings(m.index, label, in_match: true))
      end
      out.concat(match_weakening_findings)
      out.sort_by { |f| [{ 'CRIT' => 0, 'WARN' => 1, 'INFO' => 2 }.fetch(f.severity, 3), f.code] }
    end

    private

    # Inside a Match block, only report on keywords the block itself sets.
    # Everything else is inherited from the global section and was already
    # reported there - repeating it per block turns one finding into five.
    def owned?(eff, keyword, index)
      return true if index.zero?

      d = eff[keyword.downcase]
      d = d.first if d.is_a?(Array)
      !d.nil? && d.match_index == index
    end

    def scope_findings(index, scope, in_match: false)
      eff = @resolver.effective(match_index: index)
      out = []

      BOOL_CHECKS.each do |kw, want, bad, sev, code, why|
        got = @resolver.value(eff, kw)
        # An unset keyword falls back to the compiled-in default, which for the
        # riskier settings is already safe on modern OpenSSH. Report it as INFO
        # so the reader knows the audit is reading a default, not a decision.
        if got.nil?
          next if in_match

          out << Finding.new(severity: 'INFO', code: "#{code}_DEFAULT", scope: scope,
                             detail: "#{kw} is not set; relying on the compiled-in default " \
                                     "(expected #{want})",
                             evidence: nil)
          next
        end
        next unless bad.call(got)
        next unless owned?(eff, kw, index)

        out << Finding.new(severity: sev, code: code, scope: scope,
                           detail: "#{kw} #{got} - #{why}. Set #{kw} #{want}.",
                           evidence: @resolver.source(eff, kw))
      end

      # MaxAuthTries: OpenSSH's default is 6, and it counts every offered key.
      tries = @resolver.value(eff, 'MaxAuthTries')
      if tries && tries.to_i > 4 && owned?(eff, 'MaxAuthTries', index)
        out << Finding.new(severity: 'WARN', code: 'MAX_AUTH_TRIES', scope: scope,
                           detail: "MaxAuthTries #{tries} - allow at most 4 attempts per connection.",
                           evidence: @resolver.source(eff, 'MaxAuthTries'))
      end

      grace = @resolver.value(eff, 'LoginGraceTime')
      if grace && seconds(grace) > 60 && owned?(eff, 'LoginGraceTime', index)
        out << Finding.new(severity: 'WARN', code: 'LOGIN_GRACE', scope: scope,
                           detail: "LoginGraceTime #{grace} - a long grace window lets an attacker " \
                                   'hold many unauthenticated connections open.',
                           evidence: @resolver.source(eff, 'LoginGraceTime'))
      end

      # Idle session timeout: both halves have to be set for it to do anything.
      interval = @resolver.value(eff, 'ClientAliveInterval')
      countmax = @resolver.value(eff, 'ClientAliveCountMax')
      if interval.nil? || interval.to_i.zero?
        out << Finding.new(severity: 'WARN', code: 'NO_IDLE_TIMEOUT', scope: scope,
                           detail: 'ClientAliveInterval is unset or 0 - idle sessions never time out.',
                           evidence: @resolver.source(eff, 'ClientAliveInterval')) unless in_match
      elsif countmax && countmax.to_i > 3 && owned?(eff, 'ClientAliveCountMax', index)
        out << Finding.new(severity: 'INFO', code: 'IDLE_TIMEOUT_LONG', scope: scope,
                           detail: "ClientAliveInterval #{interval} x ClientAliveCountMax #{countmax} " \
                                   "= #{interval.to_i * countmax.to_i}s before an idle session drops.",
                           evidence: @resolver.source(eff, 'ClientAliveCountMax'))
      end

      unless in_match
        if @resolver.value(eff, 'AllowUsers').nil? && @resolver.value(eff, 'AllowGroups').nil? &&
           @resolver.value(eff, 'DenyUsers').nil? && @resolver.value(eff, 'DenyGroups').nil?
          out << Finding.new(severity: 'WARN', code: 'NO_ACCESS_LIST', scope: scope,
                             detail: 'No AllowUsers/AllowGroups/DenyUsers/DenyGroups - every account ' \
                                     'with a shell and a key can log in, including service accounts.',
                             evidence: nil)
        end

        level = @resolver.value(eff, 'LogLevel', 'INFO')
        unless %w[VERBOSE DEBUG DEBUG1 DEBUG2 DEBUG3].include?(level.to_s.upcase)
          out << Finding.new(severity: 'WARN', code: 'LOG_LEVEL', scope: scope,
                             detail: "LogLevel #{level} - only VERBOSE logs the key fingerprint used " \
                                     'for each login, which is what you need after an incident.',
                             evidence: @resolver.source(eff, 'LogLevel'))
        end
      end

      out.concat(algorithm_findings(eff, scope, index))
      out
    end

    # Cipher/MAC/KexAlgorithms lists support +, - and ^ prefixes that modify the
    # default set instead of replacing it. A leading "+" is the dangerous one:
    # it ADDS to the defaults, so "Ciphers +aes128-cbc" quietly re-enables CBC.
    def algorithm_findings(eff, scope, index)
      out = []
      [['Ciphers', WEAK_CIPHERS, 'CIPHERS'],
       ['MACs', WEAK_MACS, 'MACS'],
       ['KexAlgorithms', WEAK_KEX, 'KEX'],
       ['HostKeyAlgorithms', WEAK_HOSTKEY_ALGS, 'HOSTKEY_ALGS'],
       ['PubkeyAcceptedAlgorithms', WEAK_HOSTKEY_ALGS, 'PUBKEY_ALGS']].each do |kw, weak, code|
        raw = @resolver.value(eff, kw)
        next if raw.nil?
        next unless owned?(eff, kw, index)

        prefix = raw[0]
        list = raw.sub(/\A[+\-^]/, '').split(',').map(&:strip)
        # A "-" list REMOVES algorithms, so anything named there is being
        # disabled - that is the good case, not a finding.
        next if prefix == '-'

        bad = list & weak
        next if bad.empty?

        out << Finding.new(
          severity: 'CRIT', code: "WEAK_#{code}", scope: scope,
          detail: "#{kw}#{prefix == '+' ? ' (+ appends to the defaults)' : ''} enables " \
                  "#{bad.join(', ')} - #{weak_why(code)}",
          evidence: @resolver.source(eff, kw)
        )
      end
      out
    end

    def weak_why(code)
      case code
      when 'CIPHERS' then 'CBC-mode and arcfour ciphers are broken or deprecated.'
      when 'MACS' then 'MD5 and SHA-1 MACs, and 64-bit UMAC, are no longer acceptable.'
      when 'KEX' then 'SHA-1 key exchange and 1024-bit groups are within reach of a well-funded attacker.'
      else 'SHA-1 signature algorithms are deprecated; OpenSSH 8.8+ disables ssh-rsa by default.'
      end
    end

    # The finding this whole script exists for: a Match block that hands back
    # something the global section denied.
    def match_weakening_findings
      global = @resolver.effective(match_index: 0)
      out = []
      @parser.matches.each do |m|
        eff = @resolver.effective(match_index: m.index)
        label = "Match #{m.criteria} (#{m.file}:#{m.line})"
        {
          'PermitRootLogin' => %w[yes],
          'PasswordAuthentication' => %w[yes],
          'PermitEmptyPasswords' => %w[yes],
          'PubkeyAuthentication' => %w[no]
        }.each do |kw, bad_values|
          here = @resolver.value(eff, kw)
          there = @resolver.value(global, kw)
          next if here.nil?
          next unless bad_values.include?(here.to_s.downcase)
          next if there && bad_values.include?(there.to_s.downcase) # not a weakening; already bad globally

          out << Finding.new(
            severity: 'CRIT', code: 'MATCH_WEAKENS_GLOBAL', scope: label,
            detail: "#{kw} is #{here} inside this Match block but #{there || '(default)'} globally. " \
                    'A grep-based audit reads the global line and calls this host hardened.',
            evidence: @resolver.source(eff, kw)
          )
        end
      end
      out
    end

    def seconds(v)
      s = v.to_s.strip
      return s.to_i * 60 if s.end_with?('m')
      return s.to_i * 3600 if s.end_with?('h')

      s.to_i
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

    def report(parser:, resolver:, findings:, config:, show_effective:)
      @io.puts "sshd config audit  -  #{config}"
      @io.puts "files read: #{parser.files_read.join(', ')}"
      @io.puts "match blocks: #{parser.matches.empty? ? 'none' : parser.matches.map(&:criteria).join(' | ')}"
      @io.puts '=' * 78

      if show_effective
        @io.puts
        @io.puts 'effective global configuration (first value wins)'
        @io.puts '-' * 78
        resolver.effective(match_index: 0).sort.each do |k, v|
          if v.is_a?(Array)
            v.each { |d| @io.puts format('  %-28s %-32s %s:%d', d.keyword, d.value, d.file, d.line) }
          else
            @io.puts format('  %-28s %-32s %s:%d', v.keyword, v.value, v.file, v.line)
          end
        end
      end

      findings.group_by(&:scope).each do |scope, group|
        @io.puts
        @io.puts scope
        @io.puts '-' * 78
        group.each do |f|
          @io.puts "  #{paint(f.severity)}  #{f.code}"
          @io.puts "        #{f.detail}"
          @io.puts "        at #{f.evidence}" if f.evidence
        end
      end

      unless parser.errors.empty?
        @io.puts
        @io.puts 'parse problems'
        @io.puts '-' * 78
        parser.errors.each { |e| @io.puts "  #{e[:file]}:#{e[:line]}  #{e[:error]}" }
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
  end

  class JsonReporter
    def initialize(io)
      @io = io
    end

    def report(parser:, resolver:, findings:, config:, show_effective:)
      payload = {
        config: config,
        files_read: parser.files_read,
        match_blocks: parser.matches.map { |m| { criteria: m.criteria, file: m.file, line: m.line } },
        findings: findings.map do |f|
          { severity: f.severity, code: f.code, scope: f.scope, detail: f.detail, evidence: f.evidence }
        end,
        parse_errors: parser.errors
      }
      if show_effective
        payload[:effective_global] = resolver.effective(match_index: 0).transform_values do |v|
          v.is_a?(Array) ? v.map(&:value) : v.value
        end
      end
      @io.puts JSON.pretty_generate(payload)
    end
  end

  # ---------------------------------------------------------------------------
  # CLI
  # ---------------------------------------------------------------------------
  class CLI
    DEFAULT = '/etc/ssh/sshd_config'

    def self.run(argv, io = $stdout)
      opts = { root: '', config: nil, json: false, color: io.tty?, effective: false }
      OptionParser.new do |o|
        o.banner = 'Usage: sshd_config_audit.rb [options]'
        o.on('--config PATH', "sshd_config to audit (default #{DEFAULT})") { |v| opts[:config] = v }
        o.on('--root DIR', 'Treat DIR as / (for fixtures)') { |v| opts[:root] = v }
        o.on('--show-effective', 'Also dump the resolved global config') { opts[:effective] = true }
        o.on('--json', 'Emit JSON') { opts[:json] = true }
        o.on('--[no-]color', 'Force colour on/off') { |v| opts[:color] = v }
        o.on('-v', '--version') { io.puts VERSION; exit 0 }
        o.on('-h', '--help') { io.puts o; exit 0 }
      end.parse!(argv)

      config = opts[:config] || File.join(opts[:root].to_s.chomp('/'), DEFAULT)
      unless File.readable?(config)
        warn "sshd_config_audit: cannot read #{config}"
        return 2
      end

      parser = Parser.new(root: opts[:root]).parse(config)
      resolver = Resolver.new(parser.directives)
      findings = Auditor.new(parser, resolver).findings

      reporter = opts[:json] ? JsonReporter.new(io) : TextReporter.new(io, color: opts[:color])
      reporter.report(parser: parser, resolver: resolver, findings: findings,
                      config: config, show_effective: opts[:effective])

      return 2 if findings.any? { |f| f.severity == 'CRIT' }
      return 1 if findings.any? { |f| f.severity == 'WARN' }

      0
    end
  end
end

exit SshdConfigAudit::CLI.run(ARGV) if $PROGRAM_NAME == __FILE__
