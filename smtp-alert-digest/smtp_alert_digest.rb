#!/usr/bin/env ruby
# frozen_string_literal: true
#
# smtp_alert_digest.rb -- consolidate scattered cron/monitoring alerts into
# one deduplicated digest email, sent with nothing but Ruby's stdlib
# (net/smtp, openssl, json). No gems required.
#
# THE PROBLEM
# -----------
# A typical box ends up with a dozen independent cron jobs and audit scripts
# (disk checks, cert-expiry checks, backup verifiers, log scanners...), and
# each one has its own "if something's wrong, mail root" logic bolted on.
# The result: alert fatigue. Five different scripts email five times about
# the same underlying disk-full condition, every hour, forever, until
# everyone filters the mailbox and stops reading it.
#
# THE FIX
# -------
# Give every script ONE place to drop a finding instead of sending its own
# mail:
#
#   SmtpAlertDigest.record(severity: :warning, source: "disk-check",
#                           message: "/var at 92% (raid1, /dev/md1)")
#
# That appends one JSON line to a local spool file -- no network I/O, so a
# monitoring script that would otherwise fail if the mail server is down
# keeps working. Separately, on a schedule (cron: "0 * * * *" for hourly),
# you run this same file as a script:
#
#   ruby smtp_alert_digest.rb digest --to ops@example.com --from alerts@example.com \
#        --smtp-host smtp.example.com --smtp-port 587 --starttls
#
# which reads the spool, groups findings by severity, drops anything that
# already fired within the dedup window (so a flapping check doesn't spam
# every hour), sends ONE email summarizing everything new, and rotates the
# spool so the next run starts clean.
#
# Run `ruby smtp_alert_digest.rb selftest` to see the entire pipeline
# exercised end to end against a real (fake) SMTP server that this script
# spins up on 127.0.0.1, including STARTTLS and AUTH LOGIN.

require 'json'
require 'time'
require 'fileutils'
require 'digest'
require 'net/smtp'
require 'socket'
require 'optparse'
require 'openssl'

module SmtpAlertDigest
  # ---------------------------------------------------------------------
  # Constants & defaults
  # ---------------------------------------------------------------------

  # Aliases so callers don't have to remember an exact spelling.
  SEVERITY_ALIASES = {
    'critical' => 'critical', 'crit' => 'critical', 'fatal' => 'critical', 'error' => 'critical',
    'warning'  => 'warning',  'warn' => 'warning',
    'info'     => 'info',     'notice' => 'info'
  }.freeze

  # Display order, most severe first.
  SEVERITY_ORDER = %w[critical warning info].freeze

  DEFAULT_SPOOL_DIR   = ENV['SMTP_ALERT_DIGEST_SPOOL'] || File.join(Dir.home, '.local', 'spool', 'smtp-alert-digest')
  FINDINGS_FILE       = 'findings.jsonl'
  STATE_FILE          = 'state.json'
  DEFAULT_DEDUP_WINDOW = 6 * 60 * 60 # 6 hours, in seconds

  class ConfigError < StandardError; end

  # ---------------------------------------------------------------------
  # Finding -- one structured alert from a monitoring/audit script
  # ---------------------------------------------------------------------
  Finding = Struct.new(:time, :severity, :source, :message, keyword_init: true) do
    def self.from_json_line(line)
      h = JSON.parse(line)
      new(time: Time.parse(h['time']), severity: h['severity'], source: h['source'], message: h['message'])
    end

    def to_h_for_json
      { 'time' => time.utc.iso8601, 'severity' => severity, 'source' => source, 'message' => message }
    end

    # Stable identity for a finding used for dedup: same severity + source +
    # message text counts as "the same recurring problem," regardless of
    # when it was observed.
    def fingerprint
      ::Digest::SHA256.hexdigest("#{severity}|#{source}|#{message}")[0, 16]
    end
  end

  module_function

  # ---------------------------------------------------------------------
  # Public recording API -- this is what OTHER scripts call.
  # ---------------------------------------------------------------------
  #
  #   require_relative 'smtp_alert_digest'
  #   SmtpAlertDigest.record(severity: :critical, source: 'backup-verify',
  #                           message: 'nightly backup archive is 0 bytes')
  #
  # Appends one JSON line to the spool (creating the directory/file if
  # needed) and returns the Finding that was written. Safe to call
  # concurrently from multiple cron jobs: writes are advisory-locked and
  # each write is a single atomic line append.
  def record(severity:, source:, message:, spool_dir: DEFAULT_SPOOL_DIR, time: Time.now)
    key = severity.to_s.downcase
    normalized = SEVERITY_ALIASES[key]
    raise ArgumentError, "unknown severity #{severity.inspect} (expected one of #{SEVERITY_ALIASES.keys.join(', ')})" unless normalized

    finding = Finding.new(time: time, severity: normalized, source: source.to_s, message: message.to_s.strip)
    FileUtils.mkdir_p(spool_dir)
    path = File.join(spool_dir, FINDINGS_FILE)
    File.open(path, File::WRONLY | File::CREAT | File::APPEND) do |f|
      f.flock(File::LOCK_EX)
      f.puts(JSON.generate(finding.to_h_for_json))
      f.flush
      f.flock(File::LOCK_UN)
    end
    finding
  end

  # Read every finding currently sitting in the spool. Corrupt/partial lines
  # (e.g. a write that raced a crash) are skipped rather than aborting the
  # whole digest run.
  def read_spool(spool_dir: DEFAULT_SPOOL_DIR)
    path = File.join(spool_dir, FINDINGS_FILE)
    return [] unless File.exist?(path)

    findings = []
    File.foreach(path) do |line|
      line = line.strip
      next if line.empty?

      begin
        findings << Finding.from_json_line(line)
      rescue JSON::ParserError, KeyError, ArgumentError => e
        warn "smtp_alert_digest: skipping malformed spool line (#{e.class}): #{line[0, 80]}"
      end
    end
    findings
  end

  # ---------------------------------------------------------------------
  # State -- tracks which fingerprints have alerted recently, for dedup.
  # ---------------------------------------------------------------------
  def load_state(state_path)
    return { 'last_run_at' => nil, 'recent' => {} } unless File.exist?(state_path)

    JSON.parse(File.read(state_path))
  rescue JSON::ParserError
    { 'last_run_at' => nil, 'recent' => {} }
  end

  def save_state(state_path, state)
    FileUtils.mkdir_p(File.dirname(state_path))
    tmp = "#{state_path}.tmp.#{Process.pid}"
    File.write(tmp, JSON.pretty_generate(state))
    File.rename(tmp, state_path)
  end

  # Drop fingerprints whose last-alert time has aged out of the window, so
  # the state file doesn't grow forever and old problems can re-alert once
  # they're genuinely stale.
  def prune_recent(recent, window_seconds, now)
    recent.select do |_fp, iso|
      (now - Time.parse(iso)) < window_seconds
    end
  end

  # ---------------------------------------------------------------------
  # Digest assembly
  # ---------------------------------------------------------------------
  #
  # Splits findings into:
  #   included  -- new (or expired-out-of-window) findings that belong in
  #                this digest email
  #   suppressed -- findings whose fingerprint already alerted within the
  #                dedup window; counted, but not repeated in the email body
  DigestResult = Struct.new(:included, :suppressed_count, :new_recent, keyword_init: true)

  def build_digest(findings, recent, window_seconds, now)
    included = []
    suppressed = 0
    new_recent = recent.dup

    findings.each do |f|
      fp = f.fingerprint
      last_seen = new_recent[fp]
      if last_seen && (now - Time.parse(last_seen)) < window_seconds
        suppressed += 1
      else
        included << f
        new_recent[fp] = now.utc.iso8601
      end
    end

    DigestResult.new(included: included, suppressed_count: suppressed, new_recent: new_recent)
  end

  def group_by_severity(findings)
    SEVERITY_ORDER.each_with_object({}) do |sev, h|
      matches = findings.select { |f| f.severity == sev }.sort_by(&:time)
      h[sev] = matches unless matches.empty?
    end
  end

  def render_email_body(included, suppressed_count, window_seconds, hostname)
    grouped = group_by_severity(included)
    lines = []
    lines << "Alert digest for #{hostname}"
    lines << "Generated: #{Time.now.utc.iso8601}"
    lines << ''
    counts = SEVERITY_ORDER.map { |s| "#{(grouped[s] || []).size} #{s}" }.join(', ')
    lines << "#{included.size} new finding(s) (#{counts})"
    lines << "#{suppressed_count} repeat finding(s) suppressed (already alerted within the last #{window_seconds / 60} min)" if suppressed_count.positive?
    lines << ''

    SEVERITY_ORDER.each do |sev|
      next unless grouped[sev]

      lines << "== #{sev.upcase} " + ('=' * (60 - sev.length))
      grouped[sev].each do |f|
        lines << "  [#{f.time.utc.strftime('%Y-%m-%d %H:%M:%S UTC')}] #{f.source}: #{f.message}"
      end
      lines << ''
    end

    lines << '--'
    lines << 'Sent by smtp_alert_digest.rb -- one email instead of one per check.'
    lines.join("\n")
  end

  def render_subject(included, hostname)
    grouped = group_by_severity(included)
    worst = SEVERITY_ORDER.find { |s| grouped[s] }
    tag = worst ? worst.upcase : 'INFO'
    "[ALERT DIGEST][#{tag}] #{included.size} finding(s) on #{hostname}"
  end

  def build_message(from:, to:, subject:, body:)
    to_list = Array(to)
    <<~MSG
      From: #{from}
      To: #{to_list.join(', ')}
      Subject: #{subject}
      Date: #{Time.now.rfc2822}
      Message-Id: <#{::Digest::SHA256.hexdigest("#{Time.now.to_f}#{subject}")[0, 16]}@smtp-alert-digest>
      MIME-Version: 1.0
      Content-Type: text/plain; charset=UTF-8

      #{body}
    MSG
  end

  # ---------------------------------------------------------------------
  # Sending -- plain net/smtp, with STARTTLS + AUTH LOGIN/PLAIN support.
  # ---------------------------------------------------------------------
  def send_digest(message:, from:, to:, host:, port:, starttls:, tls_verify:, user: nil, password: nil, auth_type: :login, helo: Socket.gethostname)
    smtp = Net::SMTP.new(host, port)
    if starttls
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.verify_mode = tls_verify ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
      smtp.enable_starttls(ctx)
    end

    if user && password
      smtp.start(helo, user, password, auth_type) do |s|
        s.send_message(message, from, Array(to))
      end
    else
      smtp.start(helo) do |s|
        s.send_message(message, from, Array(to))
      end
    end
  end

  # ---------------------------------------------------------------------
  # Spool rotation -- archive what was just digested, start clean.
  # ---------------------------------------------------------------------
  def rotate_spool(spool_dir)
    path = File.join(spool_dir, FINDINGS_FILE)
    return unless File.exist?(path)

    archive_dir = File.join(spool_dir, 'archive')
    FileUtils.mkdir_p(archive_dir)
    stamp = Time.now.utc.strftime('%Y%m%dT%H%M%SZ')
    File.open(path, File::RDWR | File::CREAT) do |f|
      f.flock(File::LOCK_EX)
      # Move current contents to an archive file, then truncate in place so
      # a concurrent writer's already-open file handle keeps working and no
      # findings recorded mid-rotation are lost.
      contents = f.read
      unless contents.strip.empty?
        File.write(File.join(archive_dir, "findings-#{stamp}.jsonl"), contents)
      end
      f.truncate(0)
      f.flock(File::LOCK_UN)
    end
    prune_archives(archive_dir)
  end

  def prune_archives(archive_dir, keep: 20)
    files = Dir.glob(File.join(archive_dir, 'findings-*.jsonl')).sort
    excess = files.size - keep
    files.first(excess).each { |f| File.delete(f) } if excess.positive?
  end

  # ---------------------------------------------------------------------
  # The full digest run, used by both the CLI and selftest.
  # ---------------------------------------------------------------------
  Options = Struct.new(:spool_dir, :state_file, :dedup_window, :from, :to, :host, :port,
                        :starttls, :tls_verify, :user, :password, :auth_type, :force, :dry_run,
                        keyword_init: true)

  def run_digest(opts)
    now = Time.now
    state_path = opts.state_file || File.join(opts.spool_dir, STATE_FILE)
    state = load_state(state_path)
    recent = prune_recent(state['recent'] || {}, opts.dedup_window, now)

    findings = read_spool(spool_dir: opts.spool_dir)
    result = build_digest(findings, recent, opts.dedup_window, now)

    if result.included.empty? && !opts.force
      state['recent'] = result.new_recent
      state['last_run_at'] = now.utc.iso8601
      save_state(state_path, state) unless opts.dry_run
      rotate_spool(opts.spool_dir) unless opts.dry_run
      return { sent: false, reason: findings.empty? ? 'spool empty' : 'all findings suppressed as repeats', included: 0, suppressed: result.suppressed_count }
    end

    hostname = Socket.gethostname
    body = render_email_body(result.included, result.suppressed_count, opts.dedup_window, hostname)
    subject = render_subject(result.included, hostname)
    message = build_message(from: opts.from, to: opts.to, subject: subject, body: body)

    if opts.dry_run
      puts message
      return { sent: false, reason: 'dry run', included: result.included.size, suppressed: result.suppressed_count }
    end

    send_digest(message: message, from: opts.from, to: opts.to, host: opts.host, port: opts.port,
                starttls: opts.starttls, tls_verify: opts.tls_verify, user: opts.user,
                password: opts.password, auth_type: opts.auth_type)

    state['recent'] = result.new_recent
    state['last_run_at'] = now.utc.iso8601
    save_state(state_path, state)
    rotate_spool(opts.spool_dir)

    { sent: true, included: result.included.size, suppressed: result.suppressed_count, subject: subject }
  end
end

# ===========================================================================
# Self-test harness: a minimal real SMTP server (TCPServer + hand-rolled
# EHLO/STARTTLS/AUTH LOGIN/MAIL/RCPT/DATA state machine) so `selftest` proves
# the whole record -> digest -> send pipeline against genuine sockets, not a
# mock object. It speaks just enough RFC 5321 (+ RFC 3207 STARTTLS, RFC 4954
# AUTH LOGIN) for Net::SMTP to talk to it successfully.
# ===========================================================================
module SmtpAlertDigest
  module SelfTest
    class FakeSmtpServer
      attr_reader :port, :transcript, :received_messages

      def initialize(require_auth: true, expected_user: 'alerts', expected_pass: 's3cret')
        @server = TCPServer.new('127.0.0.1', 0)
        @port = @server.addr[1]
        @transcript = []
        @received_messages = []
        @mutex = Mutex.new
        @require_auth = require_auth
        @expected_user = expected_user
        @expected_pass = expected_pass
        @cert, @key = self.class.generate_self_signed_cert
      end

      def self.generate_self_signed_cert
        key = OpenSSL::PKey::RSA.new(2048)
        cert = OpenSSL::X509::Certificate.new
        cert.version = 2
        cert.serial = 1
        name = OpenSSL::X509::Name.parse('/CN=localhost')
        cert.subject = name
        cert.issuer = name
        cert.public_key = key.public_key
        cert.not_before = Time.now
        cert.not_after = Time.now + 3600
        cert.sign(key, OpenSSL::Digest.new('SHA256'))
        [cert, key]
      end

      def log(direction, text)
        @mutex.synchronize { @transcript << "#{direction} #{text}" }
      end

      # Runs the whole accept-one-connection lifecycle in a background
      # thread and returns immediately so the caller can act as the client.
      def start
        @thread = Thread.new { serve_one_connection }
        self
      end

      def join
        @thread&.join
      end

      def stop
        @server.close unless @server.closed?
      end

      private

      def serve_one_connection
        sock = @server.accept
        io = sock
        io.puts "220 fake-smtp.local ESMTP FakeSmtpServer ready\r"
        log('S:', '220 fake-smtp.local ESMTP FakeSmtpServer ready')

        tls_active = false
        authed = !@require_auth
        from = nil
        rcpts = []

        loop do
          line = io.gets
          break if line.nil?

          line = line.chomp("\r\n").chomp("\n")
          log('C:', line)
          cmd = line.split(' ', 2).first.to_s.upcase

          case cmd
          when 'EHLO', 'HELO'
            exts = ['250-fake-smtp.local greets you']
            exts << '250-STARTTLS' unless tls_active
            exts << '250-AUTH LOGIN PLAIN'
            exts[-1] = exts[-1].sub('250-', '250 ')
            exts.each { |l| io.puts "#{l}\r" }
            log('S:', exts.join(' | '))
          when 'STARTTLS'
            io.puts "220 Ready to start TLS\r"
            log('S:', '220 Ready to start TLS')
            ssl_ctx = OpenSSL::SSL::SSLContext.new
            ssl_ctx.cert = @cert
            ssl_ctx.key = @key
            ssl_sock = OpenSSL::SSL::SSLSocket.new(sock, ssl_ctx)
            ssl_sock.sync_close = true
            ssl_sock.accept
            io = ssl_sock
            tls_active = true
            log('S:', '-- TLS handshake complete, subsequent lines are inside the encrypted channel --')
          when 'AUTH'
            _, mechanism_and_rest = line.split(' ', 2)
            mechanism = mechanism_and_rest.to_s.split(' ').first
            if mechanism&.upcase == 'LOGIN'
              io.puts "334 #{['Username:'].pack('m0')}\r"
              user_b64 = io.gets.to_s.strip
              log('C:', '<base64 username>')
              io.puts "334 #{['Password:'].pack('m0')}\r"
              pass_b64 = io.gets.to_s.strip
              log('C:', '<base64 password>')
              user = user_b64.unpack1('m0')
              pass = pass_b64.unpack1('m0')
              if user == @expected_user && pass == @expected_pass
                authed = true
                io.puts "235 2.7.0 Authentication successful\r"
                log('S:', '235 2.7.0 Authentication successful')
              else
                io.puts "535 5.7.8 Authentication failed\r"
                log('S:', '535 5.7.8 Authentication failed')
              end
            else
              io.puts "504 Unrecognized authentication type\r"
            end
          when 'MAIL'
            from = line
            io.puts "250 OK\r"
            log('S:', '250 OK')
          when 'RCPT'
            rcpts << line
            io.puts "250 OK\r"
            log('S:', '250 OK')
          when 'DATA'
            io.puts "354 Start mail input; end with <CRLF>.<CRLF>\r"
            log('S:', '354 Start mail input; end with <CRLF>.<CRLF>')
            data_lines = []
            loop do
              dline = io.gets
              break if dline.nil?

              dline = dline.chomp("\r\n").chomp("\n")
              break if dline == '.'

              data_lines << dline.sub(/\A\.\./, '.') # undo dot-stuffing
            end
            @mutex.synchronize do
              @received_messages << { from: from, rcpts: rcpts.dup, body: data_lines.join("\n") }
            end
            log('C:', "<#{data_lines.size} lines of message body>")
            io.puts "250 OK: queued as 1\r"
            log('S:', '250 OK: queued as 1')
          when 'QUIT'
            io.puts "221 Bye\r"
            log('S:', '221 Bye')
            break
          else
            io.puts "500 Unrecognized command\r"
            log('S:', '500 Unrecognized command')
          end
        end
      ensure
        io.close if io && !io.closed? rescue nil
        sock.close if sock && !sock.closed? rescue nil
      end
    end

    module_function

    def run
      require 'tmpdir'
      puts '== smtp_alert_digest.rb selftest =='
      puts "ruby: #{RUBY_VERSION}, host: #{Socket.gethostname}, time: #{Time.now.utc.iso8601}"
      puts

      Dir.mktmpdir('smtp-alert-digest-selftest-') do |spool_dir|
        puts "-- spool dir: #{spool_dir}"
        puts

        # ---- Phase 1: other scripts recording findings ------------------
        puts '-- phase 1: simulating several monitoring scripts calling SmtpAlertDigest.record --'
        events = [
          [:critical, 'disk-check.rb',    '/var is at 96% capacity (raid1, /dev/md1)'],
          [:warning,  'cert-expiry.rb',   'TLS cert for mail.example.com expires in 9 days'],
          [:critical, 'disk-check.rb',    '/var is at 96% capacity (raid1, /dev/md1)'], # duplicate -> should dedup
          [:info,     'backup-verify.rb', 'nightly backup completed, 4.2GB, 812 files'],
          [:warning,  'ssh-audit.rb',     '3 failed root logins from 203.0.113.9 in the last hour']
        ]
        events.each do |sev, source, msg|
          f = SmtpAlertDigest.record(severity: sev, source: source, message: msg, spool_dir: spool_dir)
          puts "  recorded: [#{f.severity}] #{f.source}: #{f.message}"
        end
        spool_path = File.join(spool_dir, SmtpAlertDigest::FINDINGS_FILE)
        puts
        puts "-- spool file contents (#{spool_path}) --"
        puts File.read(spool_path)

        # ---- Phase 2: start the fake SMTP server -------------------------
        puts '-- phase 2: starting fake SMTP server (STARTTLS + AUTH LOGIN) on 127.0.0.1 --'
        server = FakeSmtpServer.new(require_auth: true, expected_user: 'alerts', expected_pass: 's3cret').start
        puts "  listening on 127.0.0.1:#{server.port}"
        puts

        # ---- Phase 3: run the real digest sender against it --------------
        puts '-- phase 3: running SmtpAlertDigest.run_digest (real Net::SMTP client, STARTTLS+AUTH) --'
        opts = SmtpAlertDigest::Options.new(
          spool_dir: spool_dir,
          state_file: nil,
          dedup_window: SmtpAlertDigest::DEFAULT_DEDUP_WINDOW,
          from: 'alerts@example.com',
          to: ['ops@example.com'],
          host: '127.0.0.1',
          port: server.port,
          starttls: true,
          tls_verify: false, # self-signed test cert
          user: 'alerts',
          password: 's3cret',
          auth_type: :login,
          force: false,
          dry_run: false
        )
        result = SmtpAlertDigest.run_digest(opts)
        server.join
        puts "  run_digest result: #{result.inspect}"
        puts

        puts '-- captured SMTP transcript --'
        server.transcript.each { |line| puts "  #{line}" }
        puts

        puts '-- message the fake server actually received --'
        server.received_messages.each do |m|
          puts "  MAIL: #{m[:from]}"
          m[:rcpts].each { |r| puts "  RCPT: #{r}" }
          puts '  ---- body ----'
          m[:body].each_line { |l| puts "  #{l}" }
          puts '  --------------'
        end

        # ---- Phase 4: prove dedup works on a second run -------------------
        puts
        puts '-- phase 4: recording the SAME critical finding again, then re-running the digest --'
        SmtpAlertDigest.record(severity: :critical, source: 'disk-check.rb',
                                message: '/var is at 96% capacity (raid1, /dev/md1)', spool_dir: spool_dir)
        SmtpAlertDigest.record(severity: :critical, source: 'oom-watch.rb',
                                message: 'OOM killer invoked for pid 8123 (java)', spool_dir: spool_dir)

        server2 = FakeSmtpServer.new(require_auth: true).start
        opts2 = opts.dup
        opts2.port = server2.port
        result2 = SmtpAlertDigest.run_digest(opts2)
        server2.join
        puts "  run_digest result (2nd run): #{result2.inspect}"
        puts '  captured transcript (2nd run):'
        server2.transcript.each { |line| puts "    #{line}" }
        puts
        puts '  message received (2nd run):'
        server2.received_messages.each do |m|
          puts '  ---- body ----'
          m[:body].each_line { |l| puts "  #{l}" }
          puts '  --------------'
        end

        # ---- Phase 5: prove a fully-suppressed run sends nothing -----------
        puts
        puts '-- phase 5: recording only repeats, expecting NO email to be sent --'
        SmtpAlertDigest.record(severity: :critical, source: 'disk-check.rb',
                                message: '/var is at 96% capacity (raid1, /dev/md1)', spool_dir: spool_dir)
        opts3 = opts.dup
        opts3.port = 1 # unreachable on purpose -- if this port is ever dialed, the test should fail loudly
        result3 = SmtpAlertDigest.run_digest(opts3)
        puts "  run_digest result (3rd run, all-repeats): #{result3.inspect}"
        raise 'expected 3rd run to skip sending' if result3[:sent]

        puts
        puts '== selftest PASSED =='
      end
    end
  end
end

# ===========================================================================
# CLI
# ===========================================================================
if $PROGRAM_NAME == __FILE__
  def usage
    <<~USAGE
      Usage:
        #{File.basename($PROGRAM_NAME)} record --severity SEV --source NAME --message TEXT [--spool-dir DIR]
        #{File.basename($PROGRAM_NAME)} digest  --to EMAIL [--to EMAIL ...] --from EMAIL
                             [--smtp-host HOST] [--smtp-port PORT] [--starttls] [--no-tls-verify]
                             [--smtp-user USER] [--smtp-pass PASS] [--auth-type login|plain|cram_md5]
                             [--spool-dir DIR] [--state-file FILE] [--dedup-window SECONDS]
                             [--force] [--dry-run]
        #{File.basename($PROGRAM_NAME)} selftest

      SMTP credentials can also come from SMTP_ALERT_DIGEST_USER / SMTP_ALERT_DIGEST_PASS
      environment variables instead of the command line, to keep them out of `ps`.
    USAGE
  end

  command = ARGV.shift

  case command
  when 'record'
    severity = source = message = nil
    spool_dir = SmtpAlertDigest::DEFAULT_SPOOL_DIR
    OptionParser.new do |o|
      o.on('--severity SEV') { |v| severity = v }
      o.on('--source NAME') { |v| source = v }
      o.on('--message TEXT') { |v| message = v }
      o.on('--spool-dir DIR') { |v| spool_dir = v }
    end.parse!(ARGV)

    if severity.nil? || source.nil? || message.nil?
      warn usage
      exit 1
    end

    begin
      f = SmtpAlertDigest.record(severity: severity, source: source, message: message, spool_dir: spool_dir)
      puts "recorded [#{f.severity}] #{f.source}: #{f.message}"
    rescue ArgumentError => e
      warn "error: #{e.message}"
      exit 1
    end

  when 'digest'
    to = []
    from = nil
    host = ENV['SMTP_ALERT_DIGEST_HOST'] || 'localhost'
    port = (ENV['SMTP_ALERT_DIGEST_PORT'] || 25).to_i
    starttls = false
    tls_verify = true
    user = ENV['SMTP_ALERT_DIGEST_USER']
    password = ENV['SMTP_ALERT_DIGEST_PASS']
    auth_type = :login
    spool_dir = SmtpAlertDigest::DEFAULT_SPOOL_DIR
    state_file = nil
    dedup_window = SmtpAlertDigest::DEFAULT_DEDUP_WINDOW
    force = false
    dry_run = false

    OptionParser.new do |o|
      o.on('--to EMAIL') { |v| to << v }
      o.on('--from EMAIL') { |v| from = v }
      o.on('--smtp-host HOST') { |v| host = v }
      o.on('--smtp-port PORT', Integer) { |v| port = v }
      o.on('--starttls') { starttls = true }
      o.on('--no-tls-verify') { tls_verify = false }
      o.on('--smtp-user USER') { |v| user = v }
      o.on('--smtp-pass PASS') { |v| password = v }
      o.on('--auth-type TYPE') { |v| auth_type = v.to_sym }
      o.on('--spool-dir DIR') { |v| spool_dir = v }
      o.on('--state-file FILE') { |v| state_file = v }
      o.on('--dedup-window SECONDS', Integer) { |v| dedup_window = v }
      o.on('--force') { force = true }
      o.on('--dry-run') { dry_run = true }
    end.parse!(ARGV)

    if to.empty? || from.nil?
      warn usage
      exit 1
    end

    opts = SmtpAlertDigest::Options.new(
      spool_dir: spool_dir, state_file: state_file, dedup_window: dedup_window,
      from: from, to: to, host: host, port: port, starttls: starttls, tls_verify: tls_verify,
      user: user, password: password, auth_type: auth_type, force: force, dry_run: dry_run
    )

    begin
      result = SmtpAlertDigest.run_digest(opts)
      if result[:sent]
        puts "digest sent: #{result[:included]} new finding(s), #{result[:suppressed]} suppressed as repeats -- #{result[:subject]}"
      else
        puts "no digest sent (#{result[:reason]}): #{result[:included]} new, #{result[:suppressed]} suppressed"
      end
    rescue Net::SMTPError, SystemCallError => e
      warn "failed to send digest: #{e.class}: #{e.message}"
      exit 2
    end

  when 'selftest'
    SmtpAlertDigest::SelfTest.run

  else
    warn usage
    exit 1
  end
end
