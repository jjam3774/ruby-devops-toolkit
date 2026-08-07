#!/usr/bin/env ruby
# frozen_string_literal: true
#
# alert_notifier.rb -- send de-duplicated, rate-limited alerts to Slack
# (or any JSON webhook) from cron jobs and monitoring scripts, with
# automatic retry/backoff on transient HTTP failures.
#
# Problem it solves:
#   Most of the little Ruby check scripts sysadmins write (disk space,
#   service health, cert expiry, log error spikes...) know perfectly well
#   *when* something is wrong. What they're usually missing is a reliable,
#   reusable way to tell a human -- one that doesn't spam Slack every five
#   minutes for the same still-broken thing, and that doesn't silently
#   drop the message the one time the webhook endpoint has a blip.
#
# Usage as a CLI:
#   ruby alert_notifier.rb --webhook "$SLACK_WEBHOOK_URL" \
#     --key disk-root --severity crit --title "Disk /: 96% full" \
#     --text "Only 1.2G free on / (threshold 90%)" --cooldown 1800
#
# Usage as a library (from another check script):
#   require_relative "alert_notifier"
#   notifier = AlertNotifier.new(webhook_url: ENV["SLACK_WEBHOOK_URL"])
#   notifier.alert(key: "disk-root", severity: :crit,
#                  title: "Disk / is 96% full", text: "...")
#
# Requires: Ruby >= 2.7, stdlib only (net/http, json, fileutils, optparse).
# No gems needed.

require "net/http"
require "uri"
require "json"
require "fileutils"
require "time"
require "optparse"
require "digest"
require "tmpdir"

class AlertNotifier
  SEVERITIES = %i[info warn crit].freeze

  # Slack's "danger/warning/good" attachment colors, keyed by severity.
  SEVERITY_COLOR = {
    info: "#7ec8ff",
    warn: "#fbbf24",
    crit: "#cc342d"
  }.freeze

  class DeliveryError < StandardError; end

  # webhook_url:   Slack incoming-webhook URL, or any endpoint that accepts
  #                a JSON POST body. Required unless dry_run is true.
  # state_file:    where cooldown/dedup state is persisted between runs.
  #                Defaults to a file under the system tmp dir so it survives
  #                across separate cron invocations of the *same* script.
  # default_cooldown: seconds to suppress a repeat alert with the same key.
  # max_retries:   number of delivery attempts before giving up.
  # open_timeout / read_timeout: per-request HTTP timeouts, in seconds.
  # payload_style: :slack (attachments) or :generic (flat JSON) -- controls
  #                the shape of the POST body, since not every webhook
  #                receiver (PagerDuty, a custom endpoint, ntfy.sh...)
  #                speaks Slack's attachment format.
  # dry_run:       if true, never makes a network call -- just returns what
  #                *would* have been sent. Useful for testing check scripts.
  def initialize(webhook_url: nil, state_file: nil, default_cooldown: 900,
                 max_retries: 3, open_timeout: 5, read_timeout: 5,
                 payload_style: :slack, dry_run: false)
    @webhook_url = webhook_url
    @state_file = state_file || File.join(Dir.tmpdir, "alert_notifier_state.json")
    @default_cooldown = default_cooldown
    @max_retries = max_retries
    @open_timeout = open_timeout
    @read_timeout = read_timeout
    @payload_style = payload_style
    @dry_run = dry_run
    raise ArgumentError, "webhook_url is required unless dry_run: true" if webhook_url.nil? && !dry_run
  end

  # Send an alert, unless an alert with the same `key` was already sent
  # within `cooldown` seconds -- in which case this is a silent no-op and
  # the method returns :suppressed. This is the core de-dup/rate-limit
  # mechanism: a check script can run every minute via cron, but a human
  # only gets pinged once per `cooldown` window per distinct problem.
  #
  # Returns one of: :sent, :suppressed, :dry_run
  # Raises DeliveryError if all retries are exhausted.
  def alert(key:, severity:, title:, text: nil, cooldown: nil, fields: {})
    raise ArgumentError, "severity must be one of #{SEVERITIES}" unless SEVERITIES.include?(severity)

    cooldown ||= @default_cooldown
    state = load_state

    last_sent = state.dig(key, "last_sent_at")
    if last_sent && (Time.now - Time.parse(last_sent)) < cooldown
      return :suppressed
    end

    payload = build_payload(severity: severity, title: title, text: text, fields: fields)

    if @dry_run
      record_send(state, key, severity, title)
      return :dry_run
    end

    deliver_with_retry(payload)
    record_send(state, key, severity, title)
    :sent
  end

  # Clears cooldown state for a key (or all keys if key is nil). Handy for
  # a "resolved" transition -- e.g. call this once a check goes back to OK
  # so the *next* failure alerts immediately instead of waiting out an
  # old cooldown window.
  def clear(key = nil)
    state = load_state
    key ? state.delete(key) : state.clear
    save_state(state)
  end

  private

  def build_payload(severity:, title:, text:, fields:)
    if @payload_style == :slack
      attachment = {
        "color" => SEVERITY_COLOR.fetch(severity),
        "title" => "[#{severity.to_s.upcase}] #{title}",
        "text" => text,
        "fields" => fields.map { |k, v| { "title" => k.to_s, "value" => v.to_s, "short" => true } },
        "ts" => Time.now.to_i
      }
      { "attachments" => [attachment] }
    else
      {
        "severity" => severity.to_s,
        "title" => title,
        "text" => text,
        "fields" => fields,
        "timestamp" => Time.now.utc.iso8601
      }
    end
  end

  # Delivers `payload` as JSON, retrying transient failures (5xx, timeouts,
  # connection resets) with exponential backoff (0.5s, 1s, 2s, ...). A 4xx
  # response is treated as non-retryable -- retrying a malformed request
  # won't fix it, it'll just burn time.
  def deliver_with_retry(payload)
    attempt = 0
    begin
      attempt += 1
      post_json(payload)
    rescue DeliveryError => e
      if attempt < @max_retries && e.message.include?("retryable")
        sleep(0.5 * (2**(attempt - 1)))
        retry
      end
      raise
    end
  end

  def post_json(payload)
    uri = URI.parse(@webhook_url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = (uri.scheme == "https")
    http.open_timeout = @open_timeout
    http.read_timeout = @read_timeout

    request = Net::HTTP::Post.new(uri.request_uri, "Content-Type" => "application/json")
    request.body = JSON.generate(payload)

    response =
      begin
        http.request(request)
      rescue Net::OpenTimeout, Net::ReadTimeout, Errno::ECONNREFUSED, Errno::ECONNRESET, SocketError => e
        raise DeliveryError, "retryable: network error contacting webhook: #{e.class}: #{e.message}"
      end

    case response
    when Net::HTTPSuccess
      response
    when Net::HTTPServerError # 5xx -- treat as transient/retryable
      raise DeliveryError, "retryable: webhook returned #{response.code} #{response.message}"
    else # 4xx and anything else -- not retryable
      raise DeliveryError, "webhook rejected payload: #{response.code} #{response.message}: #{response.body}"
    end
  end

  def load_state
    return {} unless File.exist?(@state_file)

    JSON.parse(File.read(@state_file))
  rescue JSON::ParserError
    {} # corrupt/partial state file -- fail open rather than crash the check
  end

  def save_state(state)
    FileUtils.mkdir_p(File.dirname(@state_file))
    tmp = "#{@state_file}.tmp.#{Process.pid}"
    File.write(tmp, JSON.pretty_generate(state))
    File.rename(tmp, @state_file) # atomic on POSIX -- avoids a half-written state file
  end

  def record_send(state, key, severity, title)
    state[key] = {
      "last_sent_at" => Time.now.utc.iso8601,
      "severity" => severity.to_s,
      "title" => title,
      "fingerprint" => Digest::SHA256.hexdigest("#{key}:#{title}")[0, 12]
    }
    save_state(state)
  end
end

# ---------------------------------------------------------------------------
# CLI entry point -- lets any check script (Ruby, bash, whatever) send an
# alert without linking against this file, e.g.:
#   df -h / | check_disk.sh || ruby alert_notifier.rb --key disk --severity crit ...
# ---------------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  options = {
    severity: :warn,
    cooldown: 900,
    payload_style: :slack,
    dry_run: false,
    state_file: nil
  }

  OptionParser.new do |opts|
    opts.banner = "Usage: alert_notifier.rb --webhook URL --key KEY --title TITLE [options]"
    opts.on("--webhook URL", "Slack/webhook URL (or set SLACK_WEBHOOK_URL env var)") { |v| options[:webhook] = v }
    opts.on("--key KEY", "Stable identifier for de-duplication/cooldown") { |v| options[:key] = v }
    opts.on("--severity SEV", %w[info warn crit], "info|warn|crit (default warn)") { |v| options[:severity] = v.to_sym }
    opts.on("--title TITLE", "Short alert title") { |v| options[:title] = v }
    opts.on("--text TEXT", "Longer alert body (optional)") { |v| options[:text] = v }
    opts.on("--cooldown SECONDS", Integer, "Suppress repeats within N seconds (default 900)") { |v| options[:cooldown] = v }
    opts.on("--state-file PATH", "Where to persist dedup state (default: tmp dir)") { |v| options[:state_file] = v }
    opts.on("--generic", "Use flat JSON payload instead of Slack attachment format") { options[:payload_style] = :generic }
    opts.on("--clear", "Clear cooldown state for --key (or all keys if --key omitted) and exit") { options[:clear] = true }
    opts.on("--dry-run", "Don't actually send -- print what would be sent") { options[:dry_run] = true }
    opts.on("-h", "--help", "Show this help") { puts opts; exit 0 }
  end.parse!

  webhook = options[:webhook] || ENV["SLACK_WEBHOOK_URL"]

  notifier = AlertNotifier.new(
    webhook_url: webhook,
    state_file: options[:state_file],
    default_cooldown: options[:cooldown],
    payload_style: options[:payload_style],
    dry_run: options[:dry_run]
  )

  if options[:clear]
    notifier.clear(options[:key])
    puts options[:key] ? "Cleared cooldown state for key=#{options[:key]}" : "Cleared all cooldown state"
    exit 0
  end

  abort "ERROR: --key is required" unless options[:key]
  abort "ERROR: --title is required" unless options[:title]
  abort "ERROR: --webhook is required (or set SLACK_WEBHOOK_URL)" unless webhook || options[:dry_run]

  begin
    result = notifier.alert(
      key: options[:key],
      severity: options[:severity],
      title: options[:title],
      text: options[:text],
      cooldown: options[:cooldown]
    )

    case result
    when :sent
      puts "ALERT SENT: [#{options[:severity]}] #{options[:title]}"
      exit 0
    when :suppressed
      puts "ALERT SUPPRESSED (cooldown active): key=#{options[:key]}"
      exit 0
    when :dry_run
      puts "DRY RUN -- would have sent: [#{options[:severity]}] #{options[:title]}"
      exit 0
    end
  rescue AlertNotifier::DeliveryError => e
    warn "ALERT DELIVERY FAILED after retries: #{e.message}"
    exit 2
  end
end
