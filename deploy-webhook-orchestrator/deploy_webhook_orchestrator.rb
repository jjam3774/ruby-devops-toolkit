#!/usr/bin/env ruby
# frozen_string_literal: true
#
# deploy_webhook_orchestrator.rb
#
# Drives a REST-based deployment API end to end: triggers a deploy, polls
# its status until it finishes (or times out), retries transient network
# failures with exponential backoff, and automatically calls a rollback
# endpoint when the deploy fails or stalls. No gems -- net/http, json,
# uri and optparse are all in the Ruby standard library.
#
# This is the shape of almost every "deploy button" a CI system calls:
# some internal or vendor API that accepts a POST to kick off work and
# hands back an id you have to poll. Wiring that up by hand in a shell
# script (curl in a while loop) gets unreadable fast once you add retry
# logic, backoff, and a rollback branch. This script is the Ruby version
# of that shell loop, structured so each concern (HTTP client, polling,
# rollback, CLI) is a separate, testable piece.

require 'net/http'
require 'uri'
require 'json'
require 'optparse'

# --------------------------------------------------------------------------
# Raised when the HTTP client exhausts its retry budget against a single
# request. Kept distinct from other StandardErrors so the CLI can report a
# clean message instead of a raw backtrace.
# --------------------------------------------------------------------------
class RequestFailed < StandardError; end

# --------------------------------------------------------------------------
# Thin, retrying JSON HTTP client. Every call in this script -- trigger,
# poll, rollback -- goes through here, so retry/backoff logic lives in
# exactly one place.
# --------------------------------------------------------------------------
class RetryingHttpClient
  # Transient failures worth retrying. A 4xx/5xx HTTP status is handled
  # separately (see #request) because it isn't a Ruby exception.
  RETRYABLE_ERRORS = [
    Errno::ECONNREFUSED,
    Errno::ECONNRESET,
    Errno::ETIMEDOUT,
    Net::OpenTimeout,
    Net::ReadTimeout,
    EOFError, # connection closed mid-response -- net/http only auto-retries this for GET, not POST
    SocketError
  ].freeze

  def initialize(base_uri, max_retries: 4, base_backoff: 0.5, logger: method(:warn))
    @base_uri = base_uri
    @max_retries = max_retries
    @base_backoff = base_backoff
    @logger = logger
  end

  # method: :get or :post. path: e.g. "/deploy". body: Hash (JSON-encoded) or nil.
  # Returns a parsed JSON Hash on any 2xx response.
  # Raises RequestFailed on a non-2xx response or after retries are exhausted.
  def request(method, path, body: nil)
    uri = URI.join(@base_uri.to_s, path)
    attempt = 0

    begin
      attempt += 1
      response = perform(method, uri, body)

      unless response.is_a?(Net::HTTPSuccess)
        raise RequestFailed, "#{method.upcase} #{path} -> HTTP #{response.code}: #{response.body}"
      end

      return response.body.to_s.empty? ? {} : JSON.parse(response.body)
    rescue *RETRYABLE_ERRORS => e
      if attempt <= @max_retries
        backoff = @base_backoff * (2**(attempt - 1))
        @logger.call("#{e.class}: #{e.message} (attempt #{attempt}/#{@max_retries + 1}), retrying in #{backoff}s")
        sleep backoff
        retry
      end
      raise RequestFailed, "#{method.upcase} #{path} failed after #{attempt} attempts: #{e.class}: #{e.message}"
    end
  end

  private

  def perform(method, uri, body)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = uri.scheme == 'https'
    http.open_timeout = 5
    http.read_timeout = 5

    request =
      case method
      when :get  then Net::HTTP::Get.new(uri)
      when :post then Net::HTTP::Post.new(uri)
      else raise ArgumentError, "unsupported method #{method}"
      end

    if body
      request['Content-Type'] = 'application/json'
      request.body = JSON.generate(body)
    end

    http.request(request)
  end
end

# --------------------------------------------------------------------------
# Orchestrates one deploy: trigger -> poll -> (rollback on failure/timeout).
# Every collaborator (HTTP client, clock, sleeper) is injectable so tests
# never need a real network or a real timer.
# --------------------------------------------------------------------------
class DeployOrchestrator
  TERMINAL_STATUSES = %w[success failed].freeze

  Result = Struct.new(:outcome, :deploy_id, :status, :rolled_back, :detail, keyword_init: true)

  def initialize(client:, deploy_path:, status_path_template:, rollback_path_template:,
                 poll_interval: 3, timeout: 300, clock: Time, sleeper: ->(s) { sleep s },
                 logger: method(:warn))
    @client = client
    @deploy_path = deploy_path
    @status_path_template = status_path_template
    @rollback_path_template = rollback_path_template
    @poll_interval = poll_interval
    @timeout = timeout
    @clock = clock
    @sleeper = sleeper
    @logger = logger
  end

  # payload: Hash sent as the deploy request body (service name, version, etc).
  def run(payload)
    deploy_id = trigger(payload)
    status = poll_until_terminal(deploy_id)

    if status == 'success'
      Result.new(outcome: :success, deploy_id: deploy_id, status: status, rolled_back: false)
    else
      # status is either "failed" or the sentinel :timeout from poll_until_terminal
      rolled_back = attempt_rollback(deploy_id)
      outcome = status == :timeout ? :timeout : :failed
      Result.new(outcome: outcome, deploy_id: deploy_id, status: status, rolled_back: rolled_back)
    end
  rescue RequestFailed => e
    Result.new(outcome: :error, deploy_id: nil, status: nil, rolled_back: false, detail: e.message)
  end

  private

  def trigger(payload)
    @logger.call("Triggering deploy: #{payload.inspect}")
    response = @client.request(:post, @deploy_path, body: payload)
    id = response['id'] || response['deploy_id']
    raise RequestFailed, "deploy trigger response had no id/deploy_id field: #{response.inspect}" unless id

    @logger.call("Deploy accepted, id=#{id}")
    id
  end

  def poll_until_terminal(deploy_id)
    deadline = @clock.now + @timeout
    path = @status_path_template % { id: deploy_id }

    loop do
      response = @client.request(:get, path)
      status = response['status']
      @logger.call("Status for #{deploy_id}: #{status}")

      return status if TERMINAL_STATUSES.include?(status)

      if @clock.now >= deadline
        @logger.call("Timed out after #{@timeout}s waiting for #{deploy_id} to finish (last status: #{status})")
        return :timeout
      end

      @sleeper.call(@poll_interval)
    end
  end

  def attempt_rollback(deploy_id)
    path = @rollback_path_template % { id: deploy_id }
    @logger.call("Rolling back #{deploy_id}...")
    @client.request(:post, path)
    @logger.call("Rollback request for #{deploy_id} accepted")
    true
  rescue RequestFailed => e
    @logger.call("Rollback for #{deploy_id} FAILED: #{e.message}")
    false
  end
end

# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  options = {
    status_path_template: '/status/%<id>s',
    rollback_path_template: '/rollback/%<id>s',
    deploy_path: '/deploy',
    poll_interval: 3,
    timeout: 300,
    max_retries: 4,
    payload: {}
  }

  parser = OptionParser.new do |opts|
    opts.banner = 'Usage: deploy_webhook_orchestrator.rb --base-url URL [options]'
    opts.on('--base-url URL', 'Base URL of the deploy API (required)') { |v| options[:base_url] = v }
    opts.on('--deploy-path PATH', "Path to POST to trigger a deploy (default #{options[:deploy_path]})") { |v| options[:deploy_path] = v }
    opts.on('--status-path-template TPL', "printf-style path with %<id>s (default #{options[:status_path_template]})") { |v| options[:status_path_template] = v }
    opts.on('--rollback-path-template TPL', "printf-style path with %<id>s (default #{options[:rollback_path_template]})") { |v| options[:rollback_path_template] = v }
    opts.on('--payload JSON', 'JSON body to send with the deploy trigger, e.g. {"service":"api","version":"1.4.2"}') { |v| options[:payload] = JSON.parse(v) }
    opts.on('--poll-interval SECONDS', Float, "Seconds between status polls (default #{options[:poll_interval]})") { |v| options[:poll_interval] = v }
    opts.on('--timeout SECONDS', Float, "Give up and roll back after this many seconds (default #{options[:timeout]})") { |v| options[:timeout] = v }
    opts.on('--max-retries N', Integer, "Retries per HTTP call on transient network errors (default #{options[:max_retries]})") { |v| options[:max_retries] = v }
    opts.on('-h', '--help', 'Show this help') { puts opts; exit 0 }
  end
  parser.parse!(ARGV)

  unless options[:base_url]
    warn parser
    exit 4
  end

  client = RetryingHttpClient.new(options[:base_url], max_retries: options[:max_retries])
  orchestrator = DeployOrchestrator.new(
    client: client,
    deploy_path: options[:deploy_path],
    status_path_template: options[:status_path_template],
    rollback_path_template: options[:rollback_path_template],
    poll_interval: options[:poll_interval],
    timeout: options[:timeout]
  )

  result = orchestrator.run(options[:payload])

  case result.outcome
  when :success
    puts "DEPLOY SUCCESS  id=#{result.deploy_id}"
    exit 0
  when :failed
    puts "DEPLOY FAILED   id=#{result.deploy_id} rolled_back=#{result.rolled_back}"
    exit(result.rolled_back ? 1 : 3)
  when :timeout
    puts "DEPLOY TIMEOUT  id=#{result.deploy_id} rolled_back=#{result.rolled_back}"
    exit(result.rolled_back ? 2 : 3)
  when :error
    puts "ORCHESTRATION ERROR: #{result.detail}"
    exit 5
  end
end
