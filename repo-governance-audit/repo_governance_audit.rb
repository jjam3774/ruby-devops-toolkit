#!/usr/bin/env ruby
# frozen_string_literal: true
#
# repo_governance_audit.rb -- audit a list of GitHub repositories for basic
# governance hygiene: branch protection on the default branch, whether
# force-pushes are still allowed to it, whether pull request review is
# required, and whether Dependabot vulnerability alerts are switched on.
# Built entirely on Ruby's stdlib net/http -- no octokit, no bundler, so it
# drops straight onto a bastion host or a CI runner.
#
# Usage:
#   export GITHUB_TOKEN=ghp_xxx   # needs repo scope to read branch protection
#   ruby repo_governance_audit.rb owner/repo1 owner/repo2
#   ruby repo_governance_audit.rb -f repos.txt --json
#   ruby repo_governance_audit.rb owner/repo --api-base http://ghe.internal/api/v3
#
# Exit status:
#   0   no CRIT findings
#   1   at least one CRIT finding
#   2   usage / configuration error
#
# Requires: Ruby 3.x, stdlib only (net/http, json, uri, optparse).

require 'net/http'
require 'uri'
require 'json'
require 'optparse'
require 'time'

# ---------------------------------------------------------------------------
# Thin wrapper around Net::HTTP that knows how to talk to the GitHub REST
# API (or an API-compatible stand-in, which is exactly what lets this be
# tested against a local WEBrick server instead of the real api.github.com
# -- see the README's testing notes). Centralizes auth headers, JSON
# decoding, and the one rate-limit retry rule GitHub actually cares about.
# ---------------------------------------------------------------------------
class GitHubClient
  RateLimited = Class.new(StandardError)

  def initialize(api_base:, token:, user_agent: 'repo-governance-audit-ruby')
    @uri_base = URI.parse(api_base)
    @token = token
    @user_agent = user_agent
  end

  # Returns [status_code, parsed_json_or_nil, headers]. Retries exactly
  # once, after sleeping until X-RateLimit-Reset, if GitHub answers a
  # secondary-rate-limit 403.
  def get(path, extra_headers = {})
    attempts = 0
    begin
      attempts += 1
      uri = @uri_base.dup
      uri.path = File.join(@uri_base.path.to_s, path)
      req = Net::HTTP::Get.new(uri)
      req['Accept'] = 'application/vnd.github+json'
      req['User-Agent'] = @user_agent
      req['Authorization'] = "Bearer #{@token}" if @token && !@token.empty?
      extra_headers.each { |k, v| req[k] = v }

      res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == 'https') do |http|
        http.request(req)
      end

      if res.code == '403' && res['X-RateLimit-Remaining'] == '0' && attempts == 1
        reset_at = Time.at(res['X-RateLimit-Reset'].to_i)
        wait = [reset_at - Time.now, 0].max
        warn "rate limited, sleeping #{wait.round}s until #{reset_at}"
        sleep([wait, 2].min) # capped in the tutorial/tests; real runs can wait the full window
        raise RateLimited
      end

      body = res.body.to_s.empty? ? nil : (JSON.parse(res.body) rescue nil)
      [res.code.to_i, body, res.to_hash]
    rescue RateLimited
      retry if attempts <= 1
    end
  end
end

Finding = Struct.new(:severity, :reason, keyword_init: true)

# ---------------------------------------------------------------------------
# Pure classification: given the JSON GitHub already handed back, decide
# what's wrong. No HTTP in here, which is what makes it unit-testable
# without a network at all -- see spec-style checks in the README.
# ---------------------------------------------------------------------------
def classify_repo(repo, protection_status, protection, vuln_alert_status)
  return { severity: :ok, findings: [Finding.new(severity: :info, reason: 'archived, skipped')] } if repo['archived']

  findings = []
  visibility = repo['private'] ? 'private' : 'public'

  case protection_status
  when 404
    sev = repo['private'] ? :warn : :crit
    findings << Finding.new(severity: sev, reason: "default branch '#{repo['default_branch']}' has no branch protection (#{visibility} repo)")
  when 403
    findings << Finding.new(severity: :info, reason: 'could not check branch protection (token lacks admin rights on this repo)')
  when 200
    if protection.dig('allow_force_pushes', 'enabled')
      findings << Finding.new(severity: :crit, reason: 'force-pushes are allowed on the default branch')
    end
    reviews = protection.dig('required_pull_request_reviews', 'required_approving_review_count')
    if reviews.nil? || reviews < 1
      findings << Finding.new(severity: :warn, reason: 'no required pull request review count set on the default branch')
    end
    unless protection.dig('enforce_admins', 'enabled')
      findings << Finding.new(severity: :warn, reason: 'branch protection does not apply to repo admins (enforce_admins is off)')
    end
    if protection.dig('required_status_checks').nil?
      findings << Finding.new(severity: :info, reason: 'no required status checks configured on the default branch')
    end
  end

  case vuln_alert_status
  when 404
    findings << Finding.new(severity: repo['private'] ? :warn : :crit, reason: 'Dependabot vulnerability alerts are disabled')
  when 403
    findings << Finding.new(severity: :info, reason: 'could not check vulnerability-alert status (token lacks admin rights)')
    # 204 == enabled, nothing to report
  end

  overall = if findings.any? { |f| f.severity == :crit }
              :crit
            elsif findings.any? { |f| f.severity == :warn }
              :warn
            else
              :ok
            end

  { severity: overall, findings: findings }
end

# ---------------------------------------------------------------------------
# One repo, three GitHub API calls, one classification.
# ---------------------------------------------------------------------------
def audit_repo(client, full_name)
  owner, repo = full_name.split('/', 2)
  raise ArgumentError, "expected owner/repo, got #{full_name.inspect}" unless owner && repo

  status, body, = client.get("/repos/#{owner}/#{repo}")
  raise "GET /repos/#{owner}/#{repo} -> HTTP #{status}" unless status == 200

  result = { repo: full_name, default_branch: body['default_branch'], private: body['private'], archived: body['archived'] }

  if body['archived']
    merged = classify_repo(body, nil, nil, nil)
  else
    branch = body['default_branch']
    prot_status, prot_body, = client.get("/repos/#{owner}/#{repo}/branches/#{branch}/protection")
    vuln_status, _vuln_body, = client.get(
      "/repos/#{owner}/#{repo}/vulnerability-alerts",
      { 'Accept' => 'application/vnd.github.dorian-preview+json' }
    )
    merged = classify_repo(body, prot_status, prot_body, vuln_status)
  end

  result.merge(merged)
end

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
options = { api_base: 'https://api.github.com', token: ENV['GITHUB_TOKEN'], json: false, repos_file: nil }
parser = OptionParser.new do |opts|
  opts.banner = 'Usage: repo_governance_audit.rb owner/repo [owner/repo ...] [options]'
  opts.on('-f', '--file FILE', 'File with one owner/repo per line') { |v| options[:repos_file] = v }
  opts.on('--token TOKEN', 'GitHub token (default: $GITHUB_TOKEN)') { |v| options[:token] = v }
  opts.on('--api-base URL', "API base URL (default: #{options[:api_base]}; point at a GHES /api/v3 for on-prem)") { |v| options[:api_base] = v }
  opts.on('--json', 'Emit a JSON report instead of text') { options[:json] = true }
  opts.on('-h', '--help', 'Show this help') { puts opts; exit 0 }
end
parser.parse!(ARGV)

repo_names = ARGV.dup
repo_names.concat(File.readlines(options[:repos_file]).map(&:strip).reject { |l| l.empty? || l.start_with?('#') }) if options[:repos_file]

if repo_names.empty?
  warn 'error: no repos given (pass owner/repo arguments or -f repos.txt)'
  exit 2
end

client = GitHubClient.new(api_base: options[:api_base], token: options[:token])
results = repo_names.map do |name|
  begin
    audit_repo(client, name)
  rescue StandardError => e
    { repo: name, severity: :crit, findings: [Finding.new(severity: :crit, reason: "audit failed: #{e.class}: #{e.message}")] }
  end
end

crit_count = results.count { |r| r[:severity] == :crit }
warn_count = results.count { |r| r[:severity] == :warn }

if options[:json]
  puts JSON.pretty_generate(
    total: results.size, crit: crit_count, warn: warn_count,
    repos: results.map do |r|
      {
        repo: r[:repo], severity: r[:severity],
        findings: r[:findings].map { |f| { severity: f.severity, reason: f.reason } }
      }
    end
  )
else
  results.each do |r|
    tag = { crit: '[CRIT]', warn: '[WARN]', ok: '[ ok ]' }[r[:severity]]
    puts "#{tag} #{r[:repo]}"
    r[:findings].each { |f| puts "        - #{f.reason}" }
  end
  puts '---'
  puts "#{results.size} repos audited, #{crit_count} CRIT, #{warn_count} WARN"
end

exit(crit_count.positive? ? 1 : 0)
