#!/usr/bin/env ruby
# frozen_string_literal: true
#
# git_release_tagger.rb — compute the next semantic version from Conventional
# Commits since the last tag, generate a grouped changelog, and create an
# annotated git tag (optionally publishing a GitHub Release too). Pure Ruby,
# no gems: shells out to `git`, and Net::HTTP for the optional GitHub call.
#
# Typical uses:
#   ./git_release_tagger.rb --repo . --dry-run
#   ./git_release_tagger.rb --repo . --apply
#   ./git_release_tagger.rb --repo . --apply --publish-github --github-repo owner/name
#     (needs GITHUB_TOKEN in the environment; never pass a token on the CLI)
#
# Exit codes (for CI integration):
#   0 = a release was computed (and created, if --apply) successfully
#   1 = no releasable commits since the last tag (nothing to do — not an error)
#   2 = fatal error (not a git repo, git command failed, GitHub API call failed)
#
# Requires: Ruby >= 2.7, `git` on PATH. No gems.

require 'optparse'
require 'json'
require 'net/http'
require 'uri'

module GitReleaseTagger
  class GitError < StandardError; end

  CONVENTIONAL_COMMIT = /\A(?<type>\w+)(?<scope>\([^)]+\))?(?<breaking>!)?:\s*(?<desc>.+)\z/.freeze

  Commit = Struct.new(:sha, :subject, :type, :scope, :breaking, :description, keyword_init: true)

  # Every `git` invocation goes through this one seam (default: Open3), so
  # the parsing/planning/changelog logic below can be fully exercised
  # against a real throwaway git repo in tests (see test_git_release_tagger.rb)
  # while error-handling paths (not a repo, git missing) can still be
  # exercised with a fake runner.
  class GitRepo
    def initialize(dir, runner: nil)
      @dir = dir
      @runner = runner || method(:default_runner)
    end

    def last_tag
      out, _err, status = run('describe', '--tags', '--abbrev=0')
      status.success? ? out.strip : nil
    end

    def commits_since(tag)
      range = tag ? "#{tag}..HEAD" : 'HEAD'
      # %B is the raw, full commit message (subject + body), so a
      # `BREAKING CHANGE:` footer in the body is visible to CommitParser
      # and not just the subject line. %x1f separates sha/message within a
      # record, %x1e separates records -- both control chars are safe
      # because commit messages practically never contain them.
      out, err, status = run('log', range, '--pretty=format:%H%x1f%B%x1e')
      raise GitError, "git log failed: #{err.strip}" unless status.success?

      out.split("\x1e").filter_map do |record|
        sha, message = record.sub(/\A\n/, '').split("\x1f", 2)
        next if sha.nil? || sha.strip.empty?

        CommitParser.parse(sha.strip, message.to_s)
      end
    end

    def create_annotated_tag(name, message)
      _out, err, status = run('tag', '-a', name, '-m', message)
      raise GitError, "git tag failed: #{err.strip}" unless status.success?

      true
    end

    def repo?
      _out, _err, status = run('rev-parse', '--is-inside-work-tree')
      status.success?
    end

    private

    def run(*args)
      @runner.call(['git', '-C', @dir, *args])
    end

    def default_runner(cmd)
      require 'open3'
      Open3.capture3(*cmd)
    end
  end

  class CommitParser
    # `message` is the full commit message (subject + body); `subject` is
    # just its first line. A `BREAKING CHANGE:` footer anywhere in the body
    # marks the commit as breaking even though the subject line itself
    # doesn't carry the `!` marker.
    def self.parse(sha, message)
      subject = message.lines.first.to_s.chomp
      m = CONVENTIONAL_COMMIT.match(subject)
      breaking_footer = message.include?('BREAKING CHANGE')
      if m
        Commit.new(sha: sha, subject: subject, type: m[:type].downcase, scope: m[:scope],
                   breaking: !m[:breaking].nil? || breaking_footer, description: m[:desc])
      else
        Commit.new(sha: sha, subject: subject, type: 'other', scope: nil, breaking: breaking_footer, description: subject)
      end
    end
  end

  # Parses "vX.Y.Z" (or "X.Y.Z") and computes the next version from a batch
  # of parsed commits, following Conventional Commits / semver rules: any
  # breaking change forces a major bump, else any `feat` forces minor, else
  # any `fix` forces patch. Returns nil when nothing in the batch warrants
  # a release (e.g. only `docs`/`chore`/`test` commits).
  class VersionPlanner
    Version = Struct.new(:major, :minor, :patch) do
      def to_s = "v#{major}.#{minor}.#{patch}"
    end

    def self.parse(tag)
      return Version.new(0, 0, 0) unless tag

      m = tag.match(/(\d+)\.(\d+)\.(\d+)/)
      raise GitError, "cannot parse version out of tag #{tag.inspect}" unless m

      Version.new(m[1].to_i, m[2].to_i, m[3].to_i)
    end

    def self.bump_kind(commits)
      return :major if commits.any?(&:breaking)
      return :minor if commits.any? { |c| c.type == 'feat' }
      return :patch if commits.any? { |c| c.type == 'fix' }

      nil
    end

    def self.next_version(current_tag, commits)
      kind = bump_kind(commits)
      return [nil, nil] unless kind

      v = parse(current_tag)
      next_v =
        case kind
        when :major then Version.new(v.major + 1, 0, 0)
        when :minor then Version.new(v.major, v.minor + 1, 0)
        when :patch then Version.new(v.major, v.minor, v.patch + 1)
        end
      [next_v, kind]
    end
  end

  class ChangelogBuilder
    GROUPS = { 'feat' => 'Features', 'fix' => 'Fixes' }.freeze

    def self.build(version, commits)
      breaking = commits.select(&:breaking)
      grouped = commits.group_by { |c| GROUPS.fetch(c.type, 'Other') }

      lines = ["## #{version}", '']
      unless breaking.empty?
        lines << '### BREAKING CHANGES'
        breaking.each { |c| lines << "- #{c.description} (#{c.sha[0, 7]})" }
        lines << ''
      end
      %w[Features Fixes Other].each do |group|
        list = grouped[group]
        next unless list && !list.empty?

        lines << "### #{group}"
        list.each { |c| lines << "- #{c.description} (#{c.sha[0, 7]})" }
        lines << ''
      end
      lines.join("\n").strip + "\n"
    end
  end

  # Creates a GitHub Release via the REST API. Entirely inert unless
  # --publish-github is explicitly passed AND a token is present — there is
  # no code path where this reaches out to GitHub on its own.
  class GitHubReleaser
    def initialize(repo_slug, token, requester: nil)
      @repo_slug = repo_slug
      @token = token
      @requester = requester || method(:default_post)
    end

    def publish(tag_name, body)
      payload = JSON.generate(tag_name: tag_name, name: tag_name, body: body)
      @requester.call(@repo_slug, payload, @token)
    end

    private

    def default_post(repo_slug, payload, token)
      uri = URI.parse("https://api.github.com/repos/#{repo_slug}/releases")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      req = Net::HTTP::Post.new(uri, 'Content-Type' => 'application/json',
                                      'Authorization' => "Bearer #{token}",
                                      'Accept' => 'application/vnd.github+json',
                                      'User-Agent' => 'git_release_tagger.rb')
      req.body = payload
      resp = http.request(req)
      { ok: resp.code.to_i < 300, code: resp.code.to_i, body: resp.body }
    end
  end

  class CLI
    def self.run(argv)
      options = { repo: '.', apply: false, publish_github: false, json: false }
      parser = OptionParser.new do |o|
        o.banner = 'Usage: git_release_tagger.rb --repo PATH [--apply] [--publish-github --github-repo owner/name] [options]'
        o.on('--repo PATH', 'Path to the git repository (default .)') { |p| options[:repo] = p }
        o.on('--apply', 'Actually create the annotated tag (default: dry-run, compute only)') { options[:apply] = true }
        o.on('--publish-github', 'Also create a GitHub Release (needs GITHUB_TOKEN env var + --github-repo)') { options[:publish_github] = true }
        o.on('--github-repo OWNER/NAME', 'GitHub repo slug for --publish-github') { |r| options[:github_repo] = r }
        o.on('--json', 'Emit a machine-readable JSON summary') { options[:json] = true }
      end
      parser.parse!(argv)

      repo = GitRepo.new(options[:repo])
      unless repo.repo?
        warn("error: #{options[:repo]} is not a git repository")
        exit 2
      end

      begin
        last_tag = repo.last_tag
        commits = repo.commits_since(last_tag)
      rescue GitError => e
        warn("error: #{e.message}")
        exit 2
      end

      next_version, kind = VersionPlanner.next_version(last_tag, commits)
      unless next_version
        puts "No releasable commits since #{last_tag || '(repo start)'} — nothing to do."
        exit 1
      end

      changelog = ChangelogBuilder.build(next_version, commits)

      result = { previous_tag: last_tag, next_version: next_version.to_s, bump: kind.to_s,
                 commit_count: commits.length, changelog: changelog, applied: false, github_release: nil }

      if options[:apply]
        begin
          repo.create_annotated_tag(next_version.to_s, changelog)
          result[:applied] = true
        rescue GitError => e
          warn("error: #{e.message}")
          exit 2
        end

        if options[:publish_github]
          token = ENV['GITHUB_TOKEN']
          if !token || !options[:github_repo]
            warn('error: --publish-github requires GITHUB_TOKEN in the environment and --github-repo')
            exit 2
          end
          releaser = GitHubReleaser.new(options[:github_repo], token)
          gh_result = releaser.publish(next_version.to_s, changelog)
          result[:github_release] = gh_result
          unless gh_result[:ok]
            warn("error: GitHub release creation failed: HTTP #{gh_result[:code]}")
            exit 2
          end
        end
      end

      if options[:json]
        puts JSON.pretty_generate(result)
      else
        puts "previous tag: #{last_tag || '(none)'}"
        puts "next version: #{next_version} (#{kind} bump, #{commits.length} commit(s))"
        puts
        puts changelog
        puts(options[:apply] ? "tag #{next_version} created." : '(dry run — pass --apply to actually create the tag)')
      end

      exit 0
    end
  end
end

GitReleaseTagger::CLI.run(ARGV) if $PROGRAM_NAME == __FILE__
