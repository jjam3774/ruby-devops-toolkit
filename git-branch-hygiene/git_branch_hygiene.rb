#!/usr/bin/env ruby
# frozen_string_literal: true
#
# git_branch_hygiene.rb -- audit and prune stale/merged local git branches
# across a fleet of repos.
#
# Problem it solves:
#   After a year or two of active development, `git branch` on a shared
#   build box or a developer's machine turns into a wall of forgotten
#   feature branches. Most are already merged and just haven't been
#   deleted; a few are genuinely abandoned; a few might still matter.
#   Nobody wants to `git branch -D` their way through 200 branches by
#   hand, and doing it wrong (deleting something unmerged) is exactly the
#   kind of mistake that erodes trust in automation. This script scans
#   one or many repos, classifies every local branch as MERGED / STALE /
#   ACTIVE relative to a default branch, and only ever deletes a branch
#   two ways: safely (git's own merge check, via `branch -d`) or with an
#   explicit, separately-flagged, force confirmation for stale-but-unmerged
#   branches.
#
# Prerequisites:
#   - Ruby >= 2.7
#   - git available on PATH
#   - stdlib only: open3, optparse, json, time, fnmatch (via File.fnmatch)
#
# Usage:
#   # Report only (safe, default) -- one repo
#   ruby git_branch_hygiene.rb --repo /srv/myapp
#
#   # Report only -- every git repo one level under a directory
#   ruby git_branch_hygiene.rb --repos-dir /srv/repos
#
#   # Actually delete branches already merged into the default branch
#   ruby git_branch_hygiene.rb --repo /srv/myapp --delete-merged
#
#   # Force-delete branches with no activity in 180+ days, even if unmerged
#   # (requires the explicit --confirm-force flag as a safety rail)
#   ruby git_branch_hygiene.rb --repo /srv/myapp --delete-stale --stale-days 180 --confirm-force
#
#   ruby git_branch_hygiene.rb --repos-dir /srv/repos --json

require "open3"
require "optparse"
require "json"
require "time"

class GitBranchHygiene
  DEFAULT_PROTECTED = %w[main master develop HEAD].freeze

  Branch = Struct.new(:name, :last_commit_at, :age_days, :merged, :status, :action, keyword_init: true) do
    def to_h
      {
        name: name,
        last_commit_at: last_commit_at&.iso8601,
        age_days: age_days,
        merged: merged,
        status: status,
        action: action
      }
    end
  end

  RepoReport = Struct.new(:repo, :default_branch, :branches, :error, keyword_init: true) do
    def to_h
      { repo: repo, default_branch: default_branch, branches: branches&.map(&:to_h), error: error }.compact
    end
  end

  # protected_patterns: array of glob-style patterns (File.fnmatch) that are
  # never touched, e.g. ["main", "master", "release/*"].
  # runner: object responding to #call(argv, chdir:) -> [stdout, status_success?]
  #         Injected so this class can be unit tested with a fake git binary,
  #         though in this script we always exercise it against real `git`
  #         in throwaway sandbox repos (see git_branch_hygiene_test.rb).
  def initialize(stale_days: 90, protected_patterns: DEFAULT_PROTECTED, runner: nil)
    @stale_days = stale_days
    @protected_patterns = protected_patterns
    @runner = runner || self.class.method(:run_git)
  end

  # Inspect one repo and classify every local branch. Does not modify
  # anything -- deletion is a separate explicit step (see #delete!).
  def scan(repo_path)
    unless git_repo?(repo_path)
      return RepoReport.new(repo: repo_path, branches: [], error: "not a git repository")
    end

    default = default_branch(repo_path)
    current = current_branch(repo_path)
    merged_set = merged_branches(repo_path, default)

    branches = list_branches(repo_path).map do |name, commit_iso|
      commit_time = commit_iso ? Time.parse(commit_iso) : nil
      age = commit_time ? ((Time.now - commit_time) / 86_400).floor : nil
      age = 0 if age&.negative? # guard against minor clock skew making a just-now commit look "future"
      merged = merged_set.include?(name)
      protected_branch = protected?(name) || name == current

      status =
        if protected_branch
          :protected
        elsif merged
          :merged
        elsif age && age >= @stale_days
          :stale
        else
          :active
        end

      Branch.new(name: name, last_commit_at: commit_time, age_days: age, merged: merged, status: status, action: :none)
    end

    RepoReport.new(repo: repo_path, default_branch: default, branches: branches, error: nil)
  rescue StandardError => e
    RepoReport.new(repo: repo_path, branches: [], error: "#{e.class}: #{e.message}")
  end

  # Deletes branches from `report` according to policy. Mutates each
  # Branch's #action field to record what happened (deleted / skipped / failed).
  #   delete_merged: if true, safely delete every :merged branch via `git branch -d`
  #                  (git itself refuses -d on anything not fully merged, so this
  #                  can never destroy unmerged work even if our own bookkeeping is wrong)
  #   delete_stale:  if true AND confirm_force is true, force-delete every :stale
  #                  branch via `git branch -D`. Requires confirm_force as a second,
  #                  independent safety rail because -D discards unmerged commits.
  def delete!(report, delete_merged: false, delete_stale: false, confirm_force: false)
    return report if report.error

    report.branches.each do |b|
      if delete_merged && b.status == :merged
        b.action = delete_branch(report.repo, b.name, force: false)
      elsif delete_stale && b.status == :stale
        if confirm_force
          b.action = delete_branch(report.repo, b.name, force: true)
        else
          b.action = :skipped_needs_confirm_force
        end
      end
    end
    report
  end

  private

  def protected?(name)
    @protected_patterns.any? { |pat| File.fnmatch(pat, name) }
  end

  def git_repo?(path)
    Dir.exist?(path) && (out, ok = @runner.call(%w[rev-parse --is-inside-work-tree], chdir: path); ok && out.strip == "true")
  end

  def default_branch(path)
    # Prefer the branch origin/HEAD points at; fall back to main, then master.
    out, ok = @runner.call(%w[symbolic-ref --short refs/remotes/origin/HEAD], chdir: path)
    return out.strip.sub("origin/", "") if ok && !out.strip.empty?

    %w[main master].each do |candidate|
      _, exists = @runner.call(["show-ref", "--verify", "--quiet", "refs/heads/#{candidate}"], chdir: path)
      return candidate if exists
    end
    current_branch(path)
  end

  def current_branch(path)
    out, ok = @runner.call(%w[symbolic-ref --short HEAD], chdir: path)
    ok ? out.strip : nil
  end

  def merged_branches(path, default)
    return [] unless default

    out, ok = @runner.call(["branch", "--merged", default, "--format=%(refname:short)"], chdir: path)
    return [] unless ok

    out.split("\n").map(&:strip).reject(&:empty?)
  end

  def list_branches(path)
    out, ok = @runner.call(["for-each-ref", "refs/heads", "--format=%(refname:short)|%(committerdate:iso-strict)"], chdir: path)
    return [] unless ok

    out.split("\n").filter_map do |line|
      name, date = line.split("|", 2)
      next if name.nil? || name.strip.empty?

      [name.strip, date&.strip]
    end
  end

  def delete_branch(path, name, force:)
    flag = force ? "-D" : "-d"
    _, ok = @runner.call(["branch", flag, name], chdir: path)
    ok ? :deleted : :failed
  end

  # Default runner: shells out to the real `git` binary via Open3.
  # Returns [combined_output_string, success_boolean].
  def self.run_git(argv, chdir:)
    stdout, stderr, status = Open3.capture3("git", *argv, chdir: chdir)
    [status.success? ? stdout : "#{stdout}#{stderr}", status.success?]
  end
end

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  options = {
    stale_days: 90,
    protected: GitBranchHygiene::DEFAULT_PROTECTED.dup,
    delete_merged: false,
    delete_stale: false,
    confirm_force: false,
    json: false
  }

  OptionParser.new do |opts|
    opts.banner = "Usage: git_branch_hygiene.rb (--repo PATH | --repos-dir DIR) [options]"
    opts.on("--repo PATH", "Path to a single git repo") { |v| options[:repo] = v }
    opts.on("--repos-dir DIR", "Directory containing multiple git repos (one level deep)") { |v| options[:repos_dir] = v }
    opts.on("--stale-days N", Integer, "Days of inactivity before an unmerged branch is 'stale' (default 90)") { |v| options[:stale_days] = v }
    opts.on("--protect LIST", "Comma-separated glob patterns never touched (default: main,master,develop,HEAD)") { |v| options[:protected] = v.split(",") }
    opts.on("--delete-merged", "Safely delete branches already merged into the default branch") { options[:delete_merged] = true }
    opts.on("--delete-stale", "Force-delete unmerged branches past --stale-days (needs --confirm-force too)") { options[:delete_stale] = true }
    opts.on("--confirm-force", "Required alongside --delete-stale to actually run the destructive force-delete") { options[:confirm_force] = true }
    opts.on("--json", "Emit machine-readable JSON") { options[:json] = true }
    opts.on("-h", "--help", "Show this help") { puts opts; exit 0 }
  end.parse!

  repos =
    if options[:repo]
      [options[:repo]]
    elsif options[:repos_dir]
      Dir.children(options[:repos_dir]).map { |c| File.join(options[:repos_dir], c) }.select { |p| File.directory?(p) }.sort
    else
      abort "ERROR: pass --repo PATH or --repos-dir DIR"
    end

  hygiene = GitBranchHygiene.new(stale_days: options[:stale_days], protected_patterns: options[:protected])

  reports = repos.map do |repo|
    report = hygiene.scan(repo)
    hygiene.delete!(report,
                     delete_merged: options[:delete_merged],
                     delete_stale: options[:delete_stale],
                     confirm_force: options[:confirm_force])
  end

  if options[:json]
    puts JSON.pretty_generate(reports.map(&:to_h))
  else
    reports.each do |r|
      puts "== #{r.repo} =="
      if r.error
        puts "  ERROR: #{r.error}"
        next
      end
      puts "  default branch: #{r.default_branch}"
      if r.branches.empty?
        puts "  (no local branches found)"
      end
      r.branches.each do |b|
        line = format("  %-8s %-35s age=%-5s merged=%-5s", b.status.to_s.upcase, b.name, (b.age_days ? "#{b.age_days}d" : "?"), b.merged)
        line += "  -> #{b.action}" unless b.action == :none
        puts line
      end
    end
  end

  merged_count = reports.sum { |r| (r.branches || []).count { |b| b.status == :merged } }
  stale_count = reports.sum { |r| (r.branches || []).count { |b| b.status == :stale } }
  deleted_count = reports.sum { |r| (r.branches || []).count { |b| b.action == :deleted } }
  has_errors = reports.any?(&:error)

  unless options[:json]
    puts "\nSummary: #{merged_count} merged, #{stale_count} stale, #{deleted_count} deleted across #{reports.size} repo(s)."
  end

  exit(has_errors ? 2 : (deleted_count.positive? || merged_count.positive? || stale_count.positive? ? 1 : 0))
end
