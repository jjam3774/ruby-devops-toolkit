#!/usr/bin/env ruby
# frozen_string_literal: true
#
# account_provisioner.rb
#
# Idempotent local Linux account provisioning: reads a YAML spec of the
# users and groups a box *should* have, compares it against what actually
# exists (via Etc), and reconciles the difference by shelling out to
# useradd/usermod/userdel/groupadd/gpasswd -- only touching accounts that
# are actually out of spec. Dry-run by default, so you can review a diff
# before anything changes.
#
# This is the "user account management" counterpart to a read-only
# auditor: instead of just reporting that an account is wrong, it can
# fix it -- the same idea as config_state_engine.rb elsewhere in this
# repo, applied specifically to /etc/passwd, /etc/group, and authorized
# SSH keys.
#
# Only the standard library is used: etc, yaml, open3, fileutils.

require 'etc'
require 'yaml'
require 'open3'
require 'fileutils'
require 'optparse'

# --------------------------------------------------------------------------
# Wraps the handful of system calls this script needs so tests can inject a
# fake runner instead of actually calling useradd/usermod/userdel. Kept as
# one small seam rather than stubbing Open3 globally.
# --------------------------------------------------------------------------
class SystemRunner
  Result = Struct.new(:success, :stdout, :stderr, keyword_init: true)

  def run(*cmd)
    stdout, stderr, status = Open3.capture3(*cmd)
    Result.new(success: status.success?, stdout: stdout, stderr: stderr)
  end
end

# --------------------------------------------------------------------------
# Read-only view of what accounts currently exist. Wraps Etc so it can be
# swapped for a fixture in tests without touching the real system's user
# database.
# --------------------------------------------------------------------------
class SystemState
  def user(name)
    Etc.getpwnam(name)
  rescue ArgumentError
    nil
  end

  def group(name)
    Etc.getgrnam(name)
  rescue ArgumentError
    nil
  end

  def group_members(name)
    grp = group(name)
    grp ? grp.mem : []
  end

  def authorized_keys_path(home)
    File.join(home, '.ssh', 'authorized_keys')
  end

  def authorized_keys(home)
    path = authorized_keys_path(home)
    File.exist?(path) ? File.read(path).lines.map(&:strip).reject(&:empty?) : []
  end

  # All accounts currently on the box, as [name, uid] pairs -- used only by
  # the (opt-in) unmanaged-account pruning pass.
  def all_users
    Etc.passwd.map { |pw| [pw.name, pw.uid] }
  end
end

# --------------------------------------------------------------------------
# A single planned change. #describe gives the human-readable line used in
# both dry-run output and the real-run log, so the two never drift apart.
# --------------------------------------------------------------------------
Action = Struct.new(:kind, :target, :detail) do
  def describe
    "#{kind.to_s.upcase.ljust(14)} #{target.to_s.ljust(20)} #{detail}"
  end
end

# --------------------------------------------------------------------------
# Core reconciler: spec (desired state) + system (actual state) -> a list
# of Actions, which #apply! then executes (or, in dry-run mode, just
# prints).
# --------------------------------------------------------------------------
class AccountProvisioner
  def initialize(spec, system_state: SystemState.new, runner: SystemRunner.new, logger: method(:puts))
    @spec = spec
    @system = system_state
    @runner = runner
    @logger = logger
  end

  # Returns an Array of Action describing every change needed to bring the
  # box into line with the spec. Never touches the system.
  def plan
    actions = []
    (@spec['groups'] || []).each { |g| actions.concat(plan_group(g)) }
    (@spec['users'] || []).each { |u| actions.concat(plan_user(u)) }
    actions.concat(plan_removals) if @spec['prune_unmanaged']
    actions
  end

  # Executes a plan. dry_run: true just logs what *would* happen.
  def apply!(actions, dry_run: true)
    actions.each do |action|
      @logger.call((dry_run ? '[dry-run] ' : '[apply]   ') + action.describe)
      next if dry_run

      execute(action)
    end
  end

  private

  def plan_group(spec)
    name = spec.fetch('name')
    existing = @system.group(name)
    return [Action.new(:create_group, name, "gid=#{spec['gid'] || 'auto'}")] unless existing

    []
  end

  def plan_user(spec)
    name = spec.fetch('name')
    actions = []
    existing = @system.user(name)
    state = spec.fetch('state', 'present')

    if state == 'absent'
      actions << Action.new(:remove_user, name, 'account should not exist') if existing
      return actions
    end

    if existing.nil?
      actions << Action.new(:create_user, name, describe_user_spec(spec))
      actions.concat(plan_groups_for(name, spec))
      actions.concat(plan_ssh_key(name, spec))
      return actions
    end

    actions.concat(plan_user_drift(name, existing, spec))
    actions.concat(plan_groups_for(name, spec))
    actions.concat(plan_ssh_key(name, spec))
    actions
  end

  def describe_user_spec(spec)
    parts = []
    parts << "shell=#{spec['shell']}" if spec['shell']
    parts << "uid=#{spec['uid']}" if spec['uid']
    parts << "comment=#{spec['comment'].inspect}" if spec['comment']
    parts.join(' ')
  end

  def plan_user_drift(name, existing, spec)
    actions = []
    if spec['shell'] && existing.shell != spec['shell']
      actions << Action.new(:modify_shell, name, "#{existing.shell} -> #{spec['shell']}")
    end
    if spec['comment'] && existing.gecos != spec['comment']
      actions << Action.new(:modify_comment, name, "#{existing.gecos.inspect} -> #{spec['comment'].inspect}")
    end
    if spec.key?('locked')
      currently_locked = locked?(name)
      if spec['locked'] && !currently_locked
        actions << Action.new(:lock, name, 'password login should be disabled')
      elsif !spec['locked'] && currently_locked
        actions << Action.new(:unlock, name, 'password login should be enabled')
      end
    end
    actions
  end

  def plan_groups_for(name, spec)
    wanted = Array(spec['groups'])
    return [] if wanted.empty?

    current = wanted.reject { |g| @system.group_members(g).include?(name) }
    return [] if current.empty?

    [Action.new(:add_to_groups, name, current.join(','))]
  end

  def plan_ssh_key(name, spec)
    return [] unless spec['ssh_authorized_key']

    home = spec['home'] || "/home/#{name}"
    existing_keys = @system.authorized_keys(home)
    wanted_key = spec['ssh_authorized_key'].strip
    return [] if existing_keys.include?(wanted_key)

    [Action.new(:install_ssh_key, name, "authorized_keys += 1 key (#{wanted_key.split.last(1).first || 'unlabeled'})")]
  end

  # Accounts that exist under a managed UID range but aren't in the spec at
  # all -- only offered when prune_unmanaged is explicitly turned on,
  # since silently deleting unlisted accounts is exactly the kind of
  # surprise this script is designed to avoid by default.
  def plan_removals
    managed_names = (@spec['users'] || []).map { |u| u['name'] }
    min_uid = @spec.fetch('managed_uid_min', 1000)
    max_uid = @spec.fetch('managed_uid_max', 60_000)

    @system.all_users.each_with_object([]) do |(name, uid), actions|
      next unless uid.between?(min_uid, max_uid)
      next if managed_names.include?(name)

      actions << Action.new(:remove_user, name, 'unmanaged account in provisioned UID range')
    end
  end

  def locked?(name)
    result = @runner.run('passwd', '-S', name)
    return false unless result.success

    # `passwd -S` second field is L (locked), NP (no password), or P (usable password)
    fields = result.stdout.split
    fields[1] == 'L'
  end

  def execute(action)
    case action.kind
    when :create_group then run!('groupadd', action.target)
    when :create_user   then create_user(action)
    when :remove_user   then run!('userdel', '-r', action.target)
    when :modify_shell  then run!('usermod', '--shell', shell_for(action), action.target)
    when :modify_comment then run!('usermod', '--comment', comment_for(action), action.target)
    when :lock           then run!('usermod', '--lock', action.target)
    when :unlock          then run!('usermod', '--unlock', action.target)
    when :add_to_groups then run!('usermod', '--append', '--groups', action.detail, action.target)
    when :install_ssh_key then install_ssh_key(action)
    else raise "unknown action kind #{action.kind}"
    end
  end

  # These two pull the value back out of the human-readable detail string
  # set during planning, so the plan/apply steps can't drift apart on what
  # the actual target value is.
  def shell_for(action) = action.detail.split(' -> ').last
  def comment_for(action) = action.detail.split(' -> ').last.gsub(/\A"|"\z/, '')

  def create_user(action)
    spec = @spec['users'].find { |u| u['name'] == action.target }
    cmd = ['useradd', '--create-home']
    cmd += ['--shell', spec['shell']] if spec['shell']
    cmd += ['--uid', spec['uid'].to_s] if spec['uid']
    cmd += ['--comment', spec['comment']] if spec['comment']
    cmd << action.target
    run!(*cmd)
  end

  def install_ssh_key(action)
    spec = @spec['users'].find { |u| u['name'] == action.target }
    home = spec['home'] || "/home/#{action.target}"
    ssh_dir = File.join(home, '.ssh')
    FileUtils.mkdir_p(ssh_dir, mode: 0o700)
    path = @system.authorized_keys_path(home)
    File.write(path, spec['ssh_authorized_key'].strip + "\n", mode: 'a')
    FileUtils.chmod(0o600, path)
    FileUtils.chown_R(action.target, action.target, ssh_dir) if Process.uid.zero?
  end

  def run!(*cmd)
    result = @runner.run(*cmd)
    @logger.call("  -> FAILED: #{cmd.join(' ')}: #{result.stderr}") unless result.success
    result
  end
end

# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  options = { apply: false }
  OptionParser.new do |opts|
    opts.banner = 'Usage: account_provisioner.rb --spec accounts.yml [--apply]'
    opts.on('--spec PATH', 'YAML spec of desired users/groups (required)') { |v| options[:spec] = v }
    opts.on('--apply', 'Actually make the changes (default: dry-run only)') { options[:apply] = true }
    opts.on('-h', '--help', 'Show this help') { puts opts; exit 0 }
  end.parse!(ARGV)

  unless options[:spec]
    warn 'error: --spec is required'
    exit 4
  end

  spec = YAML.safe_load_file(options[:spec])
  provisioner = AccountProvisioner.new(spec)
  actions = provisioner.plan

  if actions.empty?
    puts 'No drift detected -- system already matches spec.'
    exit 0
  end

  puts "#{actions.size} change(s) needed:"
  provisioner.apply!(actions, dry_run: !options[:apply])

  if !options[:apply]
    puts "\nDry run only -- re-run with --apply to make these changes."
  end
  exit 0
end
