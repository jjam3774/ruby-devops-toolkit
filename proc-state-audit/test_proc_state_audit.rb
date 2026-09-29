# frozen_string_literal: true
require 'minitest/autorun'
require 'tmpdir'
require 'json'
require 'open3'

class ProcStateAuditTest < Minitest::Test
  SCRIPT = File.expand_path('proc_state_audit.rb', __dir__)

  def stat_line(pid, comm, state, ppid)
    rest = Array.new(50, '0'); rest[0] = state; rest[1] = ppid.to_s
    "#{pid} (#{comm}) " + rest.join(' ')
  end

  def fixture(entries)
    dir = Dir.mktmpdir
    entries.each do |pid, comm, st, ppid, wchan|
      Dir.mkdir("#{dir}/#{pid}")
      File.write("#{dir}/#{pid}/stat", stat_line(pid, comm, st, ppid))
      File.write("#{dir}/#{pid}/wchan", wchan || '0')
    end
    dir
  end

  def run_audit(dir, *args)
    out, _e, st = Open3.capture3('ruby', SCRIPT, '--root', dir, '--json', *args)
    [JSON.parse(out), st.exitstatus]
  end

  def test_clean_host_is_ok
    r, code = run_audit(fixture([[1, 'init', 'S', 0], [2, 'bash', 'S', 1]]))
    assert_equal 'OK', r['status']; assert_equal 0, code
  end

  def test_zombies_grouped_by_parent
    d = fixture([[1, 'init', 'S', 0], [10, 'leaky', 'S', 1], [11, 'x', 'Z', 10], [12, 'y', 'Z', 10]])
    r, code = run_audit(d)
    assert_equal 'WARN', r['status']; assert_equal 1, code
    assert_equal 'leaky', r['zombie_parents'][0]['parent']
    assert_equal 2, r['zombie_parents'][0]['zombies']
  end

  def test_comm_with_parens_and_spaces
    r, = run_audit(fixture([[5, 'we ird) (name', 'Z', 1], [1, 'init', 'S', 0]]))
    assert_equal 1, r['zombie_count']
  end

  def test_many_dstate_is_crit
    d = fixture([[1, 'i', 'S', 0], [2, 'a', 'D', 1, 'nfs_wait'], [3, 'b', 'D', 1, 'nfs_wait'], [4, 'c', 'D', 1, 'io_schedule']])
    r, code = run_audit(d)
    assert_equal 'CRIT', r['status']; assert_equal 2, code
  end
end
