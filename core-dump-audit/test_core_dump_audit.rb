# frozen_string_literal: true
require 'minitest/autorun'
require 'tmpdir'
require 'fileutils'
require 'json'
require 'open3'

class CoreDumpAuditTest < Minitest::Test
  SCRIPT = File.expand_path('core_dump_audit.rb', __dir__)

  def tree(pattern:, suid: '0', limits: nil, dump_mb: 0)
    r = Dir.mktmpdir
    FileUtils.mkdir_p("#{r}/proc/sys/kernel"); FileUtils.mkdir_p("#{r}/proc/sys/fs")
    File.write("#{r}/proc/sys/kernel/core_pattern", pattern)
    File.write("#{r}/proc/sys/fs/suid_dumpable", suid)
    if limits
      FileUtils.mkdir_p("#{r}/etc/security/limits.d"); File.write("#{r}/etc/security/limits.d/99-core.conf", limits)
    end
    if dump_mb > 0
      FileUtils.mkdir_p("#{r}/var/lib/systemd/coredump")
      File.open("#{r}/var/lib/systemd/coredump/core.a.zst", 'wb') { |f| f.truncate(dump_mb * 1_048_576) }
    end
    r
  end

  def audit(root, *a)
    out, _e, st = Open3.capture3('ruby', SCRIPT, '--root', root, '--json', *a)
    [JSON.parse(out), st.exitstatus]
  end

  def test_healthy_host
    r, code = audit(tree(pattern: '|/lib/systemd/systemd-coredump %P %u %g %s %t %c %h'))
    assert_equal 'OK', r['overall']; assert_equal 0, code
  end

  def test_relative_pattern_warns
    r, code = audit(tree(pattern: 'core'))
    assert_equal 1, code
    assert(r['findings'].any? { |f| f['check'] == 'core_pattern' && f['sev'] == 'WARN' })
  end

  def test_unknown_pipe_handler_warns
    r, = audit(tree(pattern: '|/opt/evil/handler %p'))
    assert(r['findings'].any? { |f| f['check'] == 'core_pattern' && f['sev'] == 'WARN' })
  end

  def test_suid_dumpable_1_is_crit
    _r, code = audit(tree(pattern: '/var/core/%e', suid: '1'))
    assert_equal 2, code
  end

  def test_unlimited_core_limit
    r, = audit(tree(pattern: '/var/core/%e', limits: "* soft core unlimited\n"))
    assert(r['findings'].any? { |f| f['check'] == 'limits' && f['sev'] == 'WARN' })
  end

  def test_dump_directory_size_thresholds
    r, = audit(tree(pattern: '/var/core/%e', dump_mb: 20), '--dump-warn-mb', '10', '--dump-crit-mb', '50')
    d = r['findings'].find { |f| f['check'].start_with?('dumps:') }
    assert_equal 'WARN', d['sev']
    r, code = audit(tree(pattern: '/var/core/%e', dump_mb: 60), '--dump-warn-mb', '10', '--dump-crit-mb', '50')
    assert_equal 2, code
  end
end
