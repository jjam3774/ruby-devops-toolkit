# frozen_string_literal: true
require 'minitest/autorun'
require 'tmpdir'
require 'fileutils'
require 'json'
require 'open3'

# Runs the real script against fixture w32tm output (no Windows needed).
class TimeAuditTest < Minitest::Test
  SCRIPT = File.expand_path('win_time_service_audit.rb', __dir__)
  FIX = File.expand_path('fixtures', __dir__)

  def run_with(dir, *args)
    out, _e, st = Open3.capture3('ruby', SCRIPT, '--fixture', dir, '--json', *args)
    [JSON.parse(out), st.exitstatus]
  end

  # Copy the good fixture and stamp a sync time N hours ago so the test is deterministic.
  def good_fixture(hours_ago)
    d = Dir.mktmpdir
    FileUtils.cp_r(Dir["#{FIX}/good/*"], d)
    t = (Time.now - hours_ago * 3600).strftime('%-m/%-d/%Y %-I:%M:%S %p')
    s = File.read("#{d}/status.txt").sub(/^Last Successful Sync Time:.*$/, "Last Successful Sync Time: #{t}")
    File.write("#{d}/status.txt", s)
    d
  end

  def test_fresh_sync_passes
    r, code = run_with(good_fixture(1))
    assert_equal 'PASS', r['overall']; assert_equal 0, code
  end

  def test_stale_sync_warns_then_fails
    assert_equal 'WARN', run_with(good_fixture(30))[0]['overall']
    r, code = run_with(good_fixture(60))
    assert_equal 'FAIL', r['overall']; assert_equal 2, code
  end

  def test_bad_fixture_fails_on_cmos_and_disabled_client
    r, code = run_with("#{FIX}/bad")
    assert_equal 2, code
    checks = r['findings'].select { |f| f['sev'] == 'FAIL' }.map { |f| f['check'] }
    assert_includes checks, 'source'; assert_includes checks, 'ntpclient'
  end

  def test_standalone_expects_ntp_type
    r, = run_with(good_fixture(1), '--standalone')
    assert r['findings'].any? { |f| f['check'] == 'client-type' && f['sev'] == 'WARN' }
  end
end
