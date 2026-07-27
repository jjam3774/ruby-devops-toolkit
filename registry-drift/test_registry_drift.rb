#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Minitest harness for registry_drift.rb's DriftAuditor logic. This is the
# "stub/mock" verification mentioned in the tutorial: Win32::Registry only
# exists on Windows, so instead of skipping tests entirely we swap in
# SnapshotRegistryReader (a plain Hash-backed fake) that satisfies the same
# #read(hive, path, value) interface. That lets CI/any dev machine exercise
# every branch of the comparison logic (pass, drift, missing, type
# coercion) with zero dependency on a real Windows box.

require 'minitest/autorun'
require 'tempfile'
require_relative 'registry_drift'

class DriftAuditorTest < Minitest::Test
  def check(expected, name: 'test check')
    BaselineCheck.new(name, 'HKEY_LOCAL_MACHINE', 'SOFTWARE\\Test', 'Value', expected, 'high')
  end

  def test_pass_when_values_match
    reader = SnapshotRegistryReader.new('HKEY_LOCAL_MACHINE\\SOFTWARE\\Test\\Value' => 1)
    result = DriftAuditor.new(reader).audit([check(1)]).first
    assert_equal :pass, result.status
  end

  def test_drift_when_values_differ
    reader = SnapshotRegistryReader.new('HKEY_LOCAL_MACHINE\\SOFTWARE\\Test\\Value' => 0)
    result = DriftAuditor.new(reader).audit([check(1)]).first
    assert_equal :drift, result.status
    assert result.drifted?
  end

  def test_missing_when_key_absent_from_snapshot
    reader = SnapshotRegistryReader.new({})
    result = DriftAuditor.new(reader).audit([check(1)]).first
    assert_equal :missing, result.status
    assert result.drifted?
  end

  def test_string_and_integer_are_compared_after_normalization
    # JSON round-tripping can turn "1" into the string "1" in a snapshot; a
    # real registry DWORD read back would be the Integer 1. Both should be
    # treated as a match rather than a false-positive drift.
    reader = SnapshotRegistryReader.new('HKEY_LOCAL_MACHINE\\SOFTWARE\\Test\\Value' => '1')
    result = DriftAuditor.new(reader).audit([check(1)]).first
    assert_equal :pass, result.status
  end

  def test_multi_value_string_match
    reader = SnapshotRegistryReader.new(
      'HKEY_LOCAL_MACHINE\\SOFTWARE\\Test\\Value' => 'Bowser,MRxSmb20,NSI'
    )
    result = DriftAuditor.new(reader).audit([check('Bowser,MRxSmb20,NSI')]).first
    assert_equal :pass, result.status
  end

  def test_load_baseline_rejects_malformed_json
    Tempfile.create(['baseline', '.json']) do |f|
      f.write('not valid json')
      f.flush
      err = capture_io { assert_raises(SystemExit) { load_baseline(f.path) } }
      refute_nil err
    end
  end
end
