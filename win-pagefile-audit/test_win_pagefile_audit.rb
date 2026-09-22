#!/usr/bin/env ruby
# frozen_string_literal: true
#
# test_win_pagefile_audit.rb -- verify the analysis logic WITHOUT Windows.
#
# win32ole only exists on Windows, so the WMI collection path cannot run on a
# Linux CI box. The script is written so that collection and analysis are
# separate objects: PagefileAuditor takes a plain Hash and returns findings, and
# MockCollector produces that Hash from a JSON fixture instead of from WMI.
#
# That means everything except the four WMI queries themselves is testable
# anywhere. Run this on Linux, macOS, or Windows:
#
#   ruby test_win_pagefile_audit.rb
#
# What is NOT covered here: the actual WIN32OLE.connect string, the WQL text,
# and property-name casing. Those must be smoke-tested on a real Windows host
# with `ruby win_pagefile_audit.rb --dump-raw`.

require 'minitest/autorun'
require 'json'

# Load the script without running its CLI (main only runs under __FILE__ == $0).
require_relative 'win_pagefile_audit'

FIXTURE = File.join(__dir__, 'fixtures', 'sample_hosts.json')

def host_named(name)
  JSON.parse(File.read(FIXTURE)).find { |h| h['host'] == name }
end

def checks_for(name)
  findings, = PagefileAuditor.new.audit(host_named(name))
  findings.map(&:check)
end

class TestPagefileAuditor < Minitest::Test
  # SQLPROD01: 256 GB RAM, system-managed, 4 GB pagefile, kernel dump selected,
  # 11 GB free on C:. This is the classic "we will get no dump" host.
  def test_large_host_system_managed_is_high
    assert_includes checks_for('SQLPROD01'), 'pagefile.automatic_managed'
    findings, = PagefileAuditor.new.audit(host_named('SQLPROD01'))
    f = findings.find { |x| x.check == 'pagefile.automatic_managed' }
    assert_equal 'high', f.severity, '256 GB host should escalate to high'
  end

  def test_kernel_dump_with_tiny_boot_pagefile_is_flagged
    assert_includes checks_for('SQLPROD01'), 'dump.pagefile_too_small'
  end

  def test_undersized_pagefile_flagged
    assert_includes checks_for('SQLPROD01'), 'pagefile.undersized'
  end

  def test_growth_window_flagged_when_max_exceeds_initial
    assert_includes checks_for('SQLPROD01'), 'pagefile.growth_window'
  end

  def test_peak_pressure_detected
    # 3990 of 4096 MB = 97%.
    findings, = PagefileAuditor.new.audit(host_named('SQLPROD01'))
    f = findings.find { |x| x.check == 'pagefile.peak_pressure' }
    refute_nil f
    assert_equal 'high', f.severity
  end

  def test_volume_headroom_flagged
    # C: has ~11 GB free, pagefile may grow another 60 GB.
    assert_includes checks_for('SQLPROD01'), 'pagefile.volume_headroom'
  end

  # APPWEB07: pagefile moved to D:, kernel dump still selected. Windows stages
  # kernel dumps through the BOOT volume pagefile, so this host gets nothing.
  def test_pagefile_off_boot_volume_breaks_kernel_dump
    assert_includes checks_for('APPWEB07'), 'dump.no_boot_volume_pagefile'
  end

  def test_no_overwrite_flagged
    assert_includes checks_for('APPWEB07'), 'dump.no_overwrite'
  end

  def test_well_sized_pagefile_not_flagged_as_undersized
    refute_includes checks_for('APPWEB07'), 'pagefile.undersized'
  end

  # DCEDGE02: no pagefile at all, dumps disabled.
  def test_absent_pagefile_detected
    assert_includes checks_for('DCEDGE02'), 'pagefile.absent'
  end

  def test_dump_disabled_detected
    assert_includes checks_for('DCEDGE02'), 'dump.disabled'
  end

  def test_dump_disabled_short_circuits_other_dump_checks
    c = checks_for('DCEDGE02')
    refute_includes c, 'dump.pagefile_too_small'
    refute_includes c, 'dump.no_boot_volume_pagefile'
  end

  # BUILD03: correctly configured. 32 GB RAM, 16 GB fixed pagefile on C:,
  # kernel dump, plenty of free space. Should be clean.
  def test_healthy_host_has_no_findings
    assert_empty checks_for('BUILD03'),
                 "expected a clean host, got: #{checks_for('BUILD03').join(', ')}"
  end

  # Boundary: the kernel-dump floor must scale, not sit at a flat number.
  def test_kernel_dump_floor_scales_with_ram
    a = PagefileAuditor.new
    assert_equal 2048, a.kernel_dump_floor_mb(2048), 'small hosts need RAM-sized staging'
    assert_equal 4608, a.kernel_dump_floor_mb(32 * 1024)
    assert_equal 33_280, a.kernel_dump_floor_mb(1024 * 1024), 'capped at 32 GB + 512 MB'
  end

  # The summary block is what the operator actually reads first.
  def test_summary_reports_dump_type_by_name
    _, summary = PagefileAuditor.new.audit(host_named('SQLPROD01'))
    assert_equal 'Kernel memory dump', summary['dump_type']
    assert_equal 262_144, summary['ram_mb']
  end
end

class TestMockCollector < Minitest::Test
  def test_selects_requested_host
    data = MockCollector.new(FIXTURE, 'BUILD03').collect
    assert_equal 'BUILD03', data['host']
  end

  def test_falls_back_to_first_host
    data = MockCollector.new(FIXTURE, 'NOSUCHHOST').collect
    assert_equal 'SQLPROD01', data['host']
  end
end
