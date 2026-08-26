#!/usr/bin/env ruby
# frozen_string_literal: true
#
# windows_software_inventory_test.rb — exercises the analysis rules with
# realistic Program fixtures. No Windows, no registry, no win32ole required.
# This is how the detection logic was verified before publishing, since the
# collector needs a real Windows registry.
#
#   ruby windows_software_inventory_test.rb

require "minitest/autorun"
require_relative "windows_software_inventory"

def prog(over = {})
  Program.new(**{
    name: "Notepad++ (64-bit)",
    version: "8.6.2",
    publisher: "Notepad++ Team",
    install_date: "20260101",
    arch: "x64"
  }.merge(over))
end

class InventoryRulesTest < Minitest::Test
  def codes(programs, watch = DEFAULT_WATCH)
    audit(programs, watch).map { |f| [f[:code], f[:severity]] }
  end

  def test_clean_program_produces_no_findings
    assert_empty audit([prog], DEFAULT_WATCH)
  end

  def test_watchlist_match_is_critical
    c = codes([prog(name: "TeamViewer 15")])
    assert_includes c, ["watchlist-match", :crit]
  end

  def test_watchlist_match_is_case_insensitive
    c = codes([prog(name: "anydesk", publisher: "AnyDesk")])
    assert_includes c, ["watchlist-match", :crit]
  end

  def test_eol_java_matches_watchlist
    assert_includes codes([prog(name: "Java 8 Update 411", publisher: "Oracle")]),
                    ["watchlist-match", :crit]
  end

  def test_missing_publisher_warns
    assert_includes codes([prog(publisher: "")]), ["no-publisher", :warn]
  end

  def test_missing_version_warns
    assert_includes codes([prog(version: nil)]), ["no-version", :warn]
  end

  def test_custom_watchlist_overrides_default
    # With a custom watchlist, TeamViewer is no longer flagged but "Acme" is.
    c = codes([prog(name: "TeamViewer 15"), prog(name: "Acme Widget")], ["Acme"])
    refute_includes c, ["watchlist-match", :crit] if c.count { |x| x[0] == "watchlist-match" } != 1
    matches = audit([prog(name: "TeamViewer 15"), prog(name: "Acme Widget")], ["Acme"])
                .select { |f| f[:code] == "watchlist-match" }
    assert_equal 1, matches.size
    assert_match(/Acme/, matches.first[:name])
  end

  def test_summary_counts_architectures
    s = summarise([prog(arch: "x64"), prog(arch: "x86"), prog(arch: "x86", publisher: "")])
    assert_equal 3, s[:total]
    assert_equal 1, s[:x64]
    assert_equal 2, s[:x86]
    assert_equal 1, s[:no_publisher]
  end
end
