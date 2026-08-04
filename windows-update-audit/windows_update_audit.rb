#!/usr/bin/env ruby
# frozen_string_literal: true
#
# windows_update_audit.rb
#
# Audits Windows Update compliance on a live host via the Windows Update
# Agent COM API and WMI -- no PowerShell, no third-party gems. It answers
# the three questions a patch-compliance dashboard actually cares about:
#
#   1. Are there uninstalled updates, and how severe are they (Critical /
#      Important / Moderate / Low, per Microsoft's MSRC rating)?
#   2. Is the machine sitting on a pending reboot that's blocking updates
#      already downloaded from taking effect?
#   3. How long has it been since the last hotfix was actually installed?
#      (A quiet Windows Update service can look "compliant" while
#      silently having stopped working weeks ago -- staleness catches
#      that a green "0 pending updates" count would miss.)
#
# Because the Windows Update Agent COM API (Microsoft.Update.Session) and
# Win32_QuickFixEngineering only exist on Windows, the analysis logic is
# split from the collection logic: WmiCollector gathers a SystemSnapshot
# from the live machine (Windows only), and Analyzer classifies any
# SystemSnapshot -- live or loaded from a --fixture JSON file -- into
# OK/WARN/CRIT. That split is also a real feature, not just a test seam:
# `--export` lets a scheduled task on each Windows box drop a snapshot to
# a shared folder, and `--fixture` lets a central Linux/macOS box roll
# those snapshots up into one fleet-wide compliance report.
#
# Usage:
#   ruby windows_update_audit.rb [--export FILE]                 (Windows, live)
#   ruby windows_update_audit.rb --fixture FILE [--json]          (any OS, offline)
#
require 'json'
require 'time'
require 'optparse'

# ---------------------------------------------------------------------------
# Plain data structures shared by the live collector and the fixture loader,
# so Analyzer never has to know or care where a snapshot came from.
# ---------------------------------------------------------------------------
PendingUpdate = Struct.new(:title, :kb_ids, :severity, :is_downloaded, keyword_init: true) do
  def to_h_public
    { title: title, kb_ids: kb_ids, severity: severity, is_downloaded: is_downloaded }
  end
end

Hotfix = Struct.new(:hotfix_id, :installed_on, :description, keyword_init: true)

SystemSnapshot = Struct.new(:hostname, :pending_updates, :hotfixes, :reboot_required,
                             :collected_at, keyword_init: true) do
  def self.from_h(h)
    new(
      hostname: h['hostname'] || h[:hostname],
      reboot_required: h['reboot_required'].nil? ? h[:reboot_required] : h['reboot_required'],
      collected_at: (h['collected_at'] || h[:collected_at]),
      pending_updates: (h['pending_updates'] || h[:pending_updates] || []).map do |u|
        PendingUpdate.new(title: u['title'] || u[:title], kb_ids: u['kb_ids'] || u[:kb_ids],
                           severity: u['severity'] || u[:severity],
                           is_downloaded: u['is_downloaded'].nil? ? u[:is_downloaded] : u['is_downloaded'])
      end,
      hotfixes: (h['hotfixes'] || h[:hotfixes] || []).map do |hf|
        Hotfix.new(hotfix_id: hf['hotfix_id'] || hf[:hotfix_id],
                   installed_on: hf['installed_on'] || hf[:installed_on],
                   description: hf['description'] || hf[:description])
      end
    )
  end

  def to_h_public
    {
      hostname: hostname,
      collected_at: collected_at,
      reboot_required: reboot_required,
      pending_updates: pending_updates.map(&:to_h_public),
      hotfixes: hotfixes.map(&:to_h)
    }
  end
end

# ---------------------------------------------------------------------------
# WmiCollector: talks to a live Windows machine via WIN32OLE. Only ever
# instantiated/called when running on Windows -- see the CLI section.
# ---------------------------------------------------------------------------
class WmiCollector
  def collect
    require 'win32ole'

    session = WIN32OLE.new('Microsoft.Update.Session')
    searcher = session.CreateUpdateSearcher
    result = searcher.Search('IsInstalled=0 and IsHidden=0')

    pending = []
    result.Updates.each do |u|
      kb_ids = []
      u.KBArticleIDs.each { |kb| kb_ids << "KB#{kb}" }
      pending << PendingUpdate.new(
        title: u.Title,
        kb_ids: kb_ids,
        severity: u.MsrcSeverity.nil? || u.MsrcSeverity.empty? ? 'Unspecified' : u.MsrcSeverity,
        is_downloaded: u.IsDownloaded
      )
    end

    sysinfo = WIN32OLE.new('Microsoft.Update.SystemInfo')
    reboot_required = sysinfo.RebootRequired

    wmi = WIN32OLE.connect('winmgmts://./root/cimv2')
    hotfixes = []
    wmi.ExecQuery('SELECT HotFixID, InstalledOn, Description FROM Win32_QuickFixEngineering').each do |h|
      hotfixes << Hotfix.new(hotfix_id: h.HotFixID, installed_on: h.InstalledOn, description: h.Description)
    end

    SystemSnapshot.new(
      hostname: ENV['COMPUTERNAME'] || 'localhost',
      pending_updates: pending,
      hotfixes: hotfixes,
      reboot_required: reboot_required,
      collected_at: Time.now.utc.iso8601
    )
  end
end

# ---------------------------------------------------------------------------
# Analyzer: pure logic, no WMI/COM dependency, fully unit-testable on any
# platform against fixture snapshots. Classifies a SystemSnapshot into
# OK/WARN/CRIT with the specific reasons that drove the verdict.
# ---------------------------------------------------------------------------
class Analyzer
  SEVERITY_ORDER = { 'Critical' => 3, 'Important' => 2, 'Moderate' => 1, 'Low' => 0, 'Unspecified' => 0 }.freeze

  def initialize(warn_days: 45, crit_days: 90)
    @warn_days = warn_days
    @crit_days = crit_days
  end

  Verdict = Struct.new(:status, :reasons, :days_since_last_patch, keyword_init: true)

  def classify(snapshot)
    reasons = []
    status = 'OK'

    critical_pending = snapshot.pending_updates.select { |u| SEVERITY_ORDER[u.severity].to_i >= 3 }
    important_pending = snapshot.pending_updates.select { |u| SEVERITY_ORDER[u.severity].to_i == 2 }

    unless critical_pending.empty?
      status = 'CRIT'
      reasons << "#{critical_pending.size} Critical-severity update(s) pending: " \
                 "#{critical_pending.map { |u| u.kb_ids.join('/') }.join(', ')}"
    end

    unless important_pending.empty?
      status = worse(status, 'WARN')
      reasons << "#{important_pending.size} Important-severity update(s) pending"
    end

    if snapshot.reboot_required
      status = worse(status, 'WARN')
      reasons << 'reboot pending -- downloaded updates are not yet active'
    end

    days_since_last_patch = compute_days_since_last_patch(snapshot.hotfixes)
    if days_since_last_patch
      if days_since_last_patch >= @crit_days
        status = 'CRIT'
        reasons << "#{days_since_last_patch} days since the last installed hotfix (>= #{@crit_days}-day CRIT threshold)"
      elsif days_since_last_patch >= @warn_days
        status = worse(status, 'WARN')
        reasons << "#{days_since_last_patch} days since the last installed hotfix (>= #{@warn_days}-day WARN threshold)"
      end
    else
      status = worse(status, 'WARN')
      reasons << 'no hotfix install history found -- cannot confirm patching is active'
    end

    reasons << 'no issues found' if reasons.empty?
    Verdict.new(status: status, reasons: reasons, days_since_last_patch: days_since_last_patch)
  end

  private

  def worse(current, candidate)
    order = { 'OK' => 0, 'WARN' => 1, 'CRIT' => 2 }
    order[candidate] > order[current] ? candidate : current
  end

  # Win32_QuickFixEngineering's InstalledOn comes back as a locale-dependent
  # date string (e.g. "8/12/2026") rather than a WMI CIM_DATETIME, so we
  # parse defensively and skip anything we can't confidently read rather
  # than raising and aborting the whole audit over one bad row.
  def compute_days_since_last_patch(hotfixes)
    dates = hotfixes.filter_map { |h| parse_installed_on(h.installed_on) }
    return nil if dates.empty?

    (Date.today - dates.max).to_i
  end

  # Win32_QuickFixEngineering.InstalledOn is a locale-dependent string, not
  # a CIM_DATETIME -- on a US-locale Windows box it comes back M/D/YYYY
  # (e.g. "7/10/2026" for July 10th). Ruby's Date.parse is the wrong tool
  # here: for slash-separated dates it guesses D/M/Y, so "7/10/2026" comes
  # back as October 7th, silently 3 months off. We parse M/D/Y explicitly
  # first (the common case) and only fall back to Date.parse for ISO-ish
  # strings a --fixture file or a non-US locale might supply.
  def parse_installed_on(raw)
    return nil if raw.nil? || raw.to_s.strip.empty?

    str = raw.to_s.strip
    begin
      Date.strptime(str, '%m/%d/%Y')
    rescue ArgumentError, Date::Error
      begin
        Date.parse(str)
      rescue ArgumentError, Date::Error
        nil
      end
    end
  end
end

require 'date'

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  options = { json: false, warn_days: 45, crit_days: 90 }

  parser = OptionParser.new do |opts|
    opts.banner = 'Usage: ruby windows_update_audit.rb [--fixture FILE] [--export FILE] [options]'
    opts.on('--fixture FILE', 'Analyze a previously-exported JSON snapshot instead of live WMI') { |v| options[:fixture] = v }
    opts.on('--export FILE', 'Also write the live-collected snapshot to FILE as JSON') { |v| options[:export] = v }
    opts.on('--warn-days N', Integer, 'Days-since-last-patch WARN threshold (default: 45)') { |v| options[:warn_days] = v }
    opts.on('--crit-days N', Integer, 'Days-since-last-patch CRIT threshold (default: 90)') { |v| options[:crit_days] = v }
    opts.on('--json', 'Emit machine-readable JSON') { options[:json] = true }
  end
  parser.parse!(ARGV)

  snapshot =
    if options[:fixture]
      SystemSnapshot.from_h(JSON.parse(File.read(options[:fixture])))
    elsif RUBY_PLATFORM =~ /mingw|mswin|windows/i
      snap = WmiCollector.new.collect
      File.write(options[:export], JSON.pretty_generate(snap.to_h_public)) if options[:export]
      snap
    else
      warn "error: live WMI collection requires Windows (RUBY_PLATFORM=#{RUBY_PLATFORM}). " \
           'Pass --fixture FILE to analyze a snapshot collected elsewhere.'
      exit 2
    end

  verdict = Analyzer.new(warn_days: options[:warn_days], crit_days: options[:crit_days]).classify(snapshot)

  if options[:json]
    puts JSON.pretty_generate(
      hostname: snapshot.hostname,
      status: verdict.status,
      days_since_last_patch: verdict.days_since_last_patch,
      reboot_required: snapshot.reboot_required,
      pending_update_count: snapshot.pending_updates.size,
      reasons: verdict.reasons
    )
  else
    puts "host: #{snapshot.hostname}   status: #{verdict.status}"
    puts "pending updates: #{snapshot.pending_updates.size}   reboot required: #{snapshot.reboot_required}   " \
         "days since last patch: #{verdict.days_since_last_patch || 'unknown'}"
    puts '-' * 70
    verdict.reasons.each { |r| puts "  - #{r}" }
  end

  exit({ 'OK' => 0, 'WARN' => 1, 'CRIT' => 2 }[verdict.status])
end
