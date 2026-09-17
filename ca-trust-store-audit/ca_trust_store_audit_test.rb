#!/usr/bin/env ruby
# frozen_string_literal: true
#
# ca_trust_store_audit_test.rb -- generates a synthetic trust store with Ruby's
# own OpenSSL bindings (no `openssl` CLI needed) and asserts every rule fires.
#
# The real system store is genuinely useful to audit, but it is not a test:
# you cannot make it contain a CA:FALSE anchor or a 1024-bit key on demand.
# These fixtures are minted in-process, so each rule has exactly one
# unambiguous trigger.
#
#   ruby ca_trust_store_audit_test.rb

require 'openssl'
require 'fileutils'
require 'tmpdir'
require 'json'

SCRIPT = File.join(__dir__, 'ca_trust_store_audit.rb')

# --------------------------------------------------------------------------
# Certificate minting helpers
# --------------------------------------------------------------------------

# Build a self-signed certificate to spec. Every knob the auditor inspects is
# a parameter here, which is what lets one helper cover all six fixtures.
def mint(cn:, not_before:, not_after:, key: nil, digest: 'SHA256',
         ca: true, include_basic_constraints: true, key_usage: nil,
         issuer_cn: nil)
  key ||= OpenSSL::PKey::RSA.new(2048)
  cert = OpenSSL::X509::Certificate.new
  cert.version = 2
  cert.serial = rand(1..2**63)
  cert.subject = OpenSSL::X509::Name.parse("/C=XX/O=Fixture/CN=#{cn}")
  cert.issuer = OpenSSL::X509::Name.parse("/C=XX/O=Fixture/CN=#{issuer_cn || cn}")
  cert.public_key = key.public_key
  cert.not_before = not_before
  cert.not_after = not_after

  ef = OpenSSL::X509::ExtensionFactory.new
  ef.subject_certificate = cert
  ef.issuer_certificate = cert
  exts = []
  exts << ef.create_extension('basicConstraints', ca ? 'CA:TRUE' : 'CA:FALSE', true) if include_basic_constraints
  exts << ef.create_extension('keyUsage', key_usage, true) if key_usage
  cert.extensions = exts

  cert.sign(key, OpenSSL::Digest.new(digest))
  cert
end

NOW = Time.now

# RSA-1024 generation is rejected by OpenSSL 3 default policy in some builds;
# fall back to DSA-1024 if that happens so the weak-key path is still covered.
def weak_key
  OpenSSL::PKey::RSA.new(1024)
rescue OpenSSL::PKey::RSAError
  OpenSSL::PKey::DSA.new(1024)
end

FIXTURES = {
  # 1. Perfectly boring modern root. Must produce nothing.
  'good' => mint(cn: 'Fixture Good Root R1',
                 not_before: NOW - (365 * 86_400),
                 not_after: NOW + (3650 * 86_400),
                 key_usage: 'keyCertSign,cRLSign'),

  # 2. Expired three years ago.
  'expired' => mint(cn: 'Fixture Expired Root',
                    not_before: NOW - (3650 * 86_400),
                    not_after: NOW - (1095 * 86_400),
                    key_usage: 'keyCertSign,cRLSign'),

  # 3. Expires in 30 days -> inside the default 90-day window.
  'expiring' => mint(cn: 'Fixture Expiring Root',
                     not_before: NOW - (3650 * 86_400),
                     not_after: NOW + (30 * 86_400),
                     key_usage: 'keyCertSign,cRLSign'),

  # 4. 1024-bit key and a SHA-1 self-signature: legacy on both axes.
  'weak' => mint(cn: 'Fixture Legacy 1024 Root',
                 not_before: NOW - (3650 * 86_400),
                 not_after: NOW + (365 * 86_400),
                 key: weak_key, digest: 'SHA1',
                 key_usage: 'keyCertSign,cRLSign'),

  # 5. A leaf certificate someone installed as an anchor.
  'leaf' => mint(cn: 'internal-api.corp.example',
                 not_before: NOW - (30 * 86_400),
                 not_after: NOW + (335 * 86_400),
                 ca: false, key_usage: 'digitalSignature,keyEncipherment'),

  # 6. Ancient-style root: no basicConstraints, no keyUsage, 40-year validity.
  'ancient' => mint(cn: 'Fixture Ancient Root',
                    not_before: NOW - (20 * 365 * 86_400),
                    not_after: NOW + (20 * 365 * 86_400),
                    include_basic_constraints: false)
}.freeze

EXPECTED = {
  'Fixture Good Root R1'       => [],
  'Fixture Expired Root'       => %w[ANCHOR_EXPIRED],
  'Fixture Expiring Root'      => %w[ANCHOR_EXPIRING],
  'Fixture Legacy 1024 Root'   => %w[WEAK_KEY WEAK_SELF_SIGNATURE],
  'internal-api.corp.example'  => %w[NOT_A_CA NO_CERT_SIGN],
  'Fixture Ancient Root'       => %w[NO_BASIC_CONSTRAINTS LONG_VALIDITY]
}.freeze

failures = []
def check(failures, label)
  ok = begin
    yield
  rescue StandardError => e
    puts "    (raised #{e.class}: #{e.message})"
    false
  end
  puts format('  %-58s %s', label, ok ? 'PASS' : 'FAIL')
  failures << label unless ok
end

Dir.mktmpdir('cafix') do |root|
  # The distro-shipped bundle: one concatenated PEM file.
  bundle = File.join(root, 'ca-certificates.crt')
  File.write(bundle, FIXTURES.values_at('good', 'expired', 'expiring', 'weak', 'ancient')
                             .map(&:to_pem).join)

  # The locally-added anchor directory: one file per cert.
  local = File.join(root, 'local-anchors')
  FileUtils.mkdir_p(local)
  File.write(File.join(local, 'internal-api.crt'), FIXTURES['leaf'].to_pem)

  # A deliberately corrupt entry, appended to the bundle. One bad block must
  # not cost us the other five certificates.
  File.write(bundle, "-----BEGIN CERTIFICATE-----\nnot-base64-at-all!!!\n" \
                     "-----END CERTIFICATE-----\n", mode: 'a')

  puts "fixture store: #{root}"
  puts

  cmd = "ruby #{SCRIPT} --bundle #{bundle} --dir #{local} --local-dir #{local} --json 2>&1"
  out = `#{cmd}`
  status = $?.exitstatus
  begin
    data = JSON.parse(out)
  rescue JSON::ParserError
    puts 'FATAL: script did not emit valid JSON:'
    puts out
    exit 1
  end

  by_anchor = data['findings'].group_by { |f| f['anchor'] }

  puts 'per-anchor expectations'
  EXPECTED.each do |cn, expected|
    got = (by_anchor[cn] || []).map { |f| f['code'] }.reject { |c| c == 'LOCALLY_ADDED' }.sort
    check(failures, "#{cn} -> #{expected.empty? ? '(clean)' : expected.sort.join(',')}") do
      got == expected.sort
    end
  end

  puts
  puts 'provenance detection'
  check(failures, 'anchor from the local dir is flagged LOCALLY_ADDED') do
    (by_anchor['internal-api.corp.example'] || []).any? { |f| f['code'] == 'LOCALLY_ADDED' }
  end
  check(failures, 'anchors from the distro bundle are NOT flagged local') do
    data['findings'].none? do |f|
      f['code'] == 'LOCALLY_ADDED' && f['anchor'] != 'internal-api.corp.example'
    end
  end
  check(failures, 'summary counts exactly one locally-added anchor') do
    data['summary']['locally_added'] == 1
  end

  puts
  puts 'parsing robustness'
  check(failures, 'all 6 certificates parsed despite a corrupt PEM block') do
    data['anchors'].length == 6
  end
  check(failures, 'the corrupt block is reported, not silently dropped') do
    data['parse_errors'].length == 1 && data['parse_errors'][0].include?('ca-certificates.crt')
  end
  check(failures, 'key size and type extracted per anchor') do
    good = data['anchors'].find { |a| a['subject'] == 'Fixture Good Root R1' }
    good['key_type'] == 'RSA' && good['key_bits'] == 2048
  end
  check(failures, 'weak anchor reported at 1024 bits') do
    w = data['anchors'].find { |a| a['subject'] == 'Fixture Legacy 1024 Root' }
    w['key_bits'] == 1024
  end
  check(failures, 'basicConstraints CA:FALSE captured as is_ca=false') do
    leaf = data['anchors'].find { |a| a['subject'] == 'internal-api.corp.example' }
    leaf['is_ca'] == false && leaf['has_basic_constraints'] == true
  end
  check(failures, 'absent basicConstraints captured distinctly from CA:FALSE') do
    anc = data['anchors'].find { |a| a['subject'] == 'Fixture Ancient Root' }
    anc['has_basic_constraints'] == false
  end
  check(failures, 'negative days_until_expiry for an expired anchor') do
    e = data['anchors'].find { |a| a['subject'] == 'Fixture Expired Root' }
    e['days_until_expiry'] < 0
  end

  puts
  puts 'deduplication'
  # Same cert in both the bundle and the local dir: one anchor, two sources.
  dup_local = File.join(root, 'dup')
  FileUtils.mkdir_p(dup_local)
  File.write(File.join(dup_local, 'good.pem'), FIXTURES['good'].to_pem)
  dup = JSON.parse(`ruby #{SCRIPT} --bundle #{bundle} --dir #{dup_local} --json 2>&1`)
  check(failures, 'identical cert in two files collapses to one anchor') do
    dup['anchors'].count { |a| a['subject'] == 'Fixture Good Root R1' } == 1
  end
  check(failures, 'both file paths recorded as sources for that anchor') do
    g = dup['anchors'].find { |a| a['subject'] == 'Fixture Good Root R1' }
    g['sources'].length == 2
  end

  puts
  puts 'cli behaviour'
  check(failures, 'exit code 2 when a critical finding exists') { status == 2 }
  hi = JSON.parse(`ruby #{SCRIPT} --bundle #{bundle} --dir #{local} --local-dir #{local} --json --min-severity high 2>&1`)
  check(failures, '--min-severity high suppresses medium and low') do
    hi['findings'].map { |f| f['severity'] }.uniq.sort == %w[critical high]
  end
  wide = JSON.parse(`ruby #{SCRIPT} --bundle #{bundle} --expiry-days 3650 --json 2>&1`)
  check(failures, '--expiry-days widens the warning window') do
    wide['findings'].count { |f| f['code'] == 'ANCHOR_EXPIRING' } >= 2
  end
  `ruby #{SCRIPT} --bundle /nonexistent/path.crt >/dev/null 2>&1`
  check(failures, 'unreadable bundle exits 3, not a backtrace') { $?.exitstatus == 3 }

  puts
  puts 'text renderer'
  text = `ruby #{SCRIPT} --bundle #{bundle} --dir #{local} --local-dir #{local} 2>&1`
  check(failures, 'histogram lines present in text output') do
    text.include?('keys:') && text.include?('signatures:')
  end
  check(failures, 'next-expiry line names the soonest non-expired anchor') do
    text.include?('next expiry') && text.include?('Fixture Expiring Root')
  end
end

puts
if failures.empty?
  puts "ALL CHECKS PASSED (#{EXPECTED.size} anchors, every rule exercised)"
  exit 0
else
  puts "#{failures.length} FAILURE(S):"
  failures.each { |f| puts "  - #{f}" }
  exit 1
end
