require 'minitest/autorun'
require_relative 'win_service_recovery_audit'
class T < Minitest::Test
  def r(n) = evaluate(n, parse_qfailure(File.read("fixtures/#{n}.txt")))
  def test_ok;    assert_equal 'OK',   r('Spooler').sev; end
  def test_crit;  assert_equal 'CRIT', r('W32Time').sev; end
  def test_warn
    x = r('WinRM'); assert_equal 'WARN', x.sev
    assert(x.issues.any? { |i| i =~ /crash loop/ })
  end
  def test_infinite
    assert_includes r('EventLog').issues.join, 'never resets'
  end
  def test_parse
    p = parse_qfailure(File.read('fixtures/Spooler.txt'))
    assert_equal 86400, p[:reset_secs]; assert_equal [['RESTART',5000],['RESTART',5000],['NONE',0]], p[:actions]
  end
end
