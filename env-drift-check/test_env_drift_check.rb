require 'minitest/autorun'
require_relative 'env_drift_check'
class T < Minitest::Test
  def setup; @t, = parse_env(File.read('examples/.env.example')); end
  def test_prod
    a, d = parse_env(File.read('examples/prod.env')); r = compare(@t, a, d)
    assert_equal ['REDIS_URL'], r[:missing]; assert_equal ['LEGACY_FLAG'], r[:extra]
    assert_equal ['SECRET_KEY'], r[:placeholder]; assert_equal ['LOG_LEVEL'], r[:duplicate]
  end
  def test_staging_clean
    a, d = parse_env(File.read('examples/staging.env')); r = compare(@t, a, d)
    assert r.values.all?(&:empty?)
    assert_equal 'redis://stg:6379', a['REDIS_URL']
  end
end
