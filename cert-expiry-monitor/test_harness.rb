#!/usr/bin/env ruby
# Spins up 3 local TLS servers with self-signed certs of different expiry
# windows, then shells out to cert_expiry_monitor.rb against them (plus one
# unreachable port) to prove OK/WARN/CRIT classification and exit codes.
require 'openssl'
require 'socket'

def make_cert(days_from_now)
  key = OpenSSL::PKey::RSA.new(2048)
  cert = OpenSSL::X509::Certificate.new
  cert.version = 2
  cert.serial = rand(1..10_000)
  name = OpenSSL::X509::Name.parse('/CN=localhost')
  cert.subject = name
  cert.issuer = name
  cert.public_key = key.public_key
  cert.not_before = Time.now - 3600
  cert.not_after = Time.now + (days_from_now * 86_400)
  cert.sign(key, OpenSSL::Digest.new('SHA256'))
  [cert, key]
end

servers = []
ports = []

[[9101, 60], [9102, 15], [9103, 3]].each do |port, days|
  cert, key = make_cert(days)
  ctx = OpenSSL::SSL::SSLContext.new
  ctx.cert = cert
  ctx.key = key
  tcp = TCPServer.new('127.0.0.1', port)
  ssl_server = OpenSSL::SSL::SSLServer.new(tcp, ctx)
  servers << Thread.new do
    loop do
      begin
        conn = ssl_server.accept
        conn.sysclose
      rescue StandardError
        break
      end
    end
  end
  ports << port
end

sleep 0.5

cmd = "ruby #{__dir__}/cert_expiry_monitor.rb 127.0.0.1:9101 127.0.0.1:9102 127.0.0.1:9103 127.0.0.1:9199 --warn-days 30 --crit-days 7"
puts "+ #{cmd}"
system(cmd)
text_exit = $?.exitstatus
puts "\nexit code: #{text_exit}"

puts "\n--- JSON mode ---"
cmd_json = "ruby #{__dir__}/cert_expiry_monitor.rb 127.0.0.1:9101 127.0.0.1:9102 127.0.0.1:9103 --json"
system(cmd_json)

exit 0
