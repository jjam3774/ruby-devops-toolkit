#!/usr/bin/env ruby
# Small mock server used only to test api_health_check.rb locally.
# Not part of the published tutorial code -- for sandbox verification only.
require 'webrick'
require 'json'

port = (ARGV[0] || 9292).to_i
flaky_hits = 0

server = WEBrick::HTTPServer.new(Port: port, Logger: WEBrick::Log.new(File::NULL), AccessLog: [])

server.mount_proc '/healthy' do |_req, res|
  res.status = 200
  res.body = '{"ok": true}'
end

server.mount_proc '/down' do |_req, res|
  res.status = 500
  res.body = '{"ok": false}'
end

# Fails twice, then succeeds -- exercises the retry/backoff path.
server.mount_proc '/flaky' do |_req, res|
  flaky_hits += 1
  if flaky_hits <= 2
    res.status = 503
    res.body = '{"ok": false}'
  else
    res.status = 200
    res.body = '{"ok": true}'
  end
end

server.mount_proc '/badbody' do |_req, res|
  res.status = 200
  res.body = '{"ok": false, "reason": "degraded"}'
end

trap('INT') { server.shutdown }
server.start
