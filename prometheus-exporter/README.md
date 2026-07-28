# prometheus_exporter.rb

A minimal Prometheus "node exporter" written in pure Ruby: it reads system stats straight from `/proc`, serves them as an HTTP `/metrics` endpoint in the Prometheus text exposition format, and needs nothing but the standard library — no `prometheus-client` gem, no Sinatra, no WEBrick.

## Why this exists

Every monitoring stack eventually needs "just one more metric" from a box that doesn't have an exporter for it — a custom queue depth, an app-specific counter, a stat some vendor exporter doesn't expose. Reaching for a full framework for that is overkill. This script shows the whole exporter pattern (registry → collectors → HTTP handler → text format) in ~150 lines you can read in one sitting and bolt custom metrics onto directly.

## Prerequisites

- Ruby >= 2.7 (tested on 3.0.2, stdlib only: `socket`, `optparse` — no gems required)
- Linux, for the bundled `/proc`-based collectors (the registry and HTTP server themselves are portable to any OS — see Troubleshooting)
- A Prometheus server (or just `curl`) to scrape the endpoint

## Usage

```
ruby prometheus_exporter.rb --port 9200
curl http://localhost:9200/metrics
```

Then point Prometheus at it with a scrape config:

```yaml
scrape_configs:
  - job_name: 'ruby_node_exporter'
    static_configs:
      - targets: ['localhost:9200']
```

## How it works

1. **Register** — `registry.gauge(name, help) { block }` and `registry.counter(...)` attach a name, HELP text, a Prometheus type, and a lazily-evaluated value source.
2. **Listen** — `Exporter#start` opens a `TCPServer` on the configured port and spawns a new `Thread` per accepted connection.
3. **Parse** — each handler reads the request line (`GET /metrics HTTP/1.1`), drains headers up to the blank line, and checks the path.
4. **Render** — on a `/metrics` hit, `MetricsRegistry#render` calls every metric's value block fresh and formats each as `# HELP` / `# TYPE` / `name value`, per the Prometheus text exposition format.
5. **Respond** — a minimal but correct HTTP/1.1 response is written back with `Content-Type: text/plain; version=0.0.4`, exactly what Prometheus expects.

## Example output

```
$ ruby prometheus_exporter.rb --port 9200
prometheus_exporter listening on :9200 (GET /metrics)

$ curl http://localhost:9200/metrics
# HELP node_load1 Load average over the last minute
# TYPE node_load1 gauge
node_load1 0.0000
# HELP node_memory_total_bytes Total physical memory in bytes
# TYPE node_memory_total_bytes gauge
node_memory_total_bytes 4105633792
# HELP node_memory_available_bytes Available physical memory in bytes
# TYPE node_memory_available_bytes gauge
node_memory_available_bytes 3671957504
# HELP node_uptime_seconds Seconds since boot
# TYPE node_uptime_seconds gauge
node_uptime_seconds 1443.9700
# HELP ruby_exporter_process_uptime_seconds Seconds since this exporter process started
# TYPE ruby_exporter_process_uptime_seconds gauge
ruby_exporter_process_uptime_seconds 0.9760
# HELP ruby_exporter_scrapes_total Total number of /metrics scrapes served
# TYPE ruby_exporter_scrapes_total counter
ruby_exporter_scrapes_total 1
```

## How this was tested

Started the exporter on a scratch port in a Linux sandbox and scraped it twice with `curl`: the response was valid Prometheus text format both times, live system values (load average, memory, uptime) were present and changing between scrapes, and the `ruby_exporter_scrapes_total` counter correctly incremented from 1 to 2. A request to an unknown path correctly returned `404`.

## Troubleshooting

- **Metrics show as missing/blank on non-Linux hosts** — the bundled collectors read `/proc`, which is Linux-specific. On macOS or Windows, swap `ProcStats` for platform-appropriate sources (e.g. `sysctl` via `Open3` on macOS, or WMI via `win32ole` on Windows) — the registry and HTTP server don't need to change at all.
- **"Address already in use"** — another process (maybe a previous run of this script) is still bound to the port; pick a different `--port` or stop the earlier process.
- **Prometheus shows the target as down** — confirm the exporter is reachable from the Prometheus host specifically (firewall rules, container networking), not just from localhost.

## Extending this script

- Add labels (e.g. `node_load1{host="web-1"}`) by extending `MetricsRegistry#render` to accept a labels hash per metric.
- Add a histogram or summary type for request-latency-style metrics, following the same text-format spec.
- Wrap your own application's internal counters (queue depth, cache hit rate) as custom gauges/counters — this is the exact pattern to copy.
- Add basic auth or an allowlist check in `Exporter#handle` if the exporter will be reachable outside a trusted network.

## References

- [Prometheus exposition formats](https://prometheus.io/docs/instrumenting/exposition_formats/)
- [Ruby TCPServer docs](https://docs.ruby-lang.org/en/3.0/TCPServer.html)
