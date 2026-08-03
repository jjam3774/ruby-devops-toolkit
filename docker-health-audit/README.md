# docker-health-audit

Talks directly to the Docker Engine API — no `docker` CLI, no `docker-api` gem — to
inventory every container on a host and flag crash-loop restarts, `--privileged`
containers, and containers that bind-mount the Docker socket into themselves (a
well-known container-escape vector). Built entirely on Ruby's stdlib (`socket`, `json`,
`optparse`, `uri`, `net/http`).

## Prerequisites

- Ruby 3.x, stdlib only.
- Access to the Docker socket — either run as root, or as a user in the `docker` group
  (which is itself root-equivalent, since anyone in it can reach the same API this
  script does).
- A running Docker daemon on the host, or a `tcp://` daemon endpoint if auditing
  remotely.

## Usage

```bash
# Default: talk to /var/run/docker.sock
ruby docker_health_audit.rb

# Custom socket path (e.g. Docker Desktop, rootless Docker)
ruby docker_health_audit.rb --socket ~/.docker/run/docker.sock

# Remote daemon over TCP, or a test double
ruby docker_health_audit.rb --host http://127.0.0.1:2375 --json

# Tune the crash-loop threshold
ruby docker_health_audit.rb --restart-threshold 3
```

Exit codes: `0` no CRIT findings, `1` at least one CRIT finding, `2` connection error.

## How it works

- `http_get_over_unix_socket` opens a raw `UNIXSocket`, writes a minimal HTTP/1.1 GET
  request by hand, and parses the status line, headers, and a chunked-or-Content-Length
  body back out. Ruby's `Net::HTTP` has no built-in way to connect over a Unix domain
  socket, so this is a from-scratch client for the protocol Docker's own CLI and client
  libraries actually use by default.
- `DockerClient#get` picks between that Unix-socket path and plain `Net::HTTP` against a
  `tcp://` host depending on whether `--host` was given. Everything downstream calls
  `client.get_json(path)` and never knows which transport carried the request.
- `classify_container` is a pure function over an already-parsed
  `/containers/:id/json` inspect payload: no HTTP in here at all. It checks
  `RestartCount` against `--restart-threshold`, `HostConfig.Privileged`, and
  `HostConfig.Binds` for a `docker.sock` mount or other sensitive host paths (`/`,
  `/etc`, `/root`).

## Example output

Captured against a 4-container fixture set (one healthy, one crash-looping, one
privileged, one mounting the Docker socket):

```
$ ruby docker_health_audit.rb --socket /var/run/docker.sock
[ ok ] web  (running)
[CRIT] flaky-worker  (restarting)
        - restarted 14 times and is still restarting -- likely crash-looping
[CRIT] legacy-agent  (running)
        - running with --privileged (full host device/capability access)
[CRIT] ci-runner  (running)
        - mounts the Docker socket into the container -- typically equivalent to root on the host
---
4 containers audited, 3 CRIT, 0 WARN
```

## Testing notes

No real dockerd was available in the environment used to build this script. Both
transport paths were instead verified against real HTTP traffic from two stub servers
serving the same 4-container fixture set: a `UNIXServer`-based stub for the socket path
(exercising the hand-rolled HTTP-over-Unix-socket client, including a chunked-transfer
round trip) and a plain `TCPServer` stub for the `--host` path (exercising the
`Net::HTTP` branch). `classify_container` itself is a pure function and was exercised
directly against the same fixture data.

## Troubleshooting

- **`Errno::EACCES` connecting to the socket** — the current user isn't in the `docker`
  group and isn't root.
- **`Errno::ENOENT` on the socket path** — Docker Desktop on macOS and some rootless
  Docker setups use a different socket path (often under `~/.docker/run/docker.sock`);
  pass it with `--socket`.
- **A container reports "could not inspect"** — it likely exited and was removed
  (`--rm`) between the list call and the inspect call; reported as a WARN per container
  rather than crashing the whole audit.
- **Chunked response parsing** — this only handles the specific `Transfer-Encoding:
  chunked` shape Docker's API actually sends for these endpoints; it does not handle
  trailing headers after the final zero-length chunk, which Docker doesn't send here.

## Extending it

- Add `GET /containers/:id/stats?stream=false` to flag containers approaching their
  memory limit.
- Cross-reference each container's image digest against a registry for freshness.
- Inspect `NetworkSettings.Ports` for containers publishing directly to `0.0.0.0`.
- Loop this script over a list of Docker hosts, similar to `ssh-fleet-runner` elsewhere
  in this repo.

## References

- [Docker Engine API reference](https://docs.docker.com/engine/api/latest/)
- [Docker: runtime privilege and Linux capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [Ruby stdlib: Socket / UNIXSocket](https://docs.ruby-lang.org/en/3.0/UNIXSocket.html)
