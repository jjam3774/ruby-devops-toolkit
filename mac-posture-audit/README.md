# mac-posture-audit

Audit the Linux Mandatory Access Control (MAC) posture in pure Ruby — and answer the
question `aa-status` and `sestatus` never do: **which listening network daemon is
running with no MAC profile at all?**

![MAC posture audit data flow](img/mac-posture-flow.png)

## The problem

Every modern distro ships a Linux Security Module that is supposed to confine daemons:
AppArmor on Debian/Ubuntu/SUSE, SELinux on RHEL/Fedora/Rocky. The trouble is that the
aggregate numbers lie by omission.

* "AppArmor is active" does not mean anything is confined — a host can have the LSM
  loaded and zero profiles.
* A profile in **complain** mode logs violations and then permits them.
* A profile can be loaded in **unconfined** mode, which is a profile that confines nothing.
* Most importantly: a daemon with no profile at all is simply absent from the summary.
  `aa-status` tells you 43 profiles are in enforce mode. It does not tell you that the
  Node.js metrics exporter listening on 9100 is not one of them.

That last case is the one that matters, because it is the intersection of two facts —
"reachable from the network" and "not confined" — and neither tool reports the intersection.

## What the script does

It reads the kernel's own view of the world and correlates three interfaces:

| Interface | What it yields |
| --- | --- |
| `/sys/kernel/security/lsm` | which LSMs are active |
| `/sys/kernel/security/apparmor/profiles` | every loaded profile and its mode |
| `/sys/fs/selinux/enforce` | SELinux global mode (1 = enforcing) |
| `/proc/<pid>/attr/current` | each process's security label |
| `/proc/net/tcp`, `tcp6`, `udp`, `udp6` | listening socket inodes and ports |
| `/proc/<pid>/fd/*` | `socket:[inode]` symlinks → which PID owns which socket |

The last two are joined to produce the set of PIDs holding a listening socket, which is
then intersected with the set of unconfined processes. That intersection is reported as
`FAIL`.

It is read-only. It never loads, unloads, enforces or changes a profile.

## Prerequisites

* **Ruby 2.7+** (tested on 3.0.2). Standard library only — no gems, no `Gemfile`.
* **Linux** with either AppArmor or SELinux. The script degrades honestly on a host with
  neither: it reports a single `FAIL` saying no MAC LSM is active.
* **Root is recommended but not required.** As a normal user you will see your own
  processes; `/proc/<pid>/attr/current` and `/proc/<pid>/fd` for other users' processes
  are unreadable, so run it with `sudo` for a complete picture.

## Usage

```bash
# Human-readable report on this host
sudo ruby mac_posture_audit.rb

# Machine-readable, for a monitoring pipeline
sudo ruby mac_posture_audit.rb --json

# Replay a captured /proc + /sys tree (for tests or offline triage)
ruby mac_posture_audit.rb --root ./fixture

# Exit code only, no output — for a cron/systemd health check
sudo ruby mac_posture_audit.rb --quiet
```

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | clean |
| `1` | warnings only |
| `2` | at least one failure |
| `3` | usage error |

## How it works

### 1. Which LSM is active?

`/sys/kernel/security/lsm` is a comma-separated list the kernel publishes directly. On
older kernels the file does not exist, so the script falls back to probing for the
`apparmor` securityfs directory and the `selinux` filesystem.

### 2. Profile inventory

AppArmor's `profiles` file is one profile per line with its mode in parentheses:

```
/usr/sbin/nginx (enforce)
/usr/bin/redis-server (complain)
nvidia_modprobe (unconfined)
```

The script splits on the *last* space-paren so profile names containing spaces survive,
then tallies by mode. SELinux is simpler: `/sys/fs/selinux/enforce` is a single byte,
`1` for enforcing and `0` for permissive; a missing file means disabled.

### 3. Per-process labels

`/proc/<pid>/attr/current` holds the label. AppArmor writes `"/usr/sbin/nginx (enforce)"`
or the bare string `"unconfined"`. SELinux writes a full context,
`"system_u:system_r:httpd_t:s0"`, where the third field is the type — and any type
starting with `unconfined_` means no policy is being applied.

Kernel threads are dropped: they have an empty `/proc/<pid>/cmdline`, live entirely in
kernel space, and are outside the scope of a userspace MAC policy. Without that filter
you get dozens of meaningless "unconfined kthreadd" findings.

### 4. The socket → PID join

This is the interesting part. `/proc/net/tcp` gives you socket inodes but no PIDs:

```
sl  local_address rem_address   st ... inode
 0: 00000000:0016 00000000:0000 0A ... 910011
```

`st == 0A` is `TCP_LISTEN`. Column 9 is the inode. To find the owning process the script
walks every `/proc/<pid>/fd/` and reads the symlink targets, which look like
`socket:[910011]`. Intersecting the two sets gives you "PID 688 owns a socket listening
on port 22" — the same thing `ss -ltnp` does, without shelling out to anything.

UDP has no `LISTEN` state, so every bound UDP socket is treated as reachable.

### 5. Correlate and grade

![Severity model](img/mac-severity-matrix.png)

A process that is listening **and** unconfined is `FAIL`. A process running under a
complain-mode profile is `WARN`. Trusted-computing-base processes (`systemd`,
`systemd-journald`, `systemd-udevd`) are reported at `INFO` even when unconfined,
because confining PID 1 is not a realistic ask and flagging it just trains people to
ignore the output.

## Example output

Run against a fixture representing a typical Ubuntu application server:

```
==========================================================================
  MAC POSTURE AUDIT -- app-01 -- 2026-09-16 12:15:46
==========================================================================

  Active LSM        : apparmor
  LSMs in kernel    : capability, landlock, yama, apparmor
  Profiles loaded   : 12 (9 enforce, 2 complain, 1 unconfined)
  Processes scanned : 10 (4 confined, 6 unconfined)
  Listening daemons : 6 (3 unconfined)

--------------------------------------------------------------------------

[FAIL] pid 1655 node listens on 9100 with no MAC profile
         -> Generate a starter profile: `aa-genprof node` (or install the distro
            profile package), test in complain mode, then `aa-enforce`.
         cmd: node /opt/metrics-exporter/server.js
         label: unconfined

[FAIL] pid 1890 postgres listens on 5432 with no MAC profile
         cmd: /usr/lib/postgresql/14/bin/postgres -D /var/lib/postgresql/14/main
         label: unconfined

[FAIL] pid 688 sshd listens on 22 with no MAC profile
         cmd: /usr/sbin/sshd -D
         label: unconfined

[WARN] 2 profile(s) in complain mode (logging, not blocking)
         -> Move to enforce with `aa-enforce <profile>`: /usr/sbin/cups-browsed,
            /usr/bin/redis-server

[WARN] 1 profile(s) loaded in unconfined mode
         -> These profiles exist but confine nothing: nvidia_modprobe

[WARN] 1 running process(es) under a non-enforcing profile
         -> redis-server(1140)

[PASS] 12 AppArmor profiles loaded

--------------------------------------------------------------------------
  3 fail   3 warn   0 info   1 pass
==========================================================================
```

Note what the summary line alone would have told you: *12 profiles loaded, 9 in enforce
mode.* That sounds healthy. Three of the six things listening on this box have no profile
at all.

## Troubleshooting

**"No MAC LSM active" on a host where AppArmor is definitely installed.**
Installed is not loaded. Check `cat /sys/kernel/security/lsm`. If `apparmor` is missing,
it was not enabled at boot — add `apparmor=1 security=apparmor` to the kernel command
line, or on some cloud images install the `apparmor` package and reboot.

**Everything shows as `(unreadable)`.**
You are not root. `/proc/<pid>/attr/current` is only readable by the process owner and
root. Run with `sudo`.

**Zero listening daemons detected, but `ss -ltn` shows plenty.**
Almost always a permissions problem reading `/proc/<pid>/fd`. Run with `sudo`. In a
container, also confirm `/proc` is a real procfs mount and not masked by the runtime.

**Profiles show as loaded but every process is unconfined.**
A profile only applies at `exec()`. Daemons that were already running when the profile
was loaded keep their old (unconfined) label until they restart. Restart the service and
re-run.

**Docker/Podman containers show odd results.**
Container runtimes apply their own profile (`docker-default`, `container_t`). Inside a
container you are auditing the container's view, which is usually what you want — but
remember `/proc/net/tcp` there reflects the container's network namespace, not the host's.

**SELinux host reports `enforcing` but you expected `permissive`.**
`/sys/fs/selinux/enforce` is the *runtime* mode, which `setenforce 0` changes without
touching `/etc/selinux/config`. The script reports the runtime mode deliberately — that
is what is actually protecting you right now.

## Extending it

* **Add a baseline file.** Accept a YAML/JSON list of known-good unconfined daemons so
  the exit code only trips on *new* findings. This is what makes it usable as a nightly
  cron check.
* **Emit Prometheus metrics.** The `--json` output maps cleanly onto
  `mac_unconfined_listeners{host="..."} 3`. Point node_exporter's textfile collector at it.
* **Parse the audit log.** `/var/log/audit/audit.log` (or `journalctl -k`) carries the
  actual `apparmor="DENIED"` / `avc: denied` records. Correlating recent denials with
  complain-mode profiles tells you exactly what would break if you moved each one to
  enforce — which is the real blocker to enforcing them.
* **Cover more LSMs.** Landlock and SELinux-in-permissive-with-booleans both have state
  worth reporting. `/sys/fs/selinux/booleans/` is a directory of on/off toggles that
  silently widen policy.
* **Run it fleet-wide.** The `--json` mode plus `ssh` in a loop gives you a fleet report;
  sort by `listeners_unconfined` descending and start at the top.

## References

* [AppArmor documentation (Ubuntu Server Guide)](https://documentation.ubuntu.com/server/how-to/security/apparmor/)
* [AppArmor upstream wiki](https://gitlab.com/apparmor/apparmor/-/wikis/home)
* [SELinux Project wiki](https://github.com/SELinuxProject/selinux/wiki)
* [Red Hat: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/index)
* [`proc(5)` man page — `/proc/[pid]/attr`, `/proc/net/tcp`](https://man7.org/linux/man-pages/man5/proc.5.html)
* [Linux Security Modules (kernel docs)](https://www.kernel.org/doc/html/latest/admin-guide/LSM/index.html)
* [Ruby `Dir`, `File`, `IO` stdlib docs](https://docs.ruby-lang.org/en/master/File.html)

## License

MIT — see the repository [LICENSE](../LICENSE).
