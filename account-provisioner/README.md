# account-provisioner

Idempotent local Linux account provisioning: reads a YAML spec of the users
and groups a box *should* have, compares it against what actually exists
(via `Etc`), and reconciles the difference by shelling out to
`useradd`/`usermod`/`userdel`/`groupadd` — only touching accounts that are
actually out of spec. **Dry-run by default**, so you can review a diff
before anything changes.

This is the "user account management" counterpart to a read-only auditor:
instead of only reporting that an account is wrong, it can fix it — the same
declarative, plan-then-apply idea used elsewhere in this repo for config
files and Windows services, applied here to `/etc/passwd`, `/etc/group`,
and SSH `authorized_keys`.

## Prerequisites

- Ruby >= 3.0 (developed and tested on 3.3.6)
- No gems required — `etc`, `yaml`, `open3`, `fileutils`, `optparse` are all
  standard library
- Linux or macOS (anything with `Etc`, `useradd`/`usermod`/`userdel`,
  `passwd -S`)
- Root privileges for `--apply` to actually create/modify/remove accounts;
  the dry-run mode (the default) needs no special privileges beyond reading
  `/etc/passwd`

## Usage

```bash
# Preview what would change (safe — no privileges required, nothing is touched)
ruby account_provisioner.rb --spec accounts.yml

# Actually apply the changes (needs root)
sudo ruby account_provisioner.rb --spec accounts.yml --apply
```

Spec format (`accounts.yml`):

```yaml
managed_uid_min: 1000
managed_uid_max: 2000
prune_unmanaged: false   # true = flag any account in the UID range above that's not listed here

groups:
  - name: deploy

users:
  - name: svc_deploy
    shell: /usr/sbin/nologin
    comment: "CI deploy service account"
    groups: [deploy]
    ssh_authorized_key: "ssh-ed25519 AAAA... svc_deploy@ci-runner"

  - name: alice
    shell: /bin/bash
    comment: "Alice Nguyen"
    locked: false       # unlocked = normal password login allowed

  - name: old_contractor
    state: absent        # if this account exists, remove it
```

## How it works

- **`SystemState`** wraps `Etc.getpwnam`/`Etc.getgrnam` — the only read path
  into the live account database. It's a thin seam specifically so tests can
  swap in fixture data instead of depending on whatever accounts happen to
  exist on the machine running the test suite.
- **`AccountProvisioner#plan`** walks the spec's `groups` then `users` and
  produces an `Action` for every piece of drift: missing group, missing
  user, wrong shell, wrong comment, wrong lock state, missing group
  membership, missing SSH key, or (for `state: absent`) an account that
  shouldn't exist. It never touches the system — `plan` is pure.
- **`#apply!`** takes that plan and either prints it (`dry_run: true`, the
  default) or executes each `Action` for real via `SystemRunner`, a
  one-method `Open3.capture3` wrapper that's the single point where this
  script actually shells out.
- **`prune_unmanaged`** is opt-in and scoped to a UID range on purpose —
  silently deleting any account not in your YAML file is exactly the kind
  of surprise a provisioning tool should never spring on you by default.

## Example output

Dry run against a real (otherwise-unmanaged) sandbox box:

```
$ ruby account_provisioner.rb --spec example_accounts.yml
5 change(s) needed:
[dry-run] CREATE_GROUP   deploy               gid=auto
[dry-run] CREATE_USER    svc_deploy           shell=/usr/sbin/nologin comment="CI deploy service account"
[dry-run] ADD_TO_GROUPS  svc_deploy           deploy
[dry-run] INSTALL_SSH_KEY svc_deploy           authorized_keys += 1 key (svc_deploy@ci-runner)
[dry-run] CREATE_USER    alice                shell=/bin/bash comment="Alice Nguyen"

Dry run only -- re-run with --apply to make these changes.
exit status: 0
```

(`old_contractor: state: absent` produced no action here because that
account didn't exist on the test box in the first place — removal only
plans when there's something to remove.)

## Testing

Real Linux account provisioning is exactly the kind of side effect a test
suite should never perform for real — so `account_provisioner_test.rb`
injects `FakeSystemState` and `FakeRunner` doubles shaped like `SystemState`
and `SystemRunner`, and covers: a brand-new user being planned correctly,
precise drift detection on an existing user (shell + lock state changed,
comment left alone because it already matched), dry-run issuing zero real
commands while `--apply` issues the expected `useradd` argv, and
`state: absent` plus UID-scoped `prune_unmanaged` both working without
touching accounts outside the managed range. Run:

```bash
ruby account_provisioner_test.rb
```

The `plan`/dry-run path was additionally exercised live against this
sandbox's real `/etc/passwd` (see Example output above) to confirm the
`Etc`-backed `SystemState` behaves the same as the fixture-backed one used
in tests.

## Troubleshooting

- **Nothing happens even with `--apply`** — check you're root; `useradd`
  etc. will fail silently into `SystemRunner`'s captured stderr, which the
  script logs as `-> FAILED: ...` rather than raising, so a permissions
  problem shows as a failed action line, not a crash.
- **`ADD_TO_GROUPS` keeps showing up every run** — `usermod --append
  --groups` is intentionally additive per invocation; if the user is
  already in unrelated groups that's fine, but double check the group name
  in your spec isn't subtly different (e.g. trailing whitespace from a
  copy-pasted YAML file).
- **SSH key gets appended twice** — the drift check compares the *stripped*
  key line for an exact match; if your key in `accounts.yml` differs by even
  a trailing comment or a re-wrapped line, it looks like a new key. Keep it
  on one line exactly as `ssh-keygen` printed it.
- **`prune_unmanaged` looks like it's ignoring an account** — it only ever
  looks inside `managed_uid_min`..`managed_uid_max`; system and service
  accounts below 1000 are never touched by it, by design.

## Extending

- Add `expiry:` support (`usermod --expiredate`) for contractor accounts
  that should self-deactivate on a known date instead of waiting for
  someone to add `state: absent`.
- Support group *membership* drift the other direction — removing a user
  from a group they're in but shouldn't be, not just adding missing
  memberships.
- Add a `--diff` output mode that prints old → new values for every field,
  not just the field names, for easier code review of generated specs.
- Wire this into `config_state_engine.rb` elsewhere in this repo so account
  state and general file/config state get reconciled by the same run.

## References

- [Ruby `Etc` module docs](https://docs.ruby-lang.org/en/3.3/Etc.html)
- [`useradd(8)` / `usermod(8)` man pages](https://man7.org/linux/man-pages/man8/useradd.8.html)
- [GitHub: ruby-devops-toolkit/account-provisioner](https://github.com/jjam3774/ruby-devops-toolkit/tree/main/account-provisioner)
