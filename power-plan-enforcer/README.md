# power-plan-enforcer

Idempotent Windows power-policy enforcement across a fleet, from a single
YAML policy file: makes sure each box is on the right power plan (WMI),
has Fast Startup set the way you want it (registry), and has hibernation
on or off as policy demands (`powercfg.exe`). Three different Windows
automation surfaces — WMI, the registry, and a shelled-out command-line
tool — driven by one small reconciler.

Why this matters operationally: a server that silently drifts onto
"Balanced" power policy throttles CPU under light load — a surprising
performance regression that looks like an application bug until someone
checks `powercfg /getactivescheme`. A server with Fast Startup enabled
skips full driver re-initialization on "shutdown", a classic cause of
stale-state bugs after a maintenance reboot. Both are one WMI/registry
write away from fixed, if you remember to check every box in the fleet.

## Prerequisites

- Ruby >= 3.0 with the `win32ole` and `win32-registry` standard-library
  bindings — both ship with the standard **Windows** Ruby build (RubyInstaller
  for Windows); they don't exist on Linux/macOS Ruby builds, which is why
  this script checks `RUBY_PLATFORM` and refuses to run for real anywhere
  else
- Administrator privileges for `--apply` (changing the active power plan,
  the registry, and running `powercfg /hibernate` all require elevation)
- `powercfg.exe` on `PATH` (present by default on every supported Windows
  version)

## Usage

```powershell
# Preview what would change (still needs win32ole/win32-registry, i.e. still Windows-only)
ruby power_plan_enforcer.rb --policy policy.yml

# Actually apply (run elevated)
ruby power_plan_enforcer.rb --policy policy.yml --apply
```

Policy format (`policy.yml`):

```yaml
active_plan: "High performance"
fast_startup_enabled: false
hibernation_enabled: false
```

Any key you omit is left alone entirely — this script never guesses a
default for a setting you didn't mention.

## How it works

Three small, independently-testable collaborators, each wrapping exactly
one Windows automation surface:

- **`WmiPowerPlans`** connects to the `root\cimv2\power` WMI namespace
  (`WIN32OLE.connect('winmgmts:\\\\.\\root\\cimv2\\power')`), lists every
  `Win32_PowerPlan` instance, and calls `.Activate` on the one that matches
  `active_plan` by name.
- **`WindowsRegistry`** reads and writes the `HiberbootEnabled` `DWORD`
  under `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power` —
  that single value is what actually controls Fast Startup; there's no WMI
  class for it.
- **`PowercfgControl`** reads `HibernateEnabled` from the registry
  (`HKLM\SYSTEM\CurrentControlSet\Control\Power`) to check current state,
  but *writes* through `powercfg.exe /hibernate on|off` rather than the
  registry directly — turning hibernation on/off is what actually
  allocates or frees `hiberfil.sys` on disk, and only the supported
  `powercfg` path does that correctly.
- **`PowerPolicyEnforcer`** depends only on those three interfaces (never
  directly on `WIN32OLE` or `Win32::Registry`), which is what makes its
  `#plan`/`#apply!` logic fully unit-testable on any platform — including
  the Linux sandbox this was actually developed and tested in.

## Example output

(Illustrative — captured from a real run of the fixture-backed logic in
the test suite below, since the actual WMI/registry/powercfg calls can
only execute on real Windows. Command-line shape is identical either way.)

```
$ ruby power_plan_enforcer.rb --policy policy.yml
3 change(s) needed:
[dry-run] ACTIVATE_POWER_PLAN  Balanced -> High performance ({8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c})
[dry-run] SET_FAST_STARTUP     HiberbootEnabled 1 -> 0
[dry-run] SET_HIBERNATION      hibernation true -> false

Dry run only -- re-run with --apply to make these changes.
```

## Testing

None of `WIN32OLE`, `Win32::Registry`, or `powercfg.exe` exist on Linux —
and even on real Windows, flipping a box's power plan mid test run is not
something a test suite should ever do for real. So `power_plan_enforcer_test.rb`
exercises `PowerPolicyEnforcer`'s planning and execution logic entirely
against `FakePowerPlans`/`FakeRegistry`/`FakePowercfg` doubles shaped
exactly like the real WMI/registry/powercfg interfaces above — the same
fixture-double pattern this repo uses for its other WMI-dependent scripts
(scheduled-task-audit, win-profile-cleanup, windows-firewall-audit). All
four scenarios — wrong active plan gets corrected, an already-compliant
plan is a no-op, Fast Startup and hibernation drift both get corrected
together, and unspecified policy keys are left completely untouched — were
run live in this Linux sandbox:

```bash
ruby power_plan_enforcer_test.rb
```

## Troubleshooting

- **`This script talks to WMI and the Windows registry and can only run
  for real on Windows.`** — you ran it somewhere other than Windows. Use
  `power_plan_enforcer_test.rb` to exercise the logic anywhere else; that's
  exactly what it's for.
- **`WARNING: power plan "..." not found on this system; skipping`** — the
  plan name in your policy has to match `Win32_PowerPlan.ElementName`
  exactly (case-insensitively). Run `powercfg /list` to see the exact
  names configured on that box — custom power plans and OEM-branded ones
  often don't match the stock "Balanced"/"High performance"/"Power saver"
  names.
- **Fast Startup change doesn't seem to take effect** — `HiberbootEnabled`
  only matters if hibernation is enabled at all; if your policy also sets
  `hibernation_enabled: false`, Fast Startup is moot regardless of what the
  registry says, since Fast Startup is implemented as a partial hibernate.
- **`powercfg /hibernate off` fails with access denied** — you're not
  elevated. `--apply` genuinely needs an administrator shell; there's no
  way around that for any of these three surfaces.

## Extending

- Add monitor/disk/sleep timeout enforcement via
  `Win32_PowerSettingDataIndex` — this script deliberately scoped down to
  plan + Fast Startup + hibernation to stay testable and reviewable; the
  individual-timeout WMI classes are considerably more involved (they're
  keyed by GUID pairs, not simple named properties).
- Add a `--fleet hosts.txt` mode that connects to each host's WMI over
  DCOM (`WIN32OLE.connect("winmgmts:{impersonationLevel=impersonate}!//#{host}/root/cimv2/power")`)
  instead of only the local machine.
- Emit a machine-readable `--json` plan output (matching the pattern several
  other scripts in this repo use) so this can feed a fleet-wide compliance
  dashboard instead of only a human reading terminal output box by box.

## References

- [Win32_PowerPlan class (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/power/power-plan)
- [`powercfg` command-line reference (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options)
- [Ruby `win32ole` docs](https://docs.ruby-lang.org/en/3.3/WIN32OLE.html)
- [GitHub: ruby-devops-toolkit/power-plan-enforcer](https://github.com/jjam3774/ruby-devops-toolkit/tree/main/power-plan-enforcer)
