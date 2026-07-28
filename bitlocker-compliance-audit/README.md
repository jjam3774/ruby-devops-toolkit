# bitlocker_compliance_audit.rb

Audits BitLocker drive-encryption status on Windows via WMI (`Win32_EncryptableVolume`) and reports which volumes are compliant with a simple, sane policy: fully encrypted, actively protected, and backed by a recovery-password key protector (so IT can actually unlock the drive if the TPM/PIN path fails). Read-only by design — it reports drift, it doesn't flip encryption on for you.

## Why this exists

"Is every laptop actually encrypted?" is a routine compliance question (SOC 2, ISO 27001, a customer security questionnaire) that's easy to get wrong by trusting a policy setting instead of checking real device state. This script checks the real state, on every volume, and gives you a report you can hand to an auditor or wire into a fleet health check.

**Platform note:** `Win32_EncryptableVolume` and WMI only exist on Windows (and require Administrator privileges to query). The *compliance decision logic* (`BitLockerAuditor#evaluate`) is fully platform-independent and unit-testable anywhere — only the small `WmiVolumeConnector` class touches WIN32OLE, and it's required lazily so this file can be required for tests on Linux/macOS without win32ole installed. See `bitlocker_compliance_audit_test.rb` for a fake-WMI test harness that exercises the real logic without Windows.

## Prerequisites

- Ruby >= 2.7 built for Windows (e.g. via RubyInstaller) with the `win32ole` stdlib gem — bundled by default with RubyInstaller's Ruby
- Administrator privileges to query `Win32_EncryptableVolume` (enforced by Windows regardless of what account runs the script)
- Windows 10/11 Pro/Enterprise or Windows Server with BitLocker available

## Usage (on Windows, elevated)

```
ruby bitlocker_compliance_audit.rb
ruby bitlocker_compliance_audit.rb --json
ruby bitlocker_compliance_audit.rb --check   # exit 1 if any volume is non-compliant
```

## How it works

1. **`BitLockerAuditor#evaluate`** — the entire compliance policy for one volume: checks `ProtectionStatus == Protected`, `ConversionStatus == FullyEncrypted`, and whether a `RecoveryPassword`-type key protector is present.
2. **Severity classification** — missing encryption/protection is `:critical`; encrypted-and-protected-but-no-recovery-password is only `:warning`; everything in order is `:ok`.
3. **`WmiVolumeConnector`** — the only class touching `WIN32OLE`. Queries `Win32_EncryptableVolume` over the `root/cimv2/security/MicrosoftVolumeEncryption` WMI namespace, then calls the real `GetKeyProtectors(0)` / `GetKeyProtectorType(id)` COM methods to resolve which protector types are configured on each volume.
4. **Graceful unknown-code handling** — any WMI status code this script doesn't recognize renders as `Unknown(<code>)` instead of raising, since Microsoft has added new encryption-method variants over time.

## How this was actually tested

Since `win32ole`/WMI don't exist on Linux, the real `WmiVolumeConnector` class is **not** exercised by these tests — it's a thin wrapper around one WMI query and two COM method calls, and is documented here as untested-on-Linux. Instead, `bitlocker_compliance_audit_test.rb` defines a `FakeVolumeConnector` that hands back canned volume hashes and drives the real `BitLockerAuditor` policy through 7 scenarios / 23 assertions — all passing, including unknown-status-code handling and a mixed multi-volume fleet.

```
$ ruby bitlocker_compliance_audit_test.rb
Test 1: fully encrypted, protected, with recovery password -> compliant
  PASS  compliant is true
  PASS  severity is :ok
  ...
============================================================
RESULTS: 23 passed, 0 failed
============================================================
```

## Troubleshooting

- **"cannot load such file -- win32ole" on Linux/macOS** — expected and by design; run the real script only on Windows and use `bitlocker_compliance_audit_test.rb` to validate logic changes anywhere else.
- **WMI query fails / returns nothing, even on a Windows box** — querying `Win32_EncryptableVolume` requires Administrator privileges; run the terminal elevated.
- **A volume shows encrypted in the BitLocker Control Panel but this script flags it** — check whether it's specifically missing a RecoveryPassword protector (TPM-only setups are common and will correctly show as a WARNING here, not a false positive).
- **Removable/USB volumes reporting oddly** — `Win32_EncryptableVolume` covers BitLocker To Go volumes too; a plugged-out drive will simply not appear in the query results.

## Extending this script

- Point `WIN32OLE.connect` at a remote host's WMI namespace to audit a small fleet from one box.
- Add a `--csv` output mode for feeding straight into a spreadsheet-based compliance tracker.
- Cross-reference results against Active Directory/Intune to flag devices that report compliant to MDM but fail this direct check (or vice versa).
- Extend `FakeVolumeConnector` with a scenario for a locked, un-unlocked volume (`LockStatus`) to harden the policy further.

## References

- [Win32_EncryptableVolume class (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/secprov/win32-encryptablevolume)
- [Ruby win32ole docs](https://docs.ruby-lang.org/en/3.0/WIN32OLE.html)
