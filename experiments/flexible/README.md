# Installed flexible-credential acceptance

Run only in a newly independent Fedora KDE 44 x86_64 clone with SELinux
Enforcing and a private managed TPM2 emulator. Follow the [M8 host/guest
identity, independent-disk and cleanup guards](../m8/README.md), retaining the
original `localpin-m1` shut off. Use a full independent qcow2 with no backing
store, host shares or physical TPM, fresh UUID/MAC, root-private synthetic
accounts, and SSH host keys pinned through the trusted offline/guest-agent path.
Never use the everyday host's PAM setup, credentials or TPM failure allowance.

The current candidate is `localpin-0.1.0-0.1.alpha1.vm84.1.fc44.x86_64.rpm`,
final RPM4 SHA256:

```text
4f3294de165d516661a2b9e5ac61ebf17757be1468f6fb3273893f3755214268
```

This is targeted installed evidence for that exact runtime. Source checks,
hosted CI, historical M8 results, physical hardware and independent review are
separate. The [feature report](../../docs/development/flexible-credentials.md)
records the 118 matching runtime/build inputs, final source validation and the
remaining release gates. The installed RPM predates the final fixture/report
commit; it matches those executable inputs, not every later documentation byte.

## Reproduce the guarded cases

Prepare the dedicated accounts and private `/root/localpin-m8` directory using
the M8/M8.3 workflow. Establish actual password login and native persistent
accounting before provisioning LocalPIN. Preserve genuine nonowner native
failure history privately; this run created one actual rejected native PAM
attempt for `lp61other`, never a fabricated serialized tally. All production
password and biometric failure counters remain authoritative.

For legacy upgrade, install the real prior
`0.1.0-0.1.alpha1.vm83.11.fc44` RPM and use its actual installed CLI/private
controlling terminal to enroll a six-digit software credential. Test the stock
KDE password/PIN routes in its bounded trial. Save credential, active-pointer,
throttle and native tally bytes/security metadata only inside guest-root-private
storage, upgrade to the exact final RPM, and compare before any new verification.
Require status schema 2, legacy numeric length six/policy zero, replacement
advice and successful legacy verification. Do not convert or replace the
credential to make an upgrade pass.

Stage unchanged M8 `run.py`/`guard.py` in `/root/localpin-m8`, this directory's
`matrix.py` there as `flexible-matrix.py`, and `pty_client.py` root-owned mode0755
at `/usr/libexec/localpin/flexible-pty.py`, restoring its SELinux label. Build
and stage the current M6.1 `m61-client` as M8's nonshipping status/verification
client. The guarded matrix runs the real installed `/usr/bin/localpin` through
its own controlling PTY; no secret argument/environment/stdin option is added
to the product. Inputs travel only in bounded private fixture frames.

From the host, with the topology-verified access directory and pinned address:

```sh
python3 experiments/flexible/host.py spaced-software \
  --expected-localpin-evr 0.1.0-0.1.alpha1.vm84.1.fc44 \
  --address 192.168.122.X --access-dir .local/flexible-acceptance \
  --disposable-vm-confirmed --emulated-tpm-confirmed
python3 experiments/flexible/console.py pin \
  --address 192.168.122.X --access-dir .local/flexible-acceptance \
  --disposable-vm-confirmed --emulated-tpm-confirmed
```

The placeholder address must be the validated clone address. Each matrix case
is attempted once; it records a private intent before mutation. `software8`,
`software16`, `spaced-software`, `digit-passcode`, `long-software`,
`overlap-software`, `tpm4`, `tpm16`, `spaced-tpm` and `software10` select explicit
formats/backends. A backend change uses the installed explicit migration
command with fresh password verification. Recommendations do not choose a fixed
length. Synthetic generation excludes every bundled advisory pattern, including
wrapping sequences and repeated blocks, so it never overrides a warning.

A committed replacement can legitimately retain an earlier cooldown. A pending
result records the committed profile separately from verification. Wait for
natural expiry and rerun the same host case with `--observe-only`; its private
checkpoint binds the unchanged active generation and boot. Never repeat the
mutation, edit a throttle or reset TPM/native accounting to advance the test.
An incomplete intent without a completed checkpoint requires private inspection
and an explicitly separate observer, not an automatic retry.

For actual KDE tests, the matrix's guest-root-only current-case file carries
the value independently of the frozen legacy M8 fixture secret schema. The
console helper reuses all M8 active/inactive topology checks before/after guest
actions, matches the enrolled public type/length/backend, and sends actual
physical virtual-keyboard events. The reviewed mapping covers printable ASCII
on the guest's US keyboard layout, preserving spaces/case. Test `pin` and
`password` separately; `pin` proves Enter is required and native counters stay
unchanged on success. Raw transcripts, credentials, verifiers, native bytes,
private digests and journals remain guest-root-only. Export only inspected
sanitized booleans/counts and public candidate identity.

Use the M8.2/M8.3 actual-Konsole observers for the real menu/change form. Verify
the intended Konsole is foreground on the active dedicated Wayland VT before
keyboard input, stop on idle lock, and send each private prompt only once.
Verify masks and preparation/confirmation before the single hidden account
password prompt, actual successful exit and authoritative committed profile.

## Observations and limits

The sanitized [installed operations](results/installed-operations.json) and
[actual KDE observations](results/actual-kde.json) distinguish installed CLI/backend
checks from physical virtual-keyboard unlocks. All recorded cases used SELinux
Enforcing; none manually reset a native tally, LocalPIN throttle or TPM
dictionary-attack counter. Genuine nonowner native failure history remained intact.

| Case | Installed CLI/backend | Actual KDE |
| --- | --- | --- |
| Genuine old software six-digit record, upgraded without conversion | Pass; exact protected/native bytes and metadata retained | Old candidate PIN/password passed |
| New leading-zero software PIN, 10 digits | Pass; real Konsole menu/change form, masks and fresh password | PIN requires Enter; full password passes |
| Software PIN boundaries, 8 / 16 digits | Both pass | Fresh enrollment 8 passes; 16 not performed |
| Software passcode, 16 characters with two leading and trailing spaces | Pass | Exact spaced credential passes |
| Explicit all-digit passcode, 12 characters | Pass; kind stays passcode | Pass |
| Software passcode, 64 characters | Pass | Pass |
| Software passcode matching account-password format/length | Pass | Full password passes after one counted LocalPIN attempt |
| Software cooldown, fifth mismatch / sixth refusal | Pass; native counters unchanged | Full password passes during cooldown |
| Explicit software to TPM migration, 4-digit PIN | Commit preserves prior cooldown; verification passes after natural expiry | PIN requires Enter |
| TPM PIN, 16 digits | Pass | PIN requires Enter |
| TPM passcode, 16 characters with leading/trailing spaces | Pass | Exact credential and full password pass |
| Same v2 TPM passcode across actual reboot | Exact protected/native state retained; same credential verifies | Password login, then credential/password unlock pass |
| Explicit TPM to software migration, 10-digit PIN | Pass | Separate same-length Konsole case above; no extra migration unlock claimed |
| Own-user disable, then fresh software enrollment | Pass; disabled profile absent, fresh v2 PIN length 8 | Disabled password and fresh PIN pass |
| Missing PAM module fault | Real fault retained through recovery | PIN denied; same greeter full password passes |
| Actual administrator VT4 recovery | Dry-run unchanged; real recover restores six policies, revokes authority and disables broker/gate without changing native state | Existing locked KDE session accepts password with module still absent |
| Exact component repair, final RPM erase | Stock policies and all native bytes/security metadata retained | Post-erase stock password passes |

The reboot expired the old boot-bound trial. In prepared state the broker socket
was disabled at boot; it was explicitly started after the private preservation
checkpoint and a fresh bounded trial was opened. This proves credential/state
continuity with a new trial, not active-boot acceptance.

[Retained observations](results/retained-observations.json) include fixture and
native-policy refusals, rather than turning every attempt into a pass.
The original legacy package's accounting preparation completed with an empty
native baseline, but its first subsequent password login exposed a failed
user manager (`Failed to spawn executor`). Ordinary termination/drain of that
synthetic owner's lifecycle followed by another actual password login restored
the user bus. This was diagnostic fixture remediation on the old candidate;
it is preserved as a preparation limitation, not a passing flexible-feature
maintenance result. No counter reset or PAM policy repair was used.

The first TPM migration completed while the preceding software cooldown was
still active. The initial fixture incorrectly expected immediate availability
and stopped after checking the committed profile. The cooldown was preserved;
the later separate observer waited for natural expiry and passed without
repeating migration. An idle-lock guard also refused keyboard input before a
normal password unlock restored the intended desktop surface.
This is a retained fixture-assumption failure, not evidence of a rejected
credential commit or a reason to clear a counter.

The first actual text-console owner login was refused by native account
lockout after three valid failures. Read-only diagnosis found the lockout and
no wrong-password `pam_unix` failure for that console attempt. After the default
600-second natural expiry, the single retry passed. The ordinary owner login
and real root `sudo` on VT4 invoked the unchanged reviewed
M8.3/M8.2 recovery chain. No tally was manually cleared and no password or
native lockout policy changed. Normal successful console password authentication
cleared the owner's native tally under the existing policy. Recovery preserved
all native bytes and metadata from its subsequent checkpoint; the genuine
nonowner failure history stayed unchanged throughout. After recovery, the
existing KDE session accepted the password
with the module still absent. The exact saved component was then repaired, the
final RPM erased, and actual stock-password unlocking passed.

Do not infer unperformed cases from a passing CLI or broker probe. In particular,
software 8/16-digit boundary checks alone do not prove actual desktop unlock at
both boundaries. Trial-based reboot evidence must explicitly record expiry of
the boot-bound gate and any deliberate administrative broker restart/new trial;
it is not active-boot acceptance. Console recovery must occur on an actual
administrator text VT, followed by real password continuity. The final
[cleanup evidence](results/cleanup.json) records completed exact identity and
no-reference checks, graceful clone shutdown, and deletion of only the
independent task domain/disk/private emulator. The matching guest SSH key, host
access/recovery secrets, diagnostic logs, screenshots and task archives were
removed. Only the original two preexisting domains remain, both off; the original
`localpin-m1` stayed defined and off throughout. No guest credential state or
private authentication archive was retained on the host.

Independent human/specialist review, physical TPM/sensor validation, signed
release gates and the full release matrix remain open after targeted acceptance.
Pure fixture checks require no VM:

```sh
python3 -m unittest discover -s experiments/flexible -p 'test_*.py' -v
python3 -m py_compile experiments/flexible/*.py
```
