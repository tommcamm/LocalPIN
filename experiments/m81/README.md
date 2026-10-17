# M8.1 desktop and update acceptance

These fixtures operate only inside a dedicated Fedora KDE 44 x86_64 KVM clone
with SELinux enforcing, a private TPM emulator, synthetic accounts and the
root-only M8 fixtures staged at `/root/localpin-m8`. They never use an everyday
host's account databases or physical TPM. A host controller must independently
validate libvirt topology with `experiments/m8/guard.py` before and after every
guest action, including independent disk, original VM off, no host shares or
physical devices, and the exact emulator/UUID.

`updates.py` additionally checks real/effective root, canonical expected UUID,
both explicit disposable-VM/emulated-TPM confirmations, the guest guard markers,
root-private fixtures, active desktop gate, enrolled TPM account and supported
native KDE policy. Run only after actual UI acceptance is complete, with other
VM mutations and UI authentication paused for each before/after snapshot:

```sh
python3 /root/localpin-m8/updates.py upgrade --expected-uuid CLONE_UUID --disposable-vm-confirmed --emulated-tpm-confirmed
python3 /root/localpin-m8/updates.py reinstall --expected-uuid CLONE_UUID --disposable-vm-confirmed --emulated-tpm-confirmed
python3 /root/localpin-m8/updates.py sysusers --expected-uuid CLONE_UUID --disposable-vm-confirmed --emulated-tpm-confirmed
python3 /root/localpin-m8/updates.py authselect --expected-uuid CLONE_UUID --disposable-vm-confirmed --emulated-tpm-confirmed
```

The phases invoke ordinary `dnf upgrade --refresh -y`, real
`dnf reinstall -y pam authselect-libs`, unrelated service-account creation through
native systemd-sysusers, and native authselect regeneration. No repository
workaround, signature bypass, account reseal, counter reset or enrollment repair
is applied. Each phase records native package EVRs, exact private state and
native-image metadata before/after, then verifies the same enrolled PIN only
after state preservation is proved. A successful no-op upgrade is explicitly
not transaction proof.

Private snapshots contain registry/marker/credential/throttle/tally material;
raw DNF/history output also stays in guest-root-only directories. Export only
the sanitized `result.json` and public package-identity differences. Results
include the exact runner SHA256 for source verification. Existing phase
intent/results are never overwritten; review interrupted evidence before any
separately prepared retry.

The checked-in `results/` files record the actual run. The final-build upgrade
updated 26 packages and installed five kernel RPMs; the new kernel was actually
booted. Native PAM/authselect runtime replacement was demonstrated separately
by real reinstallation. This evidence covers the tested Fedora 44 profiles and
transactions; unseen policy changes, independent security review and physical
hardware validation retain their separate gates.

After installing the RPM containing disabled-fingerprint compatibility, stage
`profiles.py` beside `updates.py`. Its explicit `--expected-localpin-evr` gate
prevents testing the old binary accidentally. It snapshots the active account,
disables only `with-fingerprint`, verifies the native disabled factor denies
without an interactive authentication prompt or counter mutation, verifies the same enrolled PIN, and
restores the exact original feature profile in `finally`. It must not overlap
any other guest maintenance or actual locker test.

## Installed package and reboot lifecycle

Stage `installed.py` in the same private directory. Its phases are
`package-upgrade`, `downgrade-refusal`, `reboot-prepare`, `reboot-verify`,
`suspend`, `suspended-reboot-verify`, `resume` and `erase`, with the same expected
UUID and two explicit disposable/emulator confirmation flags. It uses raw
LPACCT03 equality; the historical M8 registry-normalization helper must not be
used for the new authority.

Prepare an ordinary reboot checkpoint, then let the topology-verified host
controller request the reboot. Verify a new boot UUID and enforcing SELinux,
restore only the volatile fixture guards after independently checking the
emulator topology, and run `reboot-verify`. To exercise interrupted package
maintenance, run `suspend`, repeat the actual host-controlled reboot, then run
`suspended-reboot-verify` and `resume`. The gate must remain closed until resume;
the original account, credentials and counter state must remain intact.

Run the actual KDE keyboard PIN/password/fault/recovery cases with the existing
M8 host and console guards. `erase` requires the original protected KDE backups
and proves both services restored, authority revoked and native tallies retained.
Actual password UI after erase and test VM cleanup are separate host steps.
Do not export private checkpoints or raw package logs.

The recorded disabled-factor test returned PAM9 with zero authentication
prompts and one normal informational pam_debug message. The original feature
profile was restored exactly; the same enrolled TPM PIN remained usable.

## Legacy immutable-flag ownership

Stage the corrected account-helper package, then run `legacy_flags.py` with
the same expected UUID and two disposable/emulator confirmation flags. It uses
root mount and PID namespaces and private Btrfs synthetic `/etc`, `/var` and
`/run` inputs. It loads no authentication secrets and opens no TPM.

Complete old registry layouts may clear legacy immutable flags after durable
revocation. Fresh, corrupt, unknown and current registries must preserve foreign
immutable file and directory flags and refuse the operation. Unrelated inode
flags remain set. A native-lock contention case checks that durable revocation
precedes the unfreeze boundary. Cleanup touches only exact synthetic paths.
The public result binds runner source and installed helper SHA256; host topology
validation remains mandatory before this component proof.

## Native PAM type and whitespace restrictions

Stage `policy_types.py` only after installing the strict raw-policy validator.
Supply `--expected-localpin-evr` as well as the canonical expected UUID and the
two disposable/emulator confirmation flags. The fixed dedicated account must
have an existing TPM enrollment and a live trial or active gate. Coordinate the
run with the host controller; no desktop or other maintenance test may overlap.

The runner creates a private, non-overwriting intent and backups, then prepends
uppercase `AUTH`, an unknown active type, leading NBSP before `auth`, and leading
NBSP before a comment to each generated password, fingerprint and postlogin
policy separately. Every case must refuse PIN eligibility and retain the native
factor's denial. A genuine password failure establishes history; rejection must
not erase it. After restoring each exact policy, genuine full-password success
clears ordinary counters before the next case. There is no direct tally reset.

An outer `finally` restores the original authselect profile and exact bytes of
all three policies even after a failed assertion. The same enrolled PIN must
still work afterward. Public output contains booleans, runner SHA256, package
EVR and enforcing status; raw native outcomes and counter bytes stay root-only.
