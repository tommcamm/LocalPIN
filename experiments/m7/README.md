# Disposable KDE integration experiment

These tools modify only an explicitly prepared disposable Fedora 44 KDE KVM
clone with SELinux enforcing. They are experiment managers, not installers or
activation commands. The guest `run.py`, `cases.py` and `tpm.py` own protected
test changes; host `console.py` sends actual keyboard input and observes it.
Do not run these tools on an everyday host/account.

## Prepare the independent clone and access

Follow [M6.1 preparation](../m61/README.md) for production binaries, the broker,
account authority, private account schema and a genuine stock KDE/Wayland
desktop. Retain console/offline-disk recovery. Accounts are `lp61test` UID 21061
and `lp61other` UID 21062. Generate ordinary passwords as 30 lowercase ASCII
letters inside the guest, with six ASCII digit PINs distinct from the passwords
and fixed wrong-PIN fixture. Keep `/root/localpin-m61/secrets.json` guest-root
owned mode 0600. Never transfer it to the host or export it as evidence.

Use the independent domain `localpin-m7`; keep original `localpin-m1` off.
The clone needs one independent file-backed qcow2 disk, no host filesystem
shares or passed-through devices, and at most an empty read-only file CD-ROM.
Start without a TPM. Do not reuse the original VM's disk or a host account.

Create a private host access directory such as `.local/m7` containing temporary
`id_ed25519`/public key files and `known_hosts` pinned to the clone's actual SSH
host key obtained through a trusted console/offline path. The private key must
be mode 0600. Use root SSH only to this clone with `BatchMode=yes`,
`IdentitiesOnly=yes` and `StrictHostKeyChecking=yes`; never disable host-key
checking. Its user-owned `clone.json` has this schema:

```json
{
  "name": "localpin-m7",
  "uuid": "<canonical-clone-uuid>",
  "disk": "/var/lib/libvirt/images/localpin-m7.qcow2",
  "independent_disk": true,
  "physical_tpm": false,
  "host_filesystem_shares": false
}
```

Replace the UUID placeholder with the actual libvirt/DMI clone UUID. The
controller checks identity/activity, the independent disk, original inactivity
and forbidden-device absence over one persistent libvirt system connection.
Guest UUID/experiment guards are checked on every SSH operation. Access files
must not be writable by other users.

## Build and stage exact artifacts

Build the binaries and separate test client as described in M6.1, then build
the production PAM cdylib and bounded non-root probe:

```sh
cargo build --release --locked -p localpin-pam
cc -std=c11 -O2 -Wall -Wextra -Werror \
  -isystem "${LOCALPIN_PAM_INCLUDE:-/usr/include}" \
  experiments/m7/pam.c -l:libpam.so.0 -o /tmp/localpin-m7-pam-probe
```

`LOCALPIN_PAM_INCLUDE` can point to extracted `pam-devel` headers; it changes
only test compilation. Through pinned SSH, stage these current reviewed files
under root-only guest parent directories. Retain the M6.1 binary/policy staging
layout. Do not replace installed binaries while a case is active.

| Repository/build artifact | Guest staging destination |
| --- | --- |
| `experiments/m61/run.py` | `/root/localpin-m61/run.py` |
| `experiments/m61/pty_client.py` | `/root/localpin-m61/pty_client.py` |
| `experiments/m7/run.py`, `cases.py`, `tpm.py` | corresponding files under `/root/localpin-m7/` |
| `target/release/liblocalpin_pam.so` | `/root/localpin-m7/liblocalpin_pam.so` |
| `crates/localpin-auth/policy/kde-localpin.review-required` | `/root/localpin-m7/kde-localpin.review-required` |
| `/tmp/localpin-m7-pam-probe` | `/root/localpin-m7/pam-probe` |

Use the exact reviewed KDE sample: `run.py` refuses unknown stock/integrated
digests. Its install phase copies the probe under `/usr/libexec/localpin/` and
runs it through the genuine user's manager. The probe requires real/effective
UID 21061 and bounded private framed stdin; production binaries gain no test
selectors.

Inside the verified clone, root creates `/run/localpin-m7-guard` containing the
canonical clone DMI UUID plus newline, matching the host manifest. Retain the
M6.1 guard too. These root-controlled volatile markers are clone specific;
recreate them after reboot only following independent identity verification.
The guards retain expected OS/KVM and SELinux-enforcing checks.

## Stock baseline and integrated UI

Before adapter installation, run on the host:

```sh
python3 experiments/m7/console.py --phase baseline \
  --address 192.168.122.198 --access-dir .local/m7 \
  --disposable-vm-confirmed
```

This tests ordinary password unlock, then wrong-password denial and recovery
on the same greeter PID. Use the explicit `recovery` phase first if the desktop
has idle-locked. Other phases start unlocked; `recovery` requires it locked.

Next, inside the clone:

```sh
python3 /root/localpin-m7/run.py --phase install --disposable-vm-confirmed
python3 /root/localpin-m7/run.py --phase repeated --disposable-vm-confirmed
```

Installation verifies exact identities, makes a durable original backup,
stops/revokes before policy changes, installs the actual module/probe, and
explicitly reseals/freshly enrolls. `repeated` exercises the actual `kde` stack
on one reused PAM handle with production authorities and native workers.

Then invoke host `console.py` with `--phase pin`, `password` and `wrong-pin`,
using the same host arguments. PIN input must leave the screen locked until
Enter and leave the original password tally unchanged. Wrong PIN must produce
a native failure from that greeter before full-password recovery. Fixed
candidate selectors retrieve values only transiently over pinned SSH; nothing
prints/saves them. Python does not guarantee erasure of immutable strings.

## Prepare, test and repair each software case

Start unlocked. For example, inside the clone:

```sh
python3 /root/localpin-m7/cases.py prepare --kind broker-stopped \
  --disposable-vm-confirmed
```

Run host `console.py --phase broker-stopped` with its normal host arguments,
then always repair inside the clone:

```sh
python3 /root/localpin-m7/cases.py repair --disposable-vm-confirmed
```

Repeat separately for `broker-crashed`, `broker-stalled`, `missing-module`,
`corrupt-state`, `worker-missing` and `cooldown`. Each submits the enrolled PIN,
requires native denial on the same greeter, then unlocks with the full password.
Pair UI results with guarded setup/repair evidence: the label alone does not
prove a fault. Missing-module checks need a fresh greeter, not an already loaded
mapping. Repair checks saved hashes/process identities and uses actual privileged
revocation/resealing as needed. Resolve existing fault markers before starting
another case. After interruption, inspect/repair first, then explicitly recover
the existing locked greeter.

For six-digit passwords, run guest `cases.py six-password`, host `console.py
--phase sixpassword`, then guest `cases.py ordinary-password`, with confirmation
arguments. Mutation revokes first and freshly enrolls; keep the PIN distinct.
For stronger budget evidence, issue exactly four actual wrong-PIN verifications
after the one GUI six-digit password unlock and require durable cooldown. Fresh
enrollment resets the baseline, so this proves that GUI password consumed one
PIN guess. Restore the ordinary password and fresh enrollment afterwards.

## Native policy restrictions and counters

Guest `cases.py profile-faillock` selects the exact reviewed with-faillock graph
and freshly seals/enrolls. Test native counter changes, PIN success preserving
them, password recovery, and `prepare --kind lockout`. Host `--phase
locked-account` requires both PIN and password denial on the same greeter and
deliberately leaves it locked. After guest repair, use host `--phase recovery`.
Restore the reviewed default with guest `cases.py profile-default` afterwards.

Other guarded kinds are `password-locked`, `account-expired`, `password-expired`,
`forced-change`, `restricted-shell` and `nologin`. Require production worker/status
refusal of PIN availability. Use host `locked-account` for `password-locked`;
the other named host phases test PIN denial then the original password route.
KDE uses this stack's auth/setcred operations without account management. An
account-phase restriction can therefore disable PIN while the original
auth-only password route still succeeds. Preserve that actual original
behavior; the generic both-denied phase does not fit every restriction. Always
repair before the next case and retain sanitized worker/status observations.

## Private emulated TPM

Physical TPM validation remains separate M9 work. Before attaching an emulator,
stop the broker, durably revoke through the actual account manager, and shut down
this clone. Keep the original VM off. Configure exactly one libvirt-managed
`tpm-crb`, backend `type=emulator`, `version=2.0`, with no caller-supplied
source/device. Capture/check exact XML before restart. If active XML exposes a
generated source, only the clone's private Unix socket under
`/run/libvirt/qemu/swtpm` or `/var/run/libvirt/qemu/swtpm` is accepted. Physical
passthrough, host shares and external device paths remain forbidden.

After verifying restarted identity and the managed emulator, guest root creates
regular single-link mode-0600 `/run/localpin-m7-emulator` containing canonical
UUID, newline, `emulator2.0`, newline. Recreate other volatile guards after
identity verification. Host and guest independently require explicit opt-in.

Inside the clone:

```sh
python3 /root/localpin-m7/tpm.py enroll \
  --disposable-vm-confirmed --emulated-tpm-confirmed
```

This drives the installed TPM-required CLI through a private PTY, checks secret
echo suppression, and verifies an actual native TPM credential through the
non-root PAM probe using `/dev/tpmrm0`. Run host `console.py --phase pin` with
the additional `--emulated-tpm-confirmed` flag for the actual UI route.

Run guest `tpm.py prepare` with both flags, host `console.py --phase tpm-fault`
with emulator confirmation, then guest `tpm.py repair` with both flags.
Preparation unbinds the exact guest CRB device, removing the native resource
manager while retaining its TPM credential. PIN must fail while password
recovery remains available. The fixture pins the measured platform driver
`/sys/bus/platform/drivers/tpm_crb_acpi` and requires the native class, driver
entry and reciprocal ACPI `physical_node`/`firmware_node` links to agree before
changing it. Repair rebinds that device and requires native device 0 and the same
credential. On the measured kernel, rebind instead allocated `tpm1`/`tpmrm1`;
the fixed production path remained unavailable and the repair marker stayed
pending. Never alias another node to `/dev/tpmrm0` or select a different TCTI.
Record that failed in-place strategy separately. A guarded restart of only this
clone may restore native device 0; verify the unchanged emulator XML and recreate
volatile guards. M6.1 deliberately refuses PIN after reboot loses authoritative
volatile faillock state, even with unchanged registry and credential bytes.
Record that refusal and keep password recovery available. Do not reconstruct or
clear the old counters to preserve enrollment. Explicit privileged domain
revocation, fresh provisioning and new enrollment are required to recover that
case; retire only the known device-fault marker after durable revocation.
Retain before/after state comparisons privately and export only equality facts.
No physical TPM, caller-selected TCTI or synthetic TPM record
substitutes for this path. Emulator results do not establish physical hardware
latency, reliability or usability.

## Evidence and cleanup

The controller bounds lock/unlock polling to 15 seconds. Denial phases wait at
most 12 seconds for a native failure from the exact greeter, then allow four
seconds for KDE's asynchronous randomized failure timer before recovery input.
Typing earlier can lose input while the field is disabled.

Only sanitized state, timings, submission counts, process facts and tally
digests enter host `ui-results.json`. Guest `run.py` accumulates
`/root/localpin-m7/evidence.json`; retain sanitized case setup/UI/repair results
too. Export reviewed evidence, digests, package/session facts and emulator XML
facts only. Never export secrets, account/hash files, credential/emulator state,
private SSH keys or restriction backups. Failed/interrupted phases record no
pass and can leave the dedicated desktop locked.

Repair all active markers first. Guest `run.py --phase restore
--disposable-vm-confirmed` checks the durable original backup and unchanged
artifacts, stops/revokes, restores the original KDE policy and removes the
module. Inspect unknown changed files instead of overwriting them. Stop
remaining clone-only services and retain revocation before shutdown. Remove
temporary access, shut down, then dispose of only the verified independent
clone and its owned disk/NVRAM/private emulator state after evidence export.
Remove local temporary keys/access files. Keep the original VM and host
accounts/PAM untouched. This clone cleanup does not implement M8 uninstall.

Source checks need no VM operation:

```sh
python3 -m py_compile experiments/m7/run.py experiments/m7/cases.py \
  experiments/m7/console.py experiments/m7/tpm.py
```
