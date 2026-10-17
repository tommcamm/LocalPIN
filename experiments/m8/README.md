# Disposable Fedora RPM lifecycle and recovery matrix

These fixtures operate only on an independently cloned **Fedora 44 KDE KVM VM
with SELinux enforcing and a private libvirt TPM2 emulator**. They are not part
of the RPM. Never run them against an everyday installation, physical TPM,
original VM disk, production account or host PAM configuration.

`guard.py` checks active and inactive domain definitions, a dedicated independent
qcow2 volume with no backing store, every other domain's disk references, no
host filesystem/device sharing, and the private managed emulator. `host.py` and
`console.py` repeat those checks through one persistent libvirt connection before
each guest action. They require `localpin-m1` to remain off. Guest guards
independently bind root-private markers to the clone's DMI UUID, enforce the OS,
KVM, native `/dev/tpmrm0`, dedicated accounts and SELinux enforcing.

Passing source checks does not prove the runtime matrix. A successful broker
probe does not prove an actual graphical unlock. Preserve failed observations
and report incomplete phases; do not replace a failed reboot test with fresh
enrollment and call it continuity.

## Prepare an independent clone

Use the M6.1/M7 clean offline clone preparation and trusted guest-agent/console
access workflow, with the new name `localpin-m8`, a fresh UUID/MAC and one
independent `/var/lib/libvirt/images/localpin-m8.qcow2`. Attach exactly one
`tpm-crb` with backend `type="emulator" version="2.0"`; the inactive XML must
contain no source/device override. Remove USB redirection devices. Keep console
or offline-disk recovery available. Never share the original VM's writable
volume, emulator storage or host directory with the clone.

Before any managed account incarnation exists, with the display manager stopped
and no user sessions, migrate any existing native `/run/faillock` records byte
for byte to `/var/lib/faillock` on the clone's persistent Btrfs filesystem.
Preserve counter bytes, UID, modes, extended attributes and SELinux labels.
Back up the exact original GID. If native login created a primary-group tally,
follow the administrator runbook's explicit offline destination-only GID-0
conversion; production provisioning never normalizes it. Do not reset, replace
with empty records, or recreate lost counters. Install the exact reviewed configuration
`dir = /var/lib/faillock\n` in `/etc/security/faillock.conf`. This offline fixture
preparation establishes the persistent accounting boundary; `prepare` refuses a
volatile configuration. The real migration procedure is documented with the
administration tool, not inferred from this test setup.

Create only the dedicated clone accounts `lp61test` UID 21061 and `lp61other`
UID 21062, homes `/home/<name>`, shell `/bin/bash`. Generate each ordinary account
password as 30 random lowercase letters inside the guest. Generate six ASCII
digit PINs distinct from `000000` and the account password. Store only inside
root-owned mode-0600 `/root/localpin-m8/secrets.json`:

```json
{
  "lp61test": {"uid": 21061, "password": "GUEST-ONLY", "pin": "GUEST-ONLY"},
  "lp61other": {"uid": 21062, "password": "GUEST-ONLY", "pin": "GUEST-ONLY"}
}
```

Those values are placeholders, not test credentials. Establish a genuine stock
KDE Wayland session for `lp61test` using the clone's display manager. The exact
reviewed default authselect profile and files-only passwd/group/shadow NSS
configuration remain prerequisites of the restricted appliance account model.
Do not use a declared logind session fixture or custom PAM password substitute.

The host access directory (for example ignored `.local/m8`, mode 0700) contains
temporary `id_ed25519` mode0600, the clone's trusted pinned `known_hosts`, and
`clone.json`. Get the SSH host public key through the trusted guest-agent,
console or offline path; never disable SSH host-key checking. The manifest is:

```json
{
  "name": "localpin-m8",
  "uuid": "<canonical-fresh-clone-uuid>",
  "disk": "/var/lib/libvirt/images/localpin-m8.qcow2",
  "independent_disk": true,
  "physical_tpm": false,
  "host_filesystem_shares": false
}
```

After checking host topology, guest root creates single-link regular files:

| Path | Contents | Mode |
| --- | --- | --- |
| `/run/localpin-m8-guard` | canonical UUID plus newline | 0600 |
| `/run/localpin-m8-emulator` | canonical UUID, newline, `emulator2.0`, newline | 0600 |
| `/run/localpin-m61-guard` | canonical UUID plus newline | 0644 |

The final marker permits only the separate M6.1 non-root evidence client.
Recreate the volatile markers after reboot only following fresh independent
topology/identity checks. This is a fixture opt-in, not a production bypass.

## Build and stage

Build the reviewed Fedora RPM and a second, greater-release RPM from the same
policy/schema for the real upgrade case. Native runtime dependencies must
already be available in the clone. The runner uses `rpm`, so missing dependencies
cause the actual package transaction to refuse; it does not download packages.

Stage the two root-owned RPM files in `/root/localpin-m8`, plus mode0600
`packages.json` with `install_rpm` and `upgrade_rpm` basenames. Both must identify
the actual `localpin` package. Stage `run.py` and `guard.py` there. Keep the parent
mode0700. No fixture source or secret is installed by the RPM.

Build the separate client and actual PAM-stack probe:

```sh
cargo build --release --locked -p localpinctl --example m61-client
cc -std=c11 -O2 -Wall -Wextra -Werror \
  -isystem "${LOCALPIN_PAM_INCLUDE:-/usr/include}" \
  experiments/m7/pam.c -l:libpam.so.0 -o /tmp/localpin-m8-pam-probe
```

After package install, stage `m61-client` at
`/usr/libexec/localpin/m8-client`, that probe at
`/usr/libexec/localpin/m8-pam-probe`, and this directory's `pty_client.py` at
`/usr/libexec/localpin/m8-pty.py`, all root-owned mode0755 with the appropriate
restored labels. The latter drives the real installed `/usr/bin/localpinctl`
through a private controlling PTY and checks that password/PIN input is not
echoed. Secret frames are confined to test fixtures; installed CLI behavior is
unchanged.

## Execute the lifecycle

Every host invocation needs the same bounded arguments:

```sh
python3 experiments/m8/host.py inspect --address 192.168.122.X \
  --access-dir .local/m8 --disposable-vm-confirmed --emulated-tpm-confirmed
```

`inspect` and clean `install` record the guest's native PAM, systemd, authselect,
kscreenlocker, SELinux policy, glibc and TPM2-TSS package EVRs, actual kernel
release and selected authselect profile. Preserve that inventory before removing
temporary access. Unmeasured values must remain explicitly unavailable in an
existing result; host versions cannot stand in for guest measurements.

Run the following sequence, substituting only the phase. Use `console.py` for
the explicit actual keyboard cases. Keep the desktop unlocked before each case.

| Step | Runner and phase | Evidence required |
| --- | --- | --- |
| 1 | `console.py baseline` | Original password unlock on actual stock KDE |
| 2 | `host.py install` | Real RPM install leaves KDE, enrollment and activation unchanged |
| 3 | `host.py refusal-matrix`, `fingerprint-refusal` | Changed KDE/missing module and native fingerprint/faillock graph refused; exact restoration |
| 3a | `host.py legacy-prepare`; `console.py legacy-password`; `host.py legacy-migrate`; `console.py restored-password` | Exact old owned block, actual original password route, dry-run/migration, no verifier import, actual restored password unlock |
| 4 | `host.py prepare` | Dry-run unchanged; exact owned edit, fresh disabled incarnation, persistent accounting |
| 5 | `host.py enroll` | Installed CLI TPM-required enrollment through private PTY |
| 6 | `host.py isolated` | Production broker verifies actual enrolled PIN without changing native tally |
| 7 | `host.py trial` | Bounded boot-bound opt-in before GUI tests |
| 7a | `host.py fault-missing-module`; `console.py administrative-recovery`; `host.py repair-fault`; repeat steps 4–7 | Prove the real root-console recovery procedure for this package before any activation attestation; recovery revokes old authority, so prepare and enroll fresh afterwards |
| 8 | `console.py pin`, then `password` | Enter required, actual PIN/password unlock, unchanged native tally on PIN success |
| 9 | `host.py fault-missing-module`; `console.py recovery`; `host.py repair-fault` | Actual missing module, native denial, original full-password unlock on same greeter, exact repair |
| 10 | `host.py activate` | Requires same-trial PIN/password/fallback evidence and prior actual root-console recovery for the package; product enables its socket for boot |
| 11 | `host.py fault-selinux-worker`; `console.py selinux-recovery`; `host.py repair-fault`; then `host.py package-failure` | Actual enforcing AVC, native PIN denial and full-password fallback; restored label; corrupt-backup RPM erase refusal retains enrollment |
| 12 | `host.py upgrade`, `downgrade-refusal` | Actual greater-release RPM and genuine distribution cache triggers preserve enrollment/PAM inodes; registry authority may refresh only `/etc` directory size/ctime; explicit attempted downgrade refuses |
| 13 | Repeat steps 7–10 | Upgrade leaves gate closed until fresh actual desktop tests; no fresh enrollment |
| 14 | `host.py reboot-prepare` | Private durable original credential/registry/tally snapshot |
| 15 | `reboot.py request --kind ordinary`; `reboot.py complete --kind ordinary`, with the same common host arguments | Real boot change; guarded identity check before volatile marker recreation; original VM remains off |
| 16 | `host.py reboot-verify`, `console.py pin`, `password` | Same enrollment and native tally survive; actual TPM KDE PAM and desktop unlock succeed |
| 16b | `host.py cache-interrupt`; `reboot.py request --kind cache`; `reboot.py complete --kind cache`; `host.py cache-reboot-verify`; `console.py suspended-recovery` | Actual mid-package-window reboot leaves authority revoked, all protected inputs immutable except `/etc` directory, PIN unavailable and original password usable |
| 16c | `host.py cache-resume`, `isolated`; repeat steps 7–10 | Explicit completion restores exactly the original account identities and credential; no fresh enrollment; desktop gate stays closed until new tests |
| 17 | `host.py disable`; `console.py restored-password` | Explicit disable revokes authority, removes socket boot opt-in, restores exact original KDE and permits actual original password unlock |
| 18 | Repeat steps 4–10, omitting the already-proven procedure case 7a | Separate fresh incarnation for active-erase testing, only after original-enrollment continuity proofs have completed |
| 19 | `host.py locked-tally`; `console.py restricted-recovery` | Three actual private-password failures create native lockout; PIN eligibility denies while the original default password route retains its own behavior; no counter reset |
| 20 | `host.py uninstall`; `console.py restored-password` | Actual active RPM erase restores the original route before module removal, revokes authority and retains byte-exact native failed counters; actual stock password unlock afterwards |

`prepare` selects only UID21061, because each selected UID must be enrolled and
tested before trial; UID21062 remains the separate-account fixture. It imports
no old verifier. `activate` consumes root-private `ui.json` written by actual
console tests and bound to the current trial, and invokes the production tool's explicit administrator
attestation. The production tool correctly labels this as an attestation; it
does not claim to automatically verify GUI behavior.

The reboot phase compares the original private registry, active-pointer and
credential digests **before** checking availability. It then verifies the PIN
through the real KDE PAM stack, with fresh-enrollment operations absent. The
original private snapshot never becomes exported evidence.

The separate cache interruption snapshot compares all registry authority except
the explicitly permitted `/etc` directory size/ctime fields. All account IDs,
credential bytes, other filesystem bindings and native counters remain exact.
The fixture never enables the socket on its own or skips distribution triggers.

Every applicable phase above must have actual evidence before claiming the
complete M8 exit gate. A fixture limitation or missing case keeps that portion of M8 open;
unit checks cannot replace those results.

## Evidence and cleanup

Guest `evidence.json` contains sanitized successful phase observations, while
`ui.json`, `reboot.json` and fault intent remain guest-root private. Export only
the inspected sanitized phase/UI results, package metadata and cleanup facts.
Never export secrets, registry/credential bytes, account hashes, private SSH
keys, private reboot fingerprints, raw journals or root PAM backups.

Repair any known fault before cleanup. Save the final real erase result as
`final-uninstall.json` and subsequent actual keyboard password result as
`final-ui-uninstalled-password.json` in the host access directory. After exporting
only inspected sanitized evidence, run `cleanup.py` with the common host arguments
and `--remove-owned-clone`. It verifies those results and the current guest's stock
policy, absent package/module, inactive units and revoked registry. It removes
only the matching temporary SSH key, exact clone autologin fixture and guest
private fixture files; gracefully shuts down the independently guarded clone;
checks every domain and volume for references; and deletes only its recorded
independent volume, domain and private libvirt emulator state. It then removes
temporary host access keys and named offline bootstrap copies. The original VM
must remain defined, off and unchanged throughout. Any failure leaves a durable
sanitized `cleanup.json` with incomplete steps visible for review.

Local safety checks need no VM operation:

```sh
python3 -m unittest discover -s experiments/m8 -p 'test_*.py' -v
python3 -m py_compile experiments/m8/*.py
```

The [2026-10-17 runtime evidence](results/2026-10-17-fedora44-rpm-recovery.json)
records 49 actual successful cases with the final matched RPMs, exact causal
SELinux denial evidence, effective process-group constraints, preserved
enrollment/throttle across both reboot paths, native counter preservation and
completed guarded cleanup. It explicitly lists native inventory fields that
were not measured before cleanup. These results cover the restricted reviewed
profile and private TPM emulator; physical TPM and wider release validation
remain separate work.
