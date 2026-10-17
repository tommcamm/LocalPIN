# M6.1 production-authority VM evidence

These fixtures run **only in an independent disposable Fedora 44 KDE KVM clone
with SELinux enforcing, Btrfs and no TPM or host filesystem shares**. They use
the actual production account manager, broker, password/eligibility helpers,
storage and native logind routing. They install no KDE unlock adapter. M7 and
M8 remain separate gates.

The runner requires root, the expected OS/virtualization/enforcing state,
no TPM device, a root-controlled `/run/localpin-m61-guard` containing that
clone's exact DMI UUID, and private dedicated-account inputs. These checks are
not consent to run on an ordinary guest or the everyday host. Create a clone
with console/offline-disk recovery available. The real bypass experiment found
an immutable-only design defect; the final manager requires kernel read leases.

## Prepare the clone

Build the committed workspace and the explicitly separate test client:

```sh
cargo build --workspace --all-features --release --locked --bins --examples
```

Transfer the actual binaries into `/root/localpin-m61/bin/`: `localpind`,
`localpin-account`, `localpin-worker`, `localpin-auth-worker`,
`localpin-eligibility-worker`, `localpinctl` and example `m61-client`.
Transfer the separate `m61-fences` example into `/root/localpin-m61/`.
Transfer both `crates/localpin-auth/policy/*.review-required` files into
`/root/localpin-m61/policy/`, and this directory's sources into
`/root/localpin-m61/`. The native crash source must also exist at
`/root/localpin-m61/src/experiments/m61/fault.c`.

Create dedicated `lp61test` UID 21061 and `lp61other` UID 21062 with homes under
`/home/` and bash shells. Generate disposable full passwords inside the guest,
set them through private `chpasswd` stdin, and store only in guest-root-private
`/root/localpin-m61/secrets.json`, mode 0600:

```json
{
  "lp61test": {"uid": 21061, "password": "GUEST-ONLY", "pin": "GUEST-ONLY", "new_pin": "GUEST-ONLY"},
  "lp61other": {"uid": 21062, "password": "GUEST-ONLY", "pin": "GUEST-ONLY", "new_pin": "GUEST-ONLY"}
}
```

The placeholders are a schema, not usable fixture secrets. PIN values must be
six ASCII digits. Keep this file and all real account/credential records out of
the repository and exports. Establish a genuine KDE/Wayland desktop for
`lp61test` through the guest's stock login manager. The recorded run used
clone-only autologin; a declared logind fixture was not substituted for a desktop.
Confirm `Desktop=KDE`, class `user`, a seat, a live user manager and actual
`plasmashell`/`kwin_wayland` processes.

The baseline graph and native hashes must match ADR 0012. The installation
phase deliberately changes the supported local NSS sources to `files` and
copies the reviewed private PAM services. Its component systemd service runs
without claiming M8 confinement. Root administration seals global account and
policy files and affects the whole disposable clone.

## Run the matrix inside the clone

Each Python invocation additionally requires `--disposable-vm-confirmed`:

```sh
python3 run.py --phase install --disposable-vm-confirmed
python3 run.py --phase flows --disposable-vm-confirmed
python3 eligibility.py --disposable-vm-confirmed
python3 lifecycle.py --phase bypass --disposable-vm-confirmed
python3 lifecycle.py --phase leases --disposable-vm-confirmed
python3 lifecycle.py --phase mutations --disposable-vm-confirmed
python3 lifecycle.py --phase state --disposable-vm-confirmed
python3 lifecycle.py --phase crashes --disposable-vm-confirmed
python3 lifecycle.py --phase reboot-prepare --disposable-vm-confirmed
```

Reboot this clone, wait for its genuine desktop and administrative access, then:

```sh
python3 lifecycle.py --phase reboot-verify --disposable-vm-confirmed
python3 lifecycle.py --phase reboot-active-prepare --disposable-vm-confirmed
```

Reboot the clone again, then:

```sh
python3 lifecycle.py --phase reboot-active-verify --disposable-vm-confirmed
python3 cli.py --disposable-vm-confirmed
python3 fences.py --disposable-vm-confirmed
```

The first reboot proves durable revocation. The second keeps an active
incarnation and demonstrates refusal after volatile faillock state is lost,
followed by explicit privileged fresh provisioning. The PTY fixture drives the
installed `localpinctl` and checks that password/PIN input is not echoed.
Private framed stdin is confined to the separate test client; the installed CLI
retains its foreground-terminal-only interface.

The `m61-fences` example composes the actual production authorities, workers,
engine and storage. It adds only a one-shot scheduling pause of at most 500 ms,
with original operation deadlines retained. The runner requires a fresh disabled
generation and absent staging artifacts, then tests actual concurrent
`begin-mutation` at credential staging, pending pointer publication, durable
backend success and the actual Granted delivery callback. It requires Busy while
leased, unchanged incarnation, the actual operation result, then successful
revocation and old-PIN denial after release. Installed production binaries gain
no test selectors. Repeated component restarts clear only the two clone-only
units' systemd start-rate accounting.

The crash tracer uses x86_64 `ptrace` on the actual manager, not a substituted
authority or an injected library. It asserts that each selected syscall boundary
was reached before killing that child. It handles direct rustix syscalls and
tests registry revocation/publication, flags, storage and unnamed-tally setup.
The root runner performs explicit offline quarantine housekeeping only after
all incarnations are durably revoked and the broker is stopped; this prevents
the repeated test matrix from exceeding the sixteen-entry production bound.

Sanitized results accumulate in `/root/localpin-m61/evidence.json`. Export that
file and package/session facts after checking their contents. Do not export
`secrets.json`, account files, credentials, private SSH keys or reboot identity
scratch files. Remove temporary access, shut down and dispose of the independent
clone after exporting evidence; keep the original clean VM off and unchanged.

Local source validation needs no guest mutation:

```sh
python3 -m py_compile experiments/m61/*.py
cc -std=c11 -O2 -Wall -Wextra -Werror experiments/m61/fault.c -o /tmp/localpin-m61-fault
```
