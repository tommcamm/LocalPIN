# Fedora package and confinement contract

This is a project-distributed, unsigned x86_64 Fedora 44 appliance RPM. It is an
implementation and validation input, not a release certification or Fedora
repository submission. M8's recorded 49-case installed lifecycle matrix passed
on the restricted Fedora 44 x86_64 Btrfs appliance with SELinux enforcing and a
private TPM emulator; see the [M8 report](../../docs/development/m8-packaging-recovery.md).
M9 independently reviews the PAM ABI,
account authority, installed confinement and physical TPM behavior.

## Build without installing

The builder runs the pinned Rust toolchain with `--release --workspace --locked
--offline`, verifies native x86_64 ELF artifacts, records their hashes and native
RPM inputs in `BUILD-INPUTS.json`, builds the purpose-written policy, and runs
`rpmbuild -bb`. It never installs an RPM, loads policy, edits PAM or starts a
service. The Cargo dependency cache must already contain the locked inputs.

```sh
python3 packaging/fedora/build-rpm.py --output /tmp/localpin-rpm
```

Native development inputs are TPM2-TSS 4.x, DBus, a C linker, the pinned Rust
toolchain, `rpm-build`, `checkpolicy`, `policycoreutils`, and Python 3.11 or newer.
An unpacked native development RPM may be selected with `--native-sysroot PATH`;
this only supplies pkgconfig and link search paths and installs nothing. The
TPM2-TSS build script requires matching versions across its four libraries.
Use `--release 0.2.alpha1` to build a second RPM transaction fixture from the same
reviewed policy/schema. This does not by itself demonstrate a safe upgrade.

The staged source archive includes native release binaries, their build record,
the project crate sources, and packaging sources. It is intentionally a binary
bundle for project distribution. Future Fedora repository inclusion needs a
normal source-only recipe, Fedora Rust dependency/vendoring policy, reproducible
build evaluation, license/SBOM review, package review and a controlled signing
step. Nothing here claims those requirements are satisfied.

## Installation and explicit activation

Installation supplies `/usr/bin/localpinctl`, native helpers and the root-only
integration tool under `/usr/libexec/localpin/`, the PAM module under
`/usr/lib64/security/`, private fail-closed PAM files, reviewed templates under
`/usr/share/localpin/policy/`, systemd units, tmpfiles rules, a disabled vendor
preset, and the `localpin` SELinux module. Helpers are ordinary mode-0755 native
executables; no setuid bit, file capability or pkexec/polkit authorization is
installed. The administrator invokes the integration tool through `sudo`.

The RPM does not enroll accounts, modify KDE/authselect/faillock configuration,
enable a socket or start a broker on initial install. In particular, it does not
replace the distribution's `/etc/security/faillock.conf` with a package default.
The only installed `/etc` files are LocalPIN's private deny policies, marked
`%config(noreplace)`. An explicit integration `prepare` validates the entire
supported immutable-account domain, backups, fingerprints and native dependencies
before making its separately reviewed transactional edits.

Before activation, use the integration tool's `status` and dry-run support,
provision only the verified local-account appliance, enroll and test with the
broker, and perform actual PIN, password and console-recovery tests. `record-tests`
is an administrator attestation tied to exact inputs, not an automatic proof of
desktop behavior. Trial activation expires on its bounded boot clock. The
observed parallel-fingerprint/with-faillock layout is refused: no package script
clears its counters or disables an authenticator to mask the incompatibility.

The persistent `/var/lib/faillock` directory retains the distribution's
`faillog_t` label so normal password authentication and LocalPIN consult the same
tally. A separate offline administrator transition preserves native tally bytes
and selects the exact reviewed `dir = /var/lib/faillock` configuration;
integration preparation only verifies this prerequisite. Package installation,
broker startup, and tmpfiles do not create missing per-user authority or reset a
tally. State, accounts and throttle data have no age-based cleanup rule.

## Sandbox and SELinux boundaries

`localpin.service` starts in the exact `localpin_broker_t` domain with NNP. Its
only writable state paths are `/var/lib/localpin` and `/var/lib/faillock`. The
immutable account registry and integration gate are read-only. The unit has a
private temporary directory, strict system protection, protected home/kernel/
clock/cgroup interfaces, no core dump, bounded memory/tasks/files, native syscall
architecture and no IP address family. AF_NETLINK is admitted solely because
native PAM audit writes require it. There is no audit-read/control capability.
The unit denies `setsid`; only the broker domain may call `setpgid` before a
helper exec. Helper descendants cannot detach from the charged process group.
`RestrictSUIDSGID` is deliberately omitted: systemd 259 implements it by returning
`ENOSYS` for every `openat2` call, which would disable LocalPIN's required
descriptor-relative path boundary. NNP, the capability bound, root-private
writable credential paths, and SELinux's absence of executable permission on
writable state remain enforced. See the maintained
[systemd seccomp implementation](https://github.com/systemd/systemd/blob/v259/src/shared/seccomp-util.c#L2274).

The current architecture execs one-operation native helpers inside the service's
common cgroup and filesystem sandbox. SELinux supplies the narrower per-helper
boundary: `localpin_auth_t` can run the fixed password PAM policy and write the
canonical tally; `localpin_eligibility_t` checks the fixed account policy and can
run only the preauth/account-check hooks, with unchanged-tally checks;
`localpin_backend_t` receives bounded credential records
over private IPC and alone can open the TPM. There is no shell execution,
network NSS grant, broad PAM interface, password-update helper transition, or
unconfined service exception. The broker executes no PAM stack.
Native `pam_unix` account expiry checks execute Fedora's `unix_chkpwd` helper
even for the root caller. Only the two PAM domains may transition to its
maintained `chkpwd_t` domain; their private pipes and completion notification are
scoped explicitly, and broker timeout cleanup can kill this descendant too.
NNP remains enabled because the caller already runs as root.

The capability bound is `CAP_DAC_READ_SEARCH CAP_AUDIT_WRITE`, with
SELinux granting only DAC-read/search to the broker, DAC-read/search plus audit
write to eligibility and authentication.
The backend has no capability permission. The broker's existing immutable
lifecycle authority hashes `/etc/shadow` and `/etc/gshadow` while checking pinned
inputs; its read-only `shadow_t` permission is explicit. This policy does not
claim the broker is unable to read password hashes. It cannot modify them.

Both PAM workers may open the existing canonical tally read/write because native
Linux-PAM 1.7.2 preauth uses `O_RDWR` and an exclusive lock even when checking
without changing it. Neither domain may create, unlink, relabel or change the
tally's owner or mode. Eligibility validates the exact preprovisioned user:root
0660 file and compares its bytes/metadata before and after native preauth; this
is a trusted-code invariant, not a claim of SELinux-enforced read-only access.
See [Linux-PAM's tally opening](https://github.com/linux-pam/linux-pam/blob/v1.7.2/modules/pam_faillock/faillock.c)
and [preauth evaluation](https://github.com/linux-pam/linux-pam/blob/v1.7.2/modules/pam_faillock/pam_faillock.c).

The main unit permits only `/dev/tpmrm0` read/write through the device cgroup.
The broker can only stat the TPM type; the backend domain can open it. No raw
`/dev/tpm0` access or device relabeling is installed. A software enrollment still
requires explicit user acceptance. An appliance deliberately restricted to
software may copy `/usr/share/localpin/systemd/software.conf` to
`/etc/systemd/system/localpin.service.d/90-software.conf` and reload systemd;
that override removes TPM device permission entirely.

`localpin_state_t`, `localpin_accounts_t`, and `localpin_backup_t` protect
credentials, registry and recovery material. Storage is part of the broker; no
separate storage process is claimed. The public activation gate is the only
readable integration file: its directory is 0755, gate 0644, and `control/`
containing manifests/backups/lock is 0700. `userdomain` receives only broker
socket contact and public gate reads. It receives no state, shadow, registry,
backup or TPM permissions. This socket permission does not newly confine an
otherwise unconfined desktop; the VM matrix needs a separate confined denied
client and actual desktop denial/fallback observations.

For socket activation, systemd 259 derives the kernel socket SID from the
service's exec context, while labeling the filesystem socket node separately.
The policy therefore lets `init_t` create the broker's `localpin_broker_t` socket
and uses `localpin_runtime_t` for its pathname; an object context is not placed
in the socket unit's process `SELinuxContext` setting. See the maintained
[systemd socket implementation](https://github.com/systemd/systemd/blob/v259/src/core/socket.c)
and [SELinux labeling helpers](https://github.com/systemd/systemd/blob/v259/src/shared/selinux-util.c).

Policy compilation alone does not prove successful installation, correct domain
transitions, complete permit paths or absent unexpected AVCs. Those require
enforcing VM evidence against exact Fedora package inputs. Diagnose fixed denied
operations; never disable SELinux or generate broad allow-all policy.

The first installed enforcing run exposed two distinct startup failures. The
manager initially returned `226/NAMESPACE` while mounting the custom runtime
directory; an `init_t` `mounton` grant limited to the unit's declared state,
runtime, account, gate and tally directories corrected that step. The broker
then reported `Unsupported` at its first trusted `openat2` path operation, with
no AVC: the conflicting `RestrictSUIDSGID` seccomp rule above caused it. With
that option removed, the actual broker started and a non-root client received
valid broker status. The final installed VM report separately records passing
account eligibility, native enrollment, GUI operation and package lifecycle
checks against the matched self-contained RPMs.

## Upgrade, erase and text-console recovery

On upgrade the old installed tool first compares the candidate Epoch/Version/
Release using the distribution's `rpm.labelCompare`, refuses a lower candidate,
and checks the known policy/schema and protected inputs, then closes the gate
and stops the broker. A narrow native cache window durably journals the original
registry and revokes the live registry before clearing only `/etc`'s directory
immutable flag. All protected regular files and other directories stay immutable
continuously. This lets the distribution's real `ldconfig` triggers update
`/etc/ld.so.cache` without disabling triggers or unfreezing account files.
The new tool resumes only a validated compatible suspension; the gate remains
closed and tests must be repeated before activation. Private
PAM configurations use `%config(noreplace)` and remain locally managed. The VM
upgrade test must prove RPM preserved their bytes, inode/immutability and native
enrollment, rather than assuming `%config(noreplace)` is enough. Unsupported
schema/policy transitions and version changes require explicit recovery and fresh
provisioning; they must fail before silently discarding enrollment or throttles.

Resumption runs in the new package's low-priority `transfiletriggerin`, after
RPM 6.0.2 has run installed-package transaction-in and transaction-postun
triggers, including glibc's cache updates. It does not run in `%post`. Native
completion requires the fixed protected journal, a still-revoked registry,
unchanged protected file/link/other-directory snapshots and the same `/etc`
directory identity/owner/mode. It refreezes `/etc` and retains original account
incarnations while updating only its directory metadata. The gate stays closed
on failure. An interrupted native window keeps the registry revoked until its
validated finish; a later binding or service failure may retain the exact
restored registry without reopening the gate. Ordinary account mutation invalidates the
pending journal before changing any protected input. See the exact
[RPM 6.0.2 transaction ordering](https://github.com/rpm-software-management/rpm/blob/rpm-6.0.2-release/lib/transaction.cc#L1759)
and [file-trigger priority contract](https://rpm.org/docs/6.0.x/manual/file_triggers.html).

On final erase `%preun` runs `disable`, then `package-check --removal`, then stops
and disables the socket. The integration tool, workers, module and SELinux policy
remain installed throughout that procedure. A changed owned graph, unreadable
backup or failed recovery aborts erase with a nonzero scriptlet result. Only
after successful recovery may RPM delete binaries and `%postun` remove policy.
Unrecognized administrator changes require a reviewed merge. Credential,
throttle, account, persistent tally and protected backup contents are retained;
RPM only removes empty owned directories. Do not force erase with `--noscripts`.

With a working text console and full administrator password, the short recovery
operation is:

```sh
sudo /usr/libexec/localpin/localpin-integration disable
sudo /usr/libexec/localpin/localpin-integration status
```

If owned recovery refuses a changed file, keep the package installed and inspect
the protected original/digests in `control/`; do not overwrite unrelated PAM
changes with a guessed backup. Missing-module or broken-broker tests must leave
the existing full-password route usable, and actual graphical recovery must be
demonstrated without reinstalling or rebooting the disposable VM.
