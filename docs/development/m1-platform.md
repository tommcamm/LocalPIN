# M1 platform inventory and session feasibility

Date: 2026-10-16. Status: tooling, source inspection and bounded enforcing-VM
session/account/worker evidence delivered. Production caller selection,
eligibility and UID lifecycle remain open. This report does not certify the
observed host or authorize authentication changes.

## Reproduce the inventory

The dependency-free Python collector reads metadata and the explicit candidate
service's complete PAM include/substack graph, across all four PAM phases. Run
from the repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s experiments/m1/platform -p 'test_*.py' -v
mkdir -p .local/m1
python3 experiments/m1/platform/inventory.py --service kde --symlink-root /etc/authselect --host > .local/m1/platform-inventory.json
```

`--service kde` is a candidate supplied by the operator. The collector always
marks service identity unverified: a file named `kde` does not prove the installed
locker selects it. The [PAM report](m1-pam.md) records the matching Fedora SRPM,
build definition and installed-binary inspection that establish that separately.
Use `--pid <locker-pid>` to observe the actual locker's sd-login membership when
it exists; omitting it observes the collector process.

The JSON contains exact queried RPM NEVRA values, file hashes, graph edges,
phase/module metadata, SELinux mode and session discovery observations. It
excludes PAM file contents, module arguments, usernames, raw session/seat IDs,
process command lines, environment and raw command errors. It does not read
shadow, credentials or TPM devices. Service/module filenames remain visible;
review generated metadata before sharing it. Keep the generated report under
ignored `.local/`; commit only an intentionally reviewed summary.

Exit status 0 means the supported inventory grammar was traversed without a
PAM-file error. It says nothing about desktop compatibility or optional host
queries: inspect their individual `status` fields. Exit status 2 means a graph
was incomplete. Missing files, cycles, unreadable/nonregular/oversized files,
unknown grammar and unsupported paths are explicit errors. Traversal continues
through independent edges after a failure. External symlink destinations require
an explicit allowed root; Fedora authselect links therefore use the flag above.
The collector never flattens a substack into an include, evaluates control rules,
opens a PAM transaction or validates an activation layout. It deliberately
refuses noncanonical include paths instead of guessing their interpretation.

The synthetic suite currently has 20 passing tests, including missing includes,
cycles, all phases, comments/arguments redaction, symlinks, FIFO/directory
rejection, continuation and malformed syntax, and local/remote/root/other-UID
session filters. These tests establish inventory behavior, not authorization.

## Read-only development-host observations

The collected metadata identifies Fedora 44 KDE on x86_64. Exact selected
installed package inputs were:

| Package | Observed NEVRA |
|---|---|
| kscreenlocker | `kscreenlocker-0:6.7.5-1.fc44.x86_64` |
| plasma-workspace | `plasma-workspace-0:6.7.5-1.fc44.x86_64` |
| PAM | `pam-0:1.7.2-2.fc44.x86_64` |
| authselect | `authselect-0:1.7.1-1.fc44.x86_64` |
| systemd | `systemd-0:259.9-1.fc44.x86_64` |
| SELinux policy | `selinux-policy-0:44.11-1.fc44.noarch` |
| Targeted policy | `selinux-policy-targeted-0:44.11-1.fc44.noarch` |
| swtpm | `swtpm-0:0.10.2-1.fc44.x86_64` |
| TPM2-TSS | `tpm2-tss-0:4.1.3-9.fc44.x86_64` |

Queries for the package names `fedora-release` and `fedora-release-kde` returned
nonzero; OS identity above comes from the allowed `/etc/os-release` fields. The
three installed `kernel-core` versions were `7.2.7-200.fc44`,
`7.2.9-200.fc44` and `7.2.10-200.fc44`, all epoch 0, x86_64. Installed packages
do not establish which kernel is running or which policy/features are active.

The candidate graph was fully traversed with these SHA-256 digests:

| Service file | SHA-256 |
|---|---|
| `kde` | `e8e0b586ca082b13d3bb3f7953a1aa460cc7f5c6af8ca787cbb9dffd21f9b62b` |
| `password-auth` | `2e53f704372b6c7fb69cdc4dfd6c27456d642c83feff8b1588fa1f9cb1126cd0` |
| `postlogin` | `c1ecd4d1a5b5de7d26e3336cd33551d1d65e13751b5f46405183472895838a9d` |

`kde` has an auth substack edge to `password-auth` and auth include to
`postlogin`; its account/password/session phases also reference those files.
`password-auth` and `postlogin` were symlinks resolved within the explicitly
allowed authselect directory. The host already has `pam_pinlock.so` in `kde`.
Its configuration is migration context, not a clean distribution fixture; its
contents were not copied into this repository. No file was changed.

A separate read-only `authselect current --raw` query succeeded; its feature
tokens did not include `with-faillock`, and the traversed graph contained no
`pam_faillock.so`. The recognized original auth modules in `password-auth` were
required `pam_env`, required `pam_faildelay`, sufficient `pam_unix`, then required
`pam_deny`. Its account phase has required `pam_unix`; `kde` additionally has
required account `pam_nologin`. A new sufficient module before the original auth
substack would bypass those auth checks, while KDE's auth-only flow would not
reach the account checks at all. This layout requires explicit eligibility and
required-check preservation design; it is not a ready-to-activate template.
No `with-faillock` behavior was exercised on this host.

`getenforce` returned `Disabled`, so this machine supplies no enforcing-mode
evidence. For the observed collector process, `sd_pid_get_session` returned
`-ENODATA` (-61), while `sd_pid_get_owner_uid` succeeded and identified its own
UID. This confirms why a direct-session-only lookup would miss some processes;
it does not establish the actual locker's membership. `loginctl` session listing
failed under the execution sandbox, and no live session/seat matrix was tested.

A read-only `virsh --connect qemu:///session list --all` outside the syscall
sandbox returned an empty inventory. No Fedora guest image was found in the
scoped local/Downloads/libvirt locations inspected. At that initial stage the maintainer confirmed no VM was available. That
initial host inspection started no guest and changed no host SELinux, PAM or TPM
setting. The maintainer subsequently supplied the disposable enforcing VM used
for the evidence below.

## Source evidence and decisions

The [KDE v6.7.5 PAM contract](https://github.com/KDE/kscreenlocker/blob/v6.7.5/README.pam)
describes `kde` as the default compile-time service and an auth-only consumer.
The [authentication implementation](https://github.com/KDE/kscreenlocker/blob/v6.7.5/greeter/pamauthenticator.cpp)
calls authentication and credential refresh while retaining its PAM handle;
the matching Fedora-source inspection is in the PAM report. This means an
`account` section in the file cannot by itself establish expiry/lock checks on
a PIN short circuit. An explicit, password-free eligibility path must be proved
against the actual guest policy. Failure or uncertainty keeps the PIN route
unavailable; adding a generic `pam_permit` account path cannot resolve it.

The [systemd sd-login API documentation](https://github.com/systemd/systemd/blob/v257/man/sd_pid_get_owner_uid.xml)
distinguishes direct session membership from user-manager ownership and
documents PID lookup races. The
[logind interface](https://github.com/systemd/systemd/blob/v257/man/org.freedesktop.login1.xml)
exposes all sessions and their seats. These references motivate the discovery
approach; they are reference versions, not a claim that the observed systemd
259.9 or guest behavior was fully tested. The collector reports each candidate
independently and never selects the first seat or treats `Active=yes` as caller
attestation. [ADR 0003](../adr/0003-session-and-worker-boundaries.md) defines the
provisional broker rules and the refusal cases that still require guest tests.

The [Linux-PAM parser](https://github.com/linux-pam/linux-pam/blob/v1.7.2/libpam/pam_handlers.c)
and [configuration reference](https://github.com/linux-pam/linux-pam/blob/v1.7.2/doc/man/pam.conf-syntax.xml)
establish why phase, include/substack boundaries and surrounding control rules
must survive integration. The inventory is intentionally smaller than PAM's
interpreter; an error blocks automatic interpretation instead of approximating
an unfamiliar policy.

## Collected enforcing-VM evidence

The [reviewed session inventory](../../experiments/m1/vm/results/2026-10-16-session-discovery.json)
records Fedora 44 KDE with the same selected PAM, locker, authselect, systemd and
SELinux package versions above. Its unmodified KDE service digest is
`7d91b3ad73a998e8b10f9edccd74ba04179a778c4a5e61d9176872f43c7bbac3`;
password-auth and postlogin match the listed digests. The installed greeter hash
matches the packaged-source inspection in the PAM report.

The actual greeter ran with the ordinary test UID as both real/effective UID in
`unconfined_t`. Direct sd-login lookup returned -61; user-manager ownership
resolved to the same UID. A separate corrected collector invocation from a
`systemd-run --user` unit observed that same membership shape and exactly one
own-UID local seated Wayland KDE candidate. Its sanitized JSON is the user-unit
observation, not a live greeter observation. Root/remote SSH and seatless manager
sessions were discovered and excluded. Discovery still does not attest a caller
as genuine KDE or establish production authorization.

[Real-account policy tests](m1-vm-pam.md), [stock KDE fallback](m1-vm-kde.md), and
[enforcing boundary/worker tests](m1-vm-selinux.md) now supply separate evidence.
None installs a production PIN verifier. See each report for its precise scope.

## Coverage and remaining VM gates

The linked reports above record the collected subset of this coverage matrix.
The subsequent [topology lab](m1-vm-topology.md) closes the M1 feasibility GUI
cases: genuine same-UID desktops with an actual ambiguous locker/password
fallback, and two independently routed native seats with both stock lockers
unlocked after one password entry each. Final clone recovery is complete.
The matrix also includes later production caller, policy, lifecycle and race
requirements; those are not marked implemented by feasibility observations.

Use a dedicated local test account with no reused personal password and a
snapshot that can be discarded. Before any experiment, require `Enforcing` and
record a fresh inventory with the exact guest packages. Keep a working guest
console and a snapshot. No LocalPIN activation is supplied by this milestone.

| Experiment | Required result and evidence |
|---|---|
| Real locker membership | Compare the locker's direct-session result with a process launched by `systemd-run --user`; enumerate all own-UID sessions and seats. |
| Multiple sessions/seats | Direct mappings identify their eligible session; user-manager mapping succeeds only for one eligible session. Zero or ambiguous candidates make PIN unavailable. |
| Exclusions | Other UID, root, remote, tty, greeter, closing, seatless and unsupported desktop sessions cannot authorize PIN. Session disappearance/replacement fails safely. |
| Account eligibility | Locked, expired, forced-change, deleted and policy-restricted accounts cannot obtain PIN authorization, while normal password handling and counters retain their established behavior. |
| Broker DAC/SELinux | A real guest locker domain can contact the broker socket; it cannot read broker state or access the TPM directly. Foreign UID, wrong label and inaccessible socket deny safely. |
| Password worker | A separate short-lived privileged worker can run the reviewed password/account policy and required PAM helpers under its own sandbox, including failed-password accounting. |
| Negative policy | Stop the broker and introduce a narrowly scoped guest-only socket denial. The measured unavailable result returns to the original password route; logs contain no candidate. |
| Boundary teardown | Restore the guest snapshot; record explicit pass/fail/infrastructure status and sanitized AVC cause/type/class/permission, with usernames, PIDs and full paths removed. |

The SELinux experiment must use a purpose-written narrow policy and reviewed
labels/domains. Do not generate broad allow rules or set permissive mode. The
broker's no-network/state/device sandbox and the password worker's legitimate
PAM-helper requirements are separate experiments. A same-domain Unix-socket
demo or a generic worker timeout test cannot certify either one.

The first VM session inventory exposed a collector defect: `loginctl` v259
treats a comma-separated `--property` value as one unmatched property and returns
empty output with status 0. The collector now repeats the flag for each required
property and marks missing/invalid fields as incomplete, without substituting
false eligibility observations. Two regressions cover the actual command shape,
metadata redaction and empty-success refusal. The
[versioned argument parser](https://github.com/systemd/systemd/blob/v259/src/login/loginctl.c)
supports that correction. Earlier all-false guest session rows from the defective
query must not be used as evidence of an ineligible session.

UID deletion/recreation remains unresolved: matching UID/name/home fields do
not detect an identically recreated account. Enrolled-UID reuse is unsupported,
and production activation remains blocked until an enforced lifecycle mechanism
or a visibly reviewed specification narrowing has executable evidence. A manual
promise never to reuse UIDs is not that mechanism. No session, SELinux or UID
lifecycle release gate is marked passed by this report.
