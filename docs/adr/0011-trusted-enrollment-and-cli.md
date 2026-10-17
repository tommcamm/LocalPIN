# ADR 0011: Trusted enrollment and terminal input

Date: 2026-10-17. Status: accepted development implementation; installed PAM,
confinement and production account lifecycle gates remain open.

## Decision

An own-user mutation is a single broker-owned transaction on one authenticated
socket. The broker retains the stable UID storage lock from action resolution
through final delivery. It resolves enroll, rotation, explicit backend migration
or disable against committed state before issuing the proposed generation.
Neither an old PIN nor a client authentication assertion authorizes a change.

The separate `localpin-auth-worker` runs one fixed password-only PAM service,
with an empty environment and private bounded IPC. The supervisor correlates
the result with a fresh random nonce for the complete core transaction and
accepts it only after successful worker exit and exact output validation. Four
live or retired password worker groups are permitted, with one per UID; timeout
or cancellation retains capacity until cleanup. The password conversation lasts
at most sixty seconds and a successful grant permits commit for strictly less
than sixty further seconds on the same boot, account, socket, action and
generation. No grant is persisted or returned as a reusable token.

The supported password profile is deliberately narrow: `pam_unix` password
authentication, `pam_faillock` accounting and `pam_unix` account checks. Its
canonical service contents must match the reviewed profile. Includes,
fingerprints, PIN modules, cached authorization, empty passwords and
success without a fresh hidden password prompt are refused. One hidden password
prompt is supported; module informational/error text is bounded and suppressed,
and other conversation styles fail closed. The broker relays fixed text on the
authenticated channel. PAM receives password bytes through its native C
response ABI; embedded NUL, empty and oversized responses are rejected rather
than truncated. This fixed profile is not a claim to enforce every Fedora
authselect policy. An administrator must review and package the supported
policy before installation; the shipped default is disabled.

After authentication, credential creation and trial verification run in the
existing disposable backend supervisor, sharing its four process slots and the
256 MiB KDF budget. The broker validates the returned account, incarnation,
generation, backend and parameters, persists the candidate, reopens it and
verifies that exact record before committing. TPM errors do not choose
software. Auto requests attempt TPM; a failed attempt requires a new explicit
software request and fresh password authorization. The grant's expiry,
lifecycle, live session, cancellation and generation fences are checked before
the atomic commit. Once a commit has crossed the durable pointer boundary,
disconnect or response loss cannot roll it back; status resolves the result.

The non-setuid CLI accepts secrets only through a foreground controlling
terminal. It rejects secret options, recognized secret environment channels,
plaintext pipes and simulator injection. Terminal input is bounded, hidden,
confirmed for a new PIN, and erased by its owners. Terminal settings are
restored on ordinary exit, cancellation, error and handled termination/suspend
signals; SIGKILL cannot run cleanup. Arbitrary module text cannot inject terminal
control sequences. Native PAM copies remain a review input; process exit and
disabled core dumps bound their lifetime without claiming perfect erasure.
The CLI, broker and both installed worker entry points disable process
dumpability and set the soft/hard core limits to zero before handling input.
Secret processing fails closed if that process setup cannot be established.
Foreground ownership is rechecked during terminal input; losing it cancels
the operation and restores the terminal with job-control signals guarded.

Root recovery remains the separate kernel-root protocol operation. The CLI
does not gain privilege and offers no arbitrary privileged command launcher.
System integration enable/disable remains M7/M8's separately reviewed root
tooling; the CLI refuses it with an explanation. Status/doctor expose versioned
nonsecret JSON and distinguish client presence, enrollment, recorded testing
and activation. Reaching a broker or passing a credential trial is not proof
of tested KDE integration or password recovery.

## Remaining gates

ADR 0006 still refuses production unmanaged accounts. Lifecycle provisioning
must establish a protected disabled baseline; a user enrollment request never
repairs missing/corrupt state or invents an account incarnation. Complete
development broker flows therefore use explicitly synthetic account/session
authorities in isolated test executables. Installed executables have no test
mode, alternate service path, fixture worker or simulator selector.

The M5 broker unit confines backend workers and is not an established password
worker sandbox. In particular, its empty capability set, `NoNewPrivileges` and
read-only filesystem can prevent legitimate PAM helpers and failure-accounting
writes. M8 must establish the independent password-worker execution policy and
enforcing SELinux/cgroup boundaries, including descendant escape prevention.
Building these binaries neither installs the PAM service nor activates KDE.
The isolated PAM tests cannot certify installed host authentication policy.
