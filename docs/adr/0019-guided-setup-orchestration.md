# ADR 0019: Guided terminal setup with fixed privileged operations

Date: 2026-10-17. Status: accepted for development implementation; new installed
Fedora KDE onboarding and compatible-update acceptance remain unperformed.
M9 independent review and physical hardware gates remain open.

## Context

The installed manual procedure has separate preparation, enrollment, trial,
console recovery and activation steps. Desktop owners need a discoverable
entry point and a resumable guide without weakening those requirements.
[ADR 0011](0011-trusted-enrollment-and-cli.md) deliberately kept the CLI from
launching administrative integration operations. That restriction is amended
only for the explicit fixed setup workflow below; credential authorization,
secret handling and the non-setuid boundary remain unchanged.

## Decision

The RPM installs `/usr/bin/localpin` as a symlink to `localpinctl`; both names
share commands and implementation. `localpin` opens an inline terminal menu
when run interactively and prints help otherwise. `localpin setup` runs as the
current local non-root owner in a foreground controlling terminal. It uses
bounded visible input for choices and the existing private input for secrets.
Plain output works with `NO_COLOR`, `TERM=dumb` and redirected output.

The setup runner has a closed set of administrator operations: read-only setup
status, preparation preview, confirmed preparation, trial, test attestation and
activation. It runs the fixed packaged integration helper through absolute
`/usr/bin/sudo`, with individually constructed arguments, a controlled
environment, no shell and no user-selected executable or root. Sudo handles its
own password conversation. The runner never forwards enrollment secrets or
client password grants to sudo/helper processes. Ordinary account-password
verification, enrollment and PIN confirmation retain ADR 0011's broker path.

The root helper exposes a separate versioned, bounded, nonsecret
`setup-status --uid N` report for account scope, preparation readiness,
enrollment, trial validity/time remaining, attestation and actionable blockers.
It is read-only and is not the public CLI status/doctor JSON contract; those
schema-version-1 interfaces remain unchanged. Missing or malformed report
fields stop setup rather than selecting a default action.

Wizard mutations carry `--setup-uid N`. The root tool checks that UID against
both the integration manifest and protected account registry while holding the
existing administration transaction lock. The setup UID must be the sole
managed account, or the unprepared installation must contain no other managed
account. A separate CLI preflight cannot supply this protection because state
may change before mutation. Multiuser installations use manual administration.
Existing manual operations remain available without the setup-specific guard.

Native account administration shares that integration lock before acquiring
the account-registry, native password-database and storage locks. A direct
`localpin-account` mutation therefore cannot replace account scope between the
wizard's check and its policy/account changes. When the integration helper
already holds the lock, it passes its descriptor through the fixed internal
`--integration-lock-fd N` interface. The native tool verifies the descriptor
against the canonical root-owned lock and retains the same open-file
description, avoiding recursive lock acquisition. The flag selects no path or
program. Read-only `check-policy` does not create a lock; component operation
without an integration installation remains supported.

The readiness report supplies an opaque nullable `trial_ref` for a valid trial.
It is an equality reference, not authorization. The wizard retains the reference
covering its desktop-test confirmations and passes it as `--setup-trial` along
with `--setup-uid` to `record-tests` and `activate`. Inside the root transaction,
the helper requires a still-live trial bound to the current enrollment and an
exact reference match before recording tests or activating. A separate preflight
alone cannot prevent another administrator from replacing the trial between
confirmation and mutation.

Setup inspects authoritative state on each invocation and after uncertain
results. It stores no trusted user checkpoint and does not infer completed
recovery from a local progress file. It never automatically repeats preparation
for a prepared account or a healthy active installation. Legacy, suspended,
incomplete, corrupt or incompatible state produces a concrete administrator
handoff. A trial is reused only when its boot, time, policy and enrollment
bindings are valid; otherwise setup explains that tests must be repeated.
Cancellation preserves completed stages and explains any still-open trial.
Before trial or activation, setup also requires the broker to establish an
available enrollment for the current account and KDE session. Reading a
protected credential pointer alone does not establish native account continuity
or current session eligibility.

An active installation with an enrolled PIN is a no-op for setup. If only the
user's PIN was disabled, setup offers fresh own-user enrollment with an explicit
backend choice and password verification. It verifies the active state and
broker readiness afterward without preparation, a new trial or reactivation.

The supported flow is readiness check, preparation preview and confirmation,
explicit backend selection and private enrollment, bounded trial and actual
desktop/password/failure tests. The guide then sends the owner to an
administrator text console to rehearse the existing recovery command. Recovery
revokes enrollment. Rerunning setup prepares/enrolls again and requires final
trial tests, explicit recovery and desktop-test attestations, and activation
confirmation. Attestation records the operator's statement; the wizard does
not independently observe a console or desktop test and does not present it as
automated evidence.

The one-time persistent password-accounting migration stays offline under
[ADR 0014](0014-persistent-faillock.md). Setup explains the maintenance handoff
and refuses a live tally copy or reset. Installation continues to leave services
stopped and authentication unchanged. No sudoers rule, setuid CLI or general
privileged launcher is installed.

## Consequences and validation

Owners get `dnf install` followed by `localpin setup`, with an explicit offline
prerequisite when necessary. Administrators retain the complete manual runbook,
short `localpin-integration` alias and console recovery path. The wizard adds a
reviewable privilege boundary and cannot eliminate real tests or offline work.

Synthetic parser/state-machine, fixed-process-invocation, transaction-scope and
PTY checks can establish local behavior. Installed Fedora KDE with SELinux
enforcing and a private TPM emulator must separately validate clean setup,
recovery/resume, interrupted stages and compatible updates. Historical M8.1
installed evidence and passing builds do not certify this new workflow or
complete M9 independent review or physical hardware validation.
