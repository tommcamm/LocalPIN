# localpin CLI (`localpinctl`)

The normal-user CLI uses the root-authenticated broker socket at
`/run/localpin/broker.sock`. It has no setuid mode, secret argument, environment
configuration, stdin secret input, socket override, or simulator switch.

The RPM installs `localpin` as the primary name and retains `localpinctl` for
existing commands and scripts. Source builds continue to use
`cargo run -p localpinctl -- <command>`.

```text
localpin
localpin setup
localpin doctor [--json]
localpin status [--json]
localpin enroll --backend auto|tpm2-required|software
localpin change
localpin disable
localpin migrate --backend tpm2-required|software
localpin integration enable|disable|status
localpin recover --user <local-account>
```

With no arguments, a foreground terminal opens an inline numbered menu for
setup/resume, status, diagnostics and credential management. Without a terminal,
it prints help without waiting for input. Menus use bounded visible input;
passwords and PINs use the hardened private input path below. Human output uses
subtle colors where supported and plain text when `NO_COLOR` is present,
`TERM=dumb`, or output is redirected. There is no full-screen UI dependency.

`setup` runs as the current non-root desktop owner. It checks authoritative
installation/account state, previews preparation, explicitly chooses TPM or
software protection, enrolls privately, and guides trial and real recovery
checks before final activation. The offline native-accounting migration remains
a manual maintenance handoff. Recovery revokes enrollment; rerunning setup guides
fresh preparation, enrollment and final desktop tests. No user-owned checkpoint
can authorize a skipped step. A valid live trial may be resumed; an expired,
rebooted or enrollment-changed trial needs repeated tests. Healthy active
installations remain active. Multiuser, legacy, incomplete, suspended or corrupt
state requires administrator tooling. Before trial and activation, setup checks
that the broker can establish an available enrollment for the current account
and KDE session. Cancellation preserves completed stages and reports any
remaining trial window.

The wizard invokes only fixed installed helper operations through absolute
`/usr/bin/sudo`, with closed arguments, a controlled environment and no shell.
Sudo owns its administrator-password conversation. Enrollment still runs through
the normal-user broker client and never forwards passwords/PINs to sudo or the
integration helper. The helper's separate read-only
`setup-status --uid N` report is versioned, bounded and nonsecret; it does not
change `status --json` or `doctor --json`. Wizard mutations use `--setup-uid N`
so the root helper checks the single-account scope inside the same transaction,
including both integration and account-registry scope. Test recording and
activation additionally use `--setup-trial` with the trial's opaque equality
reference; the root transaction rechecks its live enrollment binding and exact
reference before acting. The reference grants no authority. See
[ADR 0019](../../docs/adr/0019-guided-setup-orchestration.md).

Enrollment, change, migration, and own-user disable require explicit confirmation
and a fresh password-only worker conversation. New PINs must be six ASCII digits,
including leading zeroes, and must be entered twice. `auto` and `tpm2-required`
attempt TPM creation and trial verification; neither silently chooses software.
Software must be selected explicitly. Cancellation before commit preserves the
committed credential; if communication fails around commit, check status before
retrying because the client cannot infer the durable result.

Input requires terminal stdin and a foreground controlling terminal. All replies,
including PAM echo-on input, stay private on `/dev/tty`; raw secret input is bounded
and erased on drop. Ctrl-C, Ctrl-D, Ctrl-Z, and Ctrl-\\ cancel input. Original terminal
settings are restored on completion, error, and cancellation. Termination and
suspend signals are blocked only during private input, checked every 100 ms, and
delivered after restoring the terminal. Uncatchable SIGKILL cannot run cleanup.
Losing the foreground terminal cancels private input within the same polling
interval; job-control signals restore the terminal before suspension.
Worker prompt control characters are sanitized before display.
The executable and public terminal entry point disable process dumpability and
set both core-dump limits to zero before accepting input. Fatal signals cannot
persist the in-memory password or PIN through a core dump.

The CLI obtains confirmation before opening the mutation connection, preserving
the broker's short unauthenticated idle limit. Authorization and commit remain
bound to one connection and one server-issued transaction. Neither a client
Boolean nor the old PIN can authorize a credential change.

`recover` requires an already-root caller and identifies one non-root account in
the protected local `/etc/passwd`; the broker revalidates authority and account
identity. Recovery disables the credential and never reveals a PIN. System-wide
integration uses the separate fixed root tool. `integration enable` prints
`sudo localpin-integration activate` with the prerequisite
prepare/trial/desktop-test steps; `integration disable` prints the tool's
`disable` command. These compatibility commands remain guidance-only;
`setup` is the explicit wizard that invokes the fixed sudo operations.
`integration status` reads the sanitized local root gate without a broker or
terminal. See the [integration runbook](../../docs/integration-administration.md)
and [ADR 0018](../../docs/adr/0018-kde-native-update-compatibility.md). M8.1
uses [native account markers](../../docs/adr/0017-shadow-record-account-authority.md)
and preserves prior activation across compatible RPM updates without freezing
`/etc` or opening a cache-maintenance window. M8's historical matrix passed for the restricted
Fedora 44 x86_64 Btrfs appliance with SELinux enforcing; see the
[M8 report](../../docs/development/m8-packaging-recovery.md). M9 review and
physical TPM validation remain open; hosted CI is unverified.

Status JSON has independent `schema_version: 1` and only closed nonsecret fields.
`installed: "client-present"` proves the CLI is present; `broker_available` reports
whether the protected broker answered. `enrolled` and `active` are separate Boolean
fields, or `null` when no authoritative state is available, including a broker
reply that could not inspect the account. An explicitly reported backend still
establishes enrollment when its current availability fails. TPM usability stays
`null` with `tpm_usability: "not-established"` until successful usability checks
are reported; an unprobed TPM is never labeled unusable. Integration distinguishes
`"trial"` from `"active"`; a bounded trial reports `active: false` and
`tested: "not-recorded"`. Combined broker status reports
`tested: "operator-attested"` only when the readable root active gate and broker
active status agree. This labels an administrator attestation, not automatic
proof of desktop or password tests; missing or inconsistent state does not
invent an attestation. Backend preference, committed backend, availability,
cooldown duration, integration state, TPM detection/usability, and sanitized reason
are also reported. `doctor` provides actions for the broker's failure category
without reading protected credential state or claiming installation is activation.

Tests use synthetic inputs and pseudoterminals. They cover the closed parser,
secret-channel rejection, exact PIN confirmation, no echo, non-UTF-8 password
bytes, terminal restoration, fresh password mutation sequencing, transaction and
prompt binding, cancellation, and separate status states. They do not modify PAM,
local accounts, or the host broker.
