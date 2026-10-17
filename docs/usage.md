# Using LocalPIN

[Documentation](README.md) · [Installation and recovery](integration-administration.md)

LocalPIN adds a six-digit PIN to the lock screen of an already running local
Fedora KDE 44 x86_64 session. Your account password remains the recovery route.
Initial login, text consoles, SSH, sudo, polkit and disk encryption keep their
existing authentication requirements.

LocalPIN is experimental, with no supported production release. Try it in a
disposable Fedora KDE VM first. Independent review and physical hardware
validation remain outstanding; the
[desktop compatibility report](development/m8.1-desktop-compatibility.md)
describes the recorded testing and its limits.

## Start with guided setup

After [verifying and installing the RPM](integration-administration.md#install-without-activation),
open a foreground terminal in your own local KDE session and run:

```sh
localpin setup
```

Run setup as your normal user, with administrator access available through sudo.
It checks readiness, previews preparation changes, asks for confirmation before
system changes, and guides private PIN enrollment, trial tests, console recovery
and final activation. Sudo owns any administrator-password prompt; enrollment
separately verifies your account password through the existing broker.

The one-time persistent password-accounting migration still requires an
[offline maintenance console](integration-administration.md#prepare-native-accounting-once).
Setup explains the handoff and stops when accounting is missing. It does not
copy live tallies or reset counters. The target requires supported local
accounts, reviewed Fedora authentication policy and SELinux enforcing. Network
accounts, systemd-homed and arbitrary PAM customizations are outside this domain.
The guided flow supports one owner account; installations managing additional
accounts use the [manual administrator procedure](integration-administration.md#prepare-and-enroll).

You can cancel and run `localpin setup` again. It inspects protected system state
rather than a saved user checkpoint. Completed stages remain complete; cancelling
can leave a trial open until its reported expiry. If an operation's result is
uncertain, setup checks state before offering another action. A healthy active
installation is shown without repeating preparation. Incomplete transactions,
suspended updates, incompatible state or corrupt authority require the runbook.

If you previously disabled your own PIN while desktop integration remains
active, `localpin setup` offers to create a new PIN. It keeps the active
integration in place and uses fresh account-password verification.

Run `localpin` without arguments in a terminal for a numbered menu covering
setup/resume, status, diagnostics and credential management. Outside a terminal,
it shows help without prompting. Output uses subtle colors when supported and
plain text with `NO_COLOR`, `TERM=dumb` or redirected output. All existing
`localpinctl` commands remain available; `localpin` is the packaged primary name.

Setup has separate stages:

| Stage | What it means |
| --- | --- |
| Installed | The package and CLI are present. Installation does not start the broker, enroll a PIN or activate desktop integration. |
| Prepared | An administrator has prepared the supported policies and selected accounts, established disabled account baselines and started the broker. The desktop PIN gate remains closed. |
| Enrolled | Your PIN credential has been committed. This alone does not enable lock-screen PIN use. |
| Trial | An administrator has opened a ten-minute test window for this boot. PIN testing is permitted; final activation is still separate. |
| Active | An administrator has attested the required desktop/password/recovery tests and activated integration. |

Keep a known working full-password route and an administrator console available
during setup. The runbook requires a recovery rehearsal before activation;
recovery revokes the prepared account bindings. Run `localpin setup` again to
prepare and enroll, then repeat the desktop tests with the final enrollment.
A live trial is reused only while its boot, time and enrollment bindings remain
valid. An expired or changed trial requires fresh testing. The final prompts
record your explicit attestation of real tests; setup cannot observe or perform
the console rehearsal and does not treat your answers as automated evidence.

## Enroll your PIN

For manual enrollment, open a foreground terminal in your own eligible local KDE
session. Run own-user commands as yourself, without `sudo`:

```sh
localpin doctor
```

Resolve any account, session or service problem before enrolling. Choose one
backend explicitly:

| Backend | Command | Tradeoff |
| --- | --- | --- |
| TPM | `localpin enroll --backend tpm2-required` | Binds the credential to the enrolled TPM. Use only with a separately validated TPM deployment. |
| Software | `localpin enroll --backend software` | Uses protected system storage and online throttling, without TPM binding. Copied verifier material remains susceptible to offline guessing. |

`localpin enroll --backend auto` also attempts TPM creation and a trial. It
does **not** fall back to software if the TPM is unsuitable. Software enrollment
always requires your explicit choice and confirmation. A detected TPM device
alone does not establish that enrollment will work.

At the prompts, confirm the operation by typing `yes`, enter your existing
account password, then enter and confirm a PIN containing exactly six ASCII
digits (`0`–`9`). Leading zeroes are valid. Input is private and is not echoed.

Enter secrets only at the interactive prompts. Arguments, environment variables,
pipes and redirected input are unsupported; the CLI requires a real foreground
controlling terminal. If the operation expires, start it again for fresh
password authorization. The CLI reports success only after the credential is
committed.

Cancelling before commit leaves the existing credential unchanged. If a
connection fails around commit, the change may already be durable even though
the CLI did not confirm success. Run `localpin status` before retrying.
Status does not identify the PIN value; if the outcome remains unclear, use
your full password and ask the administrator for help.

After manual enrollment, run `localpin setup` to continue, or follow the
runbook's [trial and activation procedure](integration-administration.md#test-and-activate).

## Unlock your KDE session

Once trial or active integration permits PIN use:

1. Lock your existing KDE session normally.
2. Type the PIN into the existing lock-screen field, which may still say
   **Password**.
3. Press **Enter**. LocalPIN does not submit automatically after the sixth digit.

There is no separate PIN selector. You can enter your full account password in
the same field. A non-PIN input goes through the password route; an unsuccessful
PIN route also continues to password authentication with the submitted input.
After a wrong PIN, clear the field and enter your full password on the next
attempt. Password fallback remains subject to normal account restrictions and
native lockout policy.

## Cooldowns and account policy

For eligible PIN verification, LocalPIN permits up to five submitted six-digit
attempts within a rolling minute. The fifth submission is allowed and starts a
five-minute PIN cooldown. A successful PIN verification durably resets
LocalPIN's attempt history and cooldown. Once an attempt is durably reserved,
cancellation or a backend error does not refund it. Restarting the service or
rebooting does not reset the recorded budget. Use your full password during
cooldown and check `localpin doctor` for its remaining duration.

Because the field is shared, a wrong PIN can count as a native password failure,
and a six-digit account password can consume a PIN attempt. PIN success never
clears native password or biometric failures. Successful password or biometric
authentication clears them through the reviewed native accounting path; an
unavailable fingerprint sensor or service does not add a false failure. PIN use
cannot bypass account locks, expiry or native lockout. See the
[KDE accounting contract](adr/0018-kde-native-update-compatibility.md).

## Change, disable or move your credential

Use these commands from your own foreground terminal. Each requires explicit
confirmation and fresh account-password verification; knowing the old PIN is
not sufficient.

| Task | Command | Result |
| --- | --- | --- |
| Change the PIN | `localpin change` | Prompts for a new PIN on the currently enrolled backend. |
| Stop using your PIN | `localpin disable` | Disables your credential; use your account password. |
| Move to TPM protection | `localpin migrate --backend tpm2-required` | Replaces the existing credential with a new TPM-backed PIN. |
| Move to software protection | `localpin migrate --backend software` | Replaces the existing credential with a new software PIN after explicit acceptance. |

`change`, `disable` and `migrate` require an existing enrollment. Use `enroll`
only when no PIN is enrolled. Migration accepts only `tpm2-required` or
`software`, and its target must differ from the currently enrolled backend;
use `change` to replace a PIN on the same backend. If an enrolled TPM is missing,
reset or replaced, use your password and arrange an explicit migration or
recovery. LocalPIN does not maintain a software PIN fallback alongside a TPM
credential.

Own-user disable affects your credential, not the system's desktop integration.
To enroll again after disabling it, use the enrollment procedure while the
administrator-provided account baseline remains healthy. Account identity or
protected-state problems need administrator recovery first.

## Inspect status and solve common problems

```sh
localpin status
localpin doctor
localpin integration status
```

`status` summarizes your enrollment, availability, backend, cooldown and
integration. `doctor` adds suggested next steps. Both accept `--json` for
nonsecret, versioned output. `integration status` inspects the desktop gate even
when the broker cannot be reached.

Read these fields separately:

- **Installed** means the CLI is present; broker reachability is reported
  separately.
- **Enrolled** identifies the credential's backend. `unknown` means the check
  could not establish enrollment, rather than proving no credential exists.
- **TPM detected** reports device presence. Usability can remain
  `not-established`; passive status does not perform TPM enrollment.
- **Tested: administrator attested** records the activation attestation. Running
  `doctor` does not repeat desktop unlock or password-recovery tests.
- **Active** describes final activation. A `trial` permits bounded testing while
  still reporting `Active: no`. Unavailable checks can report `unknown`.

| Symptom or reason | Next step |
| --- | --- |
| PIN fails or is in cooldown | Use your full password. Check `doctor` and wait for the reported cooldown; do not reset counters to bypass it. |
| Broker unavailable | Use your password and ask the administrator to check the LocalPIN service. Enrollment cannot start it or repair its state. |
| `session` or an operation is forbidden | Use your own eligible local KDE session and run own-user commands without `sudo`. |
| Foreground terminal required | Run interactively in a terminal, without a pipe, redirected stdin or a background job. |
| PIN format or confirmation error | Restart the operation and enter the same six ASCII digits at both PIN prompts. |
| Password rejected | The credential was not changed. Use the correct account password and respect native lockout; ask the administrator about account restrictions if necessary. |
| `backend` | Ask the administrator to inspect TPM usability, or explicitly select software protection if you accept its tradeoff. |
| `account-unsupported` | Ask the administrator to check local account compatibility and provisioning. Enrollment cannot create the privileged baseline. |
| `lifecycle-unavailable`, `eligibility-unavailable`, `account`, `storage` or `policy` | Use password recovery and refer the administrator to the [account diagnostics](account-administration.md#eligibility-accounting-and-diagnostics) and installation runbook. |
| `busy` | Retry after the current bounded operation or native account tool finishes. |
| Protocol/version error | Ask the administrator to check that the CLI and broker versions match. |

## Choose the right recovery route

If you forgot your PIN but can authenticate with your account password, use
`localpin change` or `localpin disable` from your supported session.

An administrator can use `localpin recover --user <account>` as root to
disable an existing account's PIN through the working broker. This does not
retrieve a PIN, repair account lifecycle authority or restore desktop policies.
Missing or corrupt account authority requires the separate
[account recovery procedure](account-administration.md#routine-changes-and-explicit-recovery)
and fresh enrollment.

For system-wide integration problems or removal, use the
[console recovery procedure](integration-administration.md#console-recovery-and-removal).
The privileged integration tool can close the gate and restore owned policies
without a working broker, TPM or PIN module. Keep the package installed while
reviewing a failed recovery.

`localpin integration enable` and `localpin integration disable` only print
the required administrator guidance and command; they do not change system
integration. Follow the runbook for preparation, testing, activation and recovery.
