# M1 stock KDE same-entry password fallback

Date: 2026-10-16. Status: three manual UI cases passed in the disposable Fedora
44 KDE VM with SELinux Enforcing. This establishes candidate reuse through the
stock password dialog for the tested build. It grants no production PIN capability.

## Experiment and isolation

The [fallback-only module and installer](../../experiments/m1/vm/kde/README.md)
were used only in the guarded `localpin-m1` test VM. The target was the dedicated
ordinary `localpintest` account; administration used a separate connection. A
clean restorable snapshot existed before the experiments.

The module validates `PAM_SERVICE=kde`, the fixed target name, and matching
real/effective UID. It captures an echo-off response through PAM, copies it into
`PAM_AUTHTOK`, erases/frees its response allocation, and always returns
`PAM_IGNORE`. It has no PIN verifier, broker call or authorization-success branch.
The inserted `[default=ignore]` control line also continues to the untouched
original authentication stack for every module result.

The guarded installer made a durable original-policy backup and digest manifest
before its atomic edit. It set the intended SELinux label on temporary PAM/module
inodes before replacement and verified labels afterward. No distribution QML,
lock-screen theme, or authentication-policy file other than the temporary marked
block in the verified KDE service was changed by this UI installer.

The operator temporarily assigned public synthetic ordinary and six-digit
passwords to the dedicated account using protected input. A supervisory process
verified restoration of the original target shadow record twice. No existing
password was requested from the user or exported into the result records.

## Actual UI observations

The user entered candidates manually in the stock lock-screen dialog and
confirmed each successful unlock. After each successful case, the operator also
queried the screen locker's D-Bus `GetActive` state and observed `false`.

| Case | Manual observation | Corroboration |
|---|---|---|
| Six-digit account password with the capture module present | One submitted candidate unlocked the desktop | User confirmation, successful token-transfer event, and `GetActive=false` |
| Wrong candidate followed by the ordinary account password | Wrong entry did not unlock; the subsequent ordinary password unlocked through the same greeter process | User confirmation, the relevant two capture events sharing a greeter PID, and `GetActive=false` after success |
| Experiment module deliberately absent before a fresh greeter/PAM transaction | One ordinary-password submission unlocked through the original stack | User confirmation, the missing module condition, and `GetActive=false` |

The six-digit value was an account password, not a LocalPIN credential. The
wrong-then-correct case establishes a usable retry path in the same greeter
process; it does not instrument PAM-handle pointer identity. The inspected KDE
source reuses its handle, while the separate native harness directly tests
repeated calls on one handle.

The module emits only the fixed message
`LocalPIN M1 fallback capture set_item=<numeric result>` after attempting the PAM
token copy. Across the complete experiment, four such events reported result 0.
That total includes an earlier failed synthetic input-injection attempt, so it
must not be interpreted as four successful unlocks or as an exact count of the
manual submissions. The events corroborate successful token copying and the
relevant greeter process identity; they disclose no candidate, length or encoding.
An event alone does not prove password verification or an unlocked session.

The missing-module case used a fresh transaction because an already loaded
shared object can remain mapped after its file is removed. Removing a file from
an existing greeter would not by itself establish the missing-module behavior.

## Restoration and evidence limits

The installer restored the exact original KDE PAM bytes and verified their
SHA-256 digest:

```text
7d91b3ad73a998e8b10f9edccd74ba04179a778c4a5e61d9176872f43c7bbac3
```

The restoration path also checks the original SELinux context and removes only
the known experiment module and state directory. The operator confirmed the
module and experiment state were absent afterward. The target shadow record was
restored by the supervisory process, and the original authselect features were
restored after the separate lockout-profile experiment. Final whole-VM snapshot
restoration remained pending at this report update while other guarded VM
experiments continued. Audit/journal entries, package installation and other
side effects are not erased by restoring one policy file or shadow record.

The [sanitized UI result](../../experiments/m1/vm/results/2026-10-16-kde-ui.json)
records the three confirmations, capture return codes and restoration outcome.
Manual user confirmation, API state and logs support the three cases together; none
alone supplies a precise conversation trace. No real password or shadow record
belongs in checked-in evidence.

These observations complement the
[real-account policy tests](m1-vm-pam.md): twelve default-profile and sixteen
lockout-profile cases passed, including the demonstration that naive PIN success
can bypass password-lock and failure-lockout restrictions. The UI test module
always ignored, so no such success branch was installed in KDE.
The separate [eligibility experiment](m1-vm-eligibility.md) later tested a
password-free preflight for the two exact profiles with a private simulated
success gate; it supplies no PIN authorization to this UI adapter.

Remaining gates include a real production Rust PAM adapter, production privileged
account eligibility, real backend failure behavior, worker SELinux confinement,
nologin/access policy, multiple sessions/seats, and recovery. The UI observations
cover the tested keyboard/session/build only; they do not establish the complete
physical keyboard/dock/layout matrix or authorize everyday-host activation.

## Final cleanup

After these observations, the [clean snapshot was restored and the VM restarted](../../experiments/m1/vm/results/2026-10-16-cleanup.json).
The temporary guest SSH key was explicitly removed before rollback, and the local
temporary key pair was deleted. Per-run pending/false snapshot fields describe
the time of collection; this separate record establishes final cleanup.
Post-restore SELinux mode was not independently queried.
