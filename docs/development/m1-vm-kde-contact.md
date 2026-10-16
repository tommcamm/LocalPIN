# M1 real-locker fixed broker-contact extension

Date: 2026-10-16. Status: optional contact build and seven isolated native tests
passed locally; two manual stock KDE contact/fallback cases passed in the
disposable VM with SELinux Enforcing. The earlier
[three stock KDE fallback cases](m1-vm-kde.md) used the original capture-only build
and are not relabeled as broker-contact tests.

The [optional build](../../experiments/m1/vm/kde/README.md) preserves the module's
unconditional `PAM_IGNORE` result and `[default=ignore]` control rule. It adds only
fixed `PING`/`PONG` traffic to the existing fixture endpoint,
`/run/localpin-m1/contact.sock`, after exact service/target/UID validation and
before the password conversation. No candidate is passed to the contact function
or transmitted. `SO_PEERCRED` must identify a root server.

A single monotonic 250 ms socket-I/O budget covers nonblocking connect, partial
send/receive, and retries. Responses arriving at or after the deadline cannot
become a successful contact. The module logs a numeric outcome and a sanitized
SELinux type only. Scheduler delay, NSS, conversation handling, logging and the
original password stack are outside this experimental socket budget; the test
does not certify complete fallback latency.

Both capture-only and contact-fixture modules compile warning-clean. Seven
isolated native checks passed outside the development syscall sandbox, inside a
private unprivileged user/mount/network namespace with no host `/etc` or `/run`:

| Case | Numeric outcome |
|---|---|
| Endpoint absent | 3 |
| Namespace root peer, fixed exchange | 0 |
| Fragmented fixed response | 0 |
| Wrong fixed response | 8 |
| End of stream | 7 |
| Stalled response | 4 |
| Injected untrusted peer credentials | 5 |

The stalled response expired at approximately 251 ms elapsed, including scheduler
and process overhead around the 250 ms deadline. All checks completed within a
one-second scheduler-tolerant bound. The peer-denial case injects a failed trust
condition; it is not an actual cross-UID server test. The test server verified
that each received request was exactly `PING`, with no candidate bytes. The
ordinary restricted sandbox could not create namespaces and exited 77; that
infrastructure failure is separate from the passing namespace run.

The installer records the selected build mode and exact module digest in its
durable manifest. Original PAM bytes/labels are still restored through the same
verified recovery path. Actual VM evidence must separately demonstrate a manual
password unlock and correlate it with the actual greeter's contact outcome; a
running fixture broker alone cannot establish that the locker contacted it.

The [manual UI record](../../experiments/m1/vm/results/2026-10-16-kde-contact-ui.json)
records these two actual stock KDE cases. Each used one human password entry,
unlocked the desktop, and was followed by observing the locker's `GetActive`
result as false. Each contact log was correlated with the same greeter used for
that case.

| Actual locker case | Contact outcome | Greeter SELinux type | `pam_set_item` result | Manual one-entry unlock |
|---|---|---|---|---|
| Confined fixture broker reachable | 0 | `unconfined_t` | 0 | Passed |
| Fixture socket deliberately DAC denied | 3 | `unconfined_t` | 0 | Passed |

The denied case used a fresh greeter after the owned socket's permissions were
changed to `000`. This is evidence for fallback when a new actual locker
connection is denied by DAC. It is not an actual locker MAC-denial test. The
[separate confined-client boundary test](m1-vm-selinux.md) supplies the MAC-negative
evidence for its own client domain; the actual greeter remained `unconfined_t` in
both UI cases. Neither the greeter's domain nor a successful fixed exchange
establishes production caller authorization.

The [broker-hold record](../../experiments/m1/vm/results/2026-10-16-kde-contact-hold.json)
records broker readiness, application of the DAC denial and successful cleanup
after a `finish` request. Its explicit
`actual_locker_contact_proven_by_orchestrator=false` is intentional: the separate
UI/log correlation supplies that observation. The
[bounded hold fixture](../../experiments/m1/vm/kde-contact/README.md) performs no
password or account operation.

An administrative logind unlock was used once during setup to clear an automatic
pre-test lock. That setup action is excluded from the two manual cases and is not
counted as PAM authentication evidence.

After the UI cases, the original target shadow record was restored and verified
against the separately retained original. The exact original KDE PAM file was
restored with SHA-256
`7d91b3ad73a998e8b10f9edccd74ba04179a778c4a5e61d9176872f43c7bbac3`;
the test adapter, its backup and the broker-hold control directory were removed.
The hold reports cleanup complete. Whole-VM snapshot restoration is still
pending and is recorded as false in this run's UI export.

These cases establish fixed contact and ordinary-password fallback for this
experimental adapter. They do not test PIN authorization, an eligibility
decision, a production broker protocol or policy, actual locker MAC denial, or
complete fallback latency.

## Final cleanup

After these observations, the [clean snapshot was restored and the VM restarted](../../experiments/m1/vm/results/2026-10-16-cleanup.json).
The temporary guest SSH key was explicitly removed before rollback, and the local
temporary key pair was deleted. Per-run pending/false snapshot fields describe
the time of collection; this separate record establishes final cleanup.
Post-restore SELinux mode was not independently queried.
