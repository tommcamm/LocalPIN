# M1 disposable-VM SELinux boundary experiment

Date: 2026-10-16. Status: the enforcing guest passed the bounded broker/client
and negative-helper fixture, plus a separate eight-case positive own-user
password-worker experiment. Monitored reruns passed both. Three earlier boundary
attempts failed and informed the direct-systemd correction. Local boundary C
compilation and thirteen synthetic guard/policy/unit/cleanup tests pass.
No result in this report certifies the production broker/password worker or PIN
authorization.

The guest-only [fixture and instructions](../../experiments/m1/vm/selinux/README.md)
provide a purpose-written narrow SELinux policy, a root-owned Unix-socket broker,
allowed/denied confined clients with the same ordinary UID, MAC/DAC marker tests,
and a separately sandboxed private-PAM/native-helper negative baseline. The runner
requires the shared root-owned UUID-bound disposable VM marker and `Enforcing`
before installing anything, refuses collisions and cleans up only its resources.

The experiment intentionally separates these claims:

| Check | Current evidence |
|---|---|
| C fixture compiles with warnings denied | Passed locally against extracted matching PAM headers; no fixture executed on the host. |
| Guard/type-input, executable-label verification, sandbox generation and cleanup tests | Thirteen synthetic tests passed; no policy was loaded by them. |
| Purpose-written policy builds against exact guest headers | Passed in the fourth enforcing guest run. Local host has no SELinux development policy files. |
| Root broker domain, allowed client contact and denied-domain contact | Passed: exact domain assertions, allowed fixed exchange/root peer and denied confined peer checks completed. |
| MAC-readable baseline and separate DAC barrier | Passed for both confined clients. Public world-readable canary is deliberately distinct from root-only state. |
| Private permit/deny PAM plus packaged missing-account helper | Passed only the private baselines and native missing-account negative path. |
| Real locker reaches broker and falls back on denial | Separate stock KDE contact extension passed fixed exchange and fresh-connection DAC denial with one-entry password fallback. Actual locker MAC denial and production authorization remain unproved. |
| Successful password worker and account restrictions | Separate confined own-user fixture passed correct/wrong/locked/expired/recovery cases through the packaged helper and copied reviewed `password-auth` subtree. Production worker/eligibility and other profiles remain open. |
| Worker failure counters under a supported faillock profile | Pending for the confined positive worker; the tested default profile has no faillock. |

In the first guarded guest run, the broker process exited with status 1 before
any client or worker ran. Fixed C diagnostics were sent to null, so the exact
broker failure was not observable. Cleanup removed all fixture paths, units and
the module, but incorrectly reset failed unit states after unloading their unit
definitions. That produced a false cleanup failure and masked the original
failure stage. No pass was recorded. The second run preserved the broker
readiness failure and its fixed journal diagnostic: the process was in the wrong
SELinux domain. No client/worker ran and no relevant recent AVC was found. It
also established that even resetting before unlink is unreliable for fixture
units that have never started and are already unloaded. The operator confirmed
all fixture paths, units and the module were absent after both attempts.

The current runner omits unnecessary failed-state resets after confirmed stops,
preserves primary and cleanup failure stages together, and sends fixed C
diagnostics to the guest journal. Before launching, it compares each executable's
actual label with `matchpathcon` and its expected entrypoint type; only bounded
type names are exported. A domain mismatch now prints the observed and expected
bounded types, never a full SELinux context. Regression tests cover label refusal,
cleanup ordering, unsafe-stop retention and failure preservation. No policy
permission was broadened for those diagnostic corrections.

The third attempt confirmed all actual and policy-matched executable labels were
correct, but the broker observed `init_t` instead of `localpin_m1_broker_t` and
stopped. No client/worker ran; no relevant AVC was reported and cleanup completed.
Read-only inspection of the guest's installed interfaces then showed that its
`init_daemon_domain` creates initrc-domain transitions/daemon attributes but omits
the direct `init_t` transition. Its `init_domain` interface supplies that exact
transition, the `system_r` role and target-specific `process2` NNP/nosuid grants.
The guest's `nnp_nosuid_transition` policy capability is enabled.

The candidate policy now explicitly combines those maintained interfaces for
each of its four fixture domains. Each unit also requires its exact
`SELinuxContext` without an ignore-errors prefix. Broker/client NNP stays enabled;
the worker's separately reviewed setting is unchanged. No file, shadow, socket
contact or network permission was added. The
[kernel SELinux execution hook](https://github.com/torvalds/linux/blob/master/security/selinux/hooks.c)
shows that an automatic transition may retain the old SID under NNP/nosuid,
whereas a failed explicit exec SID is refused. That explains the fail-explicit
unit choice; the observations do not isolate NNP alone as the cause. The exact
guest interfaces, rather than assumptions about upstream macro definitions,
determine the correction.

The fourth guarded run passed with SELinux enforcing and emitted all six fixture
checks as true: root-owned broker socket, allowed client, denied client,
MAC/DAC marker denials, worker completion, and private permit/deny plus
missing-account helper baseline. Actual executable types matched `matchpathcon`
and each expected fixture entrypoint; the helper remained `chkpwd_exec_t`.
`cleanup_completed` was true. The optional locker-type rule was absent
(`locker_type_policy_target=null`); `actual_locker_contact_tested`,
`real_password_authentication_tested` and `complete_product_policy` remained
false. The successful bounded fixture does not change those three limits.

The guest package inputs remained Fedora 44 x86_64, PAM/pam-devel
`1.7.2-2.fc44`, authselect `1.7.1-1.fc44`, kscreenlocker `6.7.5-1.fc44`, systemd
`259.9-1.fc44` and targeted SELinux policy `44.11-1.fc44`. The successful source
used the installed Fedora interfaces described above. Raw execution records and
audit/journal data remain under ignored `.local/m1/vm`; the
[boundary result](../../experiments/m1/vm/results/2026-10-16-selinux-boundaries.json)
contains sanitized outcomes. A later monitored rerun again passed all six checks.
During the positive-worker and boundary reruns, audit remained enabled and its
lost count stayed at 76, with backlog zero before and after. The
[coverage record](../../experiments/m1/vm/results/2026-10-16-audit-coverage.json)
preserves this preexisting loss: absence of records from earlier attempts cannot
prove absence of denials. Whole-VM snapshot restoration remains a separate VM
operator action.

The root-owned broker has no real secret, TPM interface or product protocol.
Its fixed contact exchange cannot unlock a session. Clients receive neither
state-read nor TPM permissions. Tests check that a root broker UID is obtained
from the socket; this is a fixture check, not the final socket-activation
credential contract. A targeted Fedora desktop running as `unconfined_t` is not
proved newly confined by a socket allow rule; the dedicated confined-client
negative control and DAC test are necessary separate observations.

The separate [actual KDE contact report](m1-vm-kde-contact.md) records two later
manual UI cases through an optional fallback-only adapter: fixed broker contact
returned 0, then a fresh greeter's connection to the owned mode-000 socket
returned 3. Both ordinary password unlocks succeeded with one entry and a false
lock-state observation. The actual greeter was `unconfined_t`; that denied case
is DAC evidence. The dedicated confined-client MAC-negative result above remains
a different test. Successful hold setup alone was never counted as a locker
transaction, and no credential went over its fixed exchange.

The original negative worker does not reuse the broker sandbox blindly. Its private PAM baseline
must request no secret; the only helper input is a compiled public test string
for a name confirmed nonexistent. The expected helper failure is not evidence
of password acceptance or account eligibility. It cannot close M1's full worker
gate, and no direct-shadow-read or broad `auth_use_pam` grant is present. Its
`NoNewPrivileges=no` setting is an explicit experimental choice that needs
further production review. It is distinct from the following positive fixture.

The separate [positive-worker fixture](../../experiments/m1/vm/worker-positive/README.md)
ran eight cases in `localpin_m1_positive_t` as the ordinary target UID: private
permit/deny baselines, correct and wrong public synthetic passwords, locked
password, expired account, expired password and recovery. Each native assertion
passed on the first guarded run and the monitored rerun. Exact original shadow
restoration and fixture cleanup were true. The
[sanitized result](../../experiments/m1/vm/results/2026-10-16-worker-positive.json)
retains `production_worker_complete=false` and records the same package versions.

That fixture uses a private read-only copy of the exact reviewed `password-auth`
subtree, with no KDE/authselect changes or authentication shortcut. Its ordinary
worker checks its UID, domain, absent active/permitted/inheritable capabilities
and direct shadow-open denial. Successful native authentication must pass account
management. Before account mutation, installed-policy queries reject direct
`shadow_t` reads or an `updpwd_t` transition. The only helper transition is the
packaged setuid-root `unix_chkpwd` path; the broad password-helper interface is
deliberately avoided. Its separate sandbox retains only helper DAC-read/search
and audit-write capability bounds, permits AF_UNIX/AF_NETLINK for native audit,
and disables NNP for the setuid helper. These scoped choices need production
review. The result establishes this own-UID helper and subtree/profile only;
privileged production worker design, broker authorization, pure password-free
eligibility, confined faillock behavior and the release matrix remain open.

Reference behavior was checked against the
[SELinux init-domain interfaces](https://github.com/SELinuxProject/refpolicy/blob/master/policy/modules/system/init.if)
and [PAM/helper interfaces](https://github.com/SELinuxProject/refpolicy/blob/master/policy/modules/system/authlogin.if).
These explain why daemon transitions, socket contact and helper execution are
separate grants; the installed Fedora policy is the actual build/test input.
[systemd execution settings](https://github.com/systemd/systemd/blob/v259/man/systemd.exec.xml)
explain the independent unit restrictions and privilege-transition concern.
[Linux-PAM's helper implementation](https://github.com/linux-pam/linux-pam/blob/v1.7.2/modules/pam_unix/unix_chkpwd.c)
defines its missing-user negative path. No upstream source was copied into the
fixture. These references are not an independent security review.

After guest execution, record exact policy/package inputs, sanitized results,
expected and unexpected AVC conclusions, cleanup and snapshot restoration.
Keep the actual KDE and production password-worker gates open until their
complete supported paths are demonstrated. Never disable SELinux or generate broad allow
rules to resolve a fixture failure.

## Final cleanup

After these observations, the [clean snapshot was restored and the VM restarted](../../experiments/m1/vm/results/2026-10-16-cleanup.json).
The temporary guest SSH key was explicitly removed before rollback, and the local
temporary key pair was deleted. Per-run pending/false snapshot fields describe
the time of collection; this separate record establishes final cleanup.
Post-restore SELinux mode was not independently queried.
