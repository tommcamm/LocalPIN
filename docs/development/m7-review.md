# M7 development review

Date: 2026-10-17. Scope: production PAM adapter, native allocator/FFI boundary,
target binding, broker-client deadlines, exact KDE policy compatibility and
the isolated and disposable-VM evidence fixtures.

Separate agents reviewed the adapter and its harness. The review also checked
Linux-PAM v1.7.2's primary headers, item ownership, authentication token cleanup
and credential dispatch sources linked from
[ADR 0013](../adr/0013-pam-unlock-contract.md). This is **AI-assisted development
review**, not M9's independent human/specialist authentication, confinement or
hardware review. The [M7 implementation report](m7-pam-integration.md) owns the
actual stock KDE acceptance record and its remaining gates.

## Findings and corrections

- M6.1 accepted only the measured stock KDE digest and sealed the entire service
  as an immutable account-authority input. Merely adding an adapter would have
  disabled production eligibility or silently weakened that contract. ADR 0013
  adds exactly one integrated byte sequence while retaining the stock digest.
  Its complete suffix reproduces all 508 measured original bytes; the fixed
  prefix uses the absolute module path, no arguments and the reviewed control.
  Tests reject alternate controls, paths, arguments, placement, downstream
  services and line endings. Policy transitions still require durable global
  revocation, fresh account incarnations and enrollment.
- The initial client gave the final TPM request a new five-second budget after
  setup. It now computes both absolute deadlines from the same suspend-inclusive
  start: setup and software use two seconds, and only a submitted verification
  selected by authenticated enrolled TPM status may use the original five-second
  deadline. Tests prove cumulative expiration. General client helpers that
  independently renew operation budgets are deliberately unused by the adapter.
- Target/service checks originally preceded the application conversation only.
  A callback can mutate PAM items. The adapter now rechecks the exact service and
  own-user identity after capture, before contacting the broker and before
  returning a grant. Unit tests and native callback-mutation cases cover this.
- Credential refresh must preserve Linux-PAM's cached authentication control
  path. The adapter's `pam_sm_setcred` is a successful no-op in its supported
  context, with no second authentication, conversation or cached module grant.
  Native tests assert credential results after both successful and failed auth.
- The initial native harness lacked explicit known permit/deny and independent
  native password baselines. Those now precede adapter assertions, so broken
  PAM infrastructure cannot explain a passing fallback claim. The completed
  harness also covers conversation errors, invalid response codes,
  NULL response strings, subsequent fresh recovery,
  original password failure accounting and unchanged tally bytes on PIN success.
- A later independent review found that the adapter acquired an error-return
  conversation pointer before checking its result. Linux-PAM transfers response
  ownership only on success; a failed callback must release its own resources,
  and its output may already be stale. The adapter now returns without reading
  or freeing any error output. Only successful callback output enters its RAII
  cleanup owner. A native regression frees the output inside the failed
  callback and verifies fresh same-handle recovery afterward. This contract also
  limits the erasure guarantee: application cancellation cleanup remains the
  application's responsibility.

The final review found no further concrete authorization bypass in these paths.
This statement is limited to the reviewed implementation and recorded evidence.

## Native boundary and evidence limits

Only `pam.rs` permits unsafe Rust. The two exported C entry points contain
unwinding panics, including test-only injection through the actual exports.
Public C layouts and constants match the pinned Linux-PAM contract. A valid
live PAM handle and a conforming application conversation remain requirements;
the module cannot validate arbitrary native addresses or contain process aborts.

PAM item pointers remain borrowed. `pam_set_item` copies the exact submitted
candidate before the module erases and frees its separate conversation response
and string with the C allocator. RAII cleanup covers response-format rejection
and Rust unwinding after a successful callback has transferred ownership. A
non-successful callback transfers no response ownership, so the module ignores
its output pointer without dereferencing, erasing or freeing it. Review inspected
those ownership paths and `zeroize` calls; the
native harness does not interpose `free` or inspect erased/freed memory.
Historical copies, PAM-owned token copies, compiler temporaries, swap and dumps
are outside the erasure guarantee.

The adapter has no NSS callback, configurable endpoint, module arguments or
secret-bearing cache. Its bounded local passwd read and safe-file checks do not
promise cancellation of arbitrary kernel filesystem I/O. Transport deadlines
cover broker contact; initial interactive input and the original password
policy retain their own timing. An authenticated fake broker tests wire/result
mapping but cannot prove production eligibility or durable credential success.

The [native ABI smoke](../../crates/localpin-pam/tests/abi_smoke.c) checks the
Linux x86_64 public structure layouts and constants, loads the exact absolute
module artifact, resolves both exported entry points and checks NULL-handle
rejection with zero and unsupported argument counts. It never creates a PAM
handle or accesses a host authentication stack. This permits a small CI check
even where container namespace integration is unavailable.

## Recorded local checks

- Workspace formatting and all-target/all-feature locked Clippy with warnings
  denied passed. Dependency advisories, bans, licenses and sources passed.
- The complete locked all-feature workspace suite passed with one test thread:
  **298 passed, zero failed and nine intentionally ignored** across thirty
  libtest/doctest result groups. The custom job-control executable also passed.
  This includes thirteen adapter unit tests and twenty-three password/eligibility
  worker tests. The ignored entries retain their separate simulator,
  namespace-integration or subprocess-entry requirements.
- Syscall-sandboxed full runs stalled in existing native worker/socket cases.
  Those invocations were stopped and were not counted as passing. The complete
  successful run used reviewed access to subprocesses and local Unix sockets,
  without host authentication changes or physical TPM access. The dependency
  checker likewise required access to its existing advisory-cache lock.
- The isolated production-module harness passed all **63 application attempts**
  with real Linux-PAM, native `pam_unix`/`pam_faillock`, mapped UIDs and the exact
  release cdylib. Its fake root broker and readable synthetic shadow database
  remain explicit test boundaries. The harness and reproduction command are
  documented in the [M7 report](m7-pam-integration.md).
- The ABI smoke compiled with C11, `-Wall -Wextra -Werror` and the measured
  extracted PAM headers, then passed against the actual release cdylib. `nm -D
  --defined-only` found exactly `pam_sm_authenticate` and `pam_sm_setcred` as
  its defined dynamic exports. No host PAM operation was performed.
- The guarded stock KDE policy matrix passed **thirteen UI cases** in the
  independent enforcing-SELinux clone. It covered strict submitted-PIN counter
  preservation, real password failure accounting, preexisting records, native
  lockout and six runtime/account restrictions. Two successive PIN unlocks kept
  one then two native fingerprint failures; the third fingerprint failure
  caused native lockout denying both PIN and password with unchanged counters.
  Recorded explicit root reset recovered the same greeter. Final cleanup left
  the exact default profile, fresh software enrollment, no pending fault marker
  and an unlocked desktop. The implementation report owns the complete case
  table and compatibility implications.

The local workspace check logs are under `.local/m7/review-*`; they are private
development logs, not published compatibility evidence. Hosted CI execution is
not established by local checks or by adding a workflow step.

## Disposable-VM fixture review

The guest manager uses the actual production authorities, broker, workers and
KDE PAM policy. Its root-controlled DMI guards require the independent Fedora
KDE clone and enforcing SELinux. The host controller checks the clone identity,
independent disk, original VM inactivity and absence of forbidden host devices
and shares before sending keyboard events. Pinned SSH carries transient test
inputs and guarded observations; candidate values are omitted from evidence.

Policy installation first makes a durable original backup, durably revokes the
account domain, installs exact bytes and then seals fresh incarnations and
enrolls. Restoration checks the recorded module and policy digests, revokes,
restores original policy bytes/mode/context, synchronizes the file and parent
directory and synchronizes module removal. These guarded tools are experiments,
not M8's activation or package recovery implementation.

Review identified these requirements for interpreting the fault records:

- A missing module must be tested through a fresh greeter/PAM load. Renaming
  its file does not remove a previously loaded mapping; record the relevant
  process identity and fresh transaction.
- Fault labels alone prove no setup. Pair each UI result with the exact guarded
  applied fault and recovery record. A worker missing on a software credential
  is an actual native worker failure, not an observed TPM transport fault.
- Review found that fault intent was recorded after mutation and broker
  recovery relied on a numeric PID. The runner now records intent durably before
  changing state. Signals use a pidfd and validate the root UID, fixed broker
  executable, current service MainPID and recorded start time. There is no raw
  PID-signal fallback. Module/worker recovery validates artifact digests and
  safely accepts an already restored original after interrupted preparation or
  repair. Unknown files, symlinks, hardlinks and unsafe private markers refuse
  recovery. These guarded experiments do not establish M8 crash recovery.
- Profile changes accept only the two reviewed current password-auth digests
  before invoking authselect. They durably revoke first, regenerate the exact
  profile, require files-only NSS and seal fresh incarnations before enrollment.
  Account restrictions retain only the dedicated target's passwd/shadow rows in
  a private guest-root backup. Restoration validates the exact name, unique UID
  and both record formats before writing either database while revoked. Runtime
  nologin and native faillock cases do not alter account records; their explicit
  root recovery remains separate from eligibility/module behavior.
- A repeated headless PAM handle does not substitute for stock-theme keyboard
  observations. PIN success, password fallback and original tally effects need
  distinct assertions; an aggregate before/after digest does not identify which
  intermediate operation changed accounting.
- The first whole-lock tally comparison incorrectly attributed a parallel
  authenticator's failure to the submitted PIN. Exact stock KDE controls under
  the reviewed with-faillock profile also produced a valid `kde-fingerprint`
  record before typing. KDE starts this native authenticator alongside its
  interactive one. The fixture now records lock-start accounting separately and
  compares the submitted PIN's tally immediately before Enter and after unlock,
  with a bounded barrier identifying the new native fingerprint record. It
  retains every preexisting record and never disables or clears a native factor
  to make the assertion pass.
- Counter observations and own-UID test processes use `setpriv` rather than
  entering another PAM service through `runuser`. Pure-observation probes did
  not demonstrate a tally reset from the earlier wrapper; the change removes a
  possible measurement dependency rather than explaining the observed failure.
  Successful stock full-password authentication also preserved the fingerprint
  record, matching KDE's authentication/credential-only path. Independent lab
  cases explicitly record any root `faillock --reset` recovery. Accumulating
  parallel-factor failures is a material native composition effect and an M8
  activation compatibility blocker until reviewed, as recorded in ADR 0013.

The stock KDE result table, exact final artifacts, applied faults, native account
restrictions and clone cleanup belong to the [M7 report](m7-pam-integration.md).
No headless/mock result by itself completes that acceptance gate. A clone
without a TPM cannot establish actual TPM-device behavior. The separately
guarded TPM runner uses installed `localpinctl enroll --backend tpm2-required`
through a private PTY and the unmodified production `/dev/tpmrm0` route. It
requires the host's independent private-emulator XML proof and a matching
guest-root marker. Its driver-unbind fault records the exact guest ACPI device
before mutation; repair validates that identity, rebinds the CRB driver and
requires the same credential to pass real PAM verification. Source review and
syntax checks do not establish that the emulator enrollment, device-fault or
stock KDE phases actually passed; record those executed results separately.
Emulator evidence remains separate from physical hardware acceptance.

The executed TPM fault test passed native enrollment, actual PIN unlock and
same-greeter full-password recovery with native device 0 removed. In-place CRB
rebind instead produced device 1 on the measured kernel; the fixed endpoint was
not aliased and that recovery strategy did not pass. A separately guarded reboot
restored device 0 with unchanged registry/active/credential bytes, but lost
authoritative volatile faillock state. M6.1 correctly refused the existing PIN.
The proposed same-enrollment reboot strategy overlooked that documented rule;
its failed result is retained. Explicit privileged revocation and fresh TPM
enrollment subsequently passed native PAM and actual GUI PIN checks. Private
fingerprints prove the fresh registry/credential differ without exporting them.
The acceptance report distinguishes required fault/password-fallback success
from these additional failed recovery strategies and records stock-policy
restoration, password recovery and complete clone/access disposal.

M8 retains installed confinement, RPM lifecycle, opt-in activation and production
console recovery. M9 retains independent human/specialist review and physical
hardware validation. This development review authorizes no everyday-host
authentication change.
