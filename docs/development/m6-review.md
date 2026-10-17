# Separate M6 code review

Date: 2026-10-17. Scope: enrollment broker/storage composition, backend provision
and trial workers, password PAM ABI/supervisor, CLI/terminal and status handling.

Agents who did not author the password worker reviewed its native ABI, policy,
private IPC and supervision. Separate reviewers examined the broker enrollment
flow and client receive operation. The implementing agent checked the CLI and
PAM integration and addressed the findings. This is AI-assisted development
review, not M9's independent human/specialist authentication or hardware review.

## Findings and corrections

- Cancellation or session loss during generation/throttle writes could arrive
  after the broker's final check but before active generation publication.
  A fenced clock now checks socket cancellation, process/session liveness and
  deadlines at storage finalization. Storage repeats lifecycle and time checks
  after the pointer tempfile write/fsync, immediately before rename. The
  namespace regression queues cancellation while persistence is paused and
  proves the old disabled generation remains authoritative. Disconnect after
  pointer publication remains an outcome-uncertain committed operation.
- Pointer staging could also outlast the grant or encounter clock rollback.
  The same final rename gate checks strict expiry and monotonic continuity;
  final acknowledgement compares against the latest publication-time sample.
- CLI confirmation originally followed socket connection, allowing human input
  to outlast the broker's short idle timeout. Installed commands now close their
  preliminary status connection, confirm with no live transaction and reconnect
  immediately before beginning authentication/recovery.
- CLI auto/required TPM selection originally depended on a positive pre-probe
  that did not exist. It now requests TPM creation/trial explicitly. Failure
  never selects software; software requires its own explicit selection and new
  authentication. Doctor distinguishes device presence from usability evidence.
- Unknown enrollment/integration and unprobed TPM usability could be presented
  as negative facts. Unavailable/uninspected status now uses null/unknown and
  actionable lifecycle diagnostics while retaining any known enrolled backend.
- Password-worker technical failure, timeout and lifecycle refusal originally
  shared the password-rejected diagnostic. Sanitized unavailable, expired and
  forbidden errors now preserve these distinctions.
- A near-expired internal password request could start a fresh worker lifetime.
  The supervisor now subtracts request age before native execution; a stalled
  child regression verifies the remaining budget and retained capacity.

No further concrete authorization bypass was identified in review. Tests and
the limits of the evidence are recorded in the [M6 report](m6-enrollment-cli.md).

## Fresh pre-commit review

At the maintainer's request, three fresh-context review agents independently
examined the final uncommitted implementation. None authored the initial M6
change. Their scopes were password PAM/IPC/supervision; broker/storage/backend
workers; and CLI/terminal/status/protocol handling.

The review identified missing process dump protection in the CLI, broker and
credential helper. Zeroizing destructors do not run after fatal signals, and
the broker now relays full passwords as well as PINs. Those entry points now
disable dumpability and set both core-dump limits to zero before input or
worker processing. The public terminal entry point applies the same protection.
Failures refuse input/startup. Subprocess regressions verify the protection
without changing the parallel test parent's limits or producing core files.
The password helper already applied both protections.

The CLI review also reproduced terminal settings being left raw after its
process group lost foreground ownership during input. Background terminal
reads could stop it with `SIGTTIN` before the restoration guard ran. Secret
input now monitors foreground ownership throughout the read and includes
`SIGTTIN`/`SIGTTOU` in its guarded signal set, so loss of the foreground cancels
input and restores the terminal. A session/PTY subprocess regression exercises
the actual terminal entry point and checks restoration without host input or
authentication state.

All confirmed findings from this fresh review are fixed. Post-fix validation
passed formatting, all-target/all-feature Clippy with warnings denied, the locked
release build and dependency audit. The complete workspace passed 261 tests
with nine explicit opt-in/subprocess entries ignored; the standalone terminal
fixture passed all three job-control scenarios. The password-focused reviewer
also passed all 17 auth tests and the actual isolated PAM suite. The protected
enrollment namespace suite was rerun with hardened credential workers.
