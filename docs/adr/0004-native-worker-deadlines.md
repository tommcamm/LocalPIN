# ADR 0004: Bound native operations with disposable processes

Date: 2026-10-16. Status: accepted architecture direction; production
implementation and enforcing-sandbox validation pending M5/M6.

## Context and evidence

TPM2-TSS and PAM execute native code. Cancelling an asynchronous Rust task or
timing out a thread does not establish that a native call has stopped. Starting
replacement tasks without retaining occupied capacity can exhaust resources.
An expired result must never become a later authorization.

The [worker experiment](../../experiments/m1/worker/README.md) passes six tests
against native C-library blocking calls: cancellation-resistant workers are
killed and reaped, late/malformed/crashed results return unavailable, a failed
reservation starts no worker, the reservation survives timeout, the same UID
cannot start another worker, and an unrelated UID can respond within the shared
capacity. The [TPM experiment](../development/m1-tpm.md) separately stops an
actual simulator while a TPM2-TSS tool is blocked and kills/reaps that caller at
its deadline. The deadlines are experimental measurements, not product latency
certification.

## Decision

Use bounded, short-lived worker processes around native TPM and enrollment PAM
operations. The broker owns deadlines, transaction/generation identity and the
authoritative reservation; the worker cannot commit success itself. Pin the
process/job to one transaction and accept one bounded result only before its
deadline and while the generation and authorization state still match.

On timeout, cancellation, worker crash, malformed result or lost transport, close
the response path, discard results and return unavailable. Keep an already
reserved attempt consumed. Request termination, escalate to forced termination,
and reap asynchronously. Keep worker/global/UID capacity charged until the
worker is actually gone; do not spawn unlimited replacements. An unrelated UID
may proceed only within remaining global limits. Actual sandbox settings are
separate for the TPM worker and password PAM worker.

The adapter/broker response deadline must not wait indefinitely for reaping.
Uninterruptible device I/O can survive SIGKILL temporarily. The experiment's
synchronous final reap demonstrates cleanup only for interruptible blocked
calls. Production code needs an asynchronous bounded reaper and refusal when
capacity is occupied. It must close inherited sockets/descriptors, prevent
descendant escapes and discard context/session handles after a killed worker.

## Required follow-up evidence

- M3: storage fault injection proves reserve-before-invoke and durable
  success-before-authorize; worker markers are not the storage implementation.
- M5: actual Rust/native integration, protocol/generation fencing, partial and
  late replies, disconnect/cancellation, resource exhaustion and a stalled
  native call while another UID progresses. Inject delayed reaping to prove the
  response deadline and capacity rule without requiring unsafe hardware hangs.
- M5/M6: enforcing SELinux and separate systemd sandboxes, minimum capabilities,
  descriptor/process/memory limits, no general shell execution, and cleanup of
  actual TPM and PAM helper resources.
- M7: measure total KDE fallback time, including the original password stack's
  delays. A fast LocalPIN-unavailable result cannot remove those delays.
