# M1 TPM simulator experiment

This development fixture uses synthetic PINs and two newly created `swtpm` instances. It never opens `/dev/tpm*`, accepts a caller-selected TCTI, allocates persistent handles/NV indexes, or modifies host authentication. Every TPM command receives `-T swtpm:path=<private temporary socket>`. The simulator state, blobs, synthetic authorization values, unsealed data, and in-memory wire recordings are discarded at exit. Only a sanitized report may be exported.

Run from the repository root on Fedora with Python 3, `swtpm`, `tpm2-tools`, TPM2-TSS's swtpm TCTI, and `libargon2` installed:

```sh
python3 experiments/m1/tpm/run.py --report /tmp/localpin-m1-tpm-report.json
```

The script needs permission to create Unix sockets and stop/continue its own child process. A syscall sandbox may prohibit those actions; an infrastructure failure is not a TPM assertion result. The observed environment and results are in [the TPM report](../../../docs/development/m1-tpm.md).

The successful report is emitted only after every assertion passes. A failure exits nonzero without replacing the report; choose a fresh report path to avoid mistaking an older report for a new result. No PIN/auth/secret is printed. Synthetic secrets temporarily exist in mode-0600 files because this fixture drives CLI tools; the production implementation must use library calls and zeroizing memory instead.

The suite checks deterministic parent recreation across a clean simulator process restart, an exact sealed-object template, enrolled Name/public/generation matching, actual same-TPM substitution rejection, protected salted sessions and wire flags, an unencrypted response recording control, wrong-auth DA effects, an empty-policy rejection, foreign-TPM copy rejection, reserve boundaries and a deliberately stale DA preflight, global lockout, and process isolation of a stalled native TPM call. It changes DA parameters **only inside its disposable simulator**, making negative tests reproducible without waiting for recovery.

The native-call case stops `swtpm`, durably writes a synthetic reservation marker before starting `tpm2_unseal`, kills/reaps the caller at a 500 ms deadline, resumes the simulator, flushes simulator contexts, and proves a new session can unseal. This tests a blocked native transport. It does not certify cancellation of every kernel/device failure or the future Rust broker's full reservation implementation.

`run.py` is a test utility, not a release backend. Its global simulator flushes are appropriate only because each simulator is exclusively owned by this script. Production code must release only its own handles. Re-run the fixture in CI and retain only sanitized report data. The reference run is [results-2026-10-16.json](results-2026-10-16.json).
