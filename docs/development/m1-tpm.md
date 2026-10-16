# M1 TPM construction experiment

- Date: 2026-10-16.
- Result: the simulator assertions pass. This is feasibility evidence, not a hardware or release certification.
- Runner: [experiments/m1/tpm/run.py](../../experiments/m1/tpm/run.py).
- Sanitized reference output: [results-2026-10-16.json](../../experiments/m1/tpm/results-2026-10-16.json).
- Proposed construction: [ADR 0002](../adr/0002-tpm-construction.md).

## Environment and isolation

The runner executed on Fedora Linux 44, x86_64, kernel `7.2.9-200.fc44.x86_64`, Python `3.14.8`. Exact package builds were:

| Package | Build |
|---|---|
| swtpm | `0.10.2-1.fc44.x86_64` |
| libtpms | `0.10.2-3.fc44.x86_64` |
| tpm2-tools | `5.7-5.fc44.x86_64` |
| tpm2-tss | `4.1.3-9.fc44.x86_64` |
| libargon2 | `20190702-10.fc44.x86_64` |

The simulated TPM reports TPM 2.0 revision 1.83, IBM software TPM, firmware values `0x20240125` and `0x120000`. These are simulator values. No production TPM capabilities, ownership, or policy were queried.

Each run creates two simulator state directories under a mode-0700 `/tmp/localpin-m1-tpm-*` directory with private Unix sockets. Every operational tool command has an explicit generated `swtpm:` TCTI. A recording Unix relay retains command/response data only in memory. Tool `--version` does not perform a TPM operation even though it reports `tcti-default=tcti-device`.

The ordinary Codex syscall sandbox rejected Unix socket creation (`Operation not permitted`). The same harness ran successfully with approved sandbox escalation. This is an execution-environment restriction. No host PAM, device, persistent TPM handle, NV index, or global hardware policy was changed.

## Observed assertions

| Experiment | Actual observation |
|---|---|
| Parent recreation | Exact public bytes and Name match after transient flush, clean `swtpm` process stop/restart with its saved state, and recreation under owner hierarchy. Existing child blobs reload and unseal. |
| PIN derivation | Synthetic leading-zero six-digit PINs derive distinct 32-byte object auth values via libargon2 with explicit Argon2id version 0x13, 64 MiB, three passes, one lane and a fresh 16-byte salt. This is a test adapter, not the future Rust KDF implementation. |
| Object template | Parsed public area is `TPM_ALG_KEYEDHASH`, SHA-256 Name algorithm, NULL keyed-hash scheme, exact attributes `0x52`, zero-length `authPolicy`, 32-byte unique value. `fixedTPM`, `fixedParent`, `userWithAuth` are set; `noDA` and other flags are clear. |
| Identity | Loaded public bytes match enrollment. Name is SHA-256 over the marshaled `TPMT_PUBLIC`, prefixed by its algorithm ID. Public mutations, self-consistent substitute public/Name pairs and generation mismatches are rejected. An actual second object on the same TPM, with the same authorization and template, unseals successfully but fails enrollment identity comparison. |
| Session construction | Recorded `StartAuthSession` command contains an encrypted salt, unbound HMAC session type, SHA-256, AES-128-CFB. The create command has both decrypt/encrypt flags; Unseal has encrypt and no inappropriate decrypt flag. |
| Wire protection | An intentional synthetic Unseal without response encryption exposes the known secret in the recording, proving recorder coverage. With protected create/unseal, neither the raw auth bytes nor the known 32-byte secret occurs in the recorded transport. This supplements explicit session/flag checks; it is not a cryptographic proof. |
| Correct PIN | Protected Unseal returns exactly the synthetic secret belonging to the enrolled object. |
| Wrong auth | Empty auth and a different PIN's derived auth both fail with `TPM_RC_AUTH_FAIL` (`0x98e`), moving the DA counter from 0 to 1 to 2. Repeated capability reads do not move the counter. |
| Alternative policy path | An empty policy session fails with `TPM_RC_POLICY_FAIL` (`0x99d`). The accepted public area has no policy digest or PCR authorization path. Negative tests complement template review; they do not enumerate every possible TPM command. |
| Foreign TPM | The other simulator produces a different owner-primary Name; loading copied public/private blobs under it fails `TPM_RC_INTEGRITY` (`0x1df`). |
| Budget inspection | `GetCapability(properties-variable)` exposes `TPM2_PT_LOCKOUT_COUNTER`, `TPM2_PT_MAX_AUTH_FAIL`, and `TPM2_PT_PERMANENT.inLockout`. The configured simulator maximum of eight failures is read back without a failed authorization. |
| Two-attempt reserve | With maximum eight, a candidate may be submitted at counter five; a fresh preflight refuses at six. Unknown counter/maximum also refuses in the test policy. |
| Other-client race | At observed counter five a preflight allows. An independently submitted wrong authorization raises the counter to six; proceeding on the stale observation raises it to seven and consumes part of the reserve. No atomic reservation API is established. |
| Global lockout | At counter eight, even the correct auth fails with `TPM_RC_LOCKOUT` (`0x921`). Only simulator policy is adjusted to reach this state. |
| Stalled native transport | While `swtpm` is SIGSTOPed, the real native `tpm2_unseal` process remains blocked beyond 500 ms. The supervisor kills and reaps it in approximately 0.501 s, retains the prewritten/fsynced reservation marker, accepts no late output, resumes the simulator and successfully unseals through fresh contexts/session. |

Commands are invoked through TPM2-TSS native tools; no mocked TPM result is counted above. Reserve policy checks and the durable marker are deliberately small illustrative adapters. They are not M2/M3 implementations. The other-client race is an ordered interleaving of actual simulator commands, which makes the unsafe stale-observation window deterministic.

## Consequences for implementation

Proceed with a transient owner-primary and PIN-authenticated sealed data as the M4 candidate, subject to review. Recreate and validate the parent before using it to salt sessions. Match loaded object identity to the protected active-generation record before accepting authorization, and fence the generation again when committing success. A successfully unsealed arbitrary object is insufficient.

Read all required DA properties before a submitted verification. If locked, unreadable, inconsistent, or insufficient to leave two failures after one possible mismatch, return unavailable. Do not reset counters or change policy to make this pass. The race above means the reserve reduces risk but cannot guarantee protection from another TPM client.

Place blocking native work in supervised bounded workers. An expired worker must never produce an accepted late success; its previously reserved software attempt remains consumed. See [ADR 0004](../adr/0004-native-worker-deadlines.md) for the worker architecture and separate native-worker fixture. Terminating a process blocked in a simulator socket does not prove a real device task in uninterruptible kernel I/O will immediately disappear. Such a task must continue occupying a bounded worker slot; repeated failures must not cause unbounded replacement spawning.

The fixture flushes every simulator transient slot because the CLI tools restore context files without a resource manager. The Rust backend must keep a coherent ESAPI context and release only handles it owns. It must not translate this fixture's global flushes to `/dev/tpmrm0`.

## Incomplete validation

- Actual hardware usability, permitted hierarchy authorization, resource-manager behavior, firmware errors and transport trust.
- Rust `tss-esapi` construction, pinned native dependency contract, library secret ownership and zeroization.
- Abrupt power loss, TPM clear/replacement recovery, resource-manager reconnection and real suspend/resume; the tested restart is clean and retains simulator state.
- Production budget parsing, scheduling, durable reservation fault injection, cancellation/generation fencing, bounded stalled-worker recovery and unrelated UID responsiveness.
- Independent TPM specialist review of the construction, authorization model and transport assumptions.

These remain M4/M5/M9 acceptance work. No everyday lock-screen rollout is authorized by a passing simulator fixture.

## Primary references checked

The experimental behavior above was observed locally. The construction terminology was checked against [TCG TPM 2.0 Part 2 structures, revision 1.64](https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p64_Part2_Structures_15may2021.pdf), which defines the object attributes, and [the TPM public-area definition](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.16.pdf), which defines Name computation and empty `authPolicy` for no policy. These explain the validator, not a claim of audit.

Tool interfaces were checked against upstream [Create](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_create.1/), [CreatePrimary](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_createprimary.1/), [StartAuthSession](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_startauthsession.1/), [Unseal](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_unseal.1/), and [DictionaryLockout](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_dictionarylockout.1/) documentation. Parameter protection requires explicit session configuration. The test-only Argon2 call follows the [20190702 upstream C API](https://github.com/P-H-C/phc-winner-argon2/blob/20190702/include/argon2.h). Links were checked on 2026-10-16; the exact executed package builds are recorded above rather than inferred from moving documentation.
