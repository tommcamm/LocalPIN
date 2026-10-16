# ADR 0002: transient parent and PIN-authenticated sealed data

- Date: 2026-10-16.
- Status: Proposed for the M4 backend; simulator feasibility demonstrated. Independent TPM review is required before release.
- Requirements: specification sections 8, 9, 11 and 12; M1/M4/M5/M9.
- Evidence: [TPM experiment report](../development/m1-tpm.md), [executable fixture](../../experiments/m1/tpm/run.py).

## Problem

Copied credential blobs must not enable offline PIN verification, enrollment must coexist with existing TPM users, and an empty-auth or policy path must not bypass the PIN. A wrong PIN consumes a shared TPM dictionary-attack allowance; transport failures can block native calls. Merely detecting a TPM or receiving successful Unseal output cannot establish these requirements.

## Candidate decision

Use one reproducible transient owner-hierarchy RSA-2048 storage primary, with SHA-256 Name algorithm, NULL RSA scheme and AES-128-CFB symmetric inner wrapping. Its exact attributes are `fixedTPM|fixedParent|sensitiveDataOrigin|userWithAuth|restricted|decrypt` (`0x30072`), with empty primary auth, no auth policy and empty template input unique. Validate its template, returned public area and recorded Name. The initial simulator exercises an empty owner-hierarchy authorization; production probes must establish permitted access, refuse unavailable authorization and never guess/change hierarchy auth. Do not create persistent handles or NV indexes.

Use a 32-byte random secret in a child keyed-hash sealed object, SHA-256 Name algorithm, NULL keyed-hash scheme, empty `authPolicy`, and exact attributes `fixedTPM|fixedParent|userWithAuth` (`0x52`). All unspecified flags, including `noDA`, are clear. The child authorization is a 32-byte Argon2id-v19 derivation of the six ASCII PIN bytes with a random 16-byte salt, 64 MiB, three passes and one lane. Keep the KDF policy bounded and versioned. Persist the salt/parameters, protected blobs, parent/object public identity, account identity and active credential generation. Persist no independent PIN/auth verifier or unsealed data.

The selected authorization path is the object's authValue through a salted HMAC session. `userWithAuth` permits this path, while zero-length `authPolicy` provisions no policy authorization. Do not add a PCR-only, PolicyOR, empty-password or software fallback path. The fixture rejects empty auth and an empty policy session. Reviewing this exact template and the commands that can change/use it remains necessary; a handful of negative tests is insufficient to establish the entire TPM authorization model.

For each create/unseal worker, recreate and validate the parent, then start a fresh unbound salted HMAC session using that parent's validated public identity, SHA-256 and AES-128-CFB. Protect the sensitive create input and eligible response parameters. Unseal needs response encryption, with command decryption disabled because there is no decryptable command parameter. Supply the derived object auth through ESAPI's maintained HMAC/session APIs. Never transmit raw password authorization or reuse a session/unsealed result as a success cache. A securely protected local transport and validated salting key are required; a copied public key alone does not authenticate arbitrary malicious transport responses.

Before authorizing, strictly validate loaded type/algorithms, exact attributes and empty policy; recompute Name over the TPM public area; require equality with the protected enrolled public area/Name and expected parent identity; bind to the active generation. After protected successful Unseal, require the expected 32-byte output size and erase the data immediately. Success is a TPM-authenticated operation for the enrolled object and active generation; do not store a comparison hash of the secret. Commit the durable success/reset and recheck the active generation before replying. M3 must supply the authoritative protected record and revocation boundary.

## Shared budget and blocked calls

Inspect `TPM2_PT_LOCKOUT_COUNTER`, `TPM2_PT_MAX_AUTH_FAIL`, and `TPM2_PT_PERMANENT.inLockout` using GetCapability before submission. Unknown, invalid, locked or unavailable state returns PIN-unavailable. With reserve `r=2`, counter `c` and maximum `m`, submit only when `m-c > r`; this leaves at least two failures after one mismatch. The M2 policy must implement checked bounded arithmetic and refuse inconsistent values. Software throttling and a durable reservation precede the verifier; an already reserved attempt remains consumed on error or timeout.

Other TPM clients can change the shared counter after inspection. The simulator demonstrates an allowed observation at 5/8 becoming 6/8 after another client's failure; a stale submission then reaches 7/8. This construction cannot promise an atomic hardware reserve or prevent unrelated clients from exhausting shared policy. Do not reset global counters, clear the TPM, tune DA thresholds, or change hierarchy authorization during ordinary product operations.

Use a supervised short-lived native worker and bounded worker/context slots. Expiration closes its result channel, marks the reserved operation unavailable, rejects every late result and kills/reaps when possible. A kernel task that does not promptly die must retain a slot; deny new TPM work once capacity is exhausted. Do not spawn replacements without a bound. See [ADR 0004](0004-native-worker-deadlines.md). Release only the worker's own handles. The simulator fixture's global transient flushes are solely fixture cleanup, never production recovery commands.

## Evidence and consequences

The fixture demonstrates identical primary public/Name after clean simulator restart, protected successful unseal, wrong-auth counter effects, empty-policy rejection, copied-blob failure on a separate TPM, reserve/race behavior, lockout even for correct auth and a bounded killed native call with fresh-context recovery. It also constructs another same-template object on the same TPM: that object unseals with the same auth but is rejected by the enrolled identity comparison. This establishes why metadata/generation matching must precede authorization acceptance.

This baseline has no PCR/measured-boot policy. A changed storage seed, parent mismatch, TPM replacement/reset or unavailable hierarchy makes the enrolled PIN unavailable; recovery is the existing account password followed by fresh enrollment. Do not select software mode automatically. Removing credential files does not promise revocation of a copied blob against a privileged attacker on the original TPM.

M4 must implement and test this construction through `tss-esapi` and a real resource-manager connection. M5 must test the broker's complete deadlines, worker bounds and generation fences. M9 must obtain independent TPM review and hardware/firmware evidence. Clean simulator restart is not power-loss or suspend certification. This ADR selects a candidate for implementation; it does not close those gates or authorize modifying the everyday TPM.

## Alternatives

A policy-only object using PolicyAuthValue and a command-code policy could be viable, but adds policy construction/state to the baseline and needs equivalent evidence. PCR-only authorization does not require the PIN and fails this product's requirement. A standalone software verifier alongside TPM data would permit offline guessing of copied records and violates pinned-backend semantics. Persistent handles add provisioning/coexistence obligations without being needed by this experiment.

## References

The local [experiment report](../development/m1-tpm.md#primary-references-checked) records authoritative TPM structures, tool interfaces and the exact executed package builds. In particular, [TCG object attributes](https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p64_Part2_Structures_15may2021.pdf) define `userWithAuth`, `fixedTPM`, `fixedParent` and `noDA`; [TPMT_PUBLIC](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.16.pdf) defines Name and policy fields. [StartAuthSession](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_startauthsession.1/) documents salting and explicit parameter-protection configuration. Sources support terminology; observed test assertions are recorded separately.
