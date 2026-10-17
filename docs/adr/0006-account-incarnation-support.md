# ADR 0006: Require authoritative account lifecycle support

Date: 2026-10-17. Status: accepted fail-closed support restriction.
Original M2 implementation status: production
account lifecycle adapter remains unimplemented.

## Problem

Deleting and recreating an account with identical UID, name and home directory
cannot be detected from equality of those values. Randomly adding an identifier
to a LocalPIN credential also cannot detect an account change by itself. An
operator instruction to delete LocalPIN state is not enforcement.

## Decision

An account is eligible only within a trusted lifecycle authority's supported
domain. That authority supplies an opaque nonzero incarnation identifier and
must revoke it durably before deletion/reuse, serialize lifecycle changes with
LocalPIN finalization, survive crashes/reboots, and refuse service when it cannot
prove continuity. Enrollment and final authorization recheck that authority;
an incarnation change fences old credentials, transactions and backend results.
Renames may retain an incarnation only when the authority proves continuity.

The pure model accepts simulated authorities to test this contract. There is no
production authority for ordinary Fedora Unix accounts in M2. Such accounts
therefore remain unsupported for production enrollment/activation. No adapter
may return a made-up stable incarnation derived from UID/name/home or treat an
unavailable authority as eligible. The development envelope includes the opaque
binding for model tests, but is not a frozen permanent account-identity schema.

This visibly narrows the initial account support promise until an enforcing,
tested mechanism exists. A future ADR must choose and demonstrate that mechanism
before M3 writes permanent account/credential records or M5 activates an account.
Pure storage crash-consistency work can proceed with simulated identities.

## Required evidence before lifting the restriction

Implementation ownership is assigned to
[M6.1 in the roadmap](../implementation-plan.md#m61--implement-production-account-lifecycle-and-eligibility),
before M7's real-account integration/acceptance gate. That milestone must select
and demonstrate the mechanism in a new ADR, implement the production lifecycle
and password-free eligibility adapters, and provide real-account evidence.
Adding the milestone does not lift this restriction or establish a permanent
identity schema. Installed policy/confinement and package activation retain
their M8 gates.

Delete/recreate with identical UID/name/home; deletion concurrent with a backend
success or enrollment commit; rename; missing/corrupt authority state; authority
restart and crash between revocation and account mutation; bypass through every
supported account administration path; UID reuse across reboot. If all mutation
paths cannot be controlled or observed before authorization, support must remain
restricted. The model cannot establish those platform guarantees.

## M6.1 implementation note — 2026-10-17

The lifecycle requirements above are unchanged. The earlier implementation
status records M2's lack of a production authority; M6.1 now implements one for
the explicitly provisioned Fedora 44 x86_64 Btrfs appliance domain in
[ADR 0012](0012-immutable-appliance-account-authority.md). The
[M6.1 report](../development/m6.1-account-authorities.md) records its actual
component evidence and final acceptance. This is not a general lifting of the
restriction, and ordinary unmanaged Fedora accounts remain unsupported.

Active incarnations require kernel-protected account/policy inputs and a
writer-drain proof before sealing, including pre-existing writable descriptors
and shared writable mappings. Root administration takes the exclusive lifecycle
lease and durably revokes all incarnations before unfreezing those inputs.
Broker readers retain the shared lease through the storage guard and actual
response delivery. Every reseal, including identical UID/name/home recreation
or rename, uses fresh opaque incarnations and privileged disabled baselines;
there is no inferred continuity. Missing/corrupt state, old experimental registry
versions and unknown policy remain unavailable. Own-user enrollment cannot
provision or recover them, even after password authentication.

Only the domain covered by the evidence may use permanent account records.
The required evidence list above remains the milestone's exit contract; a model
or scheduling fixture alone cannot satisfy it. M7's unlock adapter, M8's
installed confinement/packaging and M9's human/specialist review and physical
hardware validation retain their separate gates.
