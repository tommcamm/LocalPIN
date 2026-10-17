# ADR 0006: Require authoritative account lifecycle support

Date: 2026-10-17. Status: accepted fail-closed M2 support restriction; production
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

Delete/recreate with identical UID/name/home; deletion concurrent with a backend
success or enrollment commit; rename; missing/corrupt authority state; authority
restart and crash between revocation and account mutation; bypass through every
supported account administration path; UID reuse across reboot. If all mutation
paths cannot be controlled or observed before authorization, support must remain
restricted. The model cannot establish those platform guarantees.
