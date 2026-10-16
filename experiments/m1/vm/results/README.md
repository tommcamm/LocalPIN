# Reviewed disposable-VM evidence

These JSON files contain sanitized observations from the 2026-10-16 Fedora 44
KDE test VM. They are test records, not credentials or production configuration.
No account hashes, passwords, remote-access keys, raw session IDs, VM addresses
or guest UUID are included. Public fixture values remain in test source only.

- `pam-default` / `pam-faillock`: twelve / sixteen guarded real-account cases.
- `kde-ui`: maintainer-confirmed stock lock-screen fallback checks, with numeric
  token observations and exact original PAM/account restoration.
- `session-discovery`: corrected collector run from a systemd user unit; its
  direct-session observation concerns that collector, not a running greeter.
- `selinux-boundaries`: bounded enforcing broker/client/negative-helper fixture.
- `worker-positive`: eight enforcing own-user PAM/helper cases, with exact
  dedicated-account restoration and fixture cleanup.
- `eligibility-default` / `eligibility-faillock`: six / nine password-free
  experimental gate cases, with unchanged failure counters and explicit fixture
  setup refusal; this is a root-private SHA512-only experiment.
- `session-registration`: five root-declared real logind registrations; no
  second real compositor or seat is claimed by those metadata cases.
- `two-real-desktops`: two genuine different-UID KDE/Wayland desktops on seat0,
  with live compositor/shell processes and own-UID filtering.
- `kde-contact-ui` / `kde-contact-hold`: two actual greeter contact/fallback
  cases and separate confined-broker setup/cleanup evidence.
- `cleanup`: final clean-snapshot restoration/restart and temporary-key removal.
- `audit-coverage`: successful boundary/positive-worker reruns with unchanged
  audit-loss count. Earlier loss prevents claiming complete historical logs.

Per-run `whole_vm_snapshot_restored=false` records the state at report emission.
It must not be rewritten later as though the test itself restored the whole VM.
Final snapshot restoration is recorded in [cleanup](2026-10-16-cleanup.json). Likewise, false production
completion and compatibility flags are intentional limits on the evidence.

See [the evidence report](../../../../docs/development/m1-feasibility.md) for
interpretation, source/package inputs and outstanding gates. Raw logs and
operator access material stay in the ignored local cache and in the discarded
VM snapshot lineage.
