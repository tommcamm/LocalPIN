# ADR 0018: KDE authentication accounting and Fedora package compatibility

Date: 2026-10-17. Status: implemented; final source checks and targeted installed
RPM acceptance passed on Fedora KDE 44 x86_64 with SELinux enforcing and a private
TPM emulator. The [M8.1 report](../development/m8.1-desktop-compatibility.md)
records the evidence and each installed case's build scope. M9 independent review, physical hardware
and release gates remain open; hosted CI execution remains unverified.

This decision supersedes ADR 0013's exact binary and service-byte compatibility
rules and ADRs 0013–0015's blanket fingerprint/faillock activation refusal. It
retains native lockout enforcement and the rule that PIN success never clears
password or biometric failures.

Fedora's authselect fingerprint service sends every non-success result through
`pam_faillock authfail`. fprintd reports no device, no enrolled prints, timeout,
cancellation and unavailable service with an unavailable result. Counting these
results makes KDE's automatically started parallel authenticator manufacture
failures. KDE also authenticates without calling PAM account management, so the
native authselect account-phase success reset does not run. Both facts were
reproduced in the historical M7 evidence.

The integration owns two authentication-only substacks, without editing
`/etc/authselect` or disabling fingerprint authentication:

- `localpin-kde-password` checks native preauth, verifies the submitted password
  using `pam_unix try_first_pass`, records a rejection with `authfail`, and reaches
  `authsucc` only after successful password verification.
- `localpin-kde-fingerprint` checks native preauth and calls `pam_fprintd`.
  `auth_err` and `maxtries` record a real rejection; every other error exits
  immediately with failure, without modifying the tally. Successful biometric
  verification reaches native `authsucc`.

Fedora's exact disabled-fingerprint `pam_debug auth=authinfo_unavail` graph is
also compatible with PIN. Its policy selector retains the original disabled
route; LocalPIN never enables a sensor that authselect has disabled.

Each corrected substack first invokes the PAM module's explicit `policy` guard.
This selector reads the live, safely owned native authselect graph without
prompting, reading a candidate, contacting the broker or touching a tally. Only
known local authentication/account directives select the correction. The guard's
success skips three fallback lines: the original native substack, a sufficient
`pam_permit`, and a requisite `pam_deny`. An unknown graph or missing guard runs
the original substack. Its success exits through permit; its failure reaches deny
and cannot fall through to direct `pam_unix` or fingerprint verification. This
preserves newly configured second factors and custom restrictions after install.
The selector's success alone is never an authentication grant.

The integration replaces only the `auth substack password-auth` and
`auth substack fingerprint-auth` references in the two KDE services. Their
remaining account/password/session directives stay in place. The LocalPIN
success control precedes the password substack, so it never reaches either
native success reset. No unconditional success reset follows a failing substack.
Native preauth continues to deny a locked account even when the supplied
password or fingerprint would otherwise match. Fingerprint results follow
fprintd's native attempt semantics; the policy does not infer individual scans
from a final unavailable result.

The eligibility worker validates active directives, controls, arguments and
ordering for both KDE services and owned substacks. Comments and ordinary
whitespace changes do not change the policy. Extra account restrictions in
`password-auth`, unsupported authentication factors in either native graph, or
auth hooks in `postlogin` still make PIN unavailable until supported explicitly.
The password and fingerprint routes automatically use their original native
graphs when those factors change. Local accounts use `files` first, optionally followed by
Fedora's `systemd` NSS provider, including its standard group
`[SUCCESS=merge]` clause; remote providers and other NSS action clauses remain
unsupported. The raw unique local record and live NSS UID/name
must agree. Account generation is provided by ADR 0017 rather than immutable
system account databases.

Fedora's installed Linux-PAM SONAME and root-owned native modules replace the
reference-VM binary hashes and `libpam.so.0.85.1` filename pin. The SONAME symlink
must be root-owned and name a single versioned basename inside `/usr/lib64`.
Its resolved file and each native module must be bounded regular root-owned
files without group/other write access. They are snapshotted and rechecked for
each operation. A DNF replacement during a transaction can cause that operation
to fall back to the password route; the next transaction uses the new package.
Package integrity and ABI maintenance belong to Fedora's trusted package update
boundary. Arbitrary custom PAM restrictions and incompatible future SONAMEs do
not become automatically supported.

`tests/kde_accounting.py` uses private user, mount, PID and network namespaces,
synthetic identities and real system PAM/faillock. It deliberately omits the
account phase, matching KDE. It checks retained preexisting failures across
repeated unavailable/error results, the real fprintd module without a system
bus, counted genuine rejection/maxtries, native password/biometric success
reset, threshold denial without counter changes, newly required native-policy
denial in both services, and original-password fallback when the guard module is
missing. It builds and exercises the real production release PAM adapter. A tiny test-only module
selects biometric return codes; this is not physical sensor acceptance. Host
accounts, PAM configuration, tallies and D-Bus are not exposed.

The [installed desktop/continuity evidence](../../experiments/m81/results/installed-desktop-and-continuity.json)
records actual stock KDE PIN/full-password, missing-module recovery, compatible
RPM upgrades and reboot/resume. A real
[DNF transaction](../../experiments/m81/results/dnf-upgrade.json) updated 26
packages and installed five new kernel RPMs, while [PAM/authselect reinstallation](../../experiments/m81/results/native-pam-reinstall.json)
replaced seven native inodes without re-enrollment. The
[disabled-fingerprint profile](../../experiments/m81/results/without-fingerprint-profile.json)
retained its native PAM9 denial with zero authentication prompts and one normal
informational message; it preserved counters and the same enrolled PIN before
restoring the original feature profile. Final source checks and the compatible
`.5` → `.6` installed RPM upgrade also passed with exact protected-state
preservation and automatic restoration of prior activation. Earlier installed
cases retain their recorded build scope. Physical biometric success is unvalidated;
synthetic return-code tests do not certify a sensor. GUI/DBus AccountsService,
full old-TPM-credential migration and alternate filesystems also retain the
report's explicit limits.

Primary contracts: [authselect fingerprint service](https://github.com/authselect/authselect/blob/master/profiles/local/fingerprint-auth),
[KDE 6.6 PAM caller](https://github.com/KDE/kscreenlocker/blob/Plasma/6.6/greeter/pamauthenticator.cpp),
[Linux-PAM native tally implementation](https://github.com/linux-pam/linux-pam/blob/v1.7.2/modules/pam_faillock/pam_faillock.c),
and [fprintd source](https://gitlab.freedesktop.org/libfprint/fprintd/-/blob/v1.94.5/pam/pam_fprintd.c).
