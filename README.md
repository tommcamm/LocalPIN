<div align="center">

# LocalPIN

**A six-digit PIN for your Fedora KDE lock screen.**

[![Experimental](https://img.shields.io/badge/status-experimental-orange?style=flat-square)](#compatibility-and-limitations)
[![CI](https://github.com/tommcamm/LocalPIN/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/tommcamm/LocalPIN/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue?style=flat-square)](#license)

[Get started](#get-started) ·
[Usage guide](docs/usage.md) ·
[Documentation](docs/README.md) ·
[Releases](https://github.com/tommcamm/LocalPIN/releases)

</div>

LocalPIN adds opt-in PIN unlocking to an existing local KDE session. Your account
password stays in place for password unlocking and recovery.

> [!WARNING]
> LocalPIN is experimental authentication software with no supported production
> release. Independent security review and physical hardware validation remain
> open. Start in a disposable VM and complete the password-fallback and console
> recovery tests in the installation guide before activation.

## Features

| Feature | What you get |
| --- | --- |
| **Keyboard-friendly unlocking** | A six-digit PIN, including leading zeroes, submitted with Enter in KDE's existing lock screen. |
| **Password fallback** | Use your account password when you prefer it or the PIN route is unavailable, subject to normal account policy. |
| **A choice of credentials** | TPM 2.0 protection or an explicitly selected Argon2id software backend. |
| **Persistent attempt limits** | PIN throttling survives service restarts and retains protection across reboots. |
| **Credential management** | Enroll, change your PIN, switch backends, or disable your PIN through the CLI. |
| **Diagnostics and recovery** | Inspect status, follow actionable diagnostics, and recover through a separate administrator console tool. |

## Get started

Use a disposable **Fedora KDE 44 x86_64 VM with SELinux enforcing** and a
recoverable snapshot first. Setup requires administrator access and the supported
local account and authentication policy described in the installation guide.

1. **Download and verify.** Get the experimental RPM and `SHA256SUMS` from
   [GitHub Releases](https://github.com/tommcamm/LocalPIN/releases). Follow the
   [download verification instructions](docs/releasing.md#verify-and-test-a-download),
   including checking the RPM signature against a separately trusted signing key.
2. **Install the package.** Follow
   [installation and recovery](docs/integration-administration.md).
   Installation leaves services stopped and desktop PIN integration disabled.
3. **Prepare and enroll.** An administrator prepares persistent password-failure
   accounting offline and provisions the selected accounts. Then enroll from
   your own foreground terminal in the local KDE session, choosing a backend
   explicitly. The [usage guide](docs/usage.md#enroll-your-pin) explains the choices.
4. **Trial, test, and activate.** Complete the runbook's bounded trial, real PIN
   and password unlock tests, console recovery rehearsal, and final activation.
   Recovery rehearsal revokes enrollment; repeat preparation, enrollment, and
   trial tests as directed before activating.

**Installation and enrollment alone do not activate PIN unlocking.** Follow the
complete runbook for the required order and recovery checks.

Testing a particular commit? [Unsigned CI testing RPMs](packaging/fedora/README.md#download-a-ci-testing-rpm)
are a separate option for disposable test environments.

## Everyday use

After setup, type your PIN into KDE's existing lock-screen field and press
**Enter**. The field may still say **Password**; there is no separate PIN selector
or automatic submission after six digits. Enter your full account password in
the same field whenever needed.

Run these commands as your normal user:

| Task | Command |
| --- | --- |
| Diagnose availability | `localpinctl doctor` |
| Check enrollment and activation | `localpinctl status` |
| Change your PIN | `localpinctl change` |
| Disable your account's PIN credential | `localpinctl disable` |

Credential changes require confirmation and fresh account-password verification.
PINs and passwords are entered privately and interactively, never as command
arguments or through pipes. See the [usage guide](docs/usage.md) for enrollment,
backend migration, cooldowns, and troubleshooting.

For system-wide recovery, use the
[administrator console recovery procedure](docs/integration-administration.md#console-recovery-and-removal).
Disabling your own PIN credential does not restore the system's PAM configuration.

## Compatibility and limitations

| Area | Current boundary |
| --- | --- |
| **Environment** | Fedora KDE 44, x86_64, SELinux enforcing, and reviewed local authselect/PAM layouts. |
| **Accounts** | Explicitly provisioned local, non-root accounts. Network accounts, systemd-homed, and custom authentication policies are outside the current domain. |
| **Where PIN works** | Unlocking an existing local graphical session. Initial login, text-console login, sudo, SSH, polkit, and disk encryption retain their existing authentication. |
| **Validation** | Targeted installed tests used a disposable Fedora KDE VM, Btrfs, and a private TPM emulator. Physical TPMs and fingerprint devices, alternate filesystems, GUI account administration, and full legacy TPM migration still need validation. |

A six-digit PIN has limited entropy. Software mode provides online throttling,
but copied verifier material remains susceptible to offline guessing. TPM
protection depends on the device and platform; full-disk encryption remains a
separate defense. LocalPIN does not protect against root, a compromised kernel
or desktop, or malware already running as you.

Wrong PINs can also count as native password failures when forwarded to password
authentication. PIN cooldown does not bypass account lockout or expiry, and
password fallback depends on the existing authentication system remaining
functional. See the [usage guide](docs/usage.md#cooldowns-and-account-policy) and
[detailed security model](docs/product-specification.md#4-security-scope-and-limitations).

## Documentation and help

- [Documentation index](docs/README.md) — user guides, administration, and technical references.
- [Contributing](CONTRIBUTING.md) — source builds, validation, and focused pull requests.
- [Issues](https://github.com/tommcamm/LocalPIN/issues) — non-sensitive bugs and feature ideas.
- [Security policy](SECURITY.md) — how to report a suspected vulnerability privately.
- [Changelog](CHANGELOG.md) — delivered changes.

## License

Copyright 2026 LocalPIN contributors. Original project material is dual-licensed
under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option
(`MIT OR Apache-2.0`). Third-party material retains its own notices and terms.
