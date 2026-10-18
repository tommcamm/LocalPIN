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
| **Guided setup and management** | An interactive terminal guide for setup, status, PIN changes, backend selection and recovery. |
| **Diagnostics and recovery** | Inspect status, follow actionable diagnostics, and recover through a separate administrator console tool. |

## Get started

Use a disposable **Fedora KDE 44 x86_64 VM with SELinux enforcing** and a
recoverable snapshot first. Setup requires administrator access and the supported
local account and authentication policy described in the installation guide.

`v0.1.0-alpha.1` predates guided setup; use the
[manual setup checklist](docs/integration-administration.md#manual-setup-checklist)
and `localpinctl` for that release. The automatic accounting steps below require
a build containing the current guided CLI and setup-managed maintenance;
earlier guided builds retain the manual accounting handoff.

1. **Choose and verify the matching build.** For the current guided flow, use a
   [CI testing RPM](packaging/fedora/README.md#download-a-ci-testing-rpm) from a
   successful run for your intended source commit. Check its `CI-BUILD.json`;
   these unsigned artifacts are for disposable VM testing. For a versioned
   release that includes guided setup, get its RPM and `SHA256SUMS` from
   [GitHub Releases](https://github.com/tommcamm/LocalPIN/releases) and follow the
   [verification instructions](docs/releasing.md#verify-and-test-a-download),
   including the RPM signature and a separately trusted signing key.
2. **Install, then start setup** from your own foreground KDE terminal:

   ```sh
   sudo dnf install ./localpin-*.x86_64.rpm
   localpin setup
   ```

   Installation leaves authentication unchanged and services stopped. Setup
   explains preparation, helps you choose TPM or software protection, enrolls
   your PIN privately, and guides trial, recovery rehearsal and activation.
3. **Complete the required checks.** On a supported fresh installation, setup
   offers to prepare persistent password accounting automatically. Save your
   work before confirming: maintenance signs out sessions and temporarily stops
   authentication. After password login, setup resumes automatically. See the
   [accounting procedure](docs/integration-administration.md#prepare-native-accounting-once)
   for scope and interrupted-maintenance recovery. Keep an
   administrator console available, perform the actual unlock/recovery tests,
   and rerun `localpin setup` to resume. Console recovery revokes enrollment;
   setup guides fresh preparation, enrollment and final trial tests afterward.

**Installation and enrollment alone do not activate PIN unlocking.** The
[installation and recovery runbook](docs/integration-administration.md) explains
all prerequisites and retains the manual administrator procedure. The new guided
flow has passed [source and targeted installed VM checks](docs/development/m8.3-accounting-maintenance.md)
for counter preservation, automatic resumption, interruption recovery, TPM setup,
actual PIN/password tests, compatible RPM update, reboot and removal. The report
identifies each tested build. Independent review, physical hardware and
signed-release gates remain open; historical evidence retains its tested scope.

## Everyday use

After setup, type your PIN into KDE's existing lock-screen field and press
**Enter**. The field may still say **Password**; there is no separate PIN selector
or automatic submission after six digits. Enter your full account password in
the same field whenever needed.

Run `localpin` as your normal user for the interactive menu, or use these commands:

| Task | Command |
| --- | --- |
| Diagnose availability | `localpin doctor` |
| Check enrollment and activation | `localpin status` |
| Change your PIN | `localpin change` |
| Disable your account's PIN credential | `localpin disable` |

`localpinctl` remains available for existing commands and scripts. Credential
changes require confirmation and fresh account-password verification.
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
