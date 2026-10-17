# Security policy

LocalPIN is experimental authentication software for unlocking an existing
Fedora KDE session. It implements a broker, six-digit PIN credential backends,
enrollment CLI, PAM integration, Fedora RPM packaging, and recovery tooling.
There is **no supported production release**.

The [M8.1 report](docs/development/m8.1-desktop-compatibility.md) records current
source checks and targeted installed tests on Fedora KDE 44 x86_64 with SELinux
enforcing and an emulated TPM. Independent M9 security review, physical hardware
validation, and release gates remain incomplete. Use a disposable test system;
the specification and passing tests do not establish production readiness.

## Reporting a vulnerability

If private vulnerability reporting is enabled, use
[the repository's Security page](https://github.com/tommcamm/LocalPIN/security)
and select **Report a vulnerability**.
Otherwise, contact the maintainer privately using contact information they have
published on their profile. No dedicated reporting address, monitored channel,
or response-time commitment has been established yet. If no private contact is
available, do not publish exploit details in an issue while waiting for a private
channel to become available.

Include the affected commit or RPM version, environment, expected and observed
behavior, and a minimal reproduction using synthetic data where possible.
Describe any apparent
authentication bypass, password-fallback failure, privilege boundary issue,
credential disclosure, account-identity failure, or throttle bypass. Do not
attach real passwords, PINs, shadow records, credential/state directories, TPM
private material, core dumps, or unsanitized authentication logs.

Public issues are appropriate for ordinary bugs and design discussions that do
not disclose an exploitable security issue.

## Release expectations

There are no maintained release branches or published security-support windows.
Supported versions and a maintained reporting channel must be established before
a production release. The [implementation plan](docs/implementation-plan.md)
tracks independent review, remaining hardware and compatibility validation,
desktop password fallback, and demonstrated recovery as release requirements.
