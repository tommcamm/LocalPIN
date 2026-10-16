# Security policy

LocalPIN is experimental and currently contains only a repository foundation.
There is no supported production release, authentication implementation, or
completed security review. The specification describes intended requirements;
it is not evidence that those requirements have been implemented or tested.

## Reporting a vulnerability

If private vulnerability reporting is enabled, use
[the repository's Security page](https://github.com/tommcamm/LocalPIN/security)
and select **Report a vulnerability**.
Otherwise, contact the maintainer privately using contact information they have
published on their profile. No dedicated reporting address, monitored channel,
or response-time commitment has been established yet. If no private contact is
available, do not publish exploit details in an issue while waiting for a private
channel to become available.

Include the affected commit, environment, expected and observed behavior, and a
minimal reproduction using synthetic data where possible. Describe any apparent
authentication bypass, password-fallback failure, privilege boundary issue,
credential disclosure, or throttle bypass. Do not attach real passwords, PINs,
credential records, TPM private material, or unsanitized authentication logs.

Public issues are appropriate for ordinary bugs and design discussions that do
not disclose an exploitable security issue.

## Release expectations

Supported versions and a maintained reporting channel must be established before
a production release. The [implementation plan](docs/implementation-plan.md)
requires independent review, enforcing SELinux validation, desktop password
fallback tests, and demonstrated recovery before rollout.
