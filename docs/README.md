# LocalPIN documentation

LocalPIN adds numeric PIN or optional passcode unlocking to an existing Fedora KDE session, with
the account password as the recovery route. It is experimental authentication
software with no supported production release. Begin in a disposable Fedora KDE
44 x86_64 VM with SELinux enforcing.

## Get started

- [Project overview](../README.md): features, compatibility, and limitations.
- [Download experimental releases](https://github.com/tommcamm/LocalPIN/releases)
  and [verify a download](releasing.md#verify-and-test-a-download).
- [Installation and recovery](integration-administration.md): verify/install the RPM,
  run `localpin setup`, approve supported offline accounting maintenance and real
  unlock/recovery tests, or follow the manual administrator procedure.
- [Unsigned CI testing RPMs](../packaging/fedora/README.md#download-a-ci-testing-rpm):
  download packages for testing a specific workflow run.

## Use LocalPIN

- [Everyday use](usage.md): choose a backend, enroll, unlock, change or disable
  a credential, interpret status, and troubleshoot.
- [CLI reference](../crates/localpinctl/README.md): the `localpin` menu and guided
  setup, compatible `localpinctl` commands, private input and diagnostic fields.

## Administer and recover

- [Integration administration](integration-administration.md): supported
  authentication policies, setup, updates, console recovery, and removal.
- [Account administration](account-administration.md): account eligibility,
  provisioning, native account changes, and credential recovery.
- [Fedora packaging and confinement](../packaging/fedora/README.md): package
  contents, SELinux boundaries, transaction behavior, and removal.
- [Security reporting](../SECURITY.md): report suspected vulnerabilities privately.

## Build and contribute

- [Contributing](../CONTRIBUTING.md): contribution workflow, branches, pull
  requests, validation, and safe authentication testing.
- [Build from source](../CONTRIBUTING.md#build-from-source) and
  [build an RPM](../packaging/fedora/README.md#build-without-installing).
- [Dependency policy and inventory](development/dependencies.md).
- [Experimental release guide](releasing.md): maintainer publication and signing.
- [Changelog](../CHANGELOG.md).

## Architecture and development references

The [product specification](product-specification.md) defines the requirements
and threat model. [Architecture decision records](adr/) explain design contracts.
The retained [implementation plan](implementation-plan.md) tracks development
work and remaining milestones. [Flexible credentials](adr/0021-flexible-credentials.md)
defines current numeric/passcode policy; its [validation record](development/flexible-credentials.md)
separates source checks from outstanding installed acceptance.

| Component | Responsibility |
| --- | --- |
| [`localpin-pam`](../crates/localpin-pam) | Small PAM adapter for the KDE unlock path |
| [`localpind`](../crates/localpind) | Broker, account authority, and supervised backend workers |
| [`localpinctl`](../crates/localpinctl) | Shared `localpin` / `localpinctl` CLI, guided setup, credential changes and diagnostics |
| [`localpin-auth`](../crates/localpin-auth) | Private password-only PAM and eligibility workers |
| [`localpin-core`](../crates/localpin-core) / [`localpin-protocol`](../crates/localpin-protocol) | Policy, bounded messages, and operation contracts |
| [`localpin-storage`](../crates/localpin-storage) | Protected files, credential generations, and durable throttling |
| [`localpin-credentials`](../crates/localpin-credentials) / [`localpin-tpm`](../crates/localpin-tpm) | Software credentials, PIN derivation, and TPM operations |
| [`packaging/fedora`](../packaging/fedora) / [`tools`](../tools) | RPM/confinement definitions and activation/recovery tooling |

The [setup-managed accounting report](development/m8.3-accounting-maintenance.md)
records source checks and build-scoped VM evidence for automatic maintenance,
counter preservation, shipped setup resumption, crash recovery and user-session
lifecycle, retaining failed observations and subsequent corrections. It also
records the TPM setup, recovery and package-lifecycle cases exercised in this
change. The [guided setup validation report](development/m8.2-guided-setup.md) records
local source, terminal and RPM checks for the
[guided setup contract](adr/0019-guided-setup-orchestration.md). The
[installed acceptance record](development/m8.2-installed-acceptance.md)
records passing targeted TPM onboarding, console recovery, identical-payload RPM
update, reboot, removal and cleanup cases, with retained failures and explicit
scope limits. Source checks do not extend prior installed results. The [desktop compatibility report](development/m8.1-desktop-compatibility.md)
records targeted installed acceptance in a disposable enforcing Fedora KDE VM
with a private TPM emulator. Historical reports in [development](development/)
retain their recorded build and environment scope; that report supersedes the
earlier immutable-appliance account model. The
[release readiness checklist](development/m9-release-readiness.md) tracks
independent review, physical hardware validation, and remaining release gates.
Installed VM results and hosted CI results do not complete those gates.
