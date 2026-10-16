# M1 PAM candidate and account-policy experiment

Date: 2026-10-16. Status: isolated API feasibility demonstrated; Fedora KDE
integration remains unverified. No everyday-host PAM service was changed, no real
password was requested, and no real password database was used by these tests.

## Delivered and reproduced

The [experiment](../../experiments/m1/pam/README.md) contains a small C PAM fixture
module and scripted conversation. The production adapter remains planned in
Rust; this experiment does not establish its FFI safety. No native dependency was
added to the Rust workspace.

Inputs actually used on Fedora 44 x86_64:

| Input | Version |
|---|---|
| PAM runtime and baseline modules | `pam-1.7.2-2.fc44.x86_64` |
| Headers, extracted locally without installation | `pam-devel-1.7.2-2.fc44.x86_64` |
| Compiler | GCC `16.2.1 20260819`, Fedora `16.2.1-2` |
| KDE source/runtime inspected | `kscreenlocker-6.7.5-1.fc44.x86_64` |
| Namespace runner | `bubblewrap-0.12.0-1.fc44.x86_64` |
| Synthetic shadow hashing | `libxcrypt-4.5.2-3.fc44.x86_64` |
| Namespace fixture generator | Python 3.14.8 |

The ordinary development sandbox returned `PAM_SYSTEM_ERR` (4) from the known
permit baseline. The runner stopped with infrastructure exit 77 before any
LocalPIN assertion; the cause was not established. The same source, run outside
that sandbox with private temporary configs, produced:

```text
BASELINE permit=success deny=PAM_AUTH_ERR prompts=0
RESULT checks=30 failed=0; mock-only, no host accounts or PAM configuration used
```

The optional namespace run produced:

```text
BASELINE permit=success deny=PAM_AUTH_ERR prompts=0
BASELINE synthetic pam_unix correct=success wrong=PAM_AUTH_ERR prompts=1
RESULT pam_unix checks=5 failed=0; synthetic namespace accounts only
```

Reproduction with locally extracted matching headers:

```sh
LOCALPIN_PAM_INCLUDE="$PWD/.local/m1/pam-devel/usr/include" experiments/m1/pam/run.sh
LOCALPIN_PAM_INCLUDE="$PWD/.local/m1/pam-devel/usr/include" LOCALPIN_PAM_UNIX=1 experiments/m1/pam/run.sh
```

The namespace test ran as an unprivileged host user using bubblewrap. It mounts
only read-only `/usr`, generated `/dev` and `/proc`, temporary directories and
synthetic `/etc` account files. It has separate user/PID/network namespaces and
`--die-with-parent`. Its namespace root is not host root. The synthetic password
hashes and files disappear with the temporary work directory.

An optional ASan/UBSan build was attempted but could not link: the installed GCC
expected missing `libasan.so.8.0.0` and `libubsan.so.1.0.0`. Sanitizer execution was
therefore **not** performed. The ordinary warning-clean builds and runs passed.

## What these tests establish

The fixture captures one PAM response, copies it with `pam_set_item(PAM_AUTHTOK)`,
zeroes/frees its response allocation, then returns either simulated PIN success
or a non-success code. Its downstream password fixture calls the real
`pam_get_authtok` helper. Successful fallback requires exactly one conversation
prompt, so a silently re-prompting downstream path fails the test.

The 30 mock assertions cover ordinary and six-digit passwords, leading zeroes,
empty input, Unicode digit lookalikes, five/seven-digit inputs, every non-NUL byte
value, and a 511-byte string. PIN-format detection accepts only six ASCII digits.
PAM's C-string representation cannot express embedded NUL; the adapter must not
claim to preserve such an input. The tests establish preservation of the bytes
already delivered by the conversation, not keyboard/Qt encoding behavior.

Simulated wrong PIN, cooldown, disabled/not-enrolled, unavailable broker, timeout,
corrupt state, identity mismatch and unsupported-service outcomes continue to
password. These are code mapping tests, not fault injection into a real broker,
backend, account resolver, or deadline implementation.

The real packaged `pam_unix.so`, using `nodelay try_first_pass` against namespace
fixtures, accepted ordinary, six-digit, and non-UTF-8/whitespace passwords with one
prompt after capture. A reused handle accepted a six-digit password, denied a
fresh wrong password, then accepted a fresh correct password. The wrong-password
baseline and forced simulated PIN mismatch prevent a permissive mock from
explaining those successes. This is direct evidence for this module/version and
options, not for the whole Fedora service graph.

On a reused PAM handle the mock suite also covers PIN success -> password success
-> password failure -> password success -> cancelled conversation -> success.
Module-side observers during `pam_setcred` and before each subsequent capture
found no stale `PAM_AUTHTOK`. Linux-PAM restricts token access from applications;
the harness inspects it only inside the fixture module. Completed failed auth
also affects the dispatcher's setcred outcome; a failed transaction must not be
asserted to have successful credential refresh. Incomplete asynchronous PAM
conversations were not exercised.

The rule `[success=done default=ignore]` preserves an earlier required failure;
a preceding requisite denial stops before asking for a candidate. A missing
optional adapter reaches the password prompt. An account-only denial does not
run during `pam_authenticate`; explicitly calling `pam_acct_mgmt` subsequently
denies. These are reasons to preserve and test the complete policy, not approval
for inserting the sample rule into a real service.

## Exact Fedora KDE source inspection

The matching source RPM was downloaded from Fedora source repositories (the
matching Koji build is linked below), extracted under ignored
`.local/m1/kscreenlocker-source`, and inspected without copying upstream source
into this repository. Its spec has no patches and no service-name CMake override.
The source sets the interactive default to `kde` in `CMakeLists.txt:121`, and
`greeter/greeterapp.cpp:138` constructs the interactive authenticator from it.
Separate fingerprint and smartcard authenticators exist. Package source inputs:

| File | SHA-256 |
|---|---|
| `kscreenlocker-6.7.5-1.fc44.src.rpm` | `30a5dd9bd1844a1322e7d7f798515c35b140c137bef82ffeffb743fdd32c2555` |
| `kscreenlocker.spec` | `a2126a82c4775238469ec073222eec08b4ca960d75c315c731b54e3bc3f83bbb` |
| source `kscreenlocker-6.7.5.tar.xz` | `6c41ce2cb79d2b85d4fbe5a3a61c09e40c70e5a869ae6f0352c7e1cb3b44606b` |
| source `CMakeLists.txt` | `a00e2b1c769e55114d311add013b6857856e81fed9ec976cf925dec4995ec5e1` |
| source `greeter/pamauthenticator.cpp` | `4fa76a0a575ba3e09fab7b06f3393a07dddd0ec3dc1de5b4ca44e6c63c3eca1f` |
| installed `kscreenlocker_greet` | `45d5a60737ff966b93f60639a662396956b28d50122741261f4351fef941be48` |
| matching `pam-devel` RPM | `1262d6e8d356912841e4614a7d5f0977593cf8d2cb550b9209e18410b677316b` |

In that source, `PamWorker::start` creates a handle at lines 238–240;
`authenticate` calls `pam_authenticate` at line 192 and refreshes credentials on
success at line 200. The destructor ends the handle at line 176. There is no
`pam_acct_mgmt` call. The installed binary imports start/authenticate/setcred,
with no account-management import, and contains UTF-16 service strings `kde`,
`kde-fingerprint`, and `kde-smartcard`. RPM verification excluding ownership/group
reported no differences; ownership/group appeared virtualized in the development
sandbox. Source inspection is strong supporting evidence for the build's
contract, but actual VM lock-screen transactions are still required.

Primary references: [Fedora source build](https://kojipkgs.fedoraproject.org/packages/kscreenlocker/6.7.5/1.fc44/src/kscreenlocker-6.7.5-1.fc44.src.rpm),
[KDE's versioned PAM contract](https://github.com/KDE/kscreenlocker/blob/v6.7.5/README.pam),
and [versioned authentication source](https://github.com/KDE/kscreenlocker/blob/v6.7.5/greeter/pamauthenticator.cpp).
The downloaded Fedora source, identified by the digests above, is the inspected
input; source line numbers refer to that tarball rather than a rendered web copy.

Linux-PAM's versioned
[token helper](https://github.com/linux-pam/linux-pam/blob/v1.7.2/libpam/pam_get_authtok.c)
returns an existing token;
[pam_unix authentication](https://github.com/linux-pam/linux-pam/blob/v1.7.2/modules/pam_unix/pam_unix_auth.c)
uses that helper. [Authentication dispatch](https://github.com/linux-pam/linux-pam/blob/v1.7.2/libpam/pam_auth.c)
and [token sanitization](https://github.com/linux-pam/linux-pam/blob/v1.7.2/libpam/pam_misc.c)
clear tokens around completed authentication. These observations explain the
measured behavior; the tests establish only the recorded installed version.

## Gates still open

The [candidate/account ADR](../adr/0001-pam-candidate-and-account-policy.md)
requires an explicit eligibility policy before PIN success. The read-only host
inventory found no active `pam_faillock` module and is unsuitable as proof for a
lockout-enabled supported profile. Required checks inside the original password
substack would be skipped by naive insertion at the beginning of `auth`; KDE's
account section is not a later safety net.

A disposable Fedora KDE VM with SELinux enforcing must still prove the complete
include/substack graph and stock-theme conversations, locked and expired account
behavior, nologin/access restrictions, authselect `with-faillock` preauth/failure
accounting and counter boundaries, and preceding required checks. That VM must
also cover real broker failures/timeouts, worker denial/crash, repeated locker
attempts, keyboard/encoding behavior, and password recovery. No activation tool
or host integration is delivered by this experiment.
