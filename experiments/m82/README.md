# Installed guided-setup acceptance

Run only in the independently guarded M8 disposable Fedora KDE 44 clone with
SELinux enforcing and its private managed TPM emulator. Follow the clone,
synthetic-account, pinned-access and evidence requirements in
[the M8 instructions](../m8/README.md). The host must validate topology before
and after every guest operation, including actual keyboard input. Do not run
this fixture on the everyday host or an original/shared VM disk.

Stage `wizard.py` beside the reviewed M8 `run.py` and `guard.py` in root-private
`/root/localpin-m8`. It starts a separate actual Konsole through the existing
KDE user's systemd manager. Distribution `script` gives the installed CLI a
foreground controlling terminal and logs **output only** to a precreated
root-owned mode-0620 file in root-controlled mode-0711 `/run/localpin-m82`.
The dedicated group can write that log but cannot read it. Raw transcripts,
launch diagnostics and intents stay guest-private. No fixture is installed by
the RPM, no stdin/secret override enters production, and no sudo rule is added.
The fixture requires Fedora's `util-linux-script` package for `/usr/bin/script`;
this is an acceptance-harness prerequisite, not a LocalPIN runtime dependency.

Inside the guarded clone, substituting the exact installed EVR and canonical
clone UUID:

```sh
python3 /root/localpin-m8/wizard.py start --case clean-setup --mode setup \
  --expected-localpin-evr EXACT_EVR --expected-uuid CLONE_UUID \
  --disposable-vm-confirmed --emulated-tpm-confirmed
python3 /root/localpin-m8/wizard.py status --case clean-setup \
  --expected-uuid CLONE_UUID --disposable-vm-confirmed --emulated-tpm-confirmed
```

The host supplies actual libvirt keyboard events to the visible Konsole.
Status returns an exact fixed prompt ID and permitted choices; it never returns
raw terminal text or secrets. Fetch synthetic credentials only through the
existing root-private fixture access and never print them in tool output.
Answer the real sudo password prompt with the dedicated account password;
separate account-password and PIN prompts remain private. The fixture does
not automatically answer prompts or record a product attestation.
An external keyboard controller must answer a secret prompt only once per new
prompt occurrence; repeated polling of the same prompt is not a new request.
Track the reported sudo/account prompt counts and stop on native authentication
refusal. Review retained native failure history and wait for ordinary native
cooldown when applicable; never reset counters or disable a factor to continue.

To create genuine native failure history for a preservation test, prefer an
incorrect password outside the six-digit PIN grammar, so the probe does not
consume shared TPM dictionary-attack budget. This run used one genuine wrong
PIN and retained the later correct-PIN refusal consistent with the measured
TPM reserve; that observation is not a passing post-upgrade PIN test. Wait for
natural recovery rather than resetting or changing TPM policy.

Pause at `pin-unlock-confirmation` and `password-failure-confirmation` to run
the actual KDE keyboard tests. Answer those confirmations only after observing
the corresponding successful tests for that exact trial. Rehearse recovery at
an actual administrator VT when testing the wizard's text-console handoff.
The older M8 recovery case used root SSH and does not prove VT login.

`--mode menu` exercises the no-argument menu; `--mode disable` exercises own-PIN
disable. `--program localpinctl` tests the compatible executable name. Each case
has a unique non-overwriting name. Finished runs can be saved with:

```sh
python3 /root/localpin-m8/wizard.py finish --case clean-setup --expect-exit 0 \
  --expected-uuid CLONE_UUID --disposable-vm-confirmed --emulated-tpm-confirmed
```

A launch request is not proof that Konsole or `script` worked. Require an actual
recognized prompt, a script completion footer, expected exit status and absent
secret echo. A stopped window or unknown prompt needs guest-private inspection;
do not infer success or retry a mutation automatically. Output logs are
user-writable test observations, never trusted integration authority. Export
only inspected sanitized result JSON and package/source identity. Preserve
failed/incomplete observations. Dispose of runtime transcripts with the clone.

## Actual offline accounting handoff

Stage `offline_accounting.py` beside the M8 helpers. A root-generated fixed
wrapper may invoke it with the canonical expected UUID and both disposable/TPM
confirmation flags. Run that wrapper through ordinary sudo from the dedicated
owner's real login on active guest VT3. Fedora sudo's normal private PTY is
accepted only when a root sudo ancestor retains the actual `/dev/tty3`
descriptor; do not change sudo defaults to satisfy the test.

The one-shot fixture requires absent managed registry and inactive LocalPIN
units. It stops the display manager, loaded SSH listeners and other gettys,
terminates other login sessions, and explicitly stops the existing dedicated
user manager's `graphical-session.target` and `plasma-workspace.target`. The
same UID's real tty3 login keeps its user manager alive; graphical logout alone
can leave a locker worker behind. The fixture then checks that only the dedicated local tty3
session and its existing authentication ancestry remain. All other host-driven
guest operations must pause until it finishes. It backs up the exact reviewed
volatile configuration and every canonical native tally under guest-root-only
storage, refuses conflicting persistent copies and unexpected ACLs, preserves
counter bytes, UID, mode and all xattrs, synchronizes copies and directories,
atomically installs the exact persistent configuration, and restores
distribution SELinux labels.
Only previously active SSH/display-manager units restart in `finally`.

Existing intents/backups prohibit automatic retries. Private before/after and
failure/restoration records remain available for inspection. A sanitized result
reports actual migration counts and preservation facts; no tally bytes or native
metadata are exported. Genuine authentication after migration can change native
accounting normally, so continuity comparisons belong to the quiesced window.
Native source tallies owned by the account with either its ordinary primary
group or root group are accepted. If a source has a nonzero primary GID,
`--canonicalize-native-groups` is required explicitly: only the new persistent
copy receives GID 0, retaining counter bytes, UID, mode, atime/mtime and all
xattrs. Its inode/ctime necessarily differ. The volatile original and exact
private backup retain their GID. Production provisioning/eligibility continue
requiring GID 0 and perform no implicit normalization. Foreign groups,
symlinks/hardlinks, ACLs, malformed records and conflicting destinations refuse.

The first installed attempt exposed an overly narrow fixture group check before
any backup or copy. The explicit
`--reviewed-retry-after-native-group-refusal` option is restricted to that exact
runner/refusal, same UUID/boot, unchanged original configuration, empty target,
absent migration snapshots/backups, and restored original access/display units.
It preserves the original intent, failure and restoration under non-overwriting
`attempt1` names before creating a new intent. Other failures require separate
review and remain ineligible for this retry.

The next installed attempt refused before copying because a real KDE locker
worker outlived graphical logout. The separate explicit
`--reviewed-retry-after-graphical-quiescence-refusal` option is restricted to
that exact second runner/refusal with the same pre-copy checks. It preserves
the first attempt and review records, and archives the second intent, failure
and restoration under `attempt2` names. Use only the retry option matching the
reviewed attempt, alongside explicit group canonicalization when required.

## Actual administrator-VT recovery

Stage `console_recovery.py` beside the same frozen, reviewed accounting helper
and M8 helpers. Invoke its fixed wrapper from the authenticated administrator
shell originating on actual VT3, with the expected UUID and both fixture
confirmation flags. The fixture requires the actual missing-module fault,
matching saved module and current manifest-bound original policy backups. It
runs the installed `recover --dry-run`, proves no protected state changed, then
runs installed `recover` without passwords, broker probes, module repair or
desktop-test attestation.

Private checkpoints bind the unchanged boot, native counter bytes/metadata,
restored original KDE/private policies, revoked registry, disabled gate and
inactive broker units. The socket's boot opt-in must be disabled; the broker
service remains a static or disabled unit. The host separately observes the
actual password UI with the module still missing, then repairs that exact fault.
An existing attempt is never overwritten. Export only inspected sanitized
result JSON; raw operation output and checkpoints remain guest-root-only.

Native revocation can remove the gate file; both its absence and the canonical
disabled file are closed states. The first console run completed both real
commands, then its verifier incorrectly required the removed gate to exist.
`--review-completed-recovery` performs observation only for that exact original
runner/failure, recorded successful command results, unchanged helper/UUID/boot,
and original checkpoint. It preserves the original failure and command records,
verifies the remaining postconditions, and writes a separate observer result
with original command-runner and current observer source hashes. It never
repeats recovery or authentication and cannot finalize another kind of failure.

Run the isolated fixture checks without guest access:

```sh
python3 -m unittest discover -s experiments/m82 -p 'test_*.py' -v
python3 -m py_compile experiments/m82/*.py
```
