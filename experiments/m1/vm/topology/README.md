# M1 genuine KDE topology evidence contract

This directory separates the remaining topology observations from the earlier
root-declared logind metadata fixture. Its `evidence.py` validator and synthetic
tests access no VM, register no sessions, launch no compositor and alter no
authentication. Separate `launch.py`/`launch.c` sources are a clone-only native
session experiment; their execution requires independent review and exact guards.
The VM operator owns the actual observations and clone recovery. No readiness
message or validator result certifies M1 completion.

```sh
python3 -m unittest discover -s experiments/m1/vm/topology -p 'test_*.py' -v
python3 experiments/m1/vm/topology/evidence.py --template > .local/m1/topology-draft.json
python3 experiments/m1/vm/topology/evidence.py --record .local/m1/topology-draft.json
```

The template is unexecuted and cannot pass. Fill it from reviewed observations,
then keep the raw machine evidence in ignored/private storage. Validation reports
fixed missing-evidence labels and exits 2 while gaps remain; malformed input exits
1. Passing only means the curated assertions are internally consistent. It does
not attest that an operator observed them. The schema deliberately forbids an
`m1_complete` or production-authorization claim.

## Required observations

The accepted [roadmap](../../../../docs/implementation-plan.md),
[session decision](../../../../docs/adr/0003-session-and-worker-boundaries.md),
and [gap assessment](../../../../docs/development/m1-multiseat-gap.md) remain
authoritative. The following two scenarios may share one physical lab run when
every condition is actually observed; neither can be inferred from the other.

1. **Two genuine concurrent desktops for the same ordinary UID.** Observe two
   distinct native local KDE sessions and their live packaged `kwin_wayland` (or
   supported native KWin) and `plasmashell` processes during one observation
   window. Resolve process/session membership and record both eligible sessions
   for that UID. Observe the actual locker's kernel identity and sd-login
   membership. For a shared-user-manager caller without a direct session,
   require owner agreement and two live eligible candidates. A reviewed,
   fallback-only routing probe must return unavailable, without guessing the
   first/active seat, and an actual one-entry password unlock must still work.
   The probe must not implement PIN success or accept a client Boolean.
2. **An independently routed second seat.** Observe two genuine native KDE
   desktops on different logind seats with separate emulated DRM/KMS GPUs and
   separately routed virtual keyboard/pointer input. Correlate actual DRM/input
   devices, compositor/session membership and each visible console. Verify
   input on one seat affects only its intended console. Manually lock and unlock
   each console through its actual stock locker and verify the unlocked state.
   A second monitor head or viewer, nested/headless compositor, remote desktop,
   root-declared session metadata or extra `DISPLAY` value cannot supply this
   evidence. The two seats may use the same UID only if scenario 1 also passes.

Native direct mappings validate their own eligible session. A direct ineligible
mapping must refuse even when another eligible session exists. An absent direct
mapping permits only a verified user-manager owner with exactly one eligible
own-UID candidate; zero/multiple candidates refuse. These are experimental routing
checks, not a production broker or caller-authenticity proof. Same-UID malware
remains within the documented threat-model limitation.

Every desktop entry needs a human-observed real console, live native components,
verified process/logind mapping and input-route verification. The same-UID case
needs the actual ambiguous shared-manager locker's one-entry password fallback;
a second classic session with a valid direct mapping does not need another
ambiguity or manual-unlock test. Each independent seat needs actual locker
observation, a one-entry password unlock and unlocked-state corroboration.
Do not use `loginctl unlock-session` as an authentication result. Setup unlocks,
if any, are recorded separately and excluded from test outcomes.

## Lab safety review before execution

- Work only in an identified disposable clone of the known clean VM, with its
  own UUID-bound root-only guard and a restorable snapshot. Verify clone identity
  and disk backing paths before offline access, device changes or start.
- Shut the clone down for offline edits; never customize a live disk or the
  everyday host. Use virtual graphics/input only, with no host-device passthrough.
  Keep the management console/guest agent and a bounded recovery path available.
- Keep SELinux enforcing. Record exact package builds, source-archive digest,
  original PAM/profile/account digests and audit counters. Review fresh expected
  versus unexpected denials. Audit loss cannot be silently treated as complete
  coverage, and permissive mode or broad generated policy is not a repair.
- Review exact launcher/unit names, executable ownership, private PAM confdir,
  supported environment and FDs before launch. A private native launcher may call
  real `pam_open_session`/`pam_systemd` and start unmodified packaged components;
  root-declared metadata alone still does not pass. Label that launch method
  explicitly rather than implying the stock login manager created it.
- Bound both the launch service and any new logind scope, because session
  registration can move the leader outside the launch cgroup. Retain a native
  watchdog and process/resource limits across that move. Confirm actual applied
  limits. Do not use UID-wide or seat-wide kills, guess a session ID, or unload
  policy while an owned process may still be alive.
- Record the exact owned units/scopes/process references and cleanup plan before
  the first mutation. Request normal PAM session closure, then stop only those
  owned resources. Confirm descendant/session disappearance before removing
  files; retain resources and restore/discard the clone if stop is uncertain.
  Do not assume the service's successful stop reaped a migrated leader.
- Restore account/PAM/authselect state, remove temporary keys and fixture paths,
  then restore or discard the clone. Preserve separate per-run and final recovery
  records; a per-run historical snapshot flag must not be retroactively changed.

## Sanitized record and interpretation

The template defines the version-1 schema. It uses fixed `desktop-a/b`,
`seat-a/b`, `gpu-a/b`, `input-a/b`, and `target/other/root` aliases. Commit no raw
usernames/UIDs, session IDs, PIDs, device paths/addresses, guest UUIDs, key material,
candidate bytes, passwords, account hashes, PAM contents or raw logs. Package
versions and a source archive SHA-256 are allowed bounded provenance. Distinct
aliases assert verified distinct objects; inventing aliases is not observation.
No arbitrary notes or unknown fields are accepted by the validator.

`status=failed/blocked/not-run` records useful negative or absent evidence, but
cannot satisfy either topology scenario. If the stock package cannot run the
required topology, retain the exact failure, package/source context and safe
password behavior. Source findings and an unexecuted workaround do not close an
actual GUI requirement. Completion then needs actual supported GUI evidence, or
a separately visible and reviewed requirement/support change; this tool does
not waive the accepted gate.

The validator requires both scenarios, enforcing-mode observations, reviewed audit
coverage without added loss, and completed recovery before it reports consistent
topology evidence. It never reports M1 complete. The final milestone decision
must also reconcile the existing PAM/TPM/platform evidence and explicitly assign
later production contracts: UID lifecycle, peer/process races, account-policy
coverage, authenticated grants, durable state, worker confinement and activation.
