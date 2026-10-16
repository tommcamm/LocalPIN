# M1 feasibility experiments

These are disposable development experiments, outside the Rust workspace and
release build. They are not installable PAM modules, enrollment tools or a
working LocalPIN product. All authentication values in the harnesses are
synthetic. Production implementation begins after the architecture gates.

| Directory | Experiment | Run from repository root |
| --- | --- | --- |
| `pam/` | Real Linux-PAM, private configuration, permit/deny baselines and synthetic candidate/password modules | `experiments/m1/pam/run.sh` |
| `platform/` | Bounded PAM graph metadata and session discovery tests | `python3 -m unittest discover -s experiments/m1/platform -p 'test_*.py' -v` |
| `tpm/` | Protected-object authorization on two disposable swtpm instances | `python3 experiments/m1/tpm/run.py` |
| `worker/` | Native-call deadlines, reservation marker, worker bounds and cleanup | `python3 experiments/m1/worker/test_supervisor.py` |
| `vm/pam/` | Real dedicated-account password, aging, lock and failure-counter cases | Read [guarded instructions](vm/pam/README.md) |
| `vm/kde/` | Fallback-only adapter for actual stock KDE UI tests | Read [backup/restore instructions](vm/kde/README.md) |
| `vm/selinux/` | Confined broker/client and negative native-helper boundaries | Read [policy instructions](vm/selinux/README.md) |
| `vm/worker-positive/` | Confined real password/account/helper cases | Read [worker instructions](vm/worker-positive/README.md) |
| `vm/eligibility/` | Password-free experimental lock/expiry/failure-counter preflight | Read [eligibility instructions](vm/eligibility/README.md) |
| `vm/sessions/` | Real logind registration/exclusion/ambiguity metadata | Read [session instructions](vm/sessions/README.md) |
| `vm/kde-contact/` | Bounded broker hold for actual locker contact/fallback | Read [contact instructions](vm/kde-contact/README.md) |

On Fedora the combined native prerequisites are `gcc python3 pam-devel swtpm
tpm2-tools libargon2`. PAM paths default to Fedora x86_64 and have documented
overrides in `pam/run.sh`. The original isolated harnesses need no root access. Guarded real-account and
SELinux fixtures under `vm/` require root inside the disposable VM.
Use a VM for installation of test prerequisites and all real-account tests.
The optional `LOCALPIN_PAM_UNIX=1 experiments/m1/pam/run.sh` mode additionally
needs `bubblewrap` and `libxcrypt`; it uses synthetic account files in a private
namespace. See the [PAM instructions](pam/README.md).

The platform collector is read-only and requires an explicit service candidate:

```sh
mkdir -p .local/m1
python3 experiments/m1/platform/inventory.py --service kde \
  --symlink-root /etc/authselect --host > .local/m1/platform.json
```

It stores digests and parsed structure without copying PAM text/arguments,
usernames, raw session identifiers or raw command errors. This inventory does
not authorize an edit or certify compatibility. Keep observations in `.local/`
and review them before sharing. An incomplete graph returns exit 2.

PAM's known baselines run first; exit 77 identifies infrastructure failure.
Codex's restricted syscall sandbox currently makes the permit baseline fail and
prevents Unix sockets used by swtpm. A scoped run outside that sandbox was needed
locally. CI runs isolated harnesses, synthetic guard tests and source compilation in a
disposable container; it never runs guest mutation commands and does not certify the real KDE, logind, SELinux or recovery matrix.

Read the [M1 evidence report](../../docs/development/m1-feasibility.md) and the
[VM setup instructions](../../docs/development/m1-vm-setup.md) for actual results
and remaining work. Do not install the original synthetic fixture module into any system PAM
service: its outcome switches are intentionally controlled by the test harness.
The separate guarded VM adapters are exclusively for the disposable guest.
