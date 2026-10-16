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

On Fedora the combined native prerequisites are `gcc python3 pam-devel swtpm
tpm2-tools libargon2`. PAM paths default to Fedora x86_64 and have documented
overrides in `pam/run.sh`. No root access is needed to run these harnesses.
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
locally. CI runs only these isolated harnesses in a disposable container; it
does not certify the real KDE, logind, SELinux or recovery matrix.

Read the [M1 evidence report](../../docs/development/m1-feasibility.md) and the
[VM setup instructions](../../docs/development/m1-vm-setup.md) for actual results
and remaining work. Do not install the fixture module into any system PAM
service: its synthetic outcome switches are intentionally controlled by the
test harness.
