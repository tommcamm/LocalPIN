# Bounded broker hold for actual KDE contact tests

This optional orchestrator holds the already reviewed fixed `PING`/`PONG` broker
for up to ten minutes while a separately reviewed VM-only KDE capture adapter
tests a genuine locker call and password fallback. It performs no password or
account operation and does not install a KDE adapter. Coordinate account/UI work
with the supervising VM operator and preserve the clean snapshot.

All commands require the shared exact root-owned disposable-VM marker, guest
root and SELinux enforcing. The hold additionally requires QEMU/KVM, no old
fixture resources and explicit snapshot confirmation. From the guest repository:

```sh
python3 -m unittest discover -s experiments/m1/vm/kde-contact -p 'test_*.py' -v
sudo python3 experiments/m1/vm/kde-contact/run.py --hold --snapshot-confirmed --locker-type unconfined_t
```

Keep that process running. In another guest-root terminal:

```sh
python3 experiments/m1/vm/kde-contact/run.py --status
python3 experiments/m1/vm/kde-contact/run.py --deny
python3 experiments/m1/vm/kde-contact/run.py --status
python3 experiments/m1/vm/kde-contact/run.py --finish
```

Wait for `ready` before the reachable-broker case and `denied` before the denial
case. Requests/state use only fixed names in a root:root 0700 control directory;
files are single-link root-owned 0600 regular files, opened no-follow. `--deny`
sets only this owned socket to mode 000. This denies **new** ordinary-UID
connections through DAC; it does not revoke an existing connection or establish
an SELinux denial from the actual locker. The separate passed confined-client
experiment establishes the MAC-negative control. `--finish` stops the owned
broker and removes the fixture's own policy/files/unit/control directory.

The orchestrator reuses the passed boundary fixture's preflight, policy, exact
context/NNP unit and cleanup helpers. It compiles a temporary copy of its C
fixture with exactly two lifetime constants changed: alarm 35 to 600 seconds and
idle poll 30 to 600 seconds. Original source and its passed runner stay unchanged.
The native alarm, service runtime limit and orchestration deadline independently
bound lifetime. The fixed peer UID, root peer validation, domain assertion,
protected state and 16-contact bound remain the same. No PIN/password is sent to
the broker, logged, accepted as an argument or stored by this orchestrator.

Only the separately observed `unconfined_t` desktop type is supported by this
adapter experiment; its rule grants contact with the fixture runtime/socket and
broker type only. Successful hold setup does not prove the actual locker made a
request or that password fallback worked. Record those using the capture
adapter's bounded numeric diagnostics, observed locker PID/type and actual lock
state, alongside the human outcome. An unconfined targeted desktop is not proved
newly confined by this test.

SIGINT/TERM initiate bounded cleanup. An uncertain service stop retains fixture
resources and requires snapshot restoration; SIGKILL/power loss also requires
snapshot recovery. Status after successful cleanup has no control directory.
Audit/journal review, exact KDE adapter restoration and account restoration are
separate operator responsibilities. This fixture is not in default CI.
