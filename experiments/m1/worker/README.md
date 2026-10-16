# Native worker deadline experiment

Run `python3 experiments/m1/worker/test_supervisor.py` from the repository root.
Only Python and the host C library are needed. Every record and process is
disposable; there are no PAM, TPM device, password, or system-service accesses.

This demonstrates process isolation around a blocking native `pause()` / `sleep()`
call, a result deadline, SIGKILL and reaping before slot reuse, a per-UID limit,
a shared two-worker bound, and responsiveness of another UID. It also checks
that a reservation write failure starts no worker and a killed worker's
synthetic reservation survives. Markers use synthetic UIDs and are never
interpreted as production throttle state. No success record is implemented.

An async timeout around a native call running in a thread cannot provide this
kill boundary. M5 must implement a bounded subprocess pool, descriptor limits,
minimal privileges, generation/result fencing and cancellation. M3 owns durable
attempt and success commits. Neither is implemented by this experiment.

The 300 ms test deadline is a scheduling experiment, not a measured production
TPM deadline. An uninterruptible kernel task may not reap promptly even after
SIGKILL; retain its occupied slot and fall back without unbounded replacement
workers. Production cleanup must be asynchronous so waiting for such a child
does not block the PAM response or an unrelated UID. This minimal supervisor's
final blocking reap does not solve that kernel case. A stopped TPM transport
test and real systemd sandbox validation are separate evidence requirements.
