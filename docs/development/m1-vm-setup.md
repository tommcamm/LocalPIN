# M1 disposable Fedora KDE VM

M1's enforcing-SELinux and real KDE tests use a disposable graphical VM. The
maintainer supplied one on 2026-10-16; collected results are linked from the
[M1 evidence report](m1-feasibility.md). This runbook remains the setup procedure
for reproducing those tests. The development host's disabled SELinux cannot
substitute for enforcing guest evidence.

## What the maintainer needs to do

1. Download the **Fedora KDE Plasma Desktop 44 Live ISO for x86_64** from the
   [official download page](https://fedoraproject.org/kde/download/). Follow its
   signature/checksum verification instructions. Use the regular KDE edition.
2. Open **Virtual Machine Manager** (already installed on the development host).
   Create a VM from the ISO: suggested name `localpin-m1`, 2 virtual CPUs,
   4096 MiB RAM, and a new 30 GiB qcow2 disk. These are test resource suggestions.
   Use a normal virtual display/keyboard and NAT or user networking. If the
   QEMU/KVM connection fails, provide the exact error before changing the host's
   virtualization configuration.
3. Install Fedora onto that new virtual disk. Create an administrator account
   for VM maintenance and a separate ordinary account named `localpintest` for
   lock-screen tests. Use disposable passwords entered interactively. Keep the
   host's passwords, PAM configuration and TPM separate from the VM.
4. In the VM, install updates and the experiment tools:

   ```sh
   sudo dnf upgrade --refresh
   sudo dnf install git gcc python3 pam-devel bubblewrap swtpm tpm2-tools libargon2 \
     policycoreutils-python-utils selinux-policy-devel setools-console
   sudo reboot
   ```

5. Check `getenforce` inside the VM: it must print `Enforcing`. Verify that
   `localpintest` can log in to KDE, lock the screen and unlock with its password.
   Keep the VM console accessible. Shut down and take a snapshot named
   `m1-clean-enforcing`, then start the VM again.
6. Tell the implementing chat **“VM ready”** with the VM's name and whether it is
   reachable only through its console or also over SSH. Do not send a password.
   We can work through the console; remote access is optional. Obtain the current
   `codex/m1-feasibility` branch through a local source copy or, once published,
   Git. The commands below require the actual implementation, not an older main.

No hardware TPM passthrough or shared host home directory is required. The TPM
experiments start their own `swtpm`; they do not use a virtual machine's default
TPM device. A container cannot replace these graphical, logind and enforcing
SELinux tests.

The [Fedora virtualization overview](https://developer.fedoraproject.org/tools/virtualization/installing-libvirt-and-virt-install-on-fedora-linux.html)
provides background on libvirt and virt-install. Use the existing manager first;
this runbook does not require changing host services or installing a new stack.

## First commands once the source is in the VM

From the LocalPIN repository, as an ordinary user:

```sh
mkdir -p .local/m1
python3 experiments/m1/platform/inventory.py --help
python3 -m unittest discover -s experiments/m1/platform -p 'test_*.py' -v
experiments/m1/pam/run.sh
LOCALPIN_PAM_UNIX=1 experiments/m1/pam/run.sh
python3 experiments/m1/worker/test_supervisor.py
python3 experiments/m1/tpm/run.py
```

Read the platform collector's help before saving an inventory. Keep raw output
under `.local/`; review and sanitize it before committing or sharing. A failed
known PAM baseline is infrastructure failure, not evidence that fallback failed.
The optional `LOCALPIN_PAM_UNIX=1` run uses bubblewrap and namespace-private
synthetic account files, never the VM's real account database. Namespace
unavailability is a separate infrastructure failure. These commands do not
install a PAM adapter in KDE or implement enrollment.

## VM evidence checklist

Record package versions, PAM graph/digests, authselect features and the source
RPM digest for the VM's actual build before changing an experimental service.

| Experiment | Required evidence |
| --- | --- |
| Packaged KDE authentication | Actual PAM service and include/substack graph; calls made by the installed build; repeated authentication on one handle |
| Real password fallback | Normal and six-digit **VM account** passwords, candidate byte handling, wrong candidate followed by password, unavailable PIN route; exactly one candidate prompt where promised |
| Account policy | Locked/expired/password-expired VM account, required checks before PIN success, existing faillock counters and fifth-attempt boundary under each supported authselect profile |
| Sessions | Locker in user manager, no eligible session, remote/TTY session, two graphical sessions/seats, ambiguous same-UID session resolution |
| SELinux and sandbox | Broker socket contact by the real locker domain, privileged password/account worker with actual PAM helpers, expected DAC/SELinux denials, private state and no direct TPM access by locker |
| Native deadline | Stopped TPM transport, bounded process cleanup, late result discarded, reserved attempt retained and unrelated UID responsive |
| Recovery | Password unlock and VM console recovery after each failure; restore the snapshot between destructive account/policy cases |

Keep the clean snapshot and an administrator console available while testing.
The synthetic modules in `experiments/m1/pam` must never be installed into a
system PAM service. The separate guarded [VM KDE adapter](../../experiments/m1/vm/kde/README.md)
is fallback-only and may be installed only in the disposable guest using its
reviewed backup/restore manager. Real-account and SELinux fixtures likewise
require their explicit guards and snapshot confirmation. This checklist defines
coverage; consult the evidence report for each collected result and remaining
gap. Restore the whole snapshot after exporting sanitized reports, including
removal of temporary remote-access keys.
