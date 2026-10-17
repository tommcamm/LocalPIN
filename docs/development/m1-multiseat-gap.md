# M1 multiple-seat GUI evidence gap: historical assessment

**2026-10-17 closure:** the [subsequent topology lab](m1-vm-topology.md) passed the
actual second-seat case in an independent disposable clone with two emulated
GPUs and independently routed input. Sequential stock-greeter introduction
produced two usable native desktops, and both stock lockers unlocked after one
ordinary password entry each. A separate private-PAM native launcher established
the same-UID two-desktop ambiguity/fallback case. Final clone cleanup and
disposal are complete. Simultaneous cold-boot greeters remain unproved. The
assessment below records what was known on 2026-10-16; its source findings and
unexecuted hypotheses are preserved as historical evidence.

Date: 2026-10-16. Status: read-only feasibility assessment; the actual second-seat
KDE GUI gate remains open. This assessment inspected the guest's installed login
manager identity, sanitized VM hardware inventory and the exact Fedora source
package. No second GPU, second-seat input, login-manager patch or second-seat GUI
test was installed or run. The upstream runtime bug described below has **not**
been reproduced in our VM.

The guest's `display-manager` unit resolves to `plasmalogin.service`, executing
`/usr/bin/plasmalogin` from `plasma-login-manager-6.7.5-1.fc44`. A separate
[metadata registration experiment](m1-vm-sessions.md) passed real logind API and
discovery-filter checks, but created no additional KDE desktop or physical seat.

The current QEMU `pc-q35-10.2` VM has one primary virtio GPU with one head, one
SPICE display backend, a USB tablet and PS/2 keyboard/mouse; it has zero passed
through host devices. That configuration provides one seat's devices. QEMU's
[multiseat guide](https://github.com/qemu/qemu/blob/master/docs/multiseat.txt)
describes a separate emulated GPU, dedicated virtual keyboard/tablet and explicit
input-to-display routing for another seat. It also distinguishes SPICE multihead
display support from its missing multiseat input routing. An extra monitor head
or second SPICE viewer would not supply independent seat input.

The host has QEMU `10.2.2-1.fc44`, libvirt `12.0.0-3.fc44` and virt-viewer
`11.0-18.fc44`. Read-only QEMU help exposes `pci-bridge-seat`, `secondary-vga`,
virtio keyboard/tablet `display` and `head` properties, and installed GTK/SDL
display backends. Local systemd `259.9-1.fc44` udev rules recognize the special
QEMU seat bridge. These are capability observations, not successful guest tests.
A future disposable-VM hardware setup could use separate emulated DRM/KMS GPUs,
dedicated routed virtual input and guest seat assignments, with GTK/SDL or
GPU-bound VNC consoles. No host device passthrough is required by that design.
[Libvirt](https://libvirt.org/formatdomain.html#video-devices) supports a secondary
virtio GPU and virtual input;
[testing-only property overrides](https://libvirt.org/drvqemu.html#overriding-properties-of-qemu-devices)
can express routing properties using stable device aliases. Such a setup is
unimplemented here and would need its own validated VM definition and rollback.

The official Fedora source package inspected was
[`plasma-login-manager-6.7.5-1.fc44.src.rpm`](https://kojipkgs.fedoraproject.org/packages/plasma-login-manager/6.7.5/1.fc44/src/plasma-login-manager-6.7.5-1.fc44.src.rpm),
SHA-256 `8f06c70db1113f015b4ad7273ade5aced172c0e3576266153cd3bf2ca73f6be3`.
Its upstream archive `plasma-login-manager-6.7.5.tar.xz` has SHA-256
`6ed7c3bbac1c79bc1a21c330923804aa6c3f720fafd6accb1a6a1fada684e84f`.
The archive was safely extracted to an ignored local directory using Python's
`tarfile` data filter. All four patches listed by the spec's `%autosetup -p1`
were then applied successfully in order: `170.patch`, `200.patch`,
`plasmalogin-environment_file.patch`, and
`plasmalogin-rpmostree-tmpfiles-hack.patch`. They change VT-switch waiting, Fedora
wallet PAM entries, the system service environment file and a tmpfiles rule;
they do not change the seat/frontend files below. No package was built or
installed. Line references are to this prepared Fedora source tree.

| Prepared source path | Source observation |
|---|---|
| `src/daemon/SeatManager.cpp:125` and `:197` | Listens for logind seats and creates a display when a seat is graphical. |
| `src/daemon/Seat.cpp:150`, `src/daemon/Display.cpp:96` and `:316` | Queries `CanTTY` and guards VT allocation. |
| `src/daemon/Greeter.cpp:101` and `:117` | Passes the seat environment, but runs every greeter under the single `plasmalogin` identity. |
| `src/frontend/startkde/startplasmalogin-wayland.cpp:67` and `:77` | Synchronizes the user-manager environment and starts the fixed `plasma-login-wayland.target`. |
| `src/frontend/startkde/plasma-login-wayland.target:2` | Requires fixed, non-instanced `plasma-login-kwin_wayland.service` and `plasma-login.service` units. |
| `src/frontend/startkde/plasma-login-kwin_wayland.service.in:9` | Uses the fixed `org.kde.KWin` bus name. |

This confirms a source architecture with one shared greeter service set, rather
than one set per seat. The inference is that simply adding a second GPU and
input does not provide dependable simultaneous stock greeters on this package.
[KDE bug 520483, comment 1](https://bugs.kde.org/show_bug.cgi?id=520483#c1)
independently reports reproduction on a different real two-seat machine and
identifies the shared services as the cause. The bug links proposed
[MR 155](https://invent.kde.org/plasma/plasma-login-manager/-/merge_requests/155)
and related [MR 156](https://invent.kde.org/plasma/plasma-login-manager/-/merge_requests/156).
Those patches were not applied or validated here; their current merge status is
not asserted. This source finding is not a runtime failure result from our VM.

M1 will retain the stock guest login manager. A later lab could investigate
sequential seat introduction after the first greeter exits, or a private PAM
launcher for a second real DRM compositor. These are unexecuted hypotheses,
with no GUI or authorization proof. A [separate actual two-desktop test](m1-vm-sessions.md) subsequently passed for
different UIDs on the existing seat. That establishes concurrent real desktops
and own-UID filtering, while leaving actual second-seat behavior and two eligible
real desktops for one UID untested.

The remaining second-seat test requires real independently routed graphics and
input, two actual local KDE desktops, verified logind/seat/greeter mappings and
manual locker interaction on each console. Root-declared metadata, a nested
compositor or a remote desktop is not recorded as a substitute. Fixture cleanup
and whole-VM snapshot restoration remain separate from completing this gate.

## Final cleanup

After these observations, the [clean snapshot was restored and the VM restarted](../../experiments/m1/vm/results/2026-10-16-cleanup.json).
The temporary guest SSH key was explicitly removed before rollback, and the local
temporary key pair was deleted. Per-run pending/false snapshot fields describe
the time of collection; this separate record establishes final cleanup.
Post-restore SELinux mode was not independently queried.
