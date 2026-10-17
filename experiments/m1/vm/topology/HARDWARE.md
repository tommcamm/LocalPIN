# Reproducing the isolated two-seat hardware and input routes

These helpers prepare XML and perform one fixed public-input check. They do not
clone, define, start, modify or stop any VM. They do not prove two KDE desktops,
password authentication, or completion of M1. Actual topology acceptance remains
in [README.md](README.md); the separate native session launcher is documented in
[README-launcher.md](README-launcher.md).

Use an independently copied disposable clone, with its own UUID, image and
restorable snapshot. Keep the original off throughout offline copying. Verify
the original identity, inactive XML, image backing chain and off state before
copying; these read-only preparation scripts cannot establish those conditions.
Do not attach the original image, a hard link to it, or a live source image as the
clone's writable disk. Do not customize a live disk. No host GPU/input passthrough
or everyday host display configuration is required.

## Private preparation inputs

Export the original inactive domain XML into a private lab directory. Keep that
XML, the configuration, generated manifest, native argv and raw observations out
of Git: they contain machine identifiers and image/network paths. The JSON must
be owned by the invoking operator, regular, single-link and mode 0600; the existing
output directory must be owned by that operator and mode 0700. A root operator
uses root-owned private files. For example, create and fill this configuration
privately, replacing every placeholder before invoking the generator:

```json
{
  "source_name": "SOURCE_DOMAIN_NAME",
  "source_uuid": "SOURCE_UUID",
  "clone_name": "NEW_CLONE_DOMAIN_NAME",
  "clone_uuid": "FRESH_CLONE_UUID",
  "clone_disk": "/absolute/new/independent-clone.qcow2",
  "memory_mib": 8192,
  "vcpus": 4
}
```

UUIDs must be canonical and the source/clone names and UUIDs must differ. The
bounded resource range is 1–8 vCPUs and 1–16 GiB RAM; select values the host can
support. This fixture requires an x86_64 q35 source with one file-backed disk,
one virtio GPU and three unused existing PCIe root ports. It refuses NVRAM,
hostdev/filesystem/TPM/shared-memory state, existing QEMU extensions, and a clone
disk pathname equal to the source's normalized pathname. Physical image
independence still needs the operator's checks; the helper never opens images.
It also refuses inherited disk sidecars/shared state, explicit channel sockets,
character-device logs and serial/console file or device endpoints. The only
retained character backends are libvirt-allocated QGA Unix and PTY serial/console
devices with no explicit source path. XML, native argv and private configuration
must be bounded regular files; nonblocking opens make FIFO rejection immediate.

```sh
python3 experiments/m1/vm/topology/prepare-hardware.py --prepare \
  --original PRIVATE_SOURCE_XML --config PRIVATE_CONFIG_JSON --out PRIVATE_OUTPUT_DIR
```

The helper writes new files only and refuses overwrites. `clone-two-seat.xml` is
the complete proposal; `clone-primary-only.xml` offers an alternative setup boot
for the same clone identity/disk. Never define both as separate domains.
`manifest.json` records generated private identifiers, paths, controller indexes
and fixed VNC ports. New NIC MACs and generation IDs are created locally. The
helper also writes hidden/active udev rules and two clone-bound guard proposals:

| Private output | Exact guest destination | Guest owner/mode |
| --- | --- | --- |
| `vm.guard` | `/etc/localpin-m1-vm-guard` | `root:root`, `0600` |
| `topology.guard` | `/etc/localpin-m1-topology-clone-guard` | `root:root`, `0600` |
| hidden udev rule | `/etc/udev/rules.d/72-localpin-m1-topology.rules` | `root:root`, `0644` |

Install these only into the verified offline clone, using the host's reviewed
image tooling. Apply normal SELinux labels. Both guard files must match the
clone's actual DMI UUID and fixed target `localpintest`. The general guard begins
`LOCALPIN-M1-DISPOSABLE-VM`; the clone guard begins
`LOCALPIN-M1-TOPOLOGY-CLONE`. Each then has exact `target=localpintest` and
`uuid=...` lines, including a final newline. Provision any temporary access
separately. Keep SELinux Enforcing and retain a recovery route. Creating these
files on an everyday host is not an allowed way to run the guest fixture.

## Review the generated hardware before boot

The proposal preserves the primary GPU, adds a second virtio GPU and distinct
virtio keyboard/tablet devices, and disables the PS/2 controller. The second
GPU/input devices sit behind QEMU's emulated `pci-bridge-seat`, reached through a
PCIe-to-PCI bridge. A scoped udev rule assigns only that bridge's descendants to
seat1. The hidden version removes its DRM `master-of-seat` tag; the active version
adds it. Install only one rule under the exact guest basename above.

The two VNC servers bind only loopback ports 5998/5999 and name different GPU
consoles explicitly. SPICE, its channels/audio/redirection, and old input devices
are removed. There is no host input or graphics passthrough. The raw VNC endpoints
have no authentication: keep their lifetime bounded, verify their listeners and
owning clone process, close other viewers during the probe, and remove both
listeners during recovery. A second viewer/head alone is never a second seat.

After independently creating the off clone's new flattened image, the operator
validates the generated XML against the installed libvirt schema and obtains
native argv with `virsh -c qemu:///system domxml-to-native qemu-argv XML`, saving
that output privately. Then run:

```sh
python3 experiments/m1/vm/topology/prepare-hardware.py --validate-native PRIVATE_NATIVE_ARGV
```

This checks loopback endpoints, bridge model, four display/head input bindings,
secondary bridge membership, absence of SPICE and disabled PS/2. It also requires
each GPU to be created before its routed input devices. Libvirt normally emits
XML input devices before video; QEMU's HID realization path can discard the
failed early console lookup. The generator therefore appends these inputs as
trailing raw `-device` arguments after libvirt's GPU devices. Matching configured
strings or an argv check alone cannot prove realized input delivery.

Start only the fresh clone paused first. Inspect QMP `query-vnc-servers` and the
device tree: two loopback listeners, distinct expected display aliases, intended
bridge/GPU/input models and no host devices. Preserve exact libvirt/QEMU versions
and the private actual argv. Resume only the clone after those checks pass. None
of this establishes desktop or authentication behavior.

## Bounded public input routing check

Run this phase with no human typing or password entry and no other VNC viewers.
Review the private endpoint/clone association first: the fixed host sender cannot
authenticate a server's identity. Do not run it against unknown listeners.

1. Copy `count-public-input.py` into the clone and invoke it as guest root. It
   requires both exact root-owned 0600 guards, their actual DMI UUID, a VM and Enforcing
   before discovering/opening input devices. It finds exactly four QEMU virtio
   keyboard/tablet event devices, verifies device numbers, and distinguishes the
   special seat bridge's descendants. It opens devices read-only, takes no input
   grab, and prints `READY` when its fixed 20 s observation window starts.
2. While that counter is ready, the host operator runs
   `python3 experiments/m1/vm/topology/probe-vnc.py` with no options. It connects
   only to `127.0.0.1:5998` and `127.0.0.1:5999`, sends F11/F12 respectively and
   two button-free pointer positions within each console's low/high coordinate
   bin. RFB3.8 negotiation uses Raw-only SetEncodings, which initializes QEMU's
   absolute-pointer path. A 50 ms key hold and 500 ms post-input connection hold stay
   within each endpoint's 4 s deadline. The second coordinate makes reruns produce
   changed absolute values. It requests no framebuffer and no clipboard data.
3. Require a single guest counter result with all four positive/cross-negative
   checks true: F11 only on the primary keyboard, F12 only on the secondary,
   low coordinates only on the primary tablet, high only on the secondary. The
   sender's successful write never proves delivery. Queue overflow fails the
   counter. Retain failed attempts honestly; do not infer a GUI pass from them.
4. Confirm the counter has exited and all event FDs are closed **before** any
   human login, password entry, or viewer interaction. The counter reads and
   discards other events during its window; it is not a promise that nonpublic
   input was never read. Export only its fixed bins/counters, never raw events.

The fixed F11/F12 keys use the installed standard QEMU keymap. F13/F14 standard
RFB keysyms were unmapped in the observed default keymap; sending them did not
produce guest key events. Repeated unchanged absolute coordinates also produce
no new evdev values. The checked-in sender avoids both exploratory pitfalls.

## Staged seat introduction and recovery

Verify initial guest inventory: seat0 exists, seat1 does not, both DRM/input
subtrees have intended assignments, and seat0's console has the stock greeter.
Manually log the target into a real first KDE desktop. Wait for the previous
Plasma Login Manager greeter session and all its kwin/frontend/launcher processes
to exit before introducing seat1: current stock greeters share a UID and user
service names, so simultaneous launch is a separate unproven case.

The reviewed root operator may replace only the owned hidden rule with its
generated active counterpart, restore its default label, reload udev rules and
trigger a change only for the verified secondary DRM card. Record the first
desktop's active session/VT before and after. Abort if that baseline changes or
seat1 fails to become `CanGraphical=yes`, `CanTTY=no` within a bounded wait.
Do not activate a VT, call TakeControl/TakeDevice, restart the login manager, or
change PAM to make this infrastructure check pass. A graphical seat record still
requires an actual independent desktop and each manual locker test.

On failure retain evidence and recover the clone. Stop/destroy and undefine only
its verified UUID; remove only its independent new image after confirming no
domain references it. Never delete backing/source images or use wildcard storage
deletion. Require both VNC listeners and all owned fixture resources gone; remove
temporary access and restore/discard the clone. Keep separate per-run and final
recovery records, and verify the original remains unchanged/off.

## Sources and local checks

The construction follows [QEMU's multiseat documentation](https://github.com/qemu/qemu/blob/v10.2.0/docs/multiseat.txt),
the [VNC console/input implementation](https://github.com/qemu/qemu/blob/v10.2.0/ui/vnc.c),
the [input binding implementation](https://github.com/qemu/qemu/blob/v10.2.0/ui/input.c),
the [virtio HID realization path](https://github.com/qemu/qemu/blob/v10.2.0/hw/input/virtio-input-hid.c),
and [libvirt's QEMU override contract](https://libvirt.org/drvqemu.html#overriding-properties-of-qemu-devices).
Keep versioned source findings separate from actual runtime observations.

`python3 -m unittest discover -s experiments/m1/vm/topology -p test_hardware.py -v`
uses synthetic XML/private files and fake RFB sockets. It starts no VM, opens no
event device, sends no real input and connects to no endpoint. The generated
schema/native checks and actual guest input counter remain separate validations.
