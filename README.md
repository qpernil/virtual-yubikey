# Virtual YubiKey

`virtual-yubikey` makes a Raspberry Pi enumerate as a composite FIDO HID and
CCID YubiKey for compatibility testing. HID carries FIDO/CTAP; CCID exposes
YubiKey Management. The USB CCID reader deliberately rejects the FIDO AID.
It is a software test double, not a security device:
keys on a general-purpose Pi do not have the tamper, extraction, or side-channel
protections of a real YubiKey.

The current build exposes FIDO HID and USB CCID interfaces. Its logical device lives in
the transport-neutral `virtual-yubikey-core` workspace crate, which implements
YubiKey Management and CTAP 2.1 behavior including PIN authorization,
credential management, resident credentials, and `previewSign`.

## Current behavior

| Layer | Behavior |
| --- | --- |
| USB identity | Full-speed (12 Mbit/s) `1050:0406`, `Yubico`, `YubiKey FIDO+CCID`, `bcdDevice` `0x0580`, no USB serial string |
| FIDO HID transport | FIDO Alliance HID report descriptor, 64-byte reports, CTAPHID 2, INIT, PING, CBOR and CANCEL |
| CCID transport | Class `0x0b`, T=1, one inserted Management slot, bulk OUT/IN and interrupt IN |
| Management | AID `A000000527471117`, firmware 5.8.0, serial and CCID capability information |
| FIDO2 | CTAPHID/CBOR, CTAP 2.1, Client PIN protocols 1/2, a 100-slot discoverable-credential store, credential management, assertions and `previewSign` |
| Persistent state | Starts empty; credentials, private keys, PIN changes and counters are atomically stored per serial under `/var/lib/virtual-yubikey` |
| Diagnostics | Lifecycle, CCID, SELECT, APDU status, and unsupported-command events in stderr/journal |

The program uses Yubico's USB VID/PID solely for controlled compatibility
testing. Do not distribute a product that presents itself as genuine Yubico
hardware.

## Source layout

| Module | Responsibility |
| --- | --- |
| `crates/virtual-yubikey-core` | Logical firmware: profile, ISO 7816 routing, Management and FIDO applet state |
| `main.rs` | Process orchestration and signal handling |
| `cli.rs` | Command-line validation |
| `diagnostics.rs` | Structured, payload-safe logging |
| `gadget.rs` | Privileged ConfigFS lifecycle and worker supervision |
| `functionfs.rs` | Unprivileged FunctionFS transport and CCID USB descriptors |
| `ctaphid.rs` | CTAPHID channels, packet reassembly, command routing and response fragmentation |
| `ccid.rs` | CCID framing, reader state, and smart-card activation |
| `smartcard.rs` | Diagnostics adapter between CCID and `virtual-yubikey-core` |

## Developing virtual firmware

The workspace deliberately separates the logical device from its physical
transport. `virtual-yubikey-core` is the firmware layer: a profile supplies the
firmware version, serial number, capabilities and form factor, while the core
owns installed applets and their state. The outer binary acts as the board and
USB controller by providing ConfigFS, FunctionFS and CCID.

New firmware behavior should therefore be developed and tested as APDU vectors
in the core first, then exercised through CCID and finally against real host
applications. USB descriptors and Management capability reports must continue
to derive from the same profile so the device never advertises behavior its
firmware does not implement.

See [`docs/applet-roadmap.md`](docs/applet-roadmap.md) for the planned FIDO,
PIV, YubiHSM Auth, secure-channel/Issuer SD, and OpenPGP work, including the
code-sharing boundary with `pkcs11rs`.

## Hardware and operating system

A Pi Zero 2 W is the simplest target. Use its **USB** micro-USB connector, not
`PWR IN`. Pi 4 and Pi 5 use the USB-C power connector for gadget mode. The Pi
3B/3B+ power connector is not wired as a USB device port.

The cable must carry USB 2 data as well as power. Early Pi 4 revision 1.1
boards can reject e-marked USB-C cables; a known data-capable, non-e-marked
cable or USB-A-to-USB-C data cable is a useful fallback.

The tested deployment uses 64-bit Raspberry Pi OS with systemd. Ubuntu for
Raspberry Pi also works when its kernel provides DWC2, ConfigFS, and FunctionFS.

## Install prerequisites

```sh
sudo apt update
sudo apt install --yes git curl build-essential
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
. "$HOME/.cargo/env"
```

Enable the device controller in `/boot/firmware/config.txt` on current images,
or `/boot/config.txt` on older images. Add this under `[all]`:

```ini
dtoverlay=dwc2,dr_mode=peripheral
```

Do not load a legacy single-function gadget such as `g_ether` or
`g_mass_storage`. Reboot and verify that the kernel exposes a controller:

```sh
sudo reboot
ls /sys/class/udc
```

A Pi 4 normally reports `fe980000.usb`.

## Build and run

```sh
cd /home/per
git clone https://github.com/qpernil/virtual-yubikey.git
cd virtual-yubikey
cargo build --release --locked --bin virtual-yubikey
sudo ./target/release/virtual-yubikey --run-as per
```

The process starts as a small root supervisor because ConfigFS gadget creation,
mounting FunctionFS, creating the HID gadget, and binding the UDC require root.
It launches a fresh copy as the selected unprivileged account, waits for that
worker to publish the FunctionFS descriptors, then binds the gadget. Once
`/dev/hidg0` appears, the supervisor assigns that node to the worker account and
signals the worker to open it. The worker handles all host-controlled USB
protocol data without regaining privileges. There is no standard Pi group
equivalent to `dialout` for gadget administration.

The supervisor creates `/var/lib/virtual-yubikey` for the worker. A serial
`12345678` device stores versioned CBOR state in
`/var/lib/virtual-yubikey/fido-12345678.cbor`. A missing file means a new empty
authenticator; an invalid existing file is a startup error and is never silently
replaced. State replacement is atomic and synchronized before a successful
mutating CTAP response is returned. The file is mode `0600`, but contains
unencrypted test PIN and private-key material and must not be treated as secure
hardware storage.

Ctrl-C unbinds and removes the gadget. An exclusive lock prevents concurrent
instances, and a later start recovers stale state left by a crash. Options:

```text
--serial DECIMAL       Management serial (default 12345678)
--udc NAME             select a controller instead of the first available one
--run-as USER          unprivileged protocol worker account
--log-level LEVEL      off, info, debug, or trace
```

Trace logging includes complete protocol payloads and may expose PINs or
cryptographic material as the emulator grows.

All currently implemented CTAP operations complete synchronously. Before a
future operation waits for user presence or other slow work, its execution must
move off the transport loop: FIDO HID must emit CTAPHID KEEPALIVE and accept
CANCEL, while CCID must emit command time-extension responses. HID and CCID
already have independent transport threads and separate connection state.

## Install as a service

After a manual test succeeds:

```sh
cd /home/per/virtual-yubikey
sudo install -o root -g root -m 0755 \
  target/release/virtual-yubikey /usr/local/sbin/virtual-yubikey
sudo install -o root -g root -m 0644 \
  systemd/virtual-yubikey.service /etc/systemd/system/virtual-yubikey.service
sudo systemctl daemon-reload
sudo systemctl enable --now virtual-yubikey.service
```

The supplied unit uses `--run-as per`; edit that argument if the Pi uses a
different unprivileged account. Verify the service and physical link with:

```sh
systemctl --no-pager --full status virtual-yubikey.service
cat /sys/class/udc/fe980000.usb/state
```

With a data-capable host connection, the UDC state should be `configured`.
