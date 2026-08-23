# Virtual YubiKey

[![CI](https://github.com/qpernil/virtual-yubikey/actions/workflows/ci.yml/badge.svg)](https://github.com/qpernil/virtual-yubikey/actions/workflows/ci.yml)

`virtual-yubikey` is an unprivileged device worker that makes a Raspberry Pi
enumerate as a composite FIDO HID and CCID, YubiKey-compatible test device.
HID carries FIDO/CTAP; CCID exposes YubiKey Management and PIV. The USB CCID
reader deliberately rejects the FIDO AID.
It is a software test double, not a security device:
keys on a general-purpose Pi do not have the tamper, extraction, or side-channel
protections of a real YubiKey.

Privileged ConfigFS, FunctionFS mount, UDC, and process-lifecycle operations
belong to the separate
[`usb-gadget-supervisor`](https://github.com/qpernil/usb-gadget-supervisor)
project. This repository owns only its independent protocol implementation,
state, worker-owned USB personality, and declarative launch profile.

The current build exposes FIDO HID and USB CCID interfaces. Its logical device lives in
the transport-neutral `virtual-yubikey-core` workspace crate, which implements
YubiKey Management and CTAP 2.1 behavior including PIN authorization,
credential management, resident credentials, and `previewSign`.

## Current behavior

| Layer | Behavior |
| --- | --- |
| USB identity | Full-speed (12 Mbit/s) `1050:0406`, `Virtual USB Gadget`, `Virtual Yubico YubiKey FIDO+CCID`, `bcdDevice` `0x0580`, no USB serial string |
| FIDO HID transport | FIDO Alliance HID report descriptor, 64-byte reports, CTAPHID 2, INIT, PING, CBOR and CANCEL |
| CCID transport | Class `0x0b`, T=1, one inserted Management slot, bulk OUT/IN and interrupt IN |
| Management | AID `A000000527471117`, firmware 5.8.0, serial and CCID capability information |
| PIV | Persistent objects, PIN/PUK and management authentication, and RSA, NIST EC, Ed25519, and X25519 key operations |
| FIDO2 | CTAPHID/CBOR, CTAP 2.1, Client PIN protocols 1/2, a 100-slot discoverable-credential store, credential management, classical and ML-DSA assertions, and `previewSign` |
| Persistent state | Starts empty; credentials, private keys, PIN changes and counters are atomically stored per serial under `/var/lib/virtual-yubikey` |
| Diagnostics | Lifecycle, CCID, SELECT, APDU status, and unsupported-command events in stderr/journal |

The development profile retains Yubico's USB VID/PID solely for controlled,
local compatibility testing while the project owner seeks Yubico's guidance.
The descriptor strings identify the implementation as a virtual USB gadget.
The contiguous `Yubico YubiKey` text in the product string is required
because Yubico's PC/SC discovery uses it to distinguish a USB CCID reader from
an NFC reader. Stock Yubico Authenticator nevertheless derives its visible
model name from the compatibility VID/PID and Management response, so it may
display `YubiKey 5A` rather than the virtual USB descriptor. That UI label does
not identify this implementation as a Yubico product. The VID/PID is not a
project assignment and must not be used for a redistributed, manufactured, or
commercial device without permission from its owner.

Implementation provenance and public sources are recorded in
[`PROVENANCE.md`](PROVENANCE.md). Dependency and trademark notices are in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

## Source layout

| Module | Responsibility |
| --- | --- |
| `../software-key-core` | Sibling path dependency providing protocol-neutral signing, verification, key serialization, RSA encodings, ECDH/X25519 agreement, and ML-DSA controls shared with clients such as `pkcs11rs` |
| `crates/virtual-yubikey-core` | Logical firmware: profile, ISO 7816 routing, and persistent Management, FIDO, and PIV applet state |
| `main.rs` | Worker startup and signal handling |
| `cli.rs` | Worker option validation |
| `diagnostics.rs` | Structured, payload-safe logging |
| `functionfs.rs` | Worker startup, supervisor control handling, and direct FunctionFS FIDO/CCID transports |
| `ctaphid.rs` | CTAPHID channels, packet reassembly, command routing and response fragmentation |
| `ccid.rs` | CCID framing, reader state, and smart-card activation |
| `smartcard.rs` | Diagnostics adapter between CCID and `virtual-yubikey-core` |
| `worker_protocol.rs` | Versioned lifecycle and `SCM_RIGHTS` resource channel shared with the supervisor |
| `usb_identity.rs` | Complete typed USB personality published by the worker as CBOR |
| `profiles/` | Root-installed worker launch and resource boundary |

For a visual explanation of Raspberry Pi USB gadget mode, its direct endpoint
data paths, the supervisor's privilege boundary, and the Virtual YubiKey,
Virtual Trezor, and Virtual YubiHSM profiles, see the
[`USB gadget architecture guide`](docs/usb-gadget-architecture.md), also
available as a [printable PDF](output/pdf/usb-gadget-architecture.pdf).

## Developing virtual firmware

The workspace deliberately separates the logical device from its physical
transport. `virtual-yubikey-core` is the firmware layer: a profile supplies the
firmware version, serial number, capabilities and form factor, while the core
owns installed applets and their state. The worker acts as the endpoint-owning
device firmware. The external supervisor provides the board's privileged USB
controller setup.

New firmware behavior should therefore be developed and tested as APDU vectors
in the core first, then exercised through CCID and finally against real host
applications. USB descriptors and Management capability reports must continue
to derive from the same profile so the device never advertises behavior its
firmware does not implement.

See [`docs/applet-roadmap.md`](docs/applet-roadmap.md) for the planned FIDO,
PIV, YubiHSM Auth, secure-channel/Issuer SD, and OpenPGP work, including the
code-sharing boundary with `pkcs11rs`.
The planned content-addressed persistence and cross-token PKCS #11 key identity
model is recorded separately in
[`docs/future-storage-model.md`](docs/future-storage-model.md); it is not the
active on-disk format yet.

## PIV development status

The logical PIV applet starts empty and persists its state separately from
FIDO. It supports the ordinary `yubico-piv-tool` lifecycle: factory PIN/PUK and
AES-192 management authentication, retry configuration/reset, data and
certificate objects, RSA-1024/2048/3072/4096 and P-256/P-384 key generation,
Ed25519/X25519 key generation, matching algorithm-specific private-key import,
metadata, signing, raw RSA private operations, ECDH/X25519 key agreement, and
key move/delete. PIV state is written atomically as `piv-<serial>.cbor` in the
configured state directory.

The remaining PIV compatibility work is hardware transcript validation,
attestation, and transport integration for touch, cancellation, and simulated
fingerprint policy. Keys configured to require touch or biometric matching
currently fail closed instead of bypassing the policy.

## Credential algorithms

The FIDO applet can create, persist, restore, assert with, and independently
verify credentials using these COSE algorithms:

| Family | Algorithms |
| --- | --- |
| ML-DSA | ML-DSA-44 (`-48`), ML-DSA-65 (`-49`), ML-DSA-87 (`-50`) |
| ECDSA | ES256 (`-7`), ESP256 (`-9`), ESP384 (`-51`), ESP512 (`-52`), ES256K (`-47`) |
| Edwards | Ed25519 (`-19`) |
| RSA-PSS | PS256 (`-37`), PS384 (`-38`), PS512 (`-39`) |
| RSA PKCS #1 v1.5 | RS256 (`-257`), RS384 (`-258`), RS512 (`-259`) |

For post-quantum compatibility testing, the emulator deliberately prefers the
strongest offered ML-DSA parameter set—87, then 65, then 44—before considering
classical algorithms in client order. This is test policy rather than an attempt
to reproduce every authenticator's negotiation policy.

ML-DSA uses the RustCrypto `ml-dsa` implementation in ordinary Raspberry Pi
software. It is suitable for interoperability development, not as evidence of
hardware protection or production side-channel resistance. ML-DSA-87 assertions
are large; the CTAPHID transport tests complete multi-report responses of the
same size without truncation.

## Hardware and operating system

A Pi Zero 2 W is the simplest target. Use its **USB** micro-USB connector, not
`PWR IN`. Pi 4 and Pi 5 use the USB-C power connector for gadget mode. The Pi
3B/3B+ power connector is not wired as a USB device port.

The cable must carry USB 2 data as well as power. Early Pi 4 revision 1.1
boards can reject e-marked USB-C cables; a known data-capable, non-e-marked
cable or USB-A-to-USB-C data cable is a useful fallback.

The deployment is tested on both 64-bit Ubuntu and 64-bit Raspberry Pi OS with
systemd. On both systems, enabling the Raspberry Pi's DWC2 controller in
peripheral mode is the only board-specific gadget prerequisite. The supervisor
then uses the resulting UDC through the kernel's ConfigFS and FunctionFS APIs.

## Install prerequisites

Raspberry Pi OS based on Debian 13 and Ubuntu 24.04 through 26.04 provide
`rustup` through APT. This is the preferred installation on Raspberry Pi
ARM64, Ubuntu ARM64, Ubuntu AMD64, and Ubuntu under WSL2. APT owns the rustup
launcher and proxy commands, while rustup keeps the selected compiler
toolchain in the invoking user's home directory.

```sh
sudo apt update
sudo apt install --yes git build-essential rustup
rustup set profile minimal
rustup toolchain install 1.85.0
rustup default 1.85.0

rustup show active-toolchain
rustc --version
cargo --version
```

Use the exact `1.85.0` toolchain rather than the moving `stable` channel so a
later rustup update cannot silently change the compiler used with the checked-in
`Cargo.lock`. Rustup automatically selects `aarch64-unknown-linux-gnu` on
64-bit Raspberry Pi and ARM Ubuntu, and `x86_64-unknown-linux-gnu` on AMD64
Ubuntu and Ubuntu under WSL2. On a minimal Ubuntu installation, enable the
Ubuntu `universe` repository first if APT cannot find `rustup`.

Machines that only run prebuilt workers need the `rustup` APT package at most;
do not install a Rust toolchain on them. In particular, no APT `rustc`,
`cargo`, LLVM, or Rust standard-library packages are required by this setup.

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

Place this repository beside the supervisor checkout, then build both binaries
from their common parent directory:

```sh
cargo build --release --locked --manifest-path virtual-yubikey/Cargo.toml \
  --bin virtual-yubikey-worker
cargo build --release --locked --manifest-path usb-gadget-supervisor/Cargo.toml
```

The worker is not launched directly. The generic supervisor reads the
root-owned schema-1 launch profile and starts the worker with a private
`SOCK_SEQPACKET` control channel on FD 3. The worker publishes its complete
FIDO HID plus CCID `UsbPersonality` as typed CBOR. The supervisor validates and
logs it, creates the ConfigFS/FunctionFS generation, and transfers the five
actual data-endpoint files with `SCM_RIGHTS`.

The main worker thread owns that control channel and handles USB setup and bus
lifecycle records. A CCID thread blocks directly on CCID OUT and writes CCID
IN. FIDO has a blocking OUT reader so cancellation reports remain observable
while its application thread is processing a command or waiting for touch.
There is no data framing, proxy, acknowledgement, or polling loop between the
worker and FunctionFS. The supervisor never handles CTAP, CCID, APDU, PIN, or
key data.

Profiles can also declare root-opened local character devices and exact GPIO
line groups. The supervisor sends their named handles in the initial
`SCM_RIGHTS` resource record. Future display/GPIO
support will use that mechanism, while every I2C
transaction, framebuffer operation, button debounce, LED animation, and touch
decision remains in this worker rather than the privileged supervisor. The
current profile declares no display resources and continues to run headlessly.

The supervisor creates `/var/lib/virtual-yubikey` for the worker. A serial
`12345678` device stores versioned CBOR state in
`/var/lib/virtual-yubikey/fido-12345678.cbor`. A missing file means a new empty
authenticator; an invalid existing file is a startup error and is never silently
replaced. State replacement is atomic and synchronized before a successful
mutating CTAP response is returned. The file is mode `0600`, but contains
unencrypted test PIN and private-key material and must not be treated as secure
hardware storage.

Persistent authenticator state uses CBOR schema version 2. Unsupported or
invalid state is a startup error and is never silently replaced; resetting to
an empty authenticator is an explicit administrative action.

On worker exit, the still-running supervisor unbinds and removes the old gadget,
then starts a completely fresh worker incarnation with fresh descriptors. A
service stop performs the same cleanup and ends the supervisor. A global
exclusive lock prevents concurrent profiles from owning the Pi UDC. The
profile supplies the worker serial and log level; its direct options are:

```text
--serial DECIMAL       Management serial (default 12345678)
--log-level LEVEL      off, info, debug, or trace
```

Trace logging includes complete protocol payloads and may expose PINs or
cryptographic material as the emulator grows.

FIDO HID `authenticatorSelection`, `authenticatorMakeCredential`, and
`authenticatorGetAssertion` wait for an explicit simulated touch. While waiting,
the worker sends CTAPHID `KEEPALIVE(UP_NEEDED)` reports and accepts a
browser-issued CTAPHID `CANCEL`. Cancellation returns
`CTAP2_ERR_KEEPALIVE_CANCEL` without changing credential state. The worker
exposes a mode-`0600` Unix datagram socket at
`/run/virtual-yubikey/touch.sock` only for the lifetime of that wait.
The separate `virtual-yubikey-touch` tool sends the one-byte user-presence event:

```sh
virtual-yubikey-touch
```

The tool fails when no operation is waiting, so touches cannot be queued for a
later request. Browser or operating-system UI remains responsible for PIN entry
and cancellation; the IPC event represents only the physical touch. The `/run`
directory is volatile and is also removed during clean service shutdown. IPC
payloads start with a one-byte command (`T` is touch); unknown commands are
ignored so future simulated fingerprint commands and their payloads can extend
the protocol without replacing the socket transport.

Every CTAP operation runs against a staged clone of the logical authenticator.
If processing lasts 100 ms, the HID endpoint starts emitting
`KEEPALIVE(PROCESSING)` every 100 ms until it can return the final CBOR response.
An active-channel `CANCEL` receives no response of its own; it makes the original
CBOR request return `CTAP2_ERR_KEEPALIVE_CANCEL`, and the staged state is
discarded. Touch waits subscribe immediately and emit `KEEPALIVE(UP_NEEDED)`
every 100 ms. After touch, the status changes to `PROCESSING` if computation
continues. These status values, response ownership, and cancellation semantics
follow the CTAPHID transport specification.

CCID operations use the separate CCID time-extension mechanism. A PIV APDU runs
on a scoped command thread; if it is still calculating after 500 ms, the CCID
endpoint thread emits `RDR_to_PC_DataBlock` time-extension frames every 500 ms
with the original slot and sequence number until it can send the final response.
One worker-wide clock schedules both transports but never writes a USB endpoint
itself. A transport subscribes only for the lifetime of a pending operation,
with its first deadline measured from that operation's start. HID and CCID keep
independent endpoint-owner threads, framing, cancellation rules, and connection
state.

Transport behavior is checked against the
[FIDO CTAP specification](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html)
and the
[USB CCID specification](https://www.usb.org/sites/default/files/DWG_Smart-Card_CCID_Rev110.pdf).
PIV APDUs follow
[NIST SP 800-73 Part 2](https://csrc.nist.gov/pubs/sp/800/73/pt2/5/final),
with YubiKey-specific extensions matched to the
[Yubico PIV command reference](https://docs.yubico.com/yesdk/users-manual/application-piv/commands.html).

## Install as a service

Install the generic supervisor once as described in its README, then build this
repository in place. Set the profile's `command` and `run_as` fields to the
worker's installed path and its dedicated unprivileged service account.

```sh
cargo build --release --locked
sudo install -o root -g root -m 0644 \
  profiles/virtual-yubikey.toml \
  /opt/usb-gadget-supervisor/profiles/virtual-yubikey.toml
sudo systemctl enable --now \
  usb-gadget-supervisor@virtual-yubikey.service
```

That is the entire device-specific installation: one small profile containing
the worker launch and resource boundary. The worker owns its USB personality;
the worker and touch helper run directly from `target/release`. A normal update
is `git pull`, rebuild, and restart; reinstall the profile only when it changes.

The supervisor rejects a profile that is not a regular root-owned file. It
accepts a worker owned by root or its configured unprivileged user, but rejects
set-ID, world-writable, or unrelated-group-writable executables. Verify the
service and physical link with:

```sh
systemctl --no-pager --full status \
  usb-gadget-supervisor@virtual-yubikey.service
cat /sys/class/udc/fe980000.usb/state
```

With a data-capable host connection, the UDC state should be `configured`.

To run the installation manually, first stop the service and invoke the
supervisor with the installed profile:

```sh
sudo systemctl stop usb-gadget-supervisor@virtual-yubikey.service
sudo /opt/usb-gadget-supervisor/usb-gadget-supervisor \
  --profile /opt/usb-gadget-supervisor/profiles/virtual-yubikey.toml
```

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) before proposing changes. Report
security-sensitive findings according to [SECURITY.md](SECURITY.md), not in a
public issue.

## Independence and trademarks

This is an independent compatibility project. It is not affiliated with,
sponsored by, or endorsed by Yubico. Yubico and YubiKey are registered
trademarks of Yubico AB. Their names are used descriptively to identify the
protocols and products with which this test implementation interoperates.

## License

This project is licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License 2.0](LICENSE-APACHE), at your option.
