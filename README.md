# Virtual YubiKey

[![CI](https://github.com/qpernil/virtual-yubikey/actions/workflows/ci.yml/badge.svg)](https://github.com/qpernil/virtual-yubikey/actions/workflows/ci.yml)

`virtual-yubikey` is an unprivileged device worker that makes a Raspberry Pi
enumerate as a composite FIDO HID and CCID, YubiKey-compatible test device.
HID carries FIDO/CTAP; CCID exposes YubiKey Management, PIV, and YubiHSM Auth.
The USB CCID reader deliberately rejects the FIDO AID.
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
YubiKey Management, PIV, YubiHSM Auth, and CTAP 2.1 behavior including PIN
authorization, credential management, resident credentials, and `previewSign`.

## Current behavior

| Layer | Behavior |
| --- | --- |
| USB identity | Full-speed (12 Mbit/s) `1050:0406`, `Virtual USB Gadget`, `Virtual Yubico YubiKey FIDO+CCID`, `bcdDevice` `0x0580`, no USB serial string |
| FIDO HID transport | FIDO Alliance HID report descriptor, 64-byte reports, CTAPHID 2, INIT, PING, CBOR and CANCEL |
| CCID transport | Class `0x0b`, T=1, one inserted Management slot, bulk OUT/IN and interrupt IN |
| Management | AID `A000000527471117`, firmware 5.8.0, serial and CCID capability information |
| PIV | Persistent objects, PIN/PUK and management authentication, and RSA, NIST EC, Ed25519, and X25519 key operations |
| YubiHSM Auth | Persistent symmetric and P-256 credentials, management and credential retry counters, touch policy, SCP03 session-key derivation, and asymmetric SCP11 authentication |
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
| `../software-key-core` | Sibling path dependency providing protocol-neutral key ownership, signing, verification, key serialization, symmetric helpers, RSA encodings, ECDH/X25519 agreement, ML-DSA controls, and ARKG-P256 derivation shared with clients such as `pkcs11rs` |
| `crates/virtual-yubikey-core` | Logical firmware: profile, ISO 7816 routing, and persistent Management, FIDO, PIV, and YubiHSM Auth applet state |
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

The logical core separates key identity from cryptographic operations:
`KeyKind` is used only at generation/import/restore boundaries, while
`SignatureScheme` is selected when an applet signs or verifies. PIV, FIDO, and
YubiHSM Auth retain parsed private keys in memory, so seed expansion and key
validation are not repeated for every APDU. PIV stores signing and X25519 keys
through the shared `SoftwarePrivateKey` union; applet algorithms and policy stay
in the PIV object. Existing applet-specific CBOR records remain persistence DTOs
rather than runtime key objects.

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

The logical PIV applet starts empty and persists separately from FIDO and
YubiHSM Auth. It supports the ordinary `yubico-piv-tool` lifecycle: factory PIN/PUK and
AES-192 management authentication, retry configuration/reset, data and
certificate objects, RSA-1024/2048/3072/4096 and P-256/P-384 key generation,
Ed25519/X25519 key generation, matching algorithm-specific private-key import,
metadata, signing, raw RSA private operations, ECDH/X25519 key agreement, and
key move/delete. PIV state is atomically replaced as `piv-<serial>.cbor` in the
configured state directory.

The remaining PIV compatibility work is hardware transcript validation,
attestation, CCID cancellation, and simulated fingerprint policy.

## YubiHSM Auth development status

The YubiHSM Auth applet implements the firmware 5.8 command set used by
`ykman` and `pkcs11rs`: version and retry discovery, credential listing,
symmetric and P-256 credential creation/import, public-key and challenge
retrieval, session-key calculation, deletion, password and management-key
changes, and factory reset. Management authorization is the submitted 16-byte
management key; credentials retain their own padded 16-byte password and
eight-attempt retry counter.

Symmetric credentials derive SCP03 ENC, MAC, and RMAC session keys. Asymmetric
credentials perform the ephemeral and static P-256 agreements, X9.63 SHA-256
derivation, and receipt validation required by YubiHSM asymmetric
authentication. A touch-required credential requests a fresh physical touch on
every session-key calculation. The wait expires after 15 seconds without a
touch, while CCID time-extension frames keep the host transaction alive. ISO
command chaining and `61xx`/`GET RESPONSE`
response chaining are handled once in the shared APDU router rather than by the
applet. Its state is independently scheduled and atomically replaced as
`hsmauth-<serial>.cbor`.

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

Credential creation follows the client's preference order and selects its first
supported algorithm, as required by CTAP/WebAuthn. Post-quantum compatibility
tests can request ML-DSA first or offer it alone; ordinary clients that prefer
ES256 therefore receive ES256 credentials.

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

Place this repository beside the supervisor and `display-backends` checkouts,
then build both binaries from their common parent directory:

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
Each endpoint helper waits for the supervisor's first `Enable` activation. If
FunctionFS cancels an operation on disable or unbind, the helper parks until a
strictly newer activation or quiescence instead of retrying a disabled
endpoint. This keeps shutdown joins deterministic without placing the
supervisor in the data path.
There is no data framing, proxy, acknowledgement, or polling loop between the
worker and FunctionFS. The supervisor never handles CTAP, CCID, APDU, PIN, or
key data.

The color profile declares the ST7789 SPI device and its exact data/command,
reset, and backlight GPIO lines. The OLED profile declares the same SPI device
with the data/command and reset lines required by the 128x64 SH1106. Both
profiles declare joystick-center GPIO13 for touch and KEY3 GPIO16 for USB
reconnect as separate active-low inputs with both-edge events. The
supervisor opens those capabilities as root and sends their named handles in
the initial `SCM_RIGHTS` resource record.
The worker selects already-native frames from the profile's `--display` value:
the original vertical 240x240 RGB565 YubiKey image for `st7789-spi`, or the
complete horizontal 128x64 one-bit dithered image for `sh1106-spi`. No image
conversion occurs on the Pi.

The common `display_backends::indicator` scheduler drives a worker-supplied
renderer through one logical LED bit. The YubiKey renderer maps that bit to the
appropriate pair of complete color or monochrome frames; panel selection,
artwork, logging, and display power remain worker concerns. Each CCID command
increments a monotonic activity epoch and marks the single command slot active.
The epoch makes a command that starts and finishes during a synchronous frame
write visible. If more short commands arrive while a pulse is already visible,
the scheduler retains one additional pulse; further commands coalesce rather
than building a delayed replay queue.

Command start produces an edge at least 8 ms after the previous edge began.
Renderer time is part of that interval rather than an added delay, so a slower
display naturally becomes the rate limit. While the command remains active, the
LED follows the measured 100 ms busy cadence: 67 ms on and 33 ms off. When the
command finishes, the YubiKey returns to off as soon as the edge interval
permits. The worker does not fabricate a USB-insertion flash: normal immediate
CCID probing is ordinary application activity.

While any application is blocked waiting for physical presence, the same
cut-outs blink until touch, cancellation, or failure ends the wait. Every
application uses the measured YubiKey 5 NFC cadence: a 384 ms half-period, or
approximately 1.30 blinks per second. FIDO, PIV, and YubiHSM Auth use one
protocol-neutral presence service; OpenPGP can join it when that applet is
implemented. General FIDO HID report traffic does not drive the activity
indication. USB suspend and worker shutdown clear the panel and turn off its
backlight. Holding KEY3 turns the display off and
publishes an empty personality, leaving the worker powered but absent from USB.
Releasing KEY3 republishes the complete personality immediately, and the same
worker restores the idle image when the new generation is bound. To the host
and observer this is a spring-loaded eject and insertion without a process
restart or an added reconnect delay.
Reconnect notifications are coalesced wakes around the sampled current KEY3
level, not a replay of edge history. Holding KEY3 at worker startup therefore
keeps USB absent, and a dropped wake cannot leave the device detached after
the physical button has been released.
Display traffic never blocks a USB endpoint thread.

The supervisor creates `/var/lib/virtual-yubikey` for the worker. A serial
`12345678` device stores versioned CBOR state in
`/var/lib/virtual-yubikey/fido-12345678.cbor` and
`/var/lib/virtual-yubikey/piv-12345678.cbor`, and
`/var/lib/virtual-yubikey/hsmauth-12345678.cbor`. Before reading or creating any
image, the worker exclusively locks
`/var/lib/virtual-yubikey/yubikey-12345678.lock`; one device-level lock covers
all applets and remains held through their final persistence flush. The
sidecar remains present when unlocked, while a concurrent owner is a startup
error. Missing state files are initialized from factory state before USB is
served; invalid existing files are startup errors and are never silently
replaced. All three state images use the shared supervisor-worker persistence engine. By
default it batches changes for up to 500 ms, atomically replaces mode-`0600`
files, and flushes pending state on USB ejection and worker shutdown.
`--persistence immediate` instead synchronizes each durable change before its
successful response is written. The files contain unencrypted test PIN and
private-key material and must not be treated as secure hardware storage.

Persistent authenticator state uses CBOR schema version 2. Unsupported or
invalid state is a startup error and is never silently replaced; resetting to
an empty authenticator is an explicit administrative action.

On worker exit, the still-running supervisor unbinds and removes the old gadget,
then starts a completely fresh worker incarnation with fresh descriptors. A
service stop performs the same cleanup and ends the supervisor. A global
exclusive lock prevents concurrent profiles from owning the Pi UDC. The
supervisor keeps every replacement detached for at least 250 ms before rebind;
initial service attachment has no artificial delay. The
profile supplies the worker serial and log level; its direct options are:

```text
--serial DECIMAL       Management serial (default 12345678)
--log-level LEVEL      off, info, debug, or trace
--display BACKEND      st7789-spi (default), sh1106-spi, or sh1106-i2c
--persistence MODE     batched (default, 500 ms) or immediate
```

Trace logging includes complete protocol payloads and may expose PINs or
cryptographic material as the emulator grows.

FIDO HID `authenticatorSelection`, `authenticatorMakeCredential`, and
`authenticatorGetAssertion` wait for an explicit touch. Pressing the display
HAT joystick straight down supplies that touch; directional movement does
nothing. While waiting, the worker sends CTAPHID `KEEPALIVE(UP_NEEDED)` reports and accepts a
browser-issued CTAPHID `CANCEL`. Cancellation returns
`CTAP2_ERR_KEEPALIVE_CANCEL` without changing credential state. The worker
exposes a mode-`0600` Unix datagram socket at
`/run/virtual-yubikey/touch.sock` only for the lifetime of that wait.
The separate `virtual-yubikey-touch` tool sends the one-byte user-presence event:

```sh
virtual-yubikey-touch
```

The checked-in `virtual-yubikey-sh1106-i2c.toml` profile drives the same
monochrome image over `/dev/i2c-1`. It is intended for an I2C-native SH1106 or
the Pi 3B `virtual-display --display=sh1106` SDL target. In that profile the
SDL target's GPIO5 output supplies touch and GPIO26 controls USB
eject/reinsertion; the direct SPI profiles retain the display-HAT GPIOs.

PIV private-key operations honor the key policy stored at generation or import:
`Never` proceeds immediately, `Always` requires a fresh touch, and `Cached`
reuses a PIV touch for 15 seconds across all PIV key slots. When policy TLVs are
omitted, touch defaults to `Never`; PIN defaults to `Always` for 9C, `Never` for
9E, and `Once` for the other private-key slots. An explicit zero-valued PIN or
touch policy is invalid rather than another encoding of omission. PIN `Once` remains
verified for the card session with no timer; `VERIFY FF/80` clears that PIN
state without clearing management-key authentication.

The management-key touch policy is likewise stored, reported by metadata,
persisted, and enforced when management authentication begins, but it supports
only `Never` (`0xff`) and `Always` (`0xfe`); the candidate `Cached` encoding
`0xfd` is rejected. A successful management authentication continues to
authorize administrative commands for the connection. The touch cache uses
monotonic time and is scoped to the PIV applet's local presence client, so a
FIDO or YubiHSM Auth touch cannot authorize a PIV operation. PIV waits use
ordinary CCID time-extension frames while the shared physical-presence service
waits for the same joystick or helper.

Holding display-HAT KEY3 requests a physical-style USB ejection. The worker
sends an empty `Configure` record and remains ejected until release; it then
sends its complete personality in a second `Configure`. It neither signals nor
restarts the supervisor. KEY1 and KEY2 are intentionally unassigned.

The GPIO thread drains edge events continuously but sends only a newly observed
press into the socket for the currently active wait, independent of which
applet requested it. The helper fails when no
operation is waiting. A press while idle, a button held before a request, switch
bounce after completion, and unread datagrams from a completed wait therefore
cannot approve a later request. Browser or operating-system UI remains
responsible for PIN entry and cancellation; the IPC event represents only the
physical touch. The `/run`
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

CCID operations use the separate CCID time-extension mechanism. A PIV or
YubiHSM Auth APDU runs
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
YubiHSM Auth APDUs follow the
[Yubico YubiHSM Auth command reference](https://docs.yubico.com/yesdk/users-manual/application-yubihsm-auth/commands/yubihsm-auth-commands.html).

## Install as a service

Install the generic supervisor once as described in its README, then build this
repository in place. Choose `profiles/virtual-yubikey.toml` for the 240x240
ST7789 color display or `profiles/virtual-yubikey-sh1106-spi.toml` for the
128x64 SH1106 monochrome OLED. Copy the selected neutral profile to a temporary
file and set its
`command` and `run_as` fields to the worker's absolute path and dedicated
unprivileged service account; do not put machine-local paths into the checked-in
template.

```sh
cargo build --release --locked
cp profiles/virtual-yubikey.toml /tmp/virtual-yubikey.toml
editor /tmp/virtual-yubikey.toml
sudo install -o root -g root -m 0644 \
  /tmp/virtual-yubikey.toml \
  /opt/usb-gadget-supervisor/profiles/virtual-yubikey.toml
sudo /opt/usb-gadget-supervisor/usb-gadget-supervisor --check-profile \
  --profile /opt/usb-gadget-supervisor/profiles/virtual-yubikey.toml
sudo systemctl enable --now \
  usb-gadget-supervisor@virtual-yubikey.service
```

That is the entire device-specific installation: one small profile containing
the worker launch and resource boundary. The worker owns its USB personality
and drives the display through the shared `display-backends` crate; the worker
and touch helper run directly from `target/release`. A normal update is
`git pull`, rebuild, and restart; reinstall the profile only when it changes.

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
