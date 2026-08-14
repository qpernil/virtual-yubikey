# Virtual YubiKey

`virtual-yubikey` makes a Raspberry Pi enumerate as a CCID-only YubiKey for
compatibility testing. CCID is intentional: `pkcs11rs` carries FIDO/CTAP over
smart-card APDUs, so this target does not need a separate FIDO HID interface.
If compatibility testing finds a host or application that requires FIDO HID,
we will add it as a second interface without changing the CCID applet model.
It is a software test double, not a security device:
keys on a general-purpose Pi do not have the tamper, extraction, or side-channel
protections of a real YubiKey.

The current feasibility build exposes one USB CCID interface and implements
enough YubiKey Management and FIDO2 smart-card behavior for discovery and
protocol experiments. The next phase will reuse the richer virtual YubiKey and
`previewSign` implementation already present in `pkcs11rs`.

## Current behavior

| Layer | Behavior |
| --- | --- |
| USB identity | `1050:0404`, `Yubico`, `YubiKey CCID`, `bcdDevice` `0x0580` |
| CCID transport | Class `0x0b`, T=1, one inserted slot, bulk OUT/IN and interrupt IN |
| Management | AID `A000000527471117`, firmware 5.8.0, serial and CCID capability information |
| FIDO2 | AID `A0000006472F0001`, SELECT and `authenticatorGetInfo` |
| Diagnostics | Lifecycle, CCID, SELECT, APDU status, and unsupported-command events in stderr/journal |

This repository no longer exposes a YubiHSM vendor interface. A future YubiHSM
mock belongs as a software backend in `yubihsm-connector`, using its normal HTTP
API. See [the reuse plan](docs/pkcs11rs-reuse.md).

The program uses Yubico's USB VID/PID solely for controlled compatibility
testing. Do not distribute a product that presents itself as genuine Yubico
hardware.

## Source layout

| Module | Responsibility |
| --- | --- |
| `main.rs` | Process orchestration and signal handling |
| `cli.rs` | Command-line validation |
| `diagnostics.rs` | Structured, payload-safe logging |
| `gadget.rs` | Privileged ConfigFS lifecycle and worker supervision |
| `functionfs.rs` | Unprivileged FunctionFS transport and CCID USB descriptors |
| `ccid.rs` | CCID framing, reader state, and smart-card activation |
| `smartcard.rs` | YubiKey Management and FIDO2 APDU routing |

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
mounting FunctionFS, and binding the UDC require root. It immediately launches
a fresh copy as the selected unprivileged account; that worker owns FunctionFS
and handles all host-controlled USB protocol data. There is no standard Pi
group equivalent to `dialout` for gadget administration.

Ctrl-C unbinds and removes the gadget. An exclusive lock prevents concurrent
instances, and a later start recovers stale state left by a crash. Options:

```text
--serial DECIMAL       USB and Management serial (default 12345678)
--udc NAME             select a controller instead of the first available one
--run-as USER          unprivileged protocol worker account
--log-level LEVEL      off, info, debug, or trace
```

Trace logging includes complete protocol payloads and may expose PINs or
cryptographic material as the emulator grows.

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

### Migrating from `yubihsm-mock`

Stop and remove the old unit before installing the renamed service so it cannot
hold the UDC or leave a second enabled service:

```sh
sudo systemctl disable --now yubihsm-mock.service
sudo rm /etc/systemd/system/yubihsm-mock.service
sudo rm /usr/local/sbin/yubihsm-mock
sudo systemctl daemon-reload
```

Then clone or rename the checkout to `/home/per/virtual-yubikey` and follow the
service installation commands above.
