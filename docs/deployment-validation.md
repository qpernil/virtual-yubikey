# Extracted Worker Deployment Validation

## Test target

The supervisor/worker migration was deployed on 2026-08-17 to
`raspberrypi-3`, an aarch64 Raspberry Pi running Debian and Raspberry Pi kernel
`6.18.39+rpt-rpi-v8`. Its USB device controller was `fe980000.usb`. The host was
macOS, connected over a data-capable USB link.

The deployed process boundary was:

```text
root  usb-gadget-supervisor
  `- per:per  virtual-yubikey-worker
```

The installation replaced the earlier root-supervisor/worker roles in one
`/usr/local/sbin/virtual-yubikey` executable. Copies of that executable and its
systemd unit were retained with a `.pre-supervisor` suffix. The existing files
under `/var/lib/virtual-yubikey` were not replaced.

## Source and compiler checks

Before installation:

- all 91 Virtual YubiKey workspace tests passed;
- all 11 USB gadget supervisor tests passed;
- both repositories passed `cargo fmt --check`;
- both passed Clippy with warnings denied; and
- both passed compilation and Clippy for `aarch64-unknown-linux-gnu`.

The actual release binaries were then built on the Pi with Rust's locked
dependency graph.

## Live results

The installed profile passed `--check-profile`. Startup produced a root-owned
supervisor and an unprivileged `per:per` worker. FunctionFS was mounted at
`/dev/ffs-virtual-yubikey`; `/dev/hidg0` was assigned mode `0600` to the worker.
The Pi reported UDC state `configured` and ConfigFS values:

```text
idVendor  0x1050
idProduct 0x0406
bcdDevice 0x0580
product   YubiKey FIDO+CCID
```

This is a historical validation record. The current profile uses truthful
`Virtual YubiKey` and `Virtual YubiKey FIDO+CCID` descriptor strings;
the compatibility VID/PID remains unchanged pending guidance from Yubico.

macOS enumerated the emulator at full speed as `YubiKey FIDO+CCID`. `ykman`
distinguished it from a physical YubiKey by Management serial `12345678`, and
reported firmware 5.8.0 with FIDO2 and PIV enabled. `ykman fido info` reached
the emulator over CTAPHID and returned its AAGUID, minimum PIN length, and PIN
retry count.

The host smart-card stack powered the virtual card, received the expected ATR,
selected the PIV AID, and exchanged `GET DATA` APDUs. `yubico-piv-tool -a
status` read the preserved CHUID, retry count, and populated P-256, Ed25519,
X25519, and RSA-2048 slots. The worker loaded the pre-migration 1,073-byte FIDO
state and 2,732-byte PIV state successfully.

The touch helper was also checked while no FIDO command was waiting. It failed
with `No such file or directory`, as intended: the mode-`0600` datagram socket
exists only during an active user-presence wait, so a touch cannot be queued.

## Failure containment

Starting a second supervisor while the service was active failed on the global
UDC lifecycle lock.

The unprivileged worker was then sent `SIGKILL` without killing the supervisor.
The control channel closed, the supervisor exited with failure after cleanup,
and systemd restarted the complete service after two seconds. The new worker
loaded the existing PIV state, the UDC returned to `configured`, and SHA-256
hashes of both persistent-state files were unchanged.

## Remaining acceptance work

This validates extraction, lifecycle, persistence loading, enumeration,
Management, read-only FIDO2, and the CCID/PIV status path. It does not yet
complete the release gate. Still required:

- compare full pre/post descriptors from a Linux host using `lsusb -v`;
- complete FIDO registration and assertion through a host application, sending
  touch through `virtual-yubikey-touch` while the request is pending;
- confirm CTAPHID cancellation during both presence wait and processing;
- run state-mutating Management and PIV workflows using `ykman` and
  `yubico-piv-tool`; and
- repeat lifecycle tests after the optional shared SSD1306/GPIO UI is added.
