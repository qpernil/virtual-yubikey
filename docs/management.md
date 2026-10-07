# USB application configuration

Management exposes separate supported and enabled USB capability masks. The
profile's installed applets determine the immutable supported mask. The enabled
mask is persistent, starts with all supported applications enabled, and can be
changed with Yubico's ordinary device-configuration protocol.

U2F (`0002`) and FIDO2/CTAP2 (`0200`) are independently configurable. The
transport-neutral profile also has separate `u2f` and `fido2` installation flags.
Either protocol keeps the shared FIDO AID selectable; disabling both rejects
FIDO SELECT. Disabled U2F commands and disabled CTAP2 APDUs return `6D00`.
An already-selected application whose entire capability is disabled rejects
commands with `6985`. HID rejects disabled MSG/CBOR commands with
`CTAPHID_ERROR/INVALID_CMD`. INIT advertises CBOR only when FIDO2 is enabled and
sets NMSG when U2F is disabled. CTAP2 GetInfo includes `U2F_V2` only while U2F
is enabled. CTAP2 assertions of existing U2F handles remain available through
the enabled CTAP2 protocol.

The worker's HID and CCID transports share one Management state. A write through
either transport affects both. OpenPGP, PIV and YubiHSM Auth capability bits also
govern their CCID application availability. Management and the configured Issuer
Security Domain remain administrative access paths. The CCID capability (`0004`)
is not a writable application bit. Unsupported capability bits are masked out.

Disabling an application preserves its credentials, wrapping keys, certificates
and counters. Re-enabling restores access to that state. USB capability changes
invalidate connection authorization and secure messaging on the next card
command; the shared FIDO authenticator also invalidates its connection state
before its next enabled operation. Disabling U2F does not reset its global counter.

## Management protocol

| Operation | CCID Management applet | FIDO HID |
| --- | --- | --- |
| Read configuration | `00 1D <page> 00` | Vendor command `42` with one-byte page |
| Write configuration | `00 1C 00 00` | Vendor command `43` |

Both transports use the same one-byte total length followed by one-byte-tag,
one-byte-length TLVs. Page zero reports serial, firmware, form factor, supported
and enabled USB capabilities, fixed timeout/device-flag defaults, and configuration
lock status. Other pages are rejected. Writes accept these settings:

| Tag | Value | Behavior |
| --- | --- | --- |
| `03` | Two-byte big-endian mask | Replace enabled USB applications |
| `0A` | 16-byte code | Set the configuration lock; all-zero code removes it |
| `0B` | 16-byte code | Authorize this transaction with the existing lock code |
| `0C` | Empty | Accept the client's reboot hint and invalidate connection authorization |
| `06`, `07`, `08` | `0000`, `0F`, `00`, respectively | Accept the fixed defaults only |

Malformed, duplicate, unknown or unsupported settings fail atomically. A locked
configuration requires its correct unlock code in the same write transaction,
regardless of TLV order. Unlocking grants no authorization for a later command.
SCP03/SCP11 can protect CCID Management writes; those channels do not bypass the
configuration lock. The stored lock is a domain- and serial-bound SHA-256 verifier;
the supplied 16-byte code is not retained. Verifier-input copies use zeroizing
storage, Management Debug output omits it, and CCID configuration-write payloads
are omitted from trace logs.

Typical host commands are:

```sh
ykman config usb --disable U2F
ykman config usb --enable U2F
ykman config usb --disable FIDO2
ykman config usb --enable FIDO2
```

These are protocol-compatible client commands; qualification of the deployed
USB worker with the physical `ykman` CLI remains separate from the in-process
client tests below.

## Persistence and transport limits

`management-<serial>.cbor` stores the USB enabled mask and configuration-lock
verifier in schema version 1. Missing files initialize with factory enablement
only after existing applet records validate. Whole-device schema version 3
includes Management state; versions 1–2 migrate with factory enablement and
preserve existing applet images. USB and embedded hosts force configuration
writes to durable storage before returning success, including in batched mode.
Configuration writes do not rewrite credential files.

Settings apply immediately to subsequent requests. The USB worker retains its
supervisor-published HID/CCID personality rather than disconnecting or changing
interface descriptors. The reboot hint clears connection authorization but does
not physically detach the device or open a new FIDO authenticator-reset window.
Management remains reachable when both FIDO protocols are disabled. Non-default
CCID auto-ejection, OTP challenge-response timeouts and USB device flags are
unsupported and rejected. The emulator has no NFC transport: it advertises no
NFC capability tags and rejects NFC configuration writes.

## Verification

Tests cover all four U2F/FIDO2 combinations, installation masks, live HID INIT
and command routing, identical HID/CCID reports, preservation of a registered
U2F handle and counter, malformed/unsupported transactions, configuration locks,
whole-device migration, and durable shared-storage restoration. SCP03 and
SCP11a/c tests cover protected configuration writes. Independent Yubikit
`ManagementSession` and `python-fido2` clients exercise writes over both
Management bindings, capability reports, protocol availability, lock enforcement,
persistence restoration, and successful authentication with the original U2F
handle after re-enabling it.

References:

- [Yubico device configuration reference](https://developers.yubico.com/yubikey-manager/Config_Reference.html)
- [Yubico ManagementSession implementation](https://developers.yubico.com/yubikey-manager/API_Documentation/_modules/yubikit/management.html)
- [ykman config commands](https://docs.yubico.com/software/yubikey/tools/ykman/Config_Commands.html)
