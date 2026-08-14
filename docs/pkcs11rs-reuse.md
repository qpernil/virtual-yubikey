# Reusing the `pkcs11rs` virtual YubiKey

## Decision

Keep `virtual-yubikey` and `pkcs11rs` as separate Git repositories. The Pi
gadget must not depend on the complete PKCS #11 provider. The transport-neutral
`virtual-yubikey-core` crate therefore lives in this repository. Reusable
behavior from the feature-gated `pkcs11rs` test mock has been migrated
manually into the core; `pkcs11rs` remains unchanged until the new crate is
proven over the standalone and USB paths.

The Linux USB layers remain here: ConfigFS, FunctionFS, CCID framing, endpoint
ownership, privilege separation, and systemd integration. PC/SC,
CryptoTokenKit, PKCS #11 slots, and provider policy remain in `pkcs11rs`.
The USB gadget exposes both CCID and FIDO HID because Yubico Authenticator uses
HID for FIDO operations even when the same physical device has a CCID interface.
`pkcs11rs` can continue transporting FIDO/CTAP over ISO 7816 APDUs. Both paths
use the same authenticator state rather than separate applet implementations.

## Current boundary

| Component | Responsibility |
| --- | --- |
| `virtual-yubikey-core` | Firmware profile, ISO 7816 APDUs, applet selection, Management behavior, FIDO routing and logical device state |
| `virtual-yubikey` binary | ConfigFS, FunctionFS, CTAPHID, CCID, privilege separation, diagnostics and systemd integration |
| future `pkcs11rs` adapter | Implements the provider's internal connector trait by calling the core directly in tests |

```text
virtual-yubikey USB HID/CCID ----> virtual-yubikey-core <---- pkcs11rs test adapter
```

The core does not depend on either top-level application. This avoids a cycle
and keeps standalone Pi builds reproducible.

## Integration sequence

1. Freeze successful Management SELECT/device-info and FIDO SELECT/GetInfo
   transcripts from macOS PC/SC, iOS CryptoTokenKit, Yubico Authenticator, and
   `pkcs11rs` as conformance fixtures.
2. Run the core's FIDO, PIN, credential-management and `previewSign`
   registration/signing tests through the standalone logical device.
3. Exercise the same commands through the Pi's USB CCID transport.
4. Add a small `pkcs11rs` test adapter and run the existing mock test suite
   against the core. Only then remove the duplicate test implementation.
5. Use workspace path dependencies during coordinated development. For independent clones,
   publish the crates or pin Git dependencies to exact locked revisions.

## Acceptance criteria

- The gadget remains a small root supervisor plus unprivileged protocol worker.
- `pkcs11rs` and the gadget generate identical Management and CTAP values from
  shared types rather than copied constants.
- Capability advertisements are derived from installed emulator handlers.
- `cargo build --release --locked` works from a standalone Pi clone.
