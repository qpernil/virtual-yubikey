# Reusing the `pkcs11rs` virtual YubiKey

## Decision

Keep `virtual-yubikey` and `pkcs11rs` as separate Git repositories. The Pi
gadget should not depend on the complete PKCS #11 provider. Instead, extract
the transport-neutral emulator already present in `pkcs11rs` into small crates
that both repositories can consume.

The Linux USB layers remain here: ConfigFS, FunctionFS, CCID framing, endpoint
ownership, privilege separation, and systemd integration. PC/SC,
CryptoTokenKit, PKCS #11 slots, and provider policy remain in `pkcs11rs`.
The USB gadget deliberately remains CCID-only because `pkcs11rs` transports
FIDO/CTAP commands over ISO 7816 APDUs; no FIDO HID interface is currently
required. If host compatibility tests demonstrate that an application requires
FIDO HID, add it as a separate USB interface backed by the same shared emulator
state rather than implementing a second applet stack.

## Proposed crates

| Crate | Responsibility |
| --- | --- |
| `yubikey-protocol` | ISO 7816 APDUs, AIDs, Management TLVs, CTAP-over-smart-card framing, and CTAP CBOR types |
| `yubikey-emulator` | Stateful Management and FIDO applet behavior without USB, PC/SC, CryptoTokenKit, or PKCS #11 dependencies |
| `preview-sign` feature or crate | Existing ARKG/`previewSign` records, request validation, and software test implementation |

```text
pkcs11rs ---------> yubikey-protocol <--------- virtual-yubikey
   |                        ^                           |
   +----> preview-sign ---- + ---- yubikey-emulator <--+
```

No shared crate should depend on either top-level application. This avoids a
dependency cycle and keeps standalone Pi builds reproducible.

## Migration sequence

1. Freeze successful Management SELECT/device-info and FIDO SELECT/GetInfo
   transcripts from macOS PC/SC, iOS CryptoTokenKit, Yubico Authenticator, and
   `pkcs11rs` as conformance fixtures.
2. Extract APDU, TLV, AID, Management, and CTAP smart-card codecs from
   `pkcs11rs` into `yubikey-protocol`.
3. Move the reusable state machine from `pkcs11rs/src/mock_yubikey.rs` into
   `yubikey-emulator`. Keep its transport interface synchronous and
   byte-oriented.
4. Move the existing `previewSign` implementation behind an explicit feature.
   Advertise `previewSign` only when the corresponding handlers are installed.
5. Use workspace path dependencies during development. For independent clones,
   publish the crates or pin Git dependencies to exact locked revisions.

## YubiHSM mock boundary

A YubiHSM mock does not belong in this USB gadget. Add it as an optional
software backend to `yubihsm-connector`, behind the connector's existing HTTP
status and API routes. Normal connector mode continues to use USB; mock mode
passes the same binary requests to an in-process YubiHSM state machine.

## Acceptance criteria

- The gadget remains a small root supervisor plus unprivileged protocol worker.
- `pkcs11rs` and the gadget generate identical Management and CTAP values from
  shared types rather than copied constants.
- Capability advertisements are derived from installed emulator handlers.
- `cargo build --release --locked` works from a standalone Pi clone.
