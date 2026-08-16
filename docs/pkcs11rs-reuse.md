# Reusing the `pkcs11rs` virtual YubiKey

## Decision

Keep `virtual-yubikey` and `pkcs11rs` as separate Git repositories. The Pi
gadget must not depend on the complete PKCS #11 provider. The transport-neutral
`virtual-yubikey-core` crate therefore lives in this repository. Reusable
behavior from the feature-gated `pkcs11rs` test mock was migrated manually into
the core and proven over the standalone and USB paths. `pkcs11rs` now consumes
`virtual-yubikey-core` through its optional `mock-yubikey` feature.

The Linux USB layers remain here: ConfigFS, FunctionFS, CCID framing, endpoint
ownership, privilege separation, and systemd integration. PC/SC,
CryptoTokenKit, PKCS #11 slots, and provider policy remain in `pkcs11rs`.
The USB gadget exposes both CCID and FIDO HID because Yubico Authenticator uses
HID for FIDO operations even when the same physical device has a CCID interface.
The physical USB CCID reader exposes Management only. `pkcs11rs` should use HID
or its direct-USB connector for FIDO and use CCID for Management discovery. The
core retains ISO 7816 FIDO routing for unit tests and possible future NFC work.

## Current boundary

| Component | Responsibility |
| --- | --- |
| `virtual-yubikey-core` | Firmware profile, ISO 7816 APDUs, applet selection, Management behavior, FIDO routing and logical device state |
| `virtual-yubikey-crypto::post_quantum` | Raw ML-DSA parameter sets, seeds, public keys, contexts, verification, and deterministic/required/preferred randomization policy |
| `virtual-yubikey-crypto::software_signing` | Protocol-neutral ECDSA, Ed25519, RSA, and ML-DSA keys, signing, verification, and compact private-key serialization |
| `virtual-yubikey` binary | ConfigFS, FunctionFS, CTAPHID, CCID, privilege separation, diagnostics and systemd integration |
| `pkcs11rs` mock adapter | Implements the provider's internal connector trait by calling the core directly in tests |

```text
virtual-yubikey USB HID/CCID ----> virtual-yubikey-core <---- pkcs11rs test adapter
                                      |
                                      v
                             virtual-yubikey-crypto <---- pkcs11rs software backend
```

The core does not depend on either top-level application. This avoids a cycle
and keeps standalone Pi builds reproducible.

The reusable signing modules contain no COSE, CTAP, USB, PKCS #11 mechanism,
object, authorization, or error-code types. FIDO maps COSE identifiers and DER
signature encoding around them. A future `pkcs11rs` integration should map
mechanisms, attributes, and `CKR_*` results around the same raw operations.

The shared RSA profiles currently cover SHA-2 with either PKCS #1 v1.5 or PSS,
including caller-supplied prehashes and PSS salt lengths. `pkcs11rs` additionally
supports raw RSA, SHA-1/SHA-3, and PSS configurations whose MGF digest differs
from the message digest. Its existing generic padding and raw-RSA code must be
promoted into this neutral layer during integration; the WebAuthn implementation
does not silently claim those combinations are supported.

## Integration sequence

1. Freeze successful Management SELECT/device-info and FIDO SELECT/GetInfo
   transcripts from macOS PC/SC, iOS CryptoTokenKit, Yubico Authenticator, and
   `pkcs11rs` as conformance fixtures.
2. Run the core's FIDO, PIN, credential-management and `previewSign`
   registration/signing tests through the standalone logical device.
3. Exercise FIDO through the Pi's USB HID transport and Management through CCID.
4. Keep the `pkcs11rs` mock adapter and its full-cycle PKCS #11 tests running
   against the core as new applets are migrated.
5. Replace duplicated ML-DSA and overlapping ECDSA/RSA software operations in
   `pkcs11rs` with the neutral APIs, retaining PKCS-specific mechanism parsing.
6. Use workspace path dependencies during coordinated development. For independent
   clones, publish the crates or pin Git dependencies to exact locked revisions.

Applet migration and secure-channel extraction are planned in
[`applet-roadmap.md`](applet-roadmap.md).

## Acceptance criteria

- The gadget remains a small root supervisor plus unprivileged protocol worker.
- `pkcs11rs` and the gadget generate identical Management and CTAP values from
  shared types rather than copied constants.
- Capability advertisements are derived from installed emulator handlers.
- `cargo build --release --locked` works from a standalone Pi clone.
