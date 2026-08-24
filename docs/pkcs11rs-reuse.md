# Reusing the `pkcs11rs` virtual YubiKey

## Decision

Keep `virtual-yubikey` and `pkcs11rs` as separate Git repositories. The Pi
gadget must not depend on the complete PKCS #11 provider. The transport-neutral
`virtual-yubikey-core` crate therefore lives in this repository. Reusable
device behavior is implemented in the core and exercised over both standalone
and USB paths. `pkcs11rs` consumes `virtual-yubikey-core` through its optional
`mock-yubikey` feature.

Protocol-neutral software key operations live in the independent sibling
`software-key-core` repository. Both this workspace and `pkcs11rs` consume the
same working tree through dependency-by-path, so neither device emulation nor
the PKCS #11 provider owns the shared implementation.

The Linux device layers remain split across the gadget projects. The generic
supervisor owns ConfigFS, the FunctionFS mount and `ep0`, UDC lifecycle,
privilege separation, and systemd integration. This repository owns CTAPHID,
CCID framing, direct FunctionFS data-endpoint I/O, and device behavior. PC/SC,
CryptoTokenKit, PKCS #11 slots, and provider policy remain in `pkcs11rs`.
The USB gadget exposes both CCID and FIDO HID because Yubico Authenticator uses
HID for FIDO operations even when the same physical device has a CCID interface.
The physical USB CCID reader exposes Management only. `pkcs11rs` should use HID
or its direct-USB connector for FIDO and use CCID for Management discovery. The
core retains ISO 7816 FIDO routing for unit tests and possible future NFC work.

## Current boundary

| Component | Responsibility |
| --- | --- |
| `virtual-yubikey-core` | Firmware profile, ISO 7816 APDUs, applet selection, Management, FIDO and PIV behavior, and persistent logical device state |
| `software-key-core::post_quantum` | Raw ML-DSA parameter sets, seeds, public keys, contexts, verification, and deterministic/required/preferred randomization policy |
| `software-key-core::rsa_signing` | Raw RSA, PKCS #1 v1.5 payload/digest signing, and PSS with independent message hash, MGF1 hash, and salt length |
| `software-key-core::software_signing` | Protocol-neutral ECDSA, Ed25519, RSA-profile, and ML-DSA keys, signing, verification, RSA CRT reconstruction, and compact private-key serialization |
| `software-key-core::software_key_agreement` | Raw ECDH for any compatible RustCrypto short-Weierstrass curve, persistent X25519 keys, public projection, serialization, contributory key agreement, and shared-secret handling |
| `software-key-core::software_symmetric` | AES block, ECB/CBC, CMAC, CCM, KWP, and Yubico OTP AEAD operations |
| `software-key-core::secure_channel` | SCP03-style KDF, cryptograms and padding plus X9.63 and Yubico password KDFs; callers retain sessions, counters, and framing |
| `software-key-core::arkg` | ARKG-P256 public derivation, authenticated tickets, and matching private-scalar derivation; previewSign retains COSE/CBOR and device seed state |
| `usb-gadget-supervisor` | ConfigFS, FunctionFS publication and `ep0`, UDC lifecycle, resource capabilities, privilege separation, and systemd integration |
| `virtual-yubikey` binary | Native USB personality, direct FunctionFS data endpoints, CTAPHID, CCID, display/input policy, and diagnostics |
| `pkcs11rs` mock adapter | Implements the provider's internal connector trait by calling the core directly in tests |

```text
virtual-yubikey USB HID/CCID ----> virtual-yubikey-core <---- pkcs11rs test adapter
                                      |
                                      v
                                 software-key-core <---- pkcs11rs software backend
```

The core does not depend on either top-level application. This avoids a cycle
and keeps standalone Pi builds reproducible.

The reusable crypto modules contain no COSE, CTAP, USB, PKCS #11 mechanism,
object, authorization, or error-code types. FIDO maps COSE identifiers and DER
signature encoding around them. `pkcs11rs` maps mechanisms, attributes, and
`CKR_*` results around the same raw operations.

The general RSA layer covers raw signatures, caller-controlled PKCS #1 v1.5
payloads, SHA-1/SHA-2/SHA-3 DigestInfo encodings, and PSS configurations whose
MGF digest differs from the message digest. The higher-level WebAuthn profiles
select only the combinations advertised by their COSE algorithms.

## Integration sequence

1. Freeze successful Management SELECT/device-info and FIDO SELECT/GetInfo
   transcripts from macOS PC/SC, iOS CryptoTokenKit, Yubico Authenticator, and
   `pkcs11rs` as conformance fixtures.
2. Run the core's FIDO, PIN, credential-management and `previewSign`
   registration/signing tests through the standalone logical device.
3. Exercise FIDO through the Pi's USB HID transport and Management through CCID.
4. Keep the `pkcs11rs` mock adapter and its full-cycle PKCS #11 tests running
   against the core as applet coverage expands.
5. Keep ML-DSA, overlapping ECDSA, and RSA software operations in `pkcs11rs`
   routed through the neutral APIs, retaining PKCS-specific mechanism parsing.
6. Use workspace path dependencies during coordinated development. For independent
   clones, publish the crates or pin Git dependencies to exact locked revisions.

Applet integration and secure-channel extraction are planned in
[`applet-roadmap.md`](applet-roadmap.md).
The future persistence and PKCS #11 key-fingerprint model is specified in
[`future-storage-model.md`](future-storage-model.md).

## Acceptance criteria

- The gadget remains a small root supervisor plus unprivileged protocol worker.
- `pkcs11rs` and the gadget generate identical Management and CTAP values from
  shared types rather than copied constants.
- Capability advertisements are derived from installed emulator handlers.
- `cargo build --release --locked` works from a standalone Pi clone.
