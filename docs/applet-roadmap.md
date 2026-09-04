# Applet and secure-channel direction

## Current boundary

`virtual-yubikey-core` is the transport-neutral implementation of the logical
device. It owns the firmware profile, ISO 7816 routing, installed applets, and
persistent applet state. The USB worker exposes that core through FIDO HID and
CCID, while `pkcs11rs` consumes the same core through its `mock-yubikey`
adapter.

The core currently implements:

- Management identity and capability reporting;
- FIDO registration, assertions, PIN and credential management, resident
  credentials, PPUAT, and `previewSign`;
- PIV discovery, authentication, objects, certificates, key lifecycle, signing,
  raw RSA operations, ECDH, Ed25519, and X25519;
- YubiHSM Auth symmetric and asymmetric credentials, retry policy, touch,
  SCP03 session derivation, and SCP11 key agreement; and
- the OpenPGP `GET CHALLENGE` subset.

The active priorities are:

1. keep FIDO, PIV, and YubiHSM Auth behavior aligned across core, USB, and
   `pkcs11rs` tests;
2. qualify the implemented applets against real host tools over USB;
3. add Issuer Security Domain behavior and target-side SCP03/SCP11; and
4. expand OpenPGP after the common CCID and secure-channel behavior is stable.

HID support is added when an applet or real client requires it. CCID remains the
primary transport for PIV, YubiHSM Auth, Issuer SD, and OpenPGP.

## Integration pattern

Applet behavior is developed as transport-neutral APDU or CTAP behavior in the
core. Each feature is then exercised at three boundaries:

1. direct protocol vectors against `virtual-yubikey-core`;
2. FIDO HID or CCID transport tests in the USB worker; and
3. full-cycle PKCS #11 tests through the `pkcs11rs` adapter where applicable.

Capability advertisements derive from installed handlers so the Management
application and USB profile do not promise unavailable behavior. Shared
protocol code stays in the core; transport lifecycle and PKCS #11 policy remain
in their owning projects.

## Cryptographic boundary

`software-key-core` owns protocol-neutral cryptographic behavior shared by the
provider and emulators: key serialization, public projection, signing and
verification, RSA encodings, ML-DSA policy, symmetric operations, ECDH, and
ARKG-P256 derivation. It composes established upstream cryptographic crates.

PIV, FIDO, USB, and PKCS #11 identifiers and policy remain in their protocol
layers. Direct RustCrypto dev-dependencies are appropriate in protocol tests
when they independently verify an encoded signature or public key; production
cryptography continues to flow through `software-key-core`.

Role-neutral secure-channel components belong in focused shared modules when
both sides require byte-identical behavior. These include:

- SCP03 derivation, cryptograms, padding, counters, and MAC chaining;
- SCP11 key agreement, receipts, transcripts, and variants;
- certificate-chain encoding, parsing, verification, and trust anchors; and
- common GlobalPlatform TLV and key/certificate formats.

Callers retain their own key stores, randomness, trust policy, session state,
persistence, transport, and error mapping.

The content-addressed token-generation and cross-token fingerprint model is
specified separately in [`future-storage-model.md`](future-storage-model.md).
Current FIDO, PIV, and YubiHSM Auth state remains in independent, atomically
replaced versioned files.

## Issuer SD and secure channels

`pkcs11rs` owns the host-side SCP03 and SCP11 implementation, secure messaging,
certificate-chain handling, and Issuer SD operations. The target-side core needs
an APDU-driven state machine that:

- selects and exposes the Issuer Security Domain;
- handles SCP03 `INITIALIZE UPDATE` and `EXTERNAL AUTHENTICATE`;
- handles the applicable SCP11 authentication variants;
- receives and validates OCE certificate chains where required;
- owns static keys, trust anchors, session keys, counters, chaining values, and
  authorization state;
- unwraps protected commands and wraps protected responses; and
- connects authenticated sessions to Issuer SD and applet operations.

Existing host/card vectors provide the conformance inputs. Shared calculations
are extracted only at a role-neutral boundary; host policy stays in `pkcs11rs`
and card policy stays in `virtual-yubikey-core`.

## Applet priorities

### FIDO

- Keep registration, credential management, resident credentials, PPUAT, and
  `previewSign` covered through core, USB HID, and PKCS #11 tests.
- Keep CTAPHID cancellation and `UP_NEEDED`/`PROCESSING` keepalives covered
  for touch-gated and computationally expensive operations.
- Preserve explicit state versions and fail closed on unsupported or corrupt
  state.
- Extend real-client USB qualification as behavior changes.

### PIV

- Keep discovery and metadata, persistent objects and certificates, PIN/PUK and
  management authentication, retries and reset, RSA and EC key lifecycle,
  signing, raw RSA operations, ECDH, Ed25519, X25519, PIN-protected object
  reads, and PIV attestation covered in the core.
- Pass representative `yubico-piv-tool` workflows over USB CCID and preserve
  their transcripts as transport regression tests.
- Add CCID abort handling and biometric policy events.
- Keep the `pkcs11rs` adapter and its full-cycle tests running against the
  shared core.

### YubiHSM Auth

- Keep symmetric and P-256 credentials, management and credential retries,
  touch policy, SCP03 session derivation, and SCP11 agreement covered in the
  core.
- Preserve independent applet state and common ISO 7816 command/response
  chaining.
- Qualify the CCID path with `ykman`, the `pkcs11rs` YubiHSM Auth client, and
  a physical YubiHSM.
- Keep `pkcs11rs` mock-device tests running against the shared core.

### Issuer Security Domain

- Implement target-side SCP03 and the required SCP11 variants.
- Add protected command and response vectors at the core boundary.
- Exercise authenticated applet operations through CCID and the provider.

### OpenPGP

- Keep the current `GET CHALLENGE` behavior covered.
- Add the OpenPGP card APDU model, data objects, PIN policy, key lifecycle, and
  client-compatible encodings.
- Qualify the applet through CCID after the shared secure-channel patterns are
  stable.
