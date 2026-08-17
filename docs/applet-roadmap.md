# Applet and secure-channel roadmap

## Direction

Develop logical YubiKey behavior in `virtual-yubikey-core`, prove it through
the Raspberry Pi USB gadget and real host tools, and then make `pkcs11rs` reuse
that behavior in its tests. Keep the existing `pkcs11rs` implementation working
throughout each migration; remove duplicated test code only after the shared
core passes both projects' tests.

The planned order is:

1. Finish FIDO and `previewSign` compatibility.
2. Add PIV and test it with `yubico-piv-tool`.
3. Add YubiHSM Auth, including the Management behavior it needs.
4. Add Issuer Security Domain behavior and target-side SCP03/SCP11.
5. Add OpenPGP after the preceding CCID applets and secure channels are stable.

HID can be added for another applet when a real client requires it. CCID remains
the first transport for PIV, YubiHSM Auth, Issuer SD, and OpenPGP.

## Migration pattern

For each applet:

1. Identify the working host implementation, test mock, vectors, and crypto in
   `pkcs11rs`.
2. Manually promote the target-side behavior into transport-neutral
   `virtual-yubikey-core` code without breaking `pkcs11rs`.
3. Test the logical applet directly with APDU vectors.
4. Test it through USB CCID against the relevant Yubico or OpenPGP tool.
5. Add or update a `pkcs11rs` adapter and run its full-cycle tests against the
   core.
6. Remove the superseded test-only implementation once both repositories use
   the shared code.

## Cryptographic boundary

Keep `virtual-yubikey-crypto` protocol-neutral and limited to behavior both
repositories actually share: key serialization, public projection, raw and
profiled signing/verification, RSA encodings, ML-DSA policy, and ECDH. It should
compose RustCrypto and other established upstream crates rather than duplicate
their primitives. PIV, FIDO, USB, and PKCS #11 identifiers and policy stay in
their respective protocol layers.

The future immutable, content-addressed token generations and cross-token key
fingerprints are specified in [`future-storage-model.md`](future-storage-model.md).
That design is deliberately deferred while the current applet behavior is
finished and remains separate from the active atomic state files.

Share code when it implements substantial protocol behavior that must agree
byte-for-byte between host and card. Likely candidates are:

- `previewSign`/ARKG derivation and encoding;
- SCP03 key derivation, cryptograms, command/response protection, padding,
  counters, and MAC chaining;
- SCP11 key agreement, receipts, authentication transcripts, and variants;
- certificate-chain encoding, parsing, verification, and trust-anchor handling;
- common GlobalPlatform TLV and key/certificate formats.

PKCS #11 mechanism policy and error mapping stay in `pkcs11rs`. USB transports,
privilege separation, and gadget lifecycle stay in `virtual-yubikey`. Applet
installation, key slots, and persistent card state stay in
`virtual-yubikey-core`.

## SCP and Issuer SD starting point

`pkcs11rs` already has production host-side SCP03 and SCP11 support, secure
messaging, certificate-chain handling, and Issuer SD operations. Its tests also
contain the calculations needed to act as the other side: deterministic card
challenges, card cryptograms, SCP11 receipts, generated certificate chains,
protected responses, and complete published exchange vectors.

That test-side code is not yet a reusable virtual card. Test connectors mostly
return scripted or precomputed responses. The missing target-side layer is an
APDU-driven state machine that:

- selects and exposes the Issuer Security Domain;
- handles SCP03 `INITIALIZE UPDATE` and `EXTERNAL AUTHENTICATE`;
- handles the applicable SCP11 authentication variants;
- receives and validates OCE certificate chains where required;
- owns static keys, trust anchors, session keys, counters, chaining values, and
  authentication state;
- unwraps protected commands and wraps protected responses;
- connects authenticated sessions to Issuer SD and applet operations.

Implementation should promote the existing test calculations and vectors into
library code rather than reimplementing them independently. Once the first
complete host/card exchange is working, extract the proven role-neutral pieces
into a focused secure-channel protocol crate or module. It should expose host
and card state machines while allowing each caller to supply its own key store,
randomness, trust policy, persistence, transport, and error mapping.

## Near-term completion criteria

### FIDO

- Keep registration, credential management, multiple resident signing keys,
  PPUAT, and `previewSign` working through core tests, USB HID, Yubico
  Authenticator, and ignored PKCS #11 hardware tests.
- Add cancellation/keepalive behavior before introducing operations that wait
  for touch or other slow work.
- Keep the atomic on-disk FIDO store explicitly versioned as credential fields
  evolve. A missing file creates an empty 100-slot authenticator; unsupported or
  corrupt state fails closed instead of silently discarding credentials. Test
  schema changes may deliberately require an announced empty-state reset.

### PIV

- The core now implements discovery and metadata, persistent objects and
  certificates, PIN/PUK and management-key authentication, retry configuration
  and reset, RSA and P-256/P-384 key generation/import, move/delete, signing,
  raw RSA private operations, ECDH, Ed25519 message signing, and X25519 key
  agreement. Ed25519 and X25519 support their YubiKey 5.7 generation, import,
  metadata, public-key, operation, and persistence encodings.
- Next, pass representative `yubico-piv-tool` workflows over USB CCID and turn
  the observed transcripts into transport-level regression tests.
- Add PIV attestation, CCID touch/cancel integration, and biometric policy
  events. Until touch is connected, a key configured with a non-`Never` touch
  policy fails closed.
- Move `pkcs11rs` tests to the shared core only after standalone compatibility
  is established.

### YubiHSM Auth

- Implement the applet commands and credential state used by `pkcs11rs`.
- Validate with the real YubiHSM Auth client path and then reuse the core from
  `pkcs11rs` tests.

### OpenPGP

- Reuse upstream cryptographic implementations and focus work on the OpenPGP
  card APDU model, data objects, PIN policy, key lifecycle, formats, and client
  compatibility.
- Begin only after the shared CCID applet and secure-channel patterns are
  stable.
