# FIDO U2F / CTAP1

The FIDO application implements U2F `REGISTER` (`01`), `AUTHENTICATE` (`02`),
and `VERSION` (`03`) alongside CTAP2. It reports `U2F_V2` in CTAP2 GetInfo
and its U2F capability through Management. NFC is not implemented.

## Transports and presence

USB HID carries U2F APDUs in `CTAPHID_MSG` on the existing FIDO interface.
INIT advertises CBOR support and clears `CAPABILITY_NMSG`. Both command and
response fragmentation use the ordinary 64-byte HID reports. CTAP2 continues
using `CTAPHID_CBOR`; no separate HID interface is needed.

CCID selects the same FIDO AID, `A0000006472F0001`, and carries U2F APDUs directly.
Short and extended APDUs, ISO command chaining and GET RESPONSE use the common
card router. The FIDO decoder also accepts the explicit zero-length extended
data field used by `python-fido2` for VERSION. SCP03/SCP11 can protect these commands through that router.
The USB CCID layout matches the read-only SELECT/VERSION/GetInfo probes of a
physical YubiKey 5.8.0. A physical 5.7.4 accepted U2F over HID but rejected the
FIDO AID over USB CCID. The emulator has no NFC transport.

Registration and authentication with control byte `03` require fresh physical
presence. The USB worker waits up to 500 ms for a touch on each U2F request and
returns `6985` if none arrives, allowing ordinary CTAP1 client polling. It does
not send CTAP2 keepalive messages for U2F. Check-only (`07`) validates the handle
and AppID and returns `6985` for a match, without signing, touching or advancing
the counter. An invalid handle returns `6A80` before a presence request.
Control byte `08` permits signing without presence and accurately reports the
presence bit in the signed response. U2F does not use the CTAP2 PIN or PIN tokens.

HID and CCID use one operation coordinator, presence service and persistent
FIDO state. A busy U2F runtime returns `6985`; CTAP2 uses its channel-busy status.
Touch authorization does not authorize concurrent operations on another transport.

## Wrapped credentials

U2F has no discoverable credentials or per-registration records. Each
registration generates a fresh random P-256 private key and returns a 64-byte
handle. The server supplies that handle on subsequent authentication requests.

The handle format is local to this emulator:

| Bytes | Content |
| --- | --- |
| 0–3 | `55 32 46 01`: format identifier and version |
| 4–15 | Fresh random 12-byte CCM nonce |
| 16–47 | Encrypted 32-byte P-256 private scalar |
| 48–63 | 16-byte CCM authentication tag |

AES-256-CCM authenticates a fixed protocol domain, format identifier and
32-byte AppID hash as associated data. The random 256-bit wrapping key is
created lazily, persisted with the FIDO applet, and independent of the serial
number. Modified handles, wrong AppIDs, and another device's handles fail
validation. Private scalars and the retained wrapping key use zeroizing storage;
Debug output excludes them. Handles are opaque credential identifiers; they
are not interchangeable with physical YubiKey handles.

Registration includes the uncompressed P-256 public key, the shared FIDO
attestation certificate and a DER ES256 signature over the U2F registration
message. Authentication returns presence, a big-endian global counter and a DER
ES256 signature over `AppID hash || presence || counter || challenge hash`.
The counter advances only for signing, is shared across U2F credentials and
transports, and fails closed at exhaustion. A global counter can reveal signing
activity across credentials, as allowed by U2F.

CTAP2 GetAssertion can use a U2F handle in an explicit allow list when the RP ID
hash matches its AppID hash. Normal CTAP2 PIN/token authorization remains in
force when requested. U2F handles also participate in CTAP2 exclusion-list
checks. They cannot be discovered or listed by credential management. CTAP1
cannot exercise CTAP2-created credentials, and vendor-specific U2F commands,
including legacy FIPS PIN commands, are unsupported.

## Persistence and reset

FIDO CBOR schema version 6 retains the wrapping key and global counter alongside
PIN state, CTAP2 credentials and the attestation identity. Versions 2–5 migrate
without losing their existing state and initialize U2F material lazily.
Malformed or incomplete version-6 wrapping-key/counter fields fail restoration.
There is no per-credential growth in the persistent image for U2F registration.

The USB worker flushes wrapping-key and signature-counter changes before
acknowledging successful U2F operations in both immediate and batched persistence
modes, including CTAP2 assertions of U2F handles. Embedded hosts flush FIDO mutations using their existing persistence path.

CTAP2 authenticatorReset requires a fresh touch and acceptance within ten seconds
of the current power cycle. A successful reset clears CTAP2 credentials and PIN
state, invalidates every U2F handle by discarding the wrapping key, and resets the
U2F counter. The next U2F registration creates fresh random wrapping material.
The FIDO attestation identity remains stable. Connection resets and applet
selection do not extend the reset window or invalidate handles. An explicit
administrative replacement of the FIDO state file also discards its credentials.

## Qualification

Core tests independently verify registration attestation and authentication
signatures, all authentication controls, AppID isolation, modification of every
handle byte, device isolation, persistence migration, restart, reset,
non-discoverability, exclusion lists, and counter exhaustion. Worker tests cover
multi-report HID requests/responses, shared HID/CCID credentials and counters,
short-APDU response chaining, and fresh-presence enforcement. SCP03 and SCP11a/c
tests cover protected U2F VERSION alongside protected CTAP2 GetInfo.

An independent `python-fido2` client verifies registration attestation,
authentication signatures, a 64-byte handle, persistence restoration with a
monotonic counter, CTAP2 assertion of the same handle, AppID rejection, and reset
invalidation against an in-process authenticator fixture.

These protocol tests do not constitute FIDO certification. Physical USB host
qualification requires deploying the worker and exercising real clients; the
read-only physical-key probes qualify exposure, not registration/signing.

References:

- [U2F raw message formats](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html)
- [U2F NFC APDU binding](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-nfc-protocol-v1.2-ps-20170411.html)
- [Yubico's wrapped-key design](https://developers.yubico.com/U2F/Protocol_details/Key_generation.html)
