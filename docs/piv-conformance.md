# PIV standards and compatibility boundary

The PIV applet is a YubiKey-compatible test implementation. It follows the PIV
card interface where that interface is exercised by YubiKey host software, but
it is not an issued federal PIV credential and does not claim NPIVP conformance.

The normative baseline is the current final set of publications:

- [FIPS 201-3](https://csrc.nist.gov/pubs/fips/201/3/final) defines the PIV
  credential and lifecycle;
- [NIST SP 800-73-5 Part 1](https://csrc.nist.gov/pubs/sp/800/73/pt1/5/final)
  defines the PIV namespace, data model, objects, and access rules;
- [NIST SP 800-73-5 Part 2](https://csrc.nist.gov/pubs/sp/800/73/pt2/5/final)
  defines the card command interface and PIV secure messaging; and
- [NIST SP 800-78-5](https://csrc.nist.gov/pubs/sp/800/78/5/final) defines
  algorithms, key sizes, and identifiers.

AES-128, AES-192, and AES-256 are standard algorithms for the PIV Card
Application Administration Key. 3TDEA is also permitted for cards expiring
through December 31, 2030, but is deprecated; cards expiring later use AES.
Management authentication uses the standard `GENERAL AUTHENTICATE` external or
mutual challenge-response flows. Changing the management key, retrieving
metadata, importing and moving keys, resetting the applet, and attestation use
Yubico-defined commands.

## Current implementation

| Area | Current behavior |
| --- | --- |
| Base card interface | `SELECT`, `GET DATA`, `VERIFY`, `CHANGE REFERENCE DATA`, `RESET RETRY COUNTER`, `GENERAL AUTHENTICATE`, `PUT DATA`, and `GENERATE ASYMMETRIC KEY PAIR` are implemented for the supported contact-interface profile. |
| Administration key | 3TDEA and AES-128/192/256 external and mutual authentication are implemented. The reset profile uses the YubiKey 5.7-and-later AES-192 default. |
| Data objects | The Discovery Object and the factory PIV attestation certificate (`5FFF01`) are built in. Other objects are management-authorized, persistent byte strings addressed by their PIV tag. The applet does not validate each object's internal PIV encoding. |
| PIN-protected object reads | `GET DATA` requires a verified PIN for fingerprints (`5FC103`), facial image (`5FC108`), printed information (`5FC109`), and iris images (`5FC121`). The pairing-code reference data (`5FC123`) is not PIN-protected by the contact-interface access rule. On-card biometric comparison and its OCC access path are not implemented. |
| Issued-card contents | Reset produces an unprovisioned YubiKey-compatible applet. It does not synthesize the mandatory CCC, CHUID, PIV Authentication certificate, Card Authentication certificate, fingerprint, facial-image, or Security Object contents of an issued PIV Card. Provisioning software may store these objects. |
| Authentication profiles | The local PIV PIN, PUK, and Administration Key are implemented. Global PIN, pairing-code verification, and on-card biometric comparison are not implemented. |
| PIV secure messaging | The NIST PIV Secure Messaging key (`04`), cipher suites, SM-AUTH, and Virtual Contact Interface are not implemented. The separate YubiKey/GlobalPlatform boundary implements SCP03 and SCP11a/b/c secure messaging around the selected PIV applet and the other selectable CCID applets. |
| Algorithms | RSA-2048/3072 and P-256/P-384 cover the applicable current PIV asymmetric profiles. RSA-1024, RSA-4096, Ed25519, and X25519 are YubiKey compatibility algorithms; ML-DSA-44/65/87 and ML-KEM-512/768/1024 use the private extension below. |
| YubiKey attestation | The persistent `F9` key and certificate object `5FFF01` implement the Yubico `ATTEST` command for generated RSA, EC, Ed25519, ML-DSA, and ML-KEM keys. Generated certificates copy their issuer and validity from `5FFF01`, use the target key as SubjectPublicKeyInfo, and carry the firmware, serial, PIN/touch-policy, and form-factor extensions. F9 may use RSA, EC, Ed25519, or ML-DSA; changing it refreshes the matching self-signed `5FFF01` certificate. PIV reset preserves the key and certificate. |

## Private post-quantum PIV extension

The [NIST PIV PQC working draft](https://pages.nist.gov/piv-standards/pqc-overview/)
identifies ML-DSA signing and ML-KEM decapsulation through `GENERAL AUTHENTICATE`,
but has not assigned interoperable PIV algorithm IDs or public-key TLVs. This
applet uses the following private IDs after its Ed25519 `E0` and X25519 `E1`:

| P1 algorithm ID | Key type | Operation |
| --- | --- | --- |
| `E2`, `E3`, `E4` | ML-DSA-44, -65, -87 | Sign the complete message supplied in `7C { 82 empty, 81 message }`; return the raw signature in `7C { 82 signature }`. |
| `E5`, `E6`, `E7` | ML-KEM-512, -768, -1024 | Decapsulate the exact-length ciphertext supplied in `7C { 82 empty, 81 ciphertext }`; return the 32-byte shared secret in `7C { 82 secret }`. |

`GENERATE ASYMMETRIC KEY PAIR` and key metadata use tag `87` inside the public
key template `7F49` for the raw ML-DSA or ML-KEM public key. This tag is also
private and may change if PIV standardization assigns a different format.
PIN and touch policies apply to both operations. Key generation and persistent
restore are supported. The private `IMPORT KEY` command (`FE`, P1 = algorithm
ID, P2 = slot) accepts a single private tag `09` containing the 32-byte
ML-DSA seed or 64-byte ML-KEM seed, optionally alongside the existing `AA`
PIN-policy and `AB` touch-policy TLVs. The exact seed length and algorithm
are validated before replacing a slot. Expanded private keys and PKCS#8 are
not accepted on this PIV wire format. Import requires management-key
authentication; use encrypted SCP03 or SCP11 secure messaging if the seed
must be confidential in transit, since management authentication alone does not
encrypt the import APDU. Imported user keys are not eligible for the
device-generated-key attestation claim.

Attestation certificates use the standard X.509 ML-DSA and ML-KEM
SubjectPublicKeyInfo encodings, and an ML-DSA F9 key signs certificates with a
standard ML-DSA signature algorithm identifier. An imported ML-DSA F9 key
gets a matching self-signed certificate and may issue virtual attestations;
that certificate alone does not establish hardware provenance. An ML-KEM key
can be an attested subject, not an attestation issuer.

ML-DSA signatures and PQC certificates can exceed one 3,072-byte CCID message.
The applet uses the shared APDU response and CCID chaining paths; consumers
must reassemble the complete response. The self-signed F9 certificate is a
virtual trust anchor, not a Yubico or production hardware attestation chain.

## Deliberate YubiKey compatibility behavior

The strict PIV Card Application PIN syntax is six to eight decimal digits.
YubiKey software and devices also accept non-decimal PIN values in the
eight-byte command field, and the upstream `yubico-piv-tool` API tests rely on
that behavior. This applet accepts the same values for compatibility. The PUK
is not a deviation: SP 800-73-5 permits any eight-byte binary PUK value.

The YubiKey also exposes algorithms, slots, policies, and administrative
commands outside the NIST PIV namespaces. These are implemented only where they
belong to the selected YubiKey firmware profile. The virtual USB personality is
contact-only, so the contactless access restrictions and YubiKey NFC behavior
are outside its transport surface.

The built-in F9 key and `5FFF01` certificate form a self-signed, explicitly
virtual test identity. They provide protocol-compatible attestation evidence
inside this emulator and do not chain to, impersonate, or carry the hardware
assurance of Yubico's PIV attestation roots.
