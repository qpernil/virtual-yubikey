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
| Data objects | The Discovery Object is built in. Other objects are management-authorized, persistent byte strings addressed by their PIV tag. The applet does not validate each object's internal PIV encoding. |
| PIN-protected object reads | Not yet implemented. `GET DATA` currently returns a stored object without enforcing the Part 1 access rule. Fingerprints (`5FC103`), facial image (`5FC108`), printed information (`5FC109`), iris images (`5FC121`), and pairing-code reference data (`5FC123`) must require a verified PIN, or OCC where that optional profile is supported. |
| Issued-card contents | Reset produces an unprovisioned YubiKey-compatible applet. It does not synthesize the mandatory CCC, CHUID, PIV Authentication certificate, Card Authentication certificate, fingerprint, facial-image, or Security Object contents of an issued PIV Card. Provisioning software may store these objects. |
| Authentication profiles | The local PIV PIN, PUK, and Administration Key are implemented. Global PIN, pairing-code verification, and on-card biometric comparison are not implemented. |
| PIV secure messaging | The NIST PIV Secure Messaging key (`04`), cipher suites, SM-AUTH, and Virtual Contact Interface are not implemented. GlobalPlatform SCP03/SCP11 support associated with the YubiKey Security Domain is a separate protocol boundary. |
| Algorithms | RSA-2048/3072 and P-256/P-384 cover the applicable current PIV asymmetric profiles. RSA-1024, RSA-4096, Ed25519, and X25519 are retained as YubiKey compatibility algorithms rather than current SP 800-78-5 PIV key profiles. |
| YubiKey attestation | Slot `F9` and the `ATTEST` command are Yubico extensions and are not yet implemented. |

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
