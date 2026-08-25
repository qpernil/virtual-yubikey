# Source and compatibility boundary

Virtual YubiKey is an independent, AI-assisted compatibility implementation.
Its implementation sources are public standards, public vendor documentation,
ordinary host APIs, and black-box interoperability tests.

No Yubico firmware, proprietary source code, internal documentation,
cryptographic keys, attestation certificates, or other confidential material
is included in, required to build, or accepted as an implementation source for
this repository.

The principal public implementation references are:

- FIDO Alliance CTAP and U2F specifications;
- W3C Web Authentication specifications;
- USB-IF CCID specifications;
- NIST SP 800-73 PIV specifications;
- ISO/IEC 7816 command and APDU behavior;
- OpenPGP card specifications; and
- Yubico's publicly available developer documentation for YubiKey Management
  and PIV extensions.

The optional physical display uses Yubico's publicly published YubiKey 5 NFC
front product image as recorded in `assets/README.md`. The image is kept as an
external brand asset with its own terms, not as an implementation source or as
code licensed by this repository.

Compatibility validation uses normal, documented host applications and
protocol exchanges with software including browsers, PC/SC, `ykman`,
`yubico-piv-tool`, and Yubico Authenticator. Independently observed protocol
facts and test transcripts become independently written Rust code and
regression tests; vendor source code is not copied.

This policy describes the project's source boundary and does not claim a
formally supervised two-team clean-room process.
