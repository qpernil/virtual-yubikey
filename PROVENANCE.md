# Implementation provenance

Virtual YubiKey is an independent, AI-assisted compatibility implementation.
It was developed with OpenAI Codex under Per Nilsson's direction in August
2026. The implementation work used public standards, public vendor
documentation, ordinary host APIs, and black-box interoperability tests.

No Yubico firmware, proprietary source code, internal documentation,
cryptographic keys, attestation certificates, or other confidential material
is included in or required to build this repository. Per Nilsson is a former
Yubico employee; no non-public Yubico material was supplied to Codex or used as
an implementation source for this project.

The principal public implementation references are:

- FIDO Alliance CTAP and U2F specifications;
- W3C Web Authentication specifications;
- USB-IF CCID specifications;
- NIST SP 800-73 PIV specifications;
- ISO/IEC 7816 command and APDU behavior;
- OpenPGP card specifications; and
- Yubico's publicly available developer documentation for YubiKey Management
  and PIV extensions.

Compatibility was validated through normal, documented host applications and
protocol exchanges with software including browsers, PC/SC, `ykman`,
`yubico-piv-tool`, and Yubico Authenticator. Observed protocol facts and test
transcripts were converted into independently written Rust code and regression
tests; vendor source code was not copied.

This document records implementation history, not a claim that the project has
completed a formally supervised two-team clean-room process.
