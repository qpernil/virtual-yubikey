# Third-party notices

## Standards and compatibility names

This project implements public FIDO, WebAuthn, CCID, PIV, ISO 7816, and OpenPGP
interfaces and publicly documented Yubico extensions. Specification names,
command identifiers, AIDs, status values, and other protocol identifiers are
used for interoperability.

Yubico and YubiKey are registered trademarks of Yubico AB. This independent
project is not affiliated with, sponsored by, or endorsed by Yubico.

The local development profile currently uses Yubico's USB VID/PID for
controlled compatibility testing. That identifier is not assigned to this
project and is not licensed here for redistributed or commercial hardware.
Stock Yubico software may infer and display a genuine-device model name from
that compatibility identity; such a label does not indicate affiliation,
sponsorship, endorsement, or product origin.

## Rust dependencies

The exact dependency graph is recorded in `Cargo.lock`. Dependencies are
obtained from crates.io and retain their own copyright and license notices.
The locked graph includes MIT, Apache-2.0, BSD, BlueOak-1.0.0, Unicode-3.0,
and compatible license combinations. The Linux worker also links the sibling
GPL-3.0-or-later `display-backends` crate, so distribution of that combined
binary must satisfy the GPL. No Yubico source package is linked or vendored by
this repository.

Redistributors should preserve applicable dependency notices and regenerate a
license inventory from the exact locked dependency graph used for their build.

## Product display image

The YubiKey product image and YubiKey marks in `assets/` belong to Yubico. They
were obtained from Yubico's public product-media CDN and are not licensed under
this repository's software licenses. See `assets/README.md` for the exact
source and derived-frame description.
