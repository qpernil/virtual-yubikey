# ARM64 worker binary

`virtual-yubikey-worker` is a Release build for Raspberry Pi targets. Deploy
this artifact through Git rather than compiling the Rust dependency graph on
the target. Existing supervisor profiles can use it after installation to
`target/release/virtual-yubikey-worker`.

The binary's Rust sources match `virtual-yubikey` revision
`3251465f3e70eb339e58c9c8122aa222a456b1d3`. It was built on `ubuntu4`, running
Ubuntu 26.04.1 LTS on ARM64, with Rust and Cargo 1.98.1 and glibc 2.43. Its
path-dependency sources match these revisions:

- `software-key-core` at `a35d9fdcdb7d22714055307822f985db988ceb7c`;
- `usb-gadget-supervisor` at `3ab6ace30d0ec266a0f6459f0b1df194f55e535a`;
- `display-backends` at `653d96cd066cdbc52bbedc4d5faf2028b014eb3e`;
- `raspberry-pi-i2c-target` at `925d083e4969d4f19acf79fc3cdb13fda4cab512`.

It is an AArch64 PIE executable requiring at most `GLIBC_2.34`, compatible
with the Debian 13 Raspberry Pi targets using glibc 2.41.

Verify and install from the repository root:

```sh
(cd prebuilt/aarch64 && sha256sum -c SHA256SUMS)
install -D -m 755 prebuilt/aarch64/virtual-yubikey-worker target/release/virtual-yubikey-worker
```

Preserve the target's supervisor profile and service activation state. Clear
virtual YubiKey applet state only when explicitly requested for deployment. The
worker uses the common per-applet storage layout described in
[shared storage](../../docs/storage.md); whole-device records are not imported.
Restart the service after replacement only if it was active.

Rebuild on a capable ARM64 machine with:

```sh
cargo build --locked --release
```

Update the binary, checksum, and build provenance in the canonical Mac
repository, commit and push them, then update target checkouts through Git.
