# ARM64 worker binary

`virtual-yubikey-worker` is a Release build for Raspberry Pi targets. Deploy
this artifact through Git rather than compiling the Rust dependency graph on
the target. Existing supervisor profiles can use it after installation to
`target/release/virtual-yubikey-worker`.

The binary was built from clean `virtual-yubikey` commit
`c896a04fdeba5069cb57a2a22168c39914c0e988` on `ubuntu4`, running Ubuntu
26.04 LTS on ARM64, with Rust and Cargo 1.98.1 and glibc 2.43. Its path
dependencies were:

- `software-key-core` at `21d14c6af8a814b11459fb8ccb16475359f45835`;
- `usb-gadget-supervisor` at `a3d48f4cb8bff3c706176758fd92283a77be5d02`;
- `display-backends` at `e9d4bf3de41567b25925fb50c5e0d37b415ab571`.

It is an AArch64 PIE executable requiring at most `GLIBC_2.34`, compatible
with the Debian 13 Raspberry Pi targets using glibc 2.41.

Verify and install from the repository root:

```sh
(cd prebuilt/aarch64 && sha256sum -c SHA256SUMS)
install -D -m 755 prebuilt/aarch64/virtual-yubikey-worker target/release/virtual-yubikey-worker
```

Preserve the target's existing supervisor profile, persistent state, and service
activation state. Restart the service after replacement only if it was active.

Rebuild on a capable ARM64 machine with:

```sh
cargo build --locked --release
```

Update the binary, checksum, and build provenance in the canonical Mac
repository, commit and push them, then update target checkouts through Git.
