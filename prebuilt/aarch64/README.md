# ARM64 worker binary

`virtual-yubikey-worker` is a Release build for Raspberry Pi targets. Deploy
this artifact through Git rather than compiling the Rust dependency graph on
the target. Existing supervisor profiles can use it after installation to
`target/release/virtual-yubikey-worker`.

The binary was built from clean `virtual-yubikey` commit
`b2962a744253b0429977baf5e3542789737e4cc8` on `ubuntu4`, running Ubuntu
26.04 LTS on ARM64, with Rust and Cargo 1.98.1 and glibc 2.43. Its path
dependencies were:

- `software-key-core` at `ca33b43e7563b7969910e211082a65f46e420b50`;
- `usb-gadget-supervisor` at `886fc1b1703807abeb27e8293334bddbef9927ff`;
- `display-backends` at `55ea8f1f96b663d57712df3a454449291f938682`.

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
