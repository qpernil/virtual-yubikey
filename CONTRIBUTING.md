# Contributing

Thank you for helping improve Virtual YubiKey.

The project is experimental. Discuss substantial protocol, persistent-state,
USB identity, or architecture changes in an issue before implementing them.
Small focused fixes and documentation corrections can go directly to a pull
request.

## Pull requests

Keep changes focused and include:

1. the compatibility problem being solved;
2. security or persistent-state implications;
3. tests for FIDO, PIV, OpenPGP, management, CCID, or CTAPHID behavior affected
   by the change; and
4. documentation updates for externally visible behavior.

Run the same checks as CI before submitting:

```sh
cargo test --locked --workspace --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

By contributing, you agree that your contribution is licensed under either the
MIT License or Apache License 2.0, at your option.
