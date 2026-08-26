# Future persistent-storage and key-identity model

## Status

This document specifies a future storage design. The current independent FIDO,
PIV, and YubiHSM Auth state files remain the supported on-disk format until the
replacement is implemented and tested. Activating the
replacement must be explicit; an unsupported or corrupt state must continue to
fail closed rather than silently starting with an empty token.

## Goals

The future store should:

- preserve every existing key record while an unrelated key or object is
  created, changed, moved, or deleted;
- make a committed token generation immutable and independently verifiable;
- publish a new generation with one small atomic pointer update;
- retain the preceding generation until garbage collection makes rollback
  unnecessary;
- distinguish physical record identity from cryptographic key identity; and
- support a PKCS #11 key fingerprint that can identify equal keys in different
  cooperating tokens without changing `CKA_ID` semantics.

The design is conceptually Git-like, but it does not use Git object formats or
require Git at runtime.

## Content-addressed generations

Every immutable record is canonical CBOR addressed by:

```text
record_reference = SHA3-256(record_type || record_schema || canonical_cbor)
```

The type and schema domain-separate hashes whose payload bytes happen to be
equal. A token generation is a tree whose entries map logical names such as a
PIV slot or FIDO credential identifier to immutable record references. A root
record references that tree plus token-wide state such as retry counters and
configuration.

A mutation follows this order:

1. Write and synchronize every new immutable record.
2. Write and synchronize the new tree and root records.
3. Atomically replace the token's small `HEAD` reference.
4. Synchronize the containing directory.
5. Retain the prior reachable generation until a later garbage-collection
   policy proves it is safe to remove.

Existing records are never rewritten merely because another key is created.
If publishing the new root fails, `HEAD` still names the complete old
generation. A record hash identifies exact stored content; it is not a stable
identifier for the cryptographic key represented by that content.

Software-token records may encrypt sensitive canonical payloads before they
are content-addressed. Virtual-device test stores may deliberately use the same
logical records without encryption. Encryption nonces consequently affect the
physical record reference but never the logical key fingerprint.

## Cross-token key fingerprints

`pkcs11rs` should expose a read-only vendor attribute named
`CKA_PKCS11RS_KEY_FINGERPRINT`. It is separate from both storage references and
the standard attributes:

- `CKA_ID` remains application-controlled and may be empty.
- `CKA_UNIQUE_ID` continues to identify one particular PKCS #11 object.
- `CKA_PKCS11RS_KEY_FINGERPRINT` identifies cryptographic key equivalence.

Related public-key, private-key, and certificate objects expose the same
asymmetric-key fingerprint. Version 1 is calculated from the canonical public
identity:

```text
0x01 || SHA3-256(
    "pkcs11rs asymmetric key fingerprint v1" ||
    DER SubjectPublicKeyInfo
)
```

Secret keys require a comparison domain because an unkeyed hash of secret key
material would provide an offline equality and guessing oracle. Tokens that
should produce comparable secret-key fingerprints are provisioned with the
same random comparison-domain key. Version 1 is calculated internally as:

```text
domain_id = SHA3-256(
    "pkcs11rs comparison domain id v1" || comparison_domain_key
)

secret_fingerprint = KMAC256(
    comparison_domain_key,
    "pkcs11rs secret key fingerprint v1" ||
    canonical CKA_KEY_TYPE || key_bit_length || secret_key_material
)

attribute_value = 0x02 || domain_id || secret_fingerprint
```

Including key type deliberately prevents identical bytes used as, for example,
an AES key and an HMAC key from being treated as the same logical key. Labels,
usage policy, `CKA_ID`, token identifiers, storage encryption, and record
references are excluded.

The secret-key attribute is available only through the authorization rules for
the private key object and is computed inside the backend. Implementations may
cache it only as encrypted derived data. Setting it through
`C_SetAttributeValue` returns `CKR_ATTRIBUTE_READ_ONLY`.

## Comparison-domain provisioning

The comparison-domain key is administrative token configuration, not an
ordinary readable PKCS #11 attribute. An SO-authorized administration command
may generate it or import the same value into several cooperating tokens. The
interface must:

- accept imported material through a protected input stream or descriptor, not
  a command-line argument;
- encrypt it independently under each token's storage key;
- never return it through PKCS #11 or the administration interface;
- zeroize plaintext provisioning buffers; and
- expose only `domain_id`, allowing an administrator to confirm whether two
  tokens' secret-key fingerprints are comparable.

Replacing the comparison-domain key is an explicit rotation operation. It
changes every calculated secret-key fingerprint without changing any stored
key. Existing hardware HSMs can participate only if their provider or firmware
can store the domain key and perform the calculation without extracting the
protected secret key.

## Migration constraints

- Introduce versioned record codecs before changing the active store.
- Build and validate a complete new generation before switching `HEAD`.
- Keep the old state file untouched until the new generation has been loaded
  and exercised successfully.
- Test power loss before every durability boundary.
- Test that creating a new key leaves all prior key-record hashes reachable and
  unchanged.
- Test that equivalent asymmetric keys have equal fingerprints across tokens.
- Test that equivalent secret keys compare equal only inside the same
  comparison domain.
- Test that comparison-domain rotation changes secret-key fingerprints and
  never exposes the domain key.
