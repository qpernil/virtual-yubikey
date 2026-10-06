# Virtual OpenPGP card

The shared core implements the OpenPGP card 3.4.1 command and data-object model
used by the `pkcs11rs` OpenPGP client. The USB profile enables the applet over
CCID. Embedded readers install it when their `applets` allowlist includes
`openpgp`. Both use the same algorithms, access rules and state encoding.

## Commands and algorithms

The applet supports application discovery (`6E`, AID, capabilities, key status,
algorithm information), GET DATA, GET DATA ODD, GET NEXT DATA, SELECT DATA,
PUT DATA, extended-header-list private-key import, VERIFY, CHANGE REFERENCE
DATA, RESET RETRY COUNTER, GENERATE ASYMMETRIC KEY PAIR, PSO signature and
decipher, INTERNAL AUTHENTICATE, MANAGE SECURITY ENVIRONMENT, GET CHALLENGE,
and TERMINATE DF / ACTIVATE FILE.

Each of the signature, decipher and authentication slots has independently
changeable algorithm attributes. Available algorithms are RSA 2048–4096 in 256-bit steps,
P-256/P-384/P-521, secp256k1 and Brainpool P256/P384/P512. Signing slots also
support Ed25519; the decipher slot supports X25519. ECDSA returns fixed-width
`r || s`, Ed25519 signs the supplied message, RSA signatures use PKCS #1 v1.5
with the supplied payload, RSA decipher removes PKCS #1 v1.5 padding, and ECDH
returns the raw shared secret. The host performs protocol-specific KDFs.

The RSA size range matches direct qualification of a physical YubiKey 5 NFC
running firmware 5.7.4. Like that hardware, algorithm information (`FA`) advertises
2048, 3072 and 4096; direct algorithm-attribute writes also accept the six
intermediate sizes. Factory slots default to RSA 2048. Device firmware and host
SDK allowlists can impose different limits.

RSA import uses the advertised standard `e,p,q` format, with a 32-bit exponent.
ECC import accepts a private scalar and optional matching public key. Changing
algorithm attributes invalidates a key that no longer matches; generating or
importing a signature key resets its signature counter. Failed imports leave
the previous key intact. Public-key reads do not require login.

Each slot has a selectable certificate occurrence (authentication, decipher,
signature), optional touch policy, fingerprint and generation-time metadata.
Private-use data objects enforce their documented user/admin access conditions.
PINs, resetting codes and private keys cannot be read through GET DATA.

## Authentication and reset

Factory PW1 is `123456`, factory PW3 is `12345678`. PW1 has two independent
connection authorization flags: reference `81` for signatures and `82` for
other private operations. They share one credential and retry counter. PW3
(reference `83`) authorizes administration. Credentials have three attempts;
wrong credentials decrement a durable counter and a blocked credential cannot
be used until recovery. A successful check restores its retry budget.

By default a signature consumes PW1 reference `81` authorization. Changing
PW status to multiple-signature mode preserves it until deauthentication or
connection reset. Reselecting the same applet preserves authorization; switching
applets, resetting the connection or loading saved state clears it. Credential
changes and recovery clear the affected user/admin authorization. The applet
retains salted PIN verifiers rather than submitted plaintext PINs.

An administrator can provision a resetting code or reset PW1 directly. The
resetting code has its own durable attempt counter. TERMINATE requires PW3
verification or a blocked PW3; ACTIVATE after termination restores factory
OpenPGP state and removes its keys and data. Other applets remain intact.

UIF values `1` and `2` request physical presence through the shared transport
presence service; value `2` cannot be disabled except by factory reset. Embedded
clients without a presence source reject operations requiring touch.

## Storage and compatibility

Every device form stores `openpgp-<serial>.cbor` through the common
[per-applet storage runtime](storage.md), with mode-0600 atomic replacement.
The OpenPGP record has schema version 1 and stores keys, certificates, verifiers, retry counters, touch policy,
metadata, the signature counter and lifecycle state. Authorization is never
persisted. Invalid records fail startup and are not silently overwritten.

These files are virtual test-device storage, without hardware key protection.
The `pkcs11rs` client preserves its existing restrictions against potentially
key-destructive administrative commands. Provisioning tests use only isolated
virtual devices.

Optional OpenPGP KDF configuration, AES PSO, PIN-block format 2, application-
specific secure messaging and Yubico OpenPGP attestation are not advertised.
GlobalPlatform SCP03/SCP11 protection remains available through the shared card
channel. Firmware-specific retry-configuration commands are not implemented.

The core tests cover PIN recovery and lifecycle, key persistence, RSA import at all nine sizes from 2048 through 4096 in 256-bit steps,
signing, authentication and decipher, every advertised EC signing and key-agreement algorithm,
Ed25519, X25519, one-signature authorization, certificates and permanent touch.
USB CCID and the embedded provider client independently verify a P-256 signature.
Live USB CCID qualification includes successful `gpg --card-status` and
`gpg-card list` discovery. Provisioning and private operations with public tools
remain a separate acceptance boundary from the transport/emulator tests.

## Physical RSA qualification

Direct APDU tests on a YubiKey 5 NFC with firmware 5.7.4 verified the following:

| RSA modulus sizes | Algorithm attributes | Key generation, import and crypto operations |
| --- | --- | --- |
| 2048–4096 in 256-bit steps (nine sizes) | Accepted in SIG, DEC and AUT | Generated signature keys and verified signatures; imported decipher/authentication keys and verified decryption/authentication signatures at every size |
| 1024, 1280, 1536, 1792 | Rejected with `6A80` in all three slots | Not attempted after attribute rejection |

A halving probe above 2048 also rejected increments of 128, 64, 32, 16, 8,
4, 2 and 1 bit with `6A80` in every slot. A 256-bit increment passed generation,
import and crypto verification in all three slots. These probes establish the
smallest accepted power-of-two increment near 2048; they do not exhaustively
test every integer size.

The hardware advertises only 2048, 3072 and 4096 in its algorithm-information
object. Intermediate sizes were tested through direct attribute writes, bypassing
host SDK allowlists. The final 4096-bit keys in all three slots survived applet
reselection and a physical unplug/reinsert. After the power cycle, private
operations required fresh PIN verification; signing, decryption and
authentication succeeded with the unchanged keys. This qualification does not
establish limits for other firmware versions or models.
The reproducible harness and device-selection guards are documented in
[the provider's qualification workflow](https://github.com/qpernil/pkcs11rs/blob/master/docs/openpgp.md#physical-rsa-qualification).

Reference: [OpenPGP card specification 3.4.1](https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf).
