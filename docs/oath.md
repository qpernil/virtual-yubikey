# YKOATH applet

The shared core implements YKOATH at AID `A0000005272101` for the USB CCID
worker and pkcs11rs embedded virtual YubiKeys. The default 5.8 profile installs OATH and
advertises Management capability `0x0020`. Management USB enablement also gates
applet selection. The factory application has no credentials or access password.

## Commands and credentials

| Instruction | Behavior |
| --- | --- |
| SELECT (`A4`, P1 `04`) | Firmware, persistent random eight-byte application ID/salt, and a fresh challenge when password protection is configured |
| PUT (`01`) | Create or overwrite a named HOTP/TOTP credential, including hash, digits, properties and HOTP initial moving factor |
| DELETE (`02`) | Remove one credential |
| SET CODE (`03`) | Install, replace or remove the application access key after current authorization |
| RESET (`04`, `DE AD`) | Clear OATH credentials and password and generate a new application ID, without authentication |
| RENAME (`05`) | Change a credential's exact name bytes without changing its secret or counter |
| LIST (`A1`) | Name and type/hash only; no calculation or counter increment |
| CALCULATE (`A2`) | Full HMAC or dynamically truncated result with the configured digit count |
| VALIDATE (`A3`) | Mutual HMAC-SHA1 challenge-response authentication |
| CALCULATE ALL (`A4`, P1 `00`) | Calculate TOTP credentials, with HOTP and touch-required placeholders |
| SEND REMAINING (`A5`) | Continue the preceding logical response after `61xx` |

HOTP and TOTP support HMAC-SHA1, SHA256 and SHA512, six to eight digits, and
14–64 secret bytes at the native protocol boundary. pkcs11rs pads shorter imported
secrets to fourteen bytes without changing HMAC semantics. Names are exact byte
strings of 1–64 bytes. The virtual applet holds up to 64 credentials. Malformed
imports and capacity failures leave existing credentials unchanged; native PUT
replaces an existing name, while pkcs11rs rejects duplicate imports.

HOTP uses a persistent 64-bit counter, initialized through the protocol's
four-byte big-endian IMF. Each successful full or truncated calculation advances
it once. Enumeration, response continuation, failed authentication and touch
timeouts do not advance it. TOTP takes the challenge supplied by the host;
periods and clock interpretation belong to the client. The optional
only-increasing property enforces strictly increasing eight-byte TOTP challenges
and persists the last accepted value.

Touch-required calculations return `PresenceRequired(Always)` before computing
or changing durable state. A fresh grant is bound to the exact pending command;
there is no touch cache. CALCULATE ALL emits placeholders for HOTP and
touch-required credentials without consuming a counter or requesting presence.
The USB worker supplies its ordinary touch wait and CCID time extensions. The
embedded connector has no touch source and returns `6985`, mapped by pkcs11rs to
`CKR_FUNCTION_CANCELED`.

## Authentication, SCP and persistence

Clients derive the 16-byte access key with PBKDF2-HMAC-SHA1, 1000 iterations,
using SELECT's application ID as salt. The applet stores this key, never the
password. SET CODE proves possession of the new key before changing it.
When configured, access requires VALIDATE except for SELECT and RESET.
Authentication uses constant-time comparisons and a single-use SELECT challenge;
a failed validation requires reselection. SELECT, deselection, power transitions
and connection reset invalidate authorization.

SCP03 and SCP11a/b/c wrap the same commands through the shared secure-messaging
layer. Establishment clears OATH authorization while preserving SELECT's pending
challenge so clients can validate after channel establishment. SCP authorization
does not itself unlock password-protected OATH. Responses are protected once,
then fragmented; plain SEND REMAINING collects ciphertext and the final R-MAC
before the client verifies and decrypts the logical response.

`oath-<serial>.cbor` stores the application ID, access key, credentials, properties,
HOTP counters and increasing-challenge state through the [shared storage
runtime](storage.md). Authorization, pending challenges, presence and response
fragments are transient. USB and embedded hosts flush OATH mutations before
returning the response. Files contain unencrypted virtual secrets and require
the same owner-only access as other applet records. Missing OATH files initialize
factory state; invalid files fail startup. Existing Management enablement masks
are preserved, so an older stored mask may require explicitly enabling OATH.
Whole-device snapshots use version 4 and read versions 1–3 with factory OATH state.

## Verification and limits

Run the core checks with `cargo test -p virtual-yubikey-core oath` and the
provider checks from the sibling pkcs11rs checkout with
`cargo test --lib --no-default-features --features embedded-virtual-yubikey oath`.

Core tests cover RFC 6238's six timestamps for every hash, RFC 4226 and independent
SHA256/SHA512 HOTP vectors, initial counters, full and truncated results, password
changes and removal, replay rejection, touch policy, capacity, malformed requests,
rename/deletion/reset, continuation, capability gating and persistence.
USB CCID tests cover touch timeout, fresh success, time extensions and counter
preservation. pkcs11rs tests exercise the actual shared core through its OATH
protocol client with plain traffic and SCP03/SCP11a/b/c, including protected
multi-fragment enumeration. Exported PKCS #11 tests cover login visibility,
import, all six type/hash combinations, length queries and short buffers,
shared SHA1 HOTP views, deletion, password changes, deselection and restart.

These are software interoperability checks. Live USB OATH host-tool qualification
and physical password/SCP OTP-vector qualification are separate from them. The
virtual applet does not supply hardware secret protection or NFC transport.

References: [YKOATH protocol](https://developers.yubico.com/OATH/YKOATH_Protocol.html),
[Yubico OATH client](https://developers.yubico.com/yubikey-manager/API_Documentation/_modules/yubikit/oath.html),
[pkcs11rs OATH mapping](https://github.com/qpernil/pkcs11rs/blob/master/docs/oath.md).
