# YKOATH applet

Hostnames and device/account identifiers below are illustrative; replace them with your own configured values.

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

Live USB qualification uses the gadget-host gadget with the 5.8 profile and serial
`12345678`, accessed from macOS with YubiKey Manager 5.9.2. The `ykman` CLI
checks OATH disable/re-enable with credential preservation, add/list/delete, all
three HOTP hashes, rename without resetting the counter, and password
installation/change/removal with incorrect-password rejection. Yubico's Python SDK
checks all six RFC 6238 timestamps per hash, ten HOTP counters per hash, and
fragmented LIST/CALCULATE ALL in plain mode, SCP03 and SCP11b. Password installation, incorrect-password
rejection, protected login, change and removal pass over USB. An actual worker
restart preserves the application ID, password, credential and next HOTP counter.
Temporary qualification credentials and password protection are removed afterward.

The deployed gadget-host device retains the same six public-fixture credentials as
the physical smoke-test YubiKeys: `HOTP-SHA1`, `HOTP-SHA256`, `HOTP-SHA512`,
`TOTP-SHA1`, `TOTP-SHA256` and `TOTP-SHA512`, all with the `pkcs11rs-smoke:`
prefix. They use the public RFC 6238 secrets, six-digit HOTP starting at counter
zero, and eight-digit TOTP with a 30-second period. Provisioning
does not calculate HOTP codes. Worker restart preserves all six credentials;
native pkcs11rs discovers their seven OTP object views after module
reinitialization.

Native pkcs11rs USB checks generate codes for all six retained samples, including
all six RFC 6238 timestamps per hash, repeated output-length queries and
short-buffer retries without extra HOTP counter consumption. `C_SetPIN` installs
and removes the application password; incorrect-password rejection and protected
login preserve the sample inventory.

A touch-required USB calculation times out after 15 seconds while CCID keeps the
connection alive. A physical joystick-center press also completes native
`C_Sign` with the expected RFC 6238 code. The display's slow presence-wait blink
and its completion on touch are visually confirmed. USB SCP11a/c and OTP vectors
against password-protected physical YubiKeys are separate qualification targets.
The virtual applet does not supply hardware secret protection or NFC transport.

iOS runtime qualification uses temporary embedded profiles with preseeded sample
credentials and an explicit pin for the matching persisted SCP11b public key.
Both Swift and Objective-C smoke apps discover six applet slots and seven OATH
object views on iOS 27.0 Simulator; the Swift app also passes on a physical iPhone
running iOS 27.2. OATH login reports SCP11b in each case. A different valid card
key is rejected with `CKR_DEVICE_ERROR`, without authenticated OATH inventory.
These checks qualify iOS discovery, login and inventory rather than OTP-vector
generation. The normal app configurations contain no embedded device or pin.

References: [YKOATH protocol](https://developers.yubico.com/OATH/YKOATH_Protocol.html),
[Yubico OATH client](https://developers.yubico.com/yubikey-manager/API_Documentation/_modules/yubikit/oath.html),
[pkcs11rs OATH mapping](https://github.com/qpernil/pkcs11rs/blob/master/docs/oath.md).
