# GlobalPlatform secure messaging

The virtual YubiKey implements card-side GlobalPlatform SCP03 and SCP11a/b/c over
CCID. Secure messaging is a property of the selected card session, not of one
applet implementation. A host selects an applet AID, establishes the secure
channel against that selected applet, and then sends authenticated and encrypted
APDUs through the common dispatcher.

Beginning SCP03 or SCP11 channel establishment starts a fresh connection to the
selected applet. It clears that applet's connection-scoped authentication while
leaving its AID selected. By contrast, reselecting the same AID preserves its
authentication state, matching validated YubiKey behavior.

SCP03 EXTERNAL AUTHENTICATE accepts both short and extended APDU encoding;
its command MAC includes the received length encoding. This permits bootstrap
administration with Yubico host tools as well as pkcs11rs.

The layer supports C-MAC, C-ENC, R-MAC, and R-ENC, protected-command
segmentation, and response chaining. It covers the Issuer Security Domain,
Management, PIV, YubiHSM Auth, FIDO2-over-CCID, and the selectable OpenPGP
fixture. Selecting another AID, resetting the card, or powering it off destroys
the live channel.

Protected FIDO2 CTAP messages preserve `P1.b8`, which advertises
`NFCCTAP_GETRESPONSE` keepalive support. This applet flag is independent of
secure-command fragmentation. The secure-messaging regression uses the same
`80 10 80 00` command header as the host's CCID CTAP transport and verifies
the encrypted response and R-MAC.

## Factory Security Domain

The factory state follows the selectors used by YubiKey host software:

| Protocol | Selector | Factory material |
| --- | --- | --- |
| SCP03 | KID `00`, KVN `FF` | AES-128 ENC, MAC, and DEK keys `404142434445464748494A4B4C4D4E4F` |
| SCP11b | KID `13`, KVN `1` | Generated persistent P-256 card key and certificate |

The SCP11b private key is generated for each virtual device state and is not a
shared default key. Its certificate chain is returned from Issuer Security
Domain data object `BF21` in issuer-to-leaf order. The final certificate carries
the card's static P-256 key, matching the layout consumed by `libykpiv`.

The root and leaf names explicitly identify a Virtual YubiKey. They do not
chain to a Yubico root and do not claim Yubico manufacture or hardware
attestation. A validating host must explicitly trust the virtual root or use the
device's uncompressed P-256 public point as a development trust anchor.

SCP11b authenticates the card and protects traffic, but it does not authenticate
the off-card entity. It therefore does not by itself authorize Security Domain
key or trust changes. Factory SCP03 does authenticate the off-card entity.
SCP11a and SCP11c require explicitly provisioned host CA trust and are not
factory-provisioned. A CA imported by PUT KEY is trusted as its fixed public
key, represented as an RFC 5914 anchor for the portable RFC 5280 validator.
Critical GlobalPlatform OCE policies work with both bare-key and certificate
trust; the uploaded chain cannot supply an additional trusted key. A valid uploaded certificate is not sufficient authority:
the first protected command must prove possession of the corresponding private
key through a valid C-MAC.

The SCP11 variants use the GlobalPlatform agreement pairs:

| Variant | First agreement | Second agreement | Card response and forward secrecy |
| --- | --- | --- | --- |
| SCP11a | Host ephemeral × card ephemeral | Host static × card static | Returns a fresh card ephemeral point and receipt; provides forward secrecy when both ephemeral keys are erased. |
| SCP11b | Host ephemeral × card ephemeral | Host ephemeral × card static | Returns a fresh card ephemeral point and receipt; provides forward secrecy but does not authenticate the host. |
| SCP11c | Host ephemeral × card static | Host static × card static | Returns only the receipt; supports offline scripts and does not provide forward secrecy because the card has no ephemeral key. |

All variants derive the receipt key and AES working keys with X9.63 SHA-256 over
the two agreements. SCP11a/b authenticate the encoded request followed by the
card ephemeral TLV. SCP11c authenticates the encoded request alone.

## Security Domain administration

Select the Issuer Security Domain and establish SCP03 or SCP11a/c before
administration. Every modifying APDU must be protected; an unprotected command
is rejected even if a secure session exists. SCP11b cannot administer keys.

| Command | INS | Supported operations |
| --- | --- | --- |
| GENERATE KEY | `F1` | Generate a P-256 SCP11a/b/c private key and return its public point |
| PUT KEY | `D8` | Import P-256 card private keys, trusted host CA public keys, or AES-128 SCP03 key sets |
| STORE DATA | `E2` | Store card certificate chains, CA subject-key identifiers, and host certificate serial allowlists |
| DELETE | `E4` | Delete matching keys and their associated certificates and policy |

Private and symmetric imports use the authenticated channel's DEK in addition
to secure messaging. SCP03 imports verify all three key check values before
changing state. Installing a custom SCP03 set removes the public factory set;
up to three custom sets are supported. Replacement requires the old version to
exist and cannot overwrite another installed version. Deleting the final key
requires the explicit delete-last flag.

Card keys use KIDs `11`, `13`, and `15`; trusted host CA public keys use
`10` or `20`–`2F`. SCP11 versions are `1`–`127`. GET DATA exposes key
information, stored card chains at `BF21`, and CA identifiers at `FF33`/`FF34`.
CPLC is available at `9F7F` through `00 CA` or `80 CA`, including protected
requests. The legacy 42-byte value is returned directly for `00 CA`, or wrapped
as a `9F7F 2A` TLV for `80 CA`. This value-versus-TLV distinction applies to all
supported GET DATA objects, following GlobalPlatform Card Specification
section 11.3.3.1.
Its four-byte IC serial field (value bytes 12–15) contains a synthetic IC serial,
mapped from the configured virtual device serial in big-endian order. This is
an emulator identity choice; physical IC and YubiKey serials are independent.
All other fields are zero because physical production metadata is unavailable.
The value follows the configured device identity across
applet selection, reload, and Security Domain reset; it requires no state-schema
migration and does not claim a physical chip manufacturer or production date.
The public Issuer SD inventory supports these data objects:

| Selector | Object | Availability |
| --- | --- | --- |
| `0066` | Security Domain Recognition Data | Supported SCP03/SCP11 implementation options |
| `00E0` | Key Information Template | Existing SCP and trusted host-CA keys |
| `9F7F` | CPLC | Stable 42-byte virtual identity |
| `BF21` | Card certificate store | `A6 {83 KID KVN}` selects the stored issuer-to-leaf chain |
| `FF34` | Card CA identifiers | Factory root identifier and explicitly stored card issuer metadata |
| `FF33` | Host CA identifiers | Configured or explicitly stored host issuer metadata |
| `0083` | Host CA key lookup | `A6 {42 CA-ID}` resolves a host CA to KID/KVN |

Recognition Data contains the `73` template and GlobalPlatform protocol OIDs:
SCP03 uses option `60`, matching INITIALIZE UPDATE; SCP11 uses option bytes
`9B 06` (a/b/c, certificate chains, S8, X.509, without GP legacy certificates,
BF20 authorization or persistent host-key storage). Optional full-card
management-version and IIN/CIN claims are omitted: the emulator implements a
Security Domain subset rather than generic GlobalPlatform card management.

Factory `FF34` metadata references the subject key identifier of the virtual
attestation root. Generated certificates include SKI and AKI extensions.
Configured certificate-backed host CAs similarly supply their root's SKI;
if an older certificate lacks SKI, RFC 5280 method 1 derives it from the public
key. Older persisted factory identities and configured host CAs recover missing
metadata without changing private keys or stored certificates. Explicit
identifiers retain precedence. Raw public-key imports require STORE DATA to
associate their caller-chosen identifiers. Replacement or deletion removes
that key's identifier. No host CA is advertised on a factory-only card.

`83` returns a two-byte KID/KVN value for `00 CA`, or `83 02 KID KVN` for
`80 CA`. Unknown host identifiers return `6A88`; malformed selectors return
`6A80`; duplicate host identifiers return `6985` because no unique reference
can be selected. Card issuer identifiers cannot resolve as host CAs.
The listed objects are available publicly and through secure messaging.

A physical firmware 5.7.4 YubiKey's public full-selector scan confirms `66`,
`E0`, `9F7F`, `BF21` (with a key selector), and `FF34`; see the
[client's public Issuer SD inventory](https://github.com/qpernil/pkcs11rs/blob/master/docs/scp11.md#public-issuer-sd-data-objects).
Definitions follow GlobalPlatform Card Specification Annex H.3 and SCP11
sections 7.3/7.4. Embedded client qualification covers public and protected
SCP03/SCP11b reads, long certificate response chaining, persistence reload,
and configured host-CA reads over SCP11a/c.
Stored card certificates must have a leaf matching the selected private key.
They are presentation material, not host trust anchors.

SCP11a/c host certificates are uploaded issuer-first with PSO (`2A`).
Validation uses the shared `software-key-core` X.509 validator and explicitly
installed CA keys. Leaf-only uploads work when the issuing CA key is installed;
intermediates may be uploaded with the leaf. Signature, validity, CA constraints,
critical extensions, and key-agreement usage are checked. A host-supplied root
never becomes trusted merely because it was uploaded. Empty serial allowlists
remove the serial restriction; nonempty lists restrict otherwise valid hosts.

Certificate-backed host CA trust uses the shared portable RFC 5280 validator,
including critical `certificatePolicies` processing. Bare host CA public keys
imported through PUT KEY use the webpki validation path, which rejects critical
certificate policies, including the policy-bearing physical OCE fixture used
by `pkcs11rs`. Such profiles require certificate-backed configured host trust
on the virtual card; the bare-key path retains this compatibility limitation.
Dynamic host-login qualification also covers the supported key-agreement
certificate profile with bare CA keys. Neither path bypasses signature,
validity, usage or trust checks.

Keys, certificate chains, CA identifiers, and allowlists share the atomically
persisted per-serial Security Domain state. Failed commands leave it unchanged.
Uploads are bounded to eight certificates of at most 8192 bytes each; allowlists
hold at most 64 serials. The implementation supports P-256 and AES-128, not every
GlobalPlatform algorithm or YubiKey retry-counter/reset policy.

The core's `provision_scp11` API provides out-of-band emulator configuration,
but normal host provisioning uses these APDUs. Host-client integration tests
cover factory SCP03 → key/CA provisioning → persistence → certificate discovery
→ SCP11a/c → protected administration, plus rejected and malformed operations.

## Host-tool behavior

`yubico-piv-tool --enc` (also accepted as the deprecated `--scp11` spelling)
reads `BF21` for KID `13`/KVN `1`, extracts the public key from the final
certificate, and verifies the SCP11 receipt. Its current `libykpiv` path has no
trust-anchor option and does not validate the certificate chain. Receipt
verification proves that the card owns the key found in the retrieved
certificate; it does not authenticate that certificate's issuer.

`pkcs11rs` can validate the certificate chain against an explicit CA certificate
or use an explicit uncompressed P-256 public point. That trust decision belongs
to the host. The virtual card exposes the chain and proves possession but never
chooses the host's trust policy.

Protocol and tool behavior are based on the
[YubiKey secure-channel description](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-scp.html)
, the
[Security Domain command implementation](https://developers.yubico.com/yubikey-manager/API_Documentation/_modules/yubikit/securitydomain.html),
and the current
[`libykpiv` SCP11 implementation](https://github.com/Yubico/yubico-piv-tool/blob/master/lib/ykpiv.c).
