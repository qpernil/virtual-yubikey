# GlobalPlatform secure messaging

The virtual YubiKey implements card-side GlobalPlatform SCP03 and SCP11a/b/c over
CCID. Secure messaging is a property of the selected card session, not of one
applet implementation. A host selects an applet AID, establishes the secure
channel against that selected applet, and then sends authenticated and encrypted
APDUs through the common dispatcher.

The layer supports C-MAC, C-ENC, R-MAC, and R-ENC, protected-command
segmentation, and response chaining. It covers the Issuer Security Domain,
Management, PIV, YubiHSM Auth, FIDO2-over-CCID, and the selectable OpenPGP
fixture. Selecting another AID, resetting the card, or powering it off destroys
the live channel.

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
factory-provisioned. A valid uploaded certificate is not sufficient authority:
the first protected command must prove possession of the corresponding private
key through a valid C-MAC.

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
Stored card certificates must have a leaf matching the selected private key.
They are presentation material, not host trust anchors.

SCP11a/c host certificates are uploaded issuer-first with PSO (`2A`).
Validation uses the shared `software-key-core` X.509 validator and explicitly
installed CA keys. Leaf-only uploads work when the issuing CA key is installed;
intermediates may be uploaded with the leaf. Signature, validity, CA constraints,
critical extensions, and key-agreement usage are checked. A host-supplied root
never becomes trusted merely because it was uploaded. Empty serial allowlists
remove the serial restriction; nonempty lists restrict otherwise valid hosts.

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
