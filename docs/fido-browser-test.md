# FIDO browser qualification

The manual fixture in [scripts/fido-browser-test](../scripts/fido-browser-test)
exercises ordinary browser WebAuthn credential creation and authentication against
a USB authenticator. It uses the same WebAuthn options as the qualified Chrome/macOS
U2F and CTAP2 runs: localhost RP, ES256, cross-platform attachment,
non-discoverable credentials, user verification discouraged, direct attestation,
a 30-second timeout request, and the security-key hint.

## Start the test

Run on the computer whose browser is connected to the USB gadget:

```sh
python3 scripts/fido-browser-test.py
```

Open `http://localhost:8769/` in Chrome. Python 3's standard library is sufficient;
there are no browser packages, build steps or external services. The server binds
only to IPv4 loopback and serves only the two fixture files. An alternative port
can be selected with `--port`. Use the `localhost` URL: the RP ID is fixed to
`localhost`. Keep the page open between creation and authentication.

The page retains the returned credential only in memory so the next authentication
can supply its ID. Reloading or changing the protocol selection clears that
selection; it does not delete credentials or change the authenticator. The page
records elapsed time, browser identity, result/error names, credential-ID length
and signature length. It does not log PINs, credential IDs, challenges, attestation
payloads or signatures. Enter an existing PIN directly in the native browser dialog
if requested. User verification being discouraged does not prevent the device
from requiring a PIN.

## Select the protocol on the device

Record the original enabled USB applications before testing. Temporarily disable
the other FIDO protocol in Yubico Authenticator or through Management. For the
standard gadget serial, targeted CLI commands are:

```sh
# Qualify U2F.
ykman --device 12345678 config usb --enable u2f --disable fido2

# Qualify FIDO2 separately.
ykman --device 12345678 config usb --enable fido2 --disable u2f
```

Use the actual gadget serial if it differs. Do not change a physical key's
configuration for this workflow. Remove other authenticators before starting a
browser request, or select the gadget explicitly in the browser dialog. These
application settings preserve credentials. The page's protocol selector changes
its instructions; it cannot force CTAP1 versus CTAP2. With both enabled, this
non-discoverable, UV-discouraged request can use U2F.

Confirm the path in payload-free worker diagnostics:

- U2F: `component=u2f event=poll`, REGISTER `ins=0x01` or AUTHENTICATE
  `ins=0x02`, with control `0x03` on the qualified Chrome/macOS stack.
- FIDO2: `component=ctap2 event=request`, MakeCredential `command=0x01` or
  GetAssertion `command=0x02`.

U2F per-poll diagnostics require `--log-level debug`; they and their timestamp
collection are disabled at the default `info` level. Indication and FIDO2
presence lifecycle events remain visible at `info`. Configure diagnostic level
through the deployment profile's worker arguments and restore it afterward.
Use `debug` for timings: `trace` includes protocol payloads.

## Manual checks

1. Select the intended protocol in the page and configure the device accordingly.
2. Click **Create credential** and leave the joystick untouched. Verify one steady
   384 ms on / 384 ms off blink. In FIDO2 mode, enter the existing PIN if requested;
   the device's touch deadline begins when its presence wait starts.
3. For FIDO2, verify that the untouched wait expires after about 30 seconds and
   logs `USER_ACTION_TIMEOUT` (`2F`). For U2F, cancel the native browser dialog to
   end polling and verify that blinking stops within one full 768 ms cycle after
   the last eligible poll. The requested WebAuthn timeout is not a reliable
   deadline for the native U2F dialog.
4. Click **Create credential** again and press the joystick centre while the
   browser waits. Verify success and that the blink stops. For U2F, hold the centre
   briefly so a poll observes its pressed level; a press/release entirely between
   polls does not authorize anything.
5. Click **Authenticate** and repeat the physical-touch check. Verify success
   with the credential created by this page. No touch IPC is used for these checks.
6. Start another authentication without touching. Cancel the native dialog.
   FIDO2 should log a cancelled wait and `KEEPALIVE_CANCEL` (`2D`); U2F polling
   should end and its indication should expire. The page's **Cancel** button
   separately exercises `AbortController`; use the native dialog to reproduce
   the qualified browser-cancellation path.
7. Repeat for the other protocol. Restore the exact original USB application
   configuration and diagnostic level when finished. If both FIDO protocols were
   originally enabled, re-enable both; leave other applications unchanged.

Browser error names such as `NotAllowedError` can cover cancellation, expiry or
rejection; use the worker events to identify the device outcome. Browser elapsed
time includes PIN entry and dialog overhead. Credential-ID lengths (64 bytes for
this emulator's U2F handles and 32 bytes for ordinary FIDO2 credentials) are useful
observations but do not establish the wire protocol.

The fixture verifies browser interoperation and physical touch behavior. It reports
browser success and response sizes; it does not independently verify signatures
or attestation. Cryptographic verification is covered by the core and host-client
tests. The measured Chrome/macOS results are recorded in
[U2F qualification](u2f.md#browser-polling-and-indication) and
[FIDO2 browser touch qualification](../README.md#browser-touch-qualification).
