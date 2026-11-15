# Shared APDU definitions

`yubikey-apdu` is a dependency-free protocol crate used by pkcs11rs command
producers and virtual-yubikey card handlers. It does not depend on the emulator,
cryptography, PC/SC, or PKCS #11.

`CommandApdu` and `ResponseApdu` provide the shared borrowed ISO 7816 wire
codec. Short and extended APDU lengths are validated strictly. P1/P2 bytes are
preserved without interpretation. U2F's legacy empty extended-Lc encoding is
handled by the FIDO applet, rather than accepted by the ISO decoder. Debug
formatting reports payload lengths without printing payload bytes.

Each applet module owns its AID and command envelopes (`ApduSpec`): CLA/INS,
named P1/P2 constraints, request and successful-response lengths, response
continuation instruction, and any additional SCP-protected response status.
`iso7816` and `scp` own their respective protocol commands. Resolve commands
with `find` against the selected applet's `COMMANDS`, never a global INS table.
For example, OpenPGP GENERATE uses P1=80/81, while PIV GENERATE uses P1=00.

Host code can construct a validated command with `ApduSpec::command`, encode
it, and send it through its transport. Card code decodes the wire frame and
validates it against the selected applet before dispatch. Both sides can check
the successful response envelope with `validate_response`. Error statuses and
TLV contents, supported algorithms, authorization, and state transitions remain
in their owning implementations. A definition describes a command, not a
promise that every card profile implements it. Host error mapping is local.

ISO command chaining is a transport operation on CLA; it does not reinterpret
P1/P2 or consult opcode exceptions. GlobalPlatform P1-based command chaining
is not implemented. This crate performs no I/O, retries, or replay. Length
correction belongs to the transport owner. A bare `6Cxx` can request one
retransmission with corrected Le; it does not by itself establish where SCP
state was consumed. The host changes only the wire Le without new protection
or another SCP state advance. `Le` remains plaintext and is excluded from
C-MAC. ISO 7816-4 defines `61xx` and `6Cxx` independently of T=0/T=1.

Tests include fixed wire vectors, short/extended length boundaries, malformed
encodings, applet-local command resolution, and response envelope checks.
