use super::*;
use crate::{ApduExchange, FidoAuthenticator, FidoConfiguration};
use der::Decode;
use signature::Verifier;

const APP: [u8; 32] = [0x42; 32];
const CHALLENGE: [u8; 32] = [0x73; 32];

fn state() -> FidoState {
    FidoState::new([1; 16], FidoConfiguration::default())
}
fn apdu(ins: u8, p1: u8, data: &[u8]) -> Vec<u8> {
    let mut raw = vec![0, ins, p1, 0, 0];
    if !data.is_empty() {
        raw.extend_from_slice(&(data.len() as u16).to_be_bytes());
        raw.extend_from_slice(data);
    }
    raw.extend_from_slice(&[0, 0]);
    raw
}
fn run(state: &mut FidoState, ins: u8, p1: u8, data: &[u8], granted: bool) -> ResponseApdu {
    let raw = apdu(ins, p1, data);
    exchange(
        state,
        &CommandApdu::decode(&raw).unwrap(),
        if granted {
            PresenceAuthorization::Granted
        } else {
            PresenceAuthorization::Absent
        },
    )
    .unwrap_or_else(|_| ResponseApdu::status(0x6985))
}
fn register(state: &mut FidoState) -> Vec<u8> {
    let data = [CHALLENGE.as_slice(), APP.as_slice()].concat();
    let response = run(state, 1, 0, &data, true);
    assert_eq!(response.status, 0x9000);
    response.data
}
fn handle(reg: &[u8]) -> &[u8] {
    &reg[67..67 + usize::from(reg[66])]
}
fn authentication(handle: &[u8], app: &[u8]) -> Vec<u8> {
    [CHALLENGE.as_slice(), app, &[handle.len() as u8], handle].concat()
}
fn verify_auth(reg: &[u8], response: &ResponseApdu, app: &[u8]) {
    assert_eq!(response.status, 0x9000);
    let message = [app, &response.data[..5], CHALLENGE.as_slice()].concat();
    let public = p256::ecdsa::VerifyingKey::from_sec1_bytes(&reg[1..66]).unwrap();
    public
        .verify(
            &message,
            &p256::ecdsa::Signature::from_der(&response.data[5..]).unwrap(),
        )
        .unwrap();
}
fn cert_len(bytes: &[u8]) -> usize {
    if bytes[1] < 128 {
        return 2 + usize::from(bytes[1]);
    }
    let size = usize::from(bytes[1] & 127);
    2 + size
        + bytes[2..2 + size]
            .iter()
            .fold(0, |n, b| n * 256 + usize::from(*b))
}

#[test]
fn browser_registration_control_requires_presence_and_creates_a_usable_key() {
    let mut state = state();
    let data = [CHALLENGE.as_slice(), APP.as_slice()].concat();
    assert_eq!(run(&mut state, 1, 3, &data, false).status, 0x6985);
    assert!(state.u2f_wrapping_key.is_none());
    let registration = run(&mut state, 1, 3, &data, true);
    assert_eq!(registration.status, 0x9000);
    let reg = registration.data;
    let request = authentication(handle(&reg), &APP);
    assert_eq!(run(&mut state, 2, 3, &request, false).status, 0x6985);
    let signed = run(&mut state, 2, 3, &request, true);
    verify_auth(&reg, &signed, &APP);
    assert_eq!(signed.data[0], 1);
    assert_eq!(u32::from_be_bytes(signed.data[1..5].try_into().unwrap()), 1);
    for unsupported in [1, 2, 4, 7, 8, 0x80, 0x83] {
        assert_eq!(run(&mut state, 1, unsupported, &data, true).status, 0x6a86);
    }
}

#[test]
fn registration_is_attested_wrapped_and_does_not_store_a_credential() {
    let mut state = state();
    let reg = register(&mut state);
    assert_eq!(reg[0], 5);
    assert_eq!(handle(&reg).len(), 64);
    assert_eq!(state.credentials.len(), 0);
    assert_eq!(state.u2f_counter, 0);
    let cert_start = 67 + usize::from(reg[66]);
    let length = cert_len(&reg[cert_start..]);
    let cert = x509_cert::Certificate::from_der(&reg[cert_start..cert_start + length]).unwrap();
    let public = cert
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .as_bytes()
        .unwrap();
    let signed = [
        &[0][..],
        APP.as_slice(),
        CHALLENGE.as_slice(),
        handle(&reg),
        &reg[1..66],
    ]
    .concat();
    p256::ecdsa::VerifyingKey::from_sec1_bytes(public)
        .unwrap()
        .verify(
            &signed,
            &p256::ecdsa::Signature::from_der(&reg[cert_start + length..]).unwrap(),
        )
        .unwrap();
    let persisted_length = state.encode_persistent().unwrap().len();
    let another = register(&mut state);
    assert_ne!(handle(&reg), handle(&another));
    assert_ne!(&reg[1..66], &another[1..66]);
    assert_eq!(persisted_length, state.encode_persistent().unwrap().len());
    assert!(state.credentials.is_empty());
    assert_eq!(state.pin.as_deref().unwrap().as_slice(), b"123456");
}

#[test]
fn presence_check_only_and_optional_presence_have_correct_signatures_and_counters() {
    let mut state = state();
    let registration = [CHALLENGE.as_slice(), APP.as_slice()].concat();
    assert_eq!(run(&mut state, 1, 0, &registration, false).status, 0x6985);
    assert!(state.u2f_wrapping_key.is_none());
    assert!(state.attestation.is_none());
    let reg = register(&mut state);
    state.take_persistent_change();
    let auth = authentication(handle(&reg), &APP);
    for mode in [3, 7] {
        assert_eq!(run(&mut state, 2, mode, &auth, false).status, 0x6985);
        assert_eq!(state.u2f_counter, 0);
        assert!(!state.take_persistent_change());
    }
    assert_eq!(run(&mut state, 2, 7, &auth, true).status, 0x6985);
    let response = run(&mut state, 2, 3, &auth, true);
    assert_eq!(&response.data[..5], &[1, 0, 0, 0, 1]);
    verify_auth(&reg, &response, &APP);
    let response = run(&mut state, 2, 8, &auth, false);
    assert_eq!(&response.data[..5], &[0, 0, 0, 0, 2]);
    verify_auth(&reg, &response, &APP);
    let reg2 = register(&mut state);
    let response = run(&mut state, 2, 3, &authentication(handle(&reg2), &APP), true);
    assert_eq!(&response.data[..5], &[1, 0, 0, 0, 3]);
    verify_auth(&reg2, &response, &APP);
}

#[test]
fn every_handle_byte_appid_and_other_device_are_authenticated_before_touch() {
    let mut state = state();
    let reg = register(&mut state);
    state.take_persistent_change();
    for offset in 0..64 {
        let mut modified = handle(&reg).to_vec();
        modified[offset] ^= 1;
        assert_eq!(
            run(&mut state, 2, 3, &authentication(&modified, &APP), false).status,
            0x6a80
        );
    }
    assert_eq!(
        run(
            &mut state,
            2,
            7,
            &authentication(handle(&reg), &[0; 32]),
            false
        )
        .status,
        0x6a80
    );
    let mut other = FidoState::new([1; 16], FidoConfiguration::default());
    register(&mut other);
    assert_eq!(
        run(&mut other, 2, 3, &authentication(handle(&reg), &APP), true).status,
        0x6a80
    );
    assert_eq!(state.u2f_counter, 0);
    assert!(!state.take_persistent_change());
}

#[test]
fn handles_and_global_counter_survive_restore_and_connection_reset() {
    let mut state = state();
    let reg = register(&mut state);
    let auth = authentication(handle(&reg), &APP);
    run(&mut state, 2, 3, &auth, true);
    let encoded = Zeroizing::new(state.encode_persistent().unwrap());
    let mut restored =
        FidoState::decode_persistent(&encoded, [1; 16], FidoConfiguration::default()).unwrap();
    restored.reset_connection();
    restored.power_cycle();
    let response = run(&mut restored, 2, 3, &auth, true);
    assert_eq!(&response.data[..5], &[1, 0, 0, 0, 2]);
    verify_auth(&reg, &response, &APP);
    assert!(restored.credentials.is_empty());
}

#[test]
fn reset_invalidates_handles_and_clears_pin_and_counter_but_keeps_attestation() {
    let mut state = state();
    let reg = register(&mut state);
    let cert = state.attestation.as_ref().unwrap().certificate().to_vec();
    let auth = authentication(handle(&reg), &APP);
    run(&mut state, 2, 3, &auth, true);
    assert_eq!(super::super::exchange(&mut state, &[7]), [0]);
    assert!(state.pin.is_none());
    assert_eq!(state.u2f_counter, 0);
    assert_eq!(run(&mut state, 2, 7, &auth, false).status, 0x6a80);
    let new_reg = register(&mut state);
    assert_eq!(state.attestation.as_ref().unwrap().certificate(), cert);
    assert_ne!(handle(&reg), handle(&new_reg));
    assert_eq!(run(&mut state, 2, 3, &auth, true).status, 0x6a80);
    assert_eq!(super::super::exchange(&mut state, &[7]), [0x30]);
    state.power_cycle();
    state.reset_deadline = Some(std::time::Instant::now() - std::time::Duration::from_secs(1));
    assert_eq!(super::super::exchange(&mut state, &[7]), [0x30]);
    state.reset_connection();
    assert_eq!(super::super::exchange(&mut state, &[7]), [0x30]);
}

#[test]
fn counter_exhaustion_fails_closed() {
    let mut state = state();
    let reg = register(&mut state);
    state.u2f_counter = u32::MAX;
    assert_eq!(
        run(&mut state, 2, 3, &authentication(handle(&reg), &APP), true).status,
        0x6f00
    );
    assert_eq!(state.u2f_counter, u32::MAX);
}

#[test]
fn short_extended_and_invalid_apdus_are_handled_without_panics() {
    let mut fido = FidoAuthenticator::new();
    for raw in [
        vec![0, 3, 0, 0],
        vec![0, 3, 0, 0, 0],
        vec![0, 3, 0, 0, 0, 0, 0],
        vec![0, 3, 0, 0, 0, 0, 0, 0, 0],
    ] {
        assert_eq!(
            fido.exchange_u2f(&raw, PresenceAuthorization::Absent),
            ApduExchange::Complete(b"U2F_V2\x90\x00".to_vec())
        );
    }
    for (raw, status) in [
        (vec![0, 3, 0], 0x6700u16),
        (vec![0, 3, 0, 0, 0, 0], 0x6700),
        (vec![0, 3, 0, 0, 1, 9, 0], 0x6700),
        (vec![1, 3, 0, 0, 0], 0x6e00),
        (vec![0, 4, 0, 0, 0], 0x6d00),
        (vec![0, 3, 1, 0, 0], 0x6a86),
        (vec![0, 3, 0, 1, 0], 0x6a86),
        (vec![0, 2, 2, 0, 0], 0x6a86),
    ] {
        assert_eq!(
            fido.exchange_u2f(&raw, PresenceAuthorization::Granted),
            ApduExchange::Complete(status.to_be_bytes().to_vec())
        );
    }
    let mut state = state();
    for size in [0, 1, 63, 65, 255] {
        assert_eq!(run(&mut state, 1, 0, &vec![0; size], true).status, 0x6700);
    }
    for size in [0, 1, 64, 66, 129, 255] {
        assert_eq!(run(&mut state, 2, 3, &vec![0; size], true).status, 0x6700);
    }
}

#[test]
fn version_five_migration_preserves_attestation_and_initializes_wrapping_lazily() {
    let mut state = state();
    register(&mut state);
    let encoded = Zeroizing::new(state.encode_persistent().unwrap());
    let mut decoder = minicbor::Decoder::new(&encoded);
    assert_eq!(decoder.map().unwrap(), Some(10));
    let start = decoder.position();
    for _ in 0..8 {
        decoder.skip().unwrap();
        decoder.skip().unwrap();
    }
    let mut old = Zeroizing::new(vec![0xa8]);
    old.extend_from_slice(&encoded[start..decoder.position()]);
    old[2] = 5;
    let mut migrated =
        FidoState::decode_persistent(&old, [1; 16], FidoConfiguration::default()).unwrap();
    assert_eq!(
        migrated.attestation.as_ref().unwrap().certificate(),
        state.attestation.as_ref().unwrap().certificate()
    );
    assert!(migrated.u2f_wrapping_key.is_none());
    assert_eq!(migrated.u2f_counter, 0);
    register(&mut migrated);
    assert_eq!(migrated.u2f_wrapping_key.as_ref().unwrap().len(), 32);
    assert!(FidoState::decode_persistent(&old, [2; 16], FidoConfiguration::default()).is_err());
}

#[test]
fn ctap2_can_assert_a_u2f_handle_and_cannot_discover_it() {
    let mut state = state();
    let rp = "https://u2f.example/app-id.json";
    let app = sha256(rp.as_bytes());
    let reg = run(
        &mut state,
        1,
        0,
        &[CHALLENGE.as_slice(), &app].concat(),
        true,
    )
    .data;
    let mut request = vec![2];
    minicbor::Encoder::new(&mut request)
        .map(3)
        .unwrap()
        .u8(1)
        .unwrap()
        .str(rp)
        .unwrap()
        .u8(2)
        .unwrap()
        .bytes(&CHALLENGE)
        .unwrap()
        .u8(3)
        .unwrap()
        .array(1)
        .unwrap()
        .map(2)
        .unwrap()
        .str("type")
        .unwrap()
        .str("public-key")
        .unwrap()
        .str("id")
        .unwrap()
        .bytes(handle(&reg))
        .unwrap();
    let response = super::super::exchange(&mut state, &request);
    assert_eq!(response[0], 0);
    let mut decoder = minicbor::Decoder::new(&response[1..]);
    assert_eq!(decoder.map().unwrap(), Some(3));
    assert_eq!(decoder.u8().unwrap(), 1);
    decoder.skip().unwrap();
    assert_eq!(decoder.u8().unwrap(), 2);
    let auth = decoder.bytes().unwrap().to_vec();
    assert_eq!(&auth[..32], app);
    assert_eq!(&auth[32..], [1, 0, 0, 0, 1]);
    assert_eq!(decoder.u8().unwrap(), 3);
    let sig = p256::ecdsa::Signature::from_der(decoder.bytes().unwrap()).unwrap();
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&reg[1..66])
        .unwrap()
        .verify(&[auth, CHALLENGE.to_vec()].concat(), &sig)
        .unwrap();
    assert!(state.credentials.is_empty());
    let mut discover = vec![2];
    minicbor::Encoder::new(&mut discover)
        .map(2)
        .unwrap()
        .u8(1)
        .unwrap()
        .str(rp)
        .unwrap()
        .u8(2)
        .unwrap()
        .bytes(&CHALLENGE)
        .unwrap();
    assert_eq!(super::super::exchange(&mut state, &discover), [0x2e]);
    let auth = run(&mut state, 2, 3, &authentication(handle(&reg), &app), true);
    assert_eq!(&auth.data[..5], [1, 0, 0, 0, 2]);
    verify_auth(&reg, &auth, &app);
}

#[test]
fn ctap2_exclusion_recognizes_wrapped_handles_without_storing_them() {
    let mut state = state();
    let rp = "u2f-exclusion.example";
    let app = sha256(rp.as_bytes());
    let reg = run(
        &mut state,
        1,
        0,
        &[CHALLENGE.as_slice(), &app].concat(),
        true,
    )
    .data;
    let mut request = vec![1];
    minicbor::Encoder::new(&mut request)
        .map(5)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&CHALLENGE)
        .unwrap()
        .u8(2)
        .unwrap()
        .map(1)
        .unwrap()
        .str("id")
        .unwrap()
        .str(rp)
        .unwrap()
        .u8(3)
        .unwrap()
        .map(1)
        .unwrap()
        .str("id")
        .unwrap()
        .bytes(&[1])
        .unwrap()
        .u8(4)
        .unwrap()
        .array(1)
        .unwrap()
        .map(2)
        .unwrap()
        .str("type")
        .unwrap()
        .str("public-key")
        .unwrap()
        .str("alg")
        .unwrap()
        .i8(-7)
        .unwrap()
        .u8(5)
        .unwrap()
        .array(1)
        .unwrap()
        .map(2)
        .unwrap()
        .str("type")
        .unwrap()
        .str("public-key")
        .unwrap()
        .str("id")
        .unwrap()
        .bytes(handle(&reg))
        .unwrap();
    assert_eq!(super::super::exchange(&mut state, &request), [0x19]);
    assert!(state.credentials.is_empty());
    assert_eq!(state.u2f_counter, 0);
}

#[test]
fn corrupt_or_missing_wrapping_metadata_fails_restoration() {
    let mut state = state();
    register(&mut state);
    let encoded = Zeroizing::new(state.encode_persistent().unwrap());
    let mut decoder = minicbor::Decoder::new(&encoded);
    decoder.map().unwrap();
    let start = decoder.position();
    for _ in 0..8 {
        decoder.skip().unwrap();
        decoder.skip().unwrap();
    }
    let end = decoder.position();
    for (key, counter) in [
        (vec![0; 31], Some(0)),
        (vec![0; 33], Some(0)),
        (vec![], Some(1)),
        (vec![0; 32], None),
    ] {
        let mut broken = Zeroizing::new(vec![if counter.is_some() { 0xaa } else { 0xa9 }]);
        broken.extend_from_slice(&encoded[start..end]);
        let mut encoder = minicbor::Encoder::new(&mut *broken);
        encoder.u8(9).unwrap().bytes(&key).unwrap();
        if let Some(counter) = counter {
            encoder.u8(10).unwrap().u32(counter).unwrap();
        }
        assert!(
            FidoState::decode_persistent(&broken, [1; 16], FidoConfiguration::default()).is_err()
        );
    }
    let mut duplicate = Zeroizing::new(encoded.to_vec());
    duplicate[0] = 0xab;
    minicbor::Encoder::new(&mut *duplicate)
        .u8(9)
        .unwrap()
        .bytes(&[1; 32])
        .unwrap();
    assert!(
        FidoState::decode_persistent(&duplicate, [1; 16], FidoConfiguration::default()).is_err()
    );
}

#[test]
fn ctap2_u2f_assertions_sign_presence_and_verification_independently() {
    let mut state = state();
    let rp = "presence.example";
    let app = sha256(rp.as_bytes());
    let reg = run(
        &mut state,
        1,
        0,
        &[CHALLENGE.as_slice(), &app].concat(),
        true,
    )
    .data;
    let public = p256::ecdsa::VerifyingKey::from_sec1_bytes(&reg[1..66]).unwrap();
    for present in [false, true] {
        for verified in [false, true] {
            let response = assertion(&mut state, handle(&reg), rp, &CHALLENGE, present, verified)
                .unwrap()
                .unwrap();
            let mut decoder = minicbor::Decoder::new(&response[1..]);
            let mut auth = Vec::new();
            let mut signature = Vec::new();
            for _ in 0..decoder.map().unwrap().unwrap() {
                match decoder.u8().unwrap() {
                    2 => auth = decoder.bytes().unwrap().to_vec(),
                    3 => signature = decoder.bytes().unwrap().to_vec(),
                    _ => decoder.skip().unwrap(),
                }
            }
            assert_eq!(auth[32], u8::from(present) | (u8::from(verified) << 2));
            auth.extend_from_slice(&CHALLENGE);
            public
                .verify(
                    &auth,
                    &p256::ecdsa::Signature::from_der(&signature).unwrap(),
                )
                .unwrap();
        }
    }
}
