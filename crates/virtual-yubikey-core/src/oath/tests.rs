use super::*;
use crate::{
    ApduExchange, Applet, DeviceProfile, FidoConfiguration, MANAGEMENT_AID, VirtualYubiKey,
};

fn device() -> VirtualYubiKey {
    VirtualYubiKey::new(DeviceProfile::yubikey_5_8_ccid(42))
}
fn apdu(ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0, ins, p1, p2];
    if !data.is_empty() {
        out.push(data.len() as u8);
        out.extend_from_slice(data);
    }
    out.push(0);
    out
}
fn send(d: &mut VirtualYubiKey, ins: u8, p1: u8, p2: u8, data: &[u8]) -> ResponseApdu {
    let bytes = d.transmit(&apdu(ins, p1, p2, data));
    let end = bytes.len() - 2;
    ResponseApdu {
        data: bytes[..end].to_vec(),
        status: u16::from_be_bytes(bytes[end..].try_into().unwrap()),
    }
}
fn select(d: &mut VirtualYubiKey) -> Vec<u8> {
    let r = send(d, 0xa4, 4, 0, &OATH_AID);
    assert_eq!(r.status, 0x9000);
    r.data
}
fn put(
    d: &mut VirtualYubiKey,
    name: &[u8],
    kind: u8,
    digits: u8,
    secret: &[u8],
    properties: u8,
    counter: u32,
) -> ResponseApdu {
    let mut data = Vec::new();
    tlv(&mut data, 0x71, name);
    let mut key = vec![kind, digits];
    key.extend_from_slice(secret);
    tlv(&mut data, 0x73, &key);
    if properties != 0 {
        data.extend_from_slice(&[0x78, properties]);
    }
    if kind & 0xf0 == 0x10 {
        tlv(&mut data, 0x7a, &counter.to_be_bytes());
    }
    send(d, 1, 0, 0, &data)
}
fn calculation(name: &[u8], challenge: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    tlv(&mut data, 0x71, name);
    tlv(&mut data, 0x74, challenge);
    data
}
fn code(r: ResponseApdu) -> u32 {
    assert_eq!(r.status, 0x9000);
    assert_eq!(&r.data[..2], &[0x76, 5]);
    u32::from_be_bytes(r.data[3..].try_into().unwrap()) % 10u32.pow(r.data[2] as u32)
}
fn set_code(d: &mut VirtualYubiKey, key: &[u8]) -> ResponseApdu {
    let mut data = Vec::new();
    if key.is_empty() {
        tlv(&mut data, 0x73, &[]);
    } else {
        tlv(&mut data, 0x73, &[&[0x21], key].concat());
        tlv(&mut data, 0x74, b"hosthost");
        tlv(&mut data, 0x75, &mac(key, b"hosthost").unwrap());
    }
    send(d, 3, 0, 0, &data)
}
fn validation(key: &[u8], selected: &[u8]) -> Vec<u8> {
    let fields = parse(selected, false).unwrap();
    let challenge = required(&fields, 0x74).unwrap();
    let mut data = Vec::new();
    tlv(&mut data, 0x75, &mac(key, challenge).unwrap());
    tlv(&mut data, 0x74, b"hosthost");
    data
}

#[test]
fn rfc6238_all_hashes_and_timestamps_full_and_truncated() {
    let mut d = device();
    select(&mut d);
    let times = [
        59u64,
        1111111109,
        1111111111,
        1234567890,
        2000000000,
        20000000000,
    ];
    let vectors = [
        (
            1,
            b"12345678901234567890".as_slice(),
            [94287082, 7081804, 14050471, 89005924, 69279037, 65353130],
        ),
        (
            2,
            b"12345678901234567890123456789012".as_slice(),
            [46119246, 68084774, 67062674, 91819424, 90698825, 77737706],
        ),
        (
            3,
            b"1234567890123456789012345678901234567890123456789012345678901234".as_slice(),
            [90693936, 25091201, 99943326, 93441116, 38618901, 47863826],
        ),
    ];
    for (hash, secret, expected) in vectors {
        assert_eq!(
            put(&mut d, b"totp", 0x20 | hash, 8, secret, 0, 0).status,
            0x9000
        );
        for (time, expected) in times.into_iter().zip(expected) {
            let data = calculation(b"totp", &(time / 30).to_be_bytes());
            let full = send(&mut d, 0xa2, 0, 0, &data);
            assert_eq!(full.status, 0x9000);
            assert_eq!(full.data[0], 0x75);
            assert_eq!(full.data.len(), [0, 23, 35, 67][hash as usize]);
            let offset = usize::from(full.data[full.data.len() - 1] & 15) + 3;
            assert_eq!(
                (u32::from_be_bytes(full.data[offset..offset + 4].try_into().unwrap())
                    & 0x7fff_ffff)
                    % 100000000,
                expected
            );
            assert_eq!(code(send(&mut d, 0xa2, 0, 1, &data)), expected);
        }
    }
    d.take_oath_persistent_change();
    assert!(!d.take_oath_persistent_change());
}

#[test]
fn hotp_all_hashes_counter_vectors_and_restart() {
    let mut d = device();
    select(&mut d);
    // Independently generated with Python hashlib/hmac; SHA1 is RFC 4226.
    let expected = HOTP_VECTORS;
    for (hash, expected) in (1..=3).zip(expected) {
        assert_eq!(
            put(
                &mut d,
                &[hash],
                0x10 | hash,
                6,
                b"12345678901234567890",
                0,
                0
            )
            .status,
            0x9000
        );
        for (counter, expected) in expected.into_iter().enumerate() {
            let before = d.oath_persistent_state().unwrap();
            send(&mut d, 0xa1, 0, 0, &[]); // LIST never consumes a counter.
            assert_eq!(before, d.oath_persistent_state().unwrap());
            assert_eq!(
                code(send(&mut d, 0xa2, 0, 1, &calculation(&[hash], b""))),
                expected,
                "hash {hash} counter {counter}"
            );
            assert!(d.take_oath_persistent_change());
            let state = d.persistent_state().unwrap();
            d = VirtualYubiKey::from_persistent_state(
                d.profile().clone(),
                FidoConfiguration::default(),
                &state,
            )
            .unwrap();
            assert_eq!(d.selected_applet(), None);
            assert!(!d.take_persistent_change());
            select(&mut d);
        }
    }
    assert_eq!(
        put(
            &mut d,
            b"initial",
            0x11,
            8,
            b"12345678901234567890",
            0,
            12345
        )
        .status,
        0x9000
    );
    assert_eq!(
        code(send(
            &mut d,
            0xa2,
            0,
            1,
            &calculation(b"initial", b"ignored")
        )),
        78611215
    );
}

#[test]
fn password_mutual_authentication_replay_reselection_reset_and_persistence() {
    let mut d = device();
    let salt = select(&mut d);
    let key = software_key_core::digest::pbkdf2_hmac(
        MessageDigest::Sha1,
        b"password",
        required(&parse(&salt, false).unwrap(), 0x71).unwrap(),
        1000,
        16,
    )
    .unwrap();
    assert_eq!(put(&mut d, b"keep", 0x21, 6, &[1; 14], 0, 0).status, 0x9000);
    assert_eq!(set_code(&mut d, &key).status, 0x9000);
    let state = d.persistent_state().unwrap();
    d = VirtualYubiKey::from_persistent_state(
        d.profile().clone(),
        FidoConfiguration::default(),
        &state,
    )
    .unwrap();
    let selected = select(&mut d);
    assert_eq!(send(&mut d, 0xa1, 0, 0, &[]).status, 0x6982);
    assert_eq!(set_code(&mut d, &[]).status, 0x6982);
    let bad = validation(&[0; 16], &selected);
    assert_eq!(send(&mut d, 0xa3, 0, 0, &bad).status, 0x6a80);
    let valid = validation(&key, &selected);
    assert_eq!(send(&mut d, 0xa3, 0, 0, &valid).status, 0x6984);
    let selected = select(&mut d);
    let valid = validation(&key, &selected);
    let response = send(&mut d, 0xa3, 0, 0, &valid);
    assert_eq!(response.status, 0x9000);
    assert_eq!(
        required(&parse(&response.data, false).unwrap(), 0x75).unwrap(),
        mac(&key, b"hosthost").unwrap().as_slice()
    );
    assert_eq!(send(&mut d, 0xa1, 0, 0, &[]).status, 0x9000);
    select(&mut d);
    assert_eq!(send(&mut d, 0xa1, 0, 0, &[]).status, 0x6982);
    assert_eq!(send(&mut d, 4, 0, 0, &[]).status, 0x6a86);
    assert_eq!(send(&mut d, 4, 0xde, 0xad, &[]).status, 0x9000);
    let after = select(&mut d);
    let fields = parse(&after, false).unwrap();
    assert!(field(&fields, 0x74).is_none());
    assert_ne!(
        field(&fields, 0x71),
        field(&parse(&salt, false).unwrap(), 0x71)
    );
    assert!(send(&mut d, 0xa1, 0, 0, &[]).data.is_empty());
    assert!(d.take_oath_persistent_change());
}

#[test]
fn touch_is_fresh_command_bound_and_counter_advances_only_after_presence() {
    let mut d = device();
    select(&mut d);
    assert_eq!(
        put(&mut d, b"touch", 0x11, 6, b"12345678901234567890", 2, 0).status,
        0x9000
    );
    d.take_oath_persistent_change();
    let request = apdu(0xa2, 0, 1, &calculation(b"touch", b""));
    assert_eq!(
        d.exchange_apdu(&request, PresenceAuthorization::Absent),
        ApduExchange::PresenceRequired(UserPresencePolicy::Always)
    );
    assert!(!d.take_oath_persistent_change());
    let mut wrong = request.clone();
    wrong[3] = 0;
    assert_eq!(
        d.exchange_apdu(&wrong, PresenceAuthorization::Granted),
        ApduExchange::Complete(vec![0x69, 0x85])
    );
    assert_eq!(
        d.exchange_apdu(&request, PresenceAuthorization::Absent),
        ApduExchange::PresenceRequired(UserPresencePolicy::Always)
    );
    assert_eq!(
        d.exchange_apdu(&request, PresenceAuthorization::Granted),
        ApduExchange::Complete(vec![0x76, 5, 6, 0x4c, 0x93, 0xcf, 0x18, 0x90, 0])
    );
    assert!(d.take_oath_persistent_change());
    assert_eq!(
        d.exchange_apdu(&request, PresenceAuthorization::Absent),
        ApduExchange::PresenceRequired(UserPresencePolicy::Always)
    );
    send(&mut d, 0xa4, 4, 0, &MANAGEMENT_AID);
    assert_eq!(
        d.exchange_apdu(&request, PresenceAuthorization::Granted),
        ApduExchange::Complete(vec![0x69, 0x85])
    );
}

#[test]
fn calculate_all_skips_hotp_and_touch_and_preserves_metadata() {
    let mut d = device();
    select(&mut d);
    for (name, kind, touch) in [(b"a", 0x11, 0), (b"b", 0x21, 2), (b"c", 0x21, 0)] {
        assert_eq!(
            put(&mut d, name, kind, 6, b"12345678901234567890", touch, 0).status,
            0x9000
        );
    }
    let state = d.oath_persistent_state().unwrap();
    let mut data = Vec::new();
    tlv(&mut data, 0x74, &1u64.to_be_bytes());
    let r = send(&mut d, 0xa4, 0, 1, &data);
    assert_eq!(r.status, 0x9000);
    let fields = parse(&r.data, false).unwrap();
    assert_eq!(
        fields,
        vec![
            (0x71, b"a".as_slice()),
            (0x77, &[6]),
            (0x71, b"b"),
            (0x7c, &[6]),
            (0x71, b"c"),
            (0x76, &[6, 0x41, 0x39, 0x7e, 0xea])
        ]
    );
    assert_eq!(state, d.oath_persistent_state().unwrap());
    assert_eq!(
        code(send(&mut d, 0xa2, 0, 1, &calculation(b"a", b""))),
        755224
    );
}

#[test]
fn continuation_uses_send_remaining_and_discards_old_fragments() {
    let mut d = device();
    select(&mut d);
    for i in 0..12 {
        let name = vec![i + 1; 64];
        assert_eq!(put(&mut d, &name, 0x21, 6, &[1; 14], 0, 0).status, 0x9000);
    }
    let first = send(&mut d, 0xa1, 0, 0, &[]);
    assert_eq!(first.status, 0x6100);
    assert_eq!(first.data.len(), 256);
    let mut all = first.data;
    loop {
        let r = send(&mut d, 0xa5, 0, 0, &[]);
        all.extend(r.data);
        if r.status == 0x9000 {
            break;
        }
        assert_eq!(r.status & 0xff00, 0x6100);
    }
    assert_eq!(parse(&all, false).unwrap().len(), 12);
    send(&mut d, 0xa1, 0, 0, &[]);
    assert_eq!(send(&mut d, 0xc0, 0, 0, &[]).status, 0x6d00);
    assert!(send(&mut d, 0xa5, 0, 0, &[]).data.is_empty());
    send(&mut d, 0xa1, 0, 0, &[]);
    select(&mut d);
    assert!(send(&mut d, 0xa5, 0, 0, &[]).data.is_empty());
}

#[test]
fn malformed_put_overwrite_rename_delete_capacity_and_increasing_policy() {
    let mut d = device();
    select(&mut d);
    assert_eq!(put(&mut d, b"", 0x21, 6, &[1; 14], 0, 0).status, WRONG_DATA);
    for (kind, digits, secret, props) in [
        (0x24, 6, vec![1; 14], 0),
        (0x21, 5, vec![1; 14], 0),
        (0x21, 6, vec![1; 13], 0),
        (0x21, 6, vec![1; 65], 0),
        (0x21, 6, vec![1; 14], 4),
    ] {
        assert_eq!(
            put(&mut d, b"bad", kind, digits, &secret, props, 0).status,
            WRONG_DATA
        );
    }
    assert_eq!(put(&mut d, b"x", 0x21, 6, &[1; 14], 1, 0).status, 0x9000);
    assert_eq!(
        code(send(
            &mut d,
            0xa2,
            0,
            1,
            &calculation(b"x", &1u64.to_be_bytes())
        )),
        579703
    );
    assert_eq!(
        send(&mut d, 0xa2, 0, 1, &calculation(b"x", &1u64.to_be_bytes())).status,
        0x6985
    );
    let state = d.oath_persistent_state().unwrap();
    d.restore_oath_persistent_state(&state).unwrap();
    select(&mut d);
    assert_eq!(
        send(&mut d, 0xa2, 0, 1, &calculation(b"x", &0u64.to_be_bytes())).status,
        0x6985
    );
    assert_eq!(put(&mut d, b"x", 0x11, 6, &[1; 14], 0, 0).status, 0x9000);
    let mut rename = Vec::new();
    tlv(&mut rename, 0x71, b"x");
    tlv(&mut rename, 0x71, b"y");
    assert_eq!(send(&mut d, 5, 0, 0, &rename).status, 0x9000);
    let mut delete = Vec::new();
    tlv(&mut delete, 0x71, b"y");
    assert_eq!(send(&mut d, 2, 0, 0, &delete).status, 0x9000);
    assert_eq!(send(&mut d, 2, 0, 0, &delete).status, NOT_FOUND);
    for i in 0..MAX_CREDENTIALS {
        assert_eq!(
            put(&mut d, &[i as u8], 0x11, 6, &[1; 14], 0, 0).status,
            0x9000
        );
    }
    assert_eq!(put(&mut d, b"full", 0x11, 6, &[1; 14], 0, 0).status, 0x6a84);
    assert_eq!(put(&mut d, &[0], 0x21, 8, &[2; 64], 2, 0).status, 0x9000);
}

#[test]
fn persistent_state_validation_and_management_capability_gating() {
    let mut d = device();
    select(&mut d);
    assert_eq!(d.selected_applet(), Some(Applet::Oath));
    let state = d.oath_persistent_state().unwrap();
    assert!(OathApplet::from_persistent_state(43, [5, 8, 0], &state).is_err());
    for length in 0..state.len() {
        assert!(OathApplet::from_persistent_state(42, [5, 8, 0], &state[..length]).is_err());
    }
    let mut trailing = state.clone();
    trailing.push(0);
    assert!(OathApplet::from_persistent_state(42, [5, 8, 0], &trailing).is_err());
    assert_ne!(
        d.profile().usb_supported_capabilities() & crate::CAPABILITY_OATH,
        0
    );
    let mask = d.profile().usb_supported_capabilities() & !crate::CAPABILITY_OATH;
    d.management()
        .write_config(&[4, 3, 2, (mask >> 8) as u8, mask as u8])
        .unwrap();
    assert_eq!(send(&mut d, 0xa4, 4, 0, &OATH_AID).status, 0x6a82);
}

const HOTP_VECTORS: [[u32; 10]; 3] = [
    [
        755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
    ],
    [
        875740, 247374, 254785, 496144, 480556, 697997, 191609, 579288, 895912, 184989,
    ],
    [
        125165, 342147, 730102, 778726, 937510, 848329, 266680, 588359, 39399, 643409,
    ],
];

#[test]
fn password_change_is_atomic_and_requires_current_authorization() {
    let mut d = device();
    select(&mut d);
    let first = [1; 16];
    let second = [2; 16];
    assert_eq!(set_code(&mut d, &first).status, 0x9000);
    let selected = select(&mut d);
    let valid = validation(&first, &selected);
    assert_eq!(send(&mut d, 0xa3, 0, 0, &valid).status, 0x9000);
    let before = d.oath_persistent_state().unwrap();
    let mut bad = Vec::new();
    tlv(&mut bad, 0x73, &[&[0x21], second.as_slice()].concat());
    tlv(&mut bad, 0x74, b"hosthost");
    tlv(&mut bad, 0x75, &[0; 20]);
    assert_eq!(send(&mut d, 3, 0, 0, &bad).status, 0x6984);
    assert_eq!(before, d.oath_persistent_state().unwrap());
    assert_eq!(set_code(&mut d, &second).status, 0x9000);
    let selected = select(&mut d);
    assert_eq!(
        send(&mut d, 0xa3, 0, 0, &validation(&first, &selected)).status,
        WRONG_DATA
    );
    let selected = select(&mut d);
    assert_eq!(
        send(&mut d, 0xa3, 0, 0, &validation(&second, &selected)).status,
        0x9000
    );
    assert_eq!(set_code(&mut d, &[]).status, 0x9000);
    let selected = select(&mut d);
    assert!(field(&parse(&selected, false).unwrap(), 0x74).is_none());
    assert_eq!(send(&mut d, 0xa1, 0, 0, &[]).status, 0x9000);
}

#[cfg(unix)]
#[test]
fn shared_disk_storage_restores_oath_and_keeps_other_applets_unchanged() {
    use crate::storage::{DeviceStorage, PersistentApplet};
    let mut nonce = [0; 8];
    getrandom::fill(&mut nonce).unwrap();
    let root = std::env::temp_dir().join(format!("oath-storage-{:x}", u64::from_ne_bytes(nonce)));
    let profile = DeviceProfile::yubikey_5_8_ccid(42);
    let (storage, mut d) =
        DeviceStorage::open(&root, profile.clone(), FidoConfiguration::default()).unwrap();
    let original: Vec<_> = PersistentApplet::ALL
        .into_iter()
        .filter(|v| *v != PersistentApplet::Oath)
        .map(|v| (v, std::fs::read(storage.path(v)).unwrap()))
        .collect();
    select(&mut d);
    assert_eq!(
        put(
            &mut d,
            b"persistent",
            0x11,
            6,
            b"12345678901234567890",
            0,
            0
        )
        .status,
        0x9000
    );
    assert_eq!(
        code(send(&mut d, 0xa2, 0, 1, &calculation(b"persistent", b""))),
        755224
    );
    assert_eq!(set_code(&mut d, &[1; 16]).status, 0x9000);
    assert_eq!(d.take_persistent_applets(), vec![PersistentApplet::Oath]);
    software_key_core::state_persistence::replace_file_atomically(
        &storage.path(PersistentApplet::Oath),
        &d.oath_persistent_state().unwrap(),
    )
    .unwrap();
    drop(storage);
    drop(d);
    let (storage, mut d) =
        DeviceStorage::open(&root, profile, FidoConfiguration::default()).unwrap();
    let selected = select(&mut d);
    assert_eq!(send(&mut d, 0xa1, 0, 0, &[]).status, 0x6982);
    assert_eq!(
        send(&mut d, 0xa3, 0, 0, &validation(&[1; 16], &selected)).status,
        0x9000
    );
    assert_eq!(
        code(send(&mut d, 0xa2, 0, 1, &calculation(b"persistent", b""))),
        287082
    );
    for (applet, bytes) in original {
        assert_eq!(std::fs::read(storage.path(applet)).unwrap(), bytes);
    }
    drop(storage);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn old_whole_device_state_preserves_applets_and_initializes_oath_but_v4_requires_it() {
    let mut d = device();
    select(&mut d);
    assert_eq!(put(&mut d, b"new", 0x11, 6, &[1; 14], 0, 0).status, 0x9000);
    let encoded = d.persistent_state().unwrap();
    let mut decoder = minicbor::Decoder::new(&encoded);
    assert_eq!(decoder.map().unwrap(), Some(8));
    let mut old = vec![0xa7];
    for _ in 0..8 {
        let start = decoder.position();
        let field = decoder.u8().unwrap();
        decoder.skip().unwrap();
        if field == 1 {
            old.extend_from_slice(&[1, 3]);
        } else if field != 8 {
            old.extend_from_slice(&encoded[start..decoder.position()]);
        }
    }
    let mut restored = VirtualYubiKey::from_persistent_state(
        d.profile().clone(),
        FidoConfiguration::default(),
        &old,
    )
    .unwrap();
    assert_eq!(
        d.management_persistent_state().unwrap(),
        restored.management_persistent_state().unwrap()
    );
    assert_eq!(
        d.piv_persistent_state().unwrap(),
        restored.piv_persistent_state().unwrap()
    );
    select(&mut restored);
    assert!(send(&mut restored, 0xa1, 0, 0, &[]).data.is_empty());
    old[2] = 4;
    assert!(
        VirtualYubiKey::from_persistent_state(
            d.profile().clone(),
            FidoConfiguration::default(),
            &old
        )
        .is_err()
    );
}
