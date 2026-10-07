use super::*;
use crate::{
    ApduExchange, FIDO2_AID, FidoConfiguration, MANAGEMENT_AID, PIV_AID, PresenceAuthorization,
    VirtualYubiKey,
};

fn config(tlvs: &[(u8, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    for &(tag, value) in tlvs {
        push_tlv(&mut body, tag, value);
    }
    let mut encoded = vec![body.len() as u8];
    encoded.extend_from_slice(&body);
    encoded
}
fn set_mask(management: &Management, mask: u16) {
    management
        .write_config(&config(&[(3, &mask.to_be_bytes())]))
        .unwrap();
}
fn apdu(cla: u8, ins: u8, p1: u8, data: &[u8]) -> Vec<u8> {
    let mut raw = vec![cla, ins, p1, 0];
    if !data.is_empty() {
        raw.push(data.len() as u8);
        raw.extend_from_slice(data);
    }
    raw.push(0);
    raw
}
fn select(device: &mut VirtualYubiKey, aid: &[u8]) -> Vec<u8> {
    device.transmit(&apdu(0, 0xa4, 4, aid))
}
fn field(bytes: &[u8], tag: u8) -> Option<&[u8]> {
    let mut at = 1;
    while at < bytes.len() {
        let size = usize::from(bytes[at + 1]);
        if bytes[at] == tag {
            return Some(&bytes[at + 2..at + 2 + size]);
        }
        at += size + 2;
    }
    None
}
fn versions(response: &[u8]) -> Vec<String> {
    let mut decoder = minicbor::Decoder::new(&response[1..]);
    let count = decoder.map().unwrap().unwrap();
    for _ in 0..count {
        if decoder.u8().unwrap() == 1 {
            return (0..decoder.array().unwrap().unwrap())
                .map(|_| decoder.str().unwrap().to_owned())
                .collect();
        }
        decoder.skip().unwrap();
    }
    panic!("missing versions")
}
#[test]
fn four_protocol_combinations_gate_live_ccid_and_core_without_changing_support() {
    let mut device = VirtualYubiKey::new(DeviceProfile::yubikey_5_8_ccid(42));
    let management = device.management();
    let supported = management.usb_supported_capabilities();
    for (u2f, fido2) in [(false, false), (true, false), (false, true), (true, true)] {
        let mask = supported & !(CAPABILITY_U2F | CAPABILITY_FIDO2)
            | if u2f { CAPABILITY_U2F } else { 0 }
            | if fido2 { CAPABILITY_FIDO2 } else { 0 };
        assert_eq!(select(&mut device, &MANAGEMENT_AID).last(), Some(&0));
        assert_eq!(
            device.transmit(&apdu(0, 0x1c, 0, &config(&[(3, &mask.to_be_bytes())]))),
            [0x90, 0]
        );
        let info = device.transmit(&apdu(0, 0x1d, 0, &[]));
        assert_eq!(
            field(&info[..info.len() - 2], 1),
            Some(supported.to_be_bytes().as_slice())
        );
        assert_eq!(
            field(&info[..info.len() - 2], 3),
            Some(mask.to_be_bytes().as_slice())
        );
        assert_eq!(
            select(&mut device, &FIDO2_AID),
            if u2f || fido2 {
                [b"U2F_V2".as_slice(), &[0x90, 0]].concat()
            } else {
                vec![0x6a, 0x82]
            }
        );
        if u2f || fido2 {
            assert_eq!(
                device.transmit(&apdu(0, 3, 0, &[])),
                if u2f {
                    [b"U2F_V2".as_slice(), &[0x90, 0]].concat()
                } else {
                    vec![0x6d, 0]
                }
            );
            let response = device.transmit(&apdu(0x80, 0x10, 0x80, &[4]));
            if fido2 {
                assert_eq!(
                    versions(&response[..response.len() - 2]).contains(&"U2F_V2".to_owned()),
                    u2f
                );
            } else {
                assert_eq!(response, [0x6d, 0]);
            }
        }
        assert_eq!(management.usb_supported_capabilities(), supported);
    }
}
#[test]
fn disabling_preserves_handles_and_shared_authenticator_follows_changes() {
    let device = VirtualYubiKey::new(DeviceProfile::yubikey_5_8_ccid(42));
    let management = device.management();
    let supported = management.usb_supported_capabilities();
    let (mut card, mut fido) = device.separate_fido();
    let register = apdu(0, 1, 0, &[0x42; 64]);
    let ApduExchange::Complete(reg) = fido.exchange_u2f(&register, PresenceAuthorization::Granted)
    else {
        panic!()
    };
    assert_eq!(&reg[reg.len() - 2..], [0x90, 0]);
    let handle = &reg[67..131];
    let auth = [&[0x42; 64][..], &[64], handle].concat();
    let before = fido.persistent_state().unwrap();
    set_mask(&management, supported & !CAPABILITY_U2F);
    assert_eq!(
        fido.exchange_u2f(&apdu(0, 2, 3, &auth), PresenceAuthorization::Granted),
        ApduExchange::Complete(vec![0x6d, 0])
    );
    assert_eq!(fido.persistent_state().unwrap(), before);
    assert!(!versions(&fido.exchange(&[4])).contains(&"U2F_V2".to_owned()));
    set_mask(&management, supported & !CAPABILITY_FIDO2);
    assert_eq!(fido.exchange(&[4]), [1]);
    let ApduExchange::Complete(response) =
        fido.exchange_u2f(&apdu(0, 2, 3, &auth), PresenceAuthorization::Granted)
    else {
        panic!()
    };
    assert_eq!(&response[1..5], &[0, 0, 0, 1]);
    assert_eq!(&response[response.len() - 2..], [0x90, 0]);
    select(&mut card, &FIDO2_AID);
    set_mask(
        &management,
        supported & !(CAPABILITY_U2F | CAPABILITY_FIDO2),
    );
    assert_eq!(card.transmit(&apdu(0, 3, 0, &[])), [0x69, 0x85]);
    assert_eq!(select(&mut card, &FIDO2_AID), [0x6a, 0x82]);
}
#[test]
fn profiles_can_install_either_protocol_without_the_other() {
    for (u2f, fido2) in [(true, false), (false, true)] {
        let mut profile = DeviceProfile::yubikey_5_8_ccid(42);
        profile.applets.u2f = u2f;
        profile.applets.fido2 = fido2;
        let management = Management::new(profile);
        set_mask(&management, u16::MAX);
        assert_eq!(management.u2f_enabled(), u2f);
        assert_eq!(management.fido2_enabled(), fido2);
        assert!(management.applet_enabled(Applet::Fido2));
    }
}
#[test]
fn malformed_tlvs_and_unsupported_settings_are_atomic_and_nfc_is_absent() {
    let management = Management::new(DeviceProfile::yubikey_5_8_ccid(42));
    let original = management.persistent_state().unwrap();
    for broken in [
        vec![],
        vec![0, 1],
        vec![2, 3, 2],
        vec![3, 3, 1, 2],
        config(&[(3, &[0, 2]), (3, &[2, 0])]),
        config(&[(3, &[0, 2]), (0x0e, &[0, 2])]),
        config(&[(6, &[0, 1])]),
        config(&[(8, &[0x80])]),
        config(&[(12, &[1])]),
    ] {
        assert_eq!(management.write_config(&broken), Err(0x6a80));
        assert_eq!(management.persistent_state().unwrap(), original);
        assert!(!management.take_persistent_change());
    }
    let info = management.read_config(0).unwrap();
    assert!(field(&info, 0x0d).is_none());
    assert!(field(&info, 0x0e).is_none());
    assert_eq!(management.read_config(1), Err(0x6a86));
    set_mask(&management, u16::MAX);
    assert_eq!(
        management.usb_enabled_capabilities().unwrap(),
        management.usb_supported_capabilities()
    );
    set_mask(&management, 0);
    assert_eq!(
        management.usb_enabled_capabilities().unwrap(),
        CAPABILITY_CCID
    );
    assert!(management.applet_enabled(Applet::Management));
    assert!(!management.applet_enabled(Applet::Piv));
}
#[test]
fn lock_requires_same_transaction_authorization_and_retains_only_a_verifier() {
    let profile = DeviceProfile::yubikey_5_8_ccid(42);
    let management = Management::new(profile.clone());
    let code = [0x31; 16];
    let wrong = [0x32; 16];
    management.write_config(&config(&[(10, &code)])).unwrap();
    assert_eq!(
        field(&management.read_config(0).unwrap(), 10),
        Some(&[1][..])
    );
    let encoded = management.persistent_state().unwrap();
    assert!(!encoded.windows(16).any(|value| value == code));
    let restored = Management::from_persistent_state(profile, &encoded).unwrap();
    assert_eq!(restored.write_config(&config(&[(3, &[0, 2])])), Err(0x6982));
    assert_eq!(
        restored.write_config(&config(&[(3, &[0, 2]), (11, &wrong)])),
        Err(0x6982)
    );
    assert_eq!(restored.persistent_state().unwrap(), encoded);
    restored.write_config(&config(&[(11, &code)])).unwrap(); // Does not grant reusable authorization.
    assert_eq!(restored.write_config(&config(&[(3, &[0, 2])])), Err(0x6982));
    restored
        .write_config(&config(&[(3, &[0, 2]), (11, &code), (10, &[0; 16])]))
        .unwrap();
    assert!(restored.u2f_enabled());
    assert!(!restored.fido2_enabled());
    assert_eq!(field(&restored.read_config(0).unwrap(), 10), Some(&[0][..]));
    assert!(!format!("{restored:?}").contains("313131"));
}
#[test]
fn full_device_restore_and_version_two_migration_preserve_all_credential_images() {
    let profile = DeviceProfile::yubikey_5_8_ccid(42);
    let mut device = VirtualYubiKey::new(profile.clone());
    let fido = device.fido_persistent_state().unwrap();
    let piv = device.piv_persistent_state().unwrap();
    let mask = device.management().usb_supported_capabilities() & !CAPABILITY_U2F;
    set_mask(&device.management(), mask);
    let encoded = device.persistent_state().unwrap();
    let mut restored = VirtualYubiKey::from_persistent_state(
        profile.clone(),
        FidoConfiguration::default(),
        &encoded,
    )
    .unwrap();
    assert_eq!(
        restored.management().usb_enabled_capabilities().unwrap(),
        mask
    );
    assert_eq!(restored.fido_persistent_state().unwrap(), fido);
    assert_eq!(restored.piv_persistent_state().unwrap(), piv);
    assert!(!restored.take_persistent_change());
    let mut decoder = minicbor::Decoder::new(&encoded);
    assert_eq!(decoder.map().unwrap(), Some(7));
    let mut old = vec![0xa6];
    for _ in 0..6 {
        let start = decoder.position();
        let key = decoder.u8().unwrap();
        decoder.skip().unwrap();
        if key == 1 {
            old.extend_from_slice(&[1, 2]);
        } else {
            old.extend_from_slice(&encoded[start..decoder.position()]);
        }
    }
    let migrated =
        VirtualYubiKey::from_persistent_state(profile, FidoConfiguration::default(), &old).unwrap();
    assert!(migrated.management().u2f_enabled());
    assert_eq!(migrated.fido_persistent_state().unwrap(), fido);
    assert_eq!(migrated.piv_persistent_state().unwrap(), piv);
    select(&mut device, &PIV_AID);
    set_mask(&device.management(), mask & !CAPABILITY_PIV);
    assert_eq!(device.transmit(&apdu(0, 0xfd, 0, &[])), [0x69, 0x85]);
}
#[test]
fn corrupt_persistent_management_state_fails_closed() {
    let profile = DeviceProfile::yubikey_5_8_ccid(42);
    let management = Management::new(profile.clone());
    let encoded = management.persistent_state().unwrap();
    assert!(
        Management::from_persistent_state(DeviceProfile::yubikey_5_8_ccid(43), &encoded).is_err()
    );
    for broken in [
        &encoded[..encoded.len() - 1],
        &[0xa1, 1, 1][..],
        &[0xa4, 1, 1, 2, 24, 42, 3, 0, 4, 0x41, 0][..],
        &[0xa2, 1, 1, 1, 1][..],
    ] {
        assert!(Management::from_persistent_state(profile.clone(), broken).is_err());
    }
}

#[test]
fn fido_reset_keeps_management_enablement_and_configuration_lock() {
    let device = VirtualYubiKey::new(DeviceProfile::yubikey_5_8_ccid(42));
    let management = device.management();
    let mask = management.usb_supported_capabilities() & !CAPABILITY_U2F;
    management
        .write_config(&config(&[(3, &mask.to_be_bytes()), (10, &[0x31; 16])]))
        .unwrap();
    let before = management.persistent_state().unwrap();
    let (_, mut fido) = device.separate_fido();
    assert_eq!(fido.exchange(&[7]), [0x30]);
    assert_eq!(
        fido.exchange_with_presence(&[7], PresenceAuthorization::Granted),
        [0]
    );
    assert_eq!(management.persistent_state().unwrap(), before);
    assert_eq!(
        field(&management.read_config(0).unwrap(), 10),
        Some(&[1][..])
    );
    assert!(!management.u2f_enabled());
    assert!(management.fido2_enabled());
}
