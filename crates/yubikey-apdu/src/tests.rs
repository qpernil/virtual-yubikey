use crate::*;
#[test]
fn fixed_wire_cases_preserve_every_header_byte() {
    for raw in [
        &[0x00, 0x47, 0x80, 0x00, 0x02, 0xb6, 0x00, 0x00][..],
        &[0x00, 0x20, 0xff, 0x83][..],
        &[0x00, 0x84, 0, 0, 0, 0, 0x10][..],
        &[0x80, 0xd8, 0xff, 0x81, 0, 0, 3, 1, 2, 3, 0, 0][..],
        &[0x80, 0x10, 0x80, 0, 1, 4, 0][..],
        &[0, 4, 0xde, 0xad][..],
    ] {
        let command = CommandApdu::decode(raw).unwrap();
        assert_eq!(command.encode().unwrap(), raw);
    }
}
#[test]
fn malformed_lengths_and_u2f_legacy_encoding_are_not_generic_iso() {
    for raw in [
        &[0, 0, 0][..],
        &[0, 0xca, 0, 0, 0, 0][..],
        &[0, 3, 0, 0, 0, 0, 0, 0, 0][..],
        &[0, 0xca, 0, 0, 2, 1][..],
    ] {
        assert!(CommandApdu::decode(raw).is_err());
    }
}
#[test]
fn commands_are_resolved_only_in_their_owning_applet() {
    let pgp = openpgp::GENERATE
        .command(0x80, 0, &[0xb6, 0], Some(256))
        .unwrap();
    assert!(find(openpgp::COMMANDS, &pgp).is_ok());
    assert_eq!(find(piv::COMMANDS, &pgp), Err(SpecError::Parameters));
    let piv = piv::GENERATE
        .command(0, 0x9c, &[0xac, 0], Some(256))
        .unwrap();
    assert_eq!(find(openpgp::COMMANDS, &piv), Err(SpecError::Parameters));
    let reset = oath::RESET.command(0xde, 0xad, &[], None).unwrap();
    assert!(find(oath::COMMANDS, &reset).is_ok());
    assert_eq!(find(hsmauth::COMMANDS, &reset), Err(SpecError::Parameters));
    let store = security_domain::STORE_DATA
        .command(0x90, 0, &[0xa6, 0], None)
        .unwrap();
    assert_eq!(store.p1, 0x90);
    assert_eq!(store.encode().unwrap()[2], 0x90);
}
#[test]
fn response_rules_are_explicit_and_do_not_reinterpret_errors() {
    assert!(
        piv::VERSION
            .validate_response(&ResponseApdu {
                data: &[5, 7, 4],
                status: 0x9000
            })
            .is_ok()
    );
    assert_eq!(
        piv::VERSION.validate_response(&ResponseApdu {
            data: &[],
            status: 0x9000
        }),
        Err(SpecError::Response)
    );
    assert!(
        piv::VERSION
            .validate_response(&ResponseApdu {
                data: &[],
                status: 0x6982
            })
            .is_ok()
    );
    assert_eq!(fido::MESSAGE.protected_status, Some(0x9100));
    assert_eq!(piv::VERSION.protected_status, None);
    assert_eq!(oath::LIST.response_continuation, 0xa5);
    assert_eq!(openpgp::GET_DATA.response_continuation, 0xc0);
}
#[test]
fn debug_output_does_not_contain_payloads() {
    let command = hsmauth::CHALLENGE
        .command(0, 0, b"secret-password", None)
        .unwrap();
    assert!(!format!("{command:?}").contains("secret-password"));
    assert!(
        !format!(
            "{:?}",
            ResponseApdu {
                data: b"secret-password",
                status: 0x9000
            }
        )
        .contains("secret-password")
    );
}

#[test]
fn short_and_extended_length_boundaries_round_trip_without_parameter_changes() {
    for size in [0, 1, 247, 255, 256, 65535] {
        let data = vec![0xa5; size];
        for le in [None, Some(1), Some(256), Some(257), Some(65536)] {
            for extended in [false, true] {
                let command = CommandApdu {
                    cla: 0x80,
                    ins: 0xd8,
                    p1: 0xff,
                    p2: 0x81,
                    data: &data,
                    le,
                    extended,
                };
                let raw = command.encode().unwrap();
                let decoded = CommandApdu::decode(&raw).unwrap();
                assert_eq!(
                    [decoded.cla, decoded.ins, decoded.p1, decoded.p2],
                    [0x80, 0xd8, 0xff, 0x81]
                );
                assert_eq!(decoded.data, data);
                assert_eq!(decoded.le, le);
                assert_eq!(decoded.encode().unwrap(), raw);
            }
        }
    }
    let data = vec![0; 65536];
    assert!(
        CommandApdu {
            cla: 0,
            ins: 0,
            p1: 0,
            p2: 0,
            data: &data,
            le: None,
            extended: false
        }
        .encode()
        .is_err()
    );
    for le in [0, 65537] {
        assert!(
            CommandApdu {
                cla: 0,
                ins: 0,
                p1: 0,
                p2: 0,
                data: &[],
                le: Some(le),
                extended: false
            }
            .encode()
            .is_err()
        );
    }
}

#[test]
fn response_length_accepts_the_iso_maximum_and_request_length_remains_limited() {
    let data = vec![0; 65536];
    assert!(
        openpgp::GET_DATA
            .validate_response(&ResponseApdu {
                data: &data,
                status: 0x9000
            })
            .is_ok()
    );
    assert!(openpgp::PUT_DATA.command(0, 0, &data, None).is_err());
}
