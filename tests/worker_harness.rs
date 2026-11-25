//! Real worker process tests; no USB kernel gadget or mock protocol device.
#![cfg(unix)]

use std::{
    process::Command,
    time::{Duration, Instant},
};
use usb_gadget_harness::{Harness, Kind, Resource, TestDirectory, UsbBusEvent};

const HID_OUT: u8 = 0x03;
const HID_IN: u8 = 0x83;
const CCID_OUT: u8 = 0x01;
const CCID_IN: u8 = 0x81;

fn launch(directory: &TestDirectory) -> Harness {
    let mut command = Command::new(env!("CARGO_BIN_EXE_virtual-yubikey-worker"));
    command.args(["--serial", "12345678", "--persistence", "immediate"]);
    Harness::spawn(
        &mut command,
        directory,
        &[
            Resource::Sink("display-spi"),
            Resource::Sink("display-control"),
            Resource::DigitalInput("touch-button"),
            Resource::DigitalInput("reconnect-button"),
        ],
    )
    .unwrap()
}
fn ready(directory: &TestDirectory) -> Harness {
    let mut worker = launch(directory);
    let personality = worker.configure().unwrap();
    assert_eq!(
        &personality.device_descriptor[8..12],
        &[0x50, 0x10, 0x06, 0x04]
    );
    worker.activate().unwrap();
    barrier(&mut worker);
    assert_eq!(
        worker.endpoint(0x82).unwrap().receive().unwrap(),
        [0x50, 0x03]
    );
    worker
}
fn barrier(worker: &mut Harness) {
    assert_eq!(
        worker.control([0xc0, 0xff, 0, 0, 0, 0, 0, 0], &[]).unwrap(),
        [0]
    );
}

fn send_hid(worker: &Harness, channel: u32, command: u8, payload: &[u8]) {
    let mut initial = [0; 64];
    initial[..4].copy_from_slice(&channel.to_be_bytes());
    initial[4] = command | 0x80;
    initial[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    let first = payload.len().min(57);
    initial[7..7 + first].copy_from_slice(&payload[..first]);
    worker.endpoint(HID_OUT).unwrap().send(&initial).unwrap();
    for (sequence, chunk) in payload[first..].chunks(59).enumerate() {
        let mut report = [0; 64];
        report[..4].copy_from_slice(&channel.to_be_bytes());
        report[4] = sequence as u8;
        report[5..5 + chunk.len()].copy_from_slice(chunk);
        worker.endpoint(HID_OUT).unwrap().send(&report).unwrap();
    }
}
fn receive_hid(worker: &Harness, channel: u32, command: u8) -> Vec<u8> {
    let first = worker.endpoint(HID_IN).unwrap().receive().unwrap();
    assert_eq!(first.len(), 64);
    assert_eq!(&first[..4], &channel.to_be_bytes());
    assert_eq!(first[4], command | 0x80);
    let length = u16::from_be_bytes([first[5], first[6]]) as usize;
    let mut payload = first[7..7 + length.min(57)].to_vec();
    let mut sequence = 0;
    while payload.len() < length {
        let report = worker.endpoint(HID_IN).unwrap().receive().unwrap();
        assert_eq!(report.len(), 64);
        assert_eq!(&report[..4], &channel.to_be_bytes());
        assert_eq!(report[4], sequence);
        let count = (length - payload.len()).min(59);
        payload.extend_from_slice(&report[5..5 + count]);
        sequence += 1;
    }
    payload
}
fn hid(worker: &Harness, channel: u32, command: u8, payload: &[u8]) -> Vec<u8> {
    send_hid(worker, channel, command, payload);
    receive_hid(worker, channel, command)
}
fn init(worker: &Harness) -> u32 {
    let nonce = *b"harness1";
    let reply = hid(worker, u32::MAX, 6, &nonce);
    assert_eq!(reply.len(), 17);
    assert_eq!(&reply[..8], &nonce);
    let channel = u32::from_be_bytes(reply[8..12].try_into().unwrap());
    assert_ne!(channel, 0);
    assert_ne!(channel, u32::MAX);
    channel
}
fn ccid_request(kind: u8, sequence: u8, payload: &[u8]) -> Vec<u8> {
    let mut request = vec![kind];
    request.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    request.extend_from_slice(&[0, sequence, 0, 0, 0]);
    request.extend_from_slice(payload);
    request
}
fn receive_ccid(worker: &Harness, sequence: u8) -> Vec<u8> {
    loop {
        let response = worker.endpoint(CCID_IN).unwrap().receive().unwrap();
        if response.is_empty() {
            continue;
        }
        assert!(response.len() >= 10);
        assert_eq!(response[6], sequence);
        assert_eq!(
            u32::from_le_bytes(response[1..5].try_into().unwrap()) as usize,
            response.len() - 10
        );
        if response[7] & 0xc0 == 0x80 {
            continue;
        } // Real worker keepalive.
        assert_eq!(response[7] & 0xc0, 0);
        return response;
    }
}
fn u2f_apdu(instruction: u8, p1: u8, data: &[u8]) -> Vec<u8> {
    let mut apdu = vec![0, instruction, p1, 0, 0];
    apdu.extend_from_slice(&(data.len() as u16).to_be_bytes());
    apdu.extend_from_slice(data);
    apdu
}

#[test]
fn real_worker_routes_hid_ccid_control_and_bus_lifecycle() {
    let directory = TestDirectory::new().unwrap();
    let mut worker = ready(&directory);
    let report = worker
        .control([0x81, 6, 0, 0x22, 0, 0, 34, 0], &[])
        .unwrap();
    assert_eq!(report.len(), 35);
    assert_eq!(&report[..5], &[2, 6, 0xd0, 0xf1, 9]);
    assert_eq!(
        worker.control([0x21, 0x0a, 0, 0, 0, 0, 0, 0], &[]).unwrap(),
        [1]
    );
    let channel = init(&worker);
    let payload: Vec<_> = (0..200).map(|index| index as u8).collect();
    assert_eq!(hid(&worker, channel, 1, &payload), payload);
    let version = hid(&worker, channel, 3, &[0, 3, 0, 0, 0]);
    assert_eq!(version, b"U2F_V2\x90\x00");
    let info = hid(&worker, channel, 0x10, &[4]);
    assert_eq!(info[0], 0); // CTAP GetInfo.
    worker
        .endpoint(CCID_OUT)
        .unwrap()
        .send(&ccid_request(0x62, 1, &[]))
        .unwrap();
    let atr = receive_ccid(&worker, 1);
    assert_eq!(atr[0], 0x80);
    assert_eq!(atr[10], 0x3b);
    let aid = virtual_yubikey_core::MANAGEMENT_AID;
    let mut select = vec![0, 0xa4, 4, 0, aid.len() as u8];
    select.extend_from_slice(&aid);
    select.push(0);
    let request = ccid_request(0x6f, 2, &select);
    // Transfer boundaries do not need to coincide with CCID message boundaries.
    for fragment in request.chunks(5) {
        worker.endpoint(CCID_OUT).unwrap().send(fragment).unwrap();
    }
    assert_eq!(
        &receive_ccid(&worker, 2)[10..],
        b"Virtual mgr - FW version 5.8.0\x90\x00"
    );
    worker.bus_event(UsbBusEvent::Suspend).unwrap();
    worker.bus_event(UsbBusEvent::Resume).unwrap();
    barrier(&mut worker);
    assert_eq!(hid(&worker, channel, 1, b"resume"), b"resume");
    worker.bus_event(UsbBusEvent::Disable).unwrap();
    barrier(&mut worker);
    worker.bus_event(UsbBusEvent::Enable).unwrap();
    barrier(&mut worker);
    assert_eq!(worker.endpoint(0x82).unwrap().receive().unwrap(), [0x50, 3]);
    assert_eq!(hid(&worker, channel, 1, b"enabled again"), b"enabled again");
    worker.shutdown().unwrap();
}

#[test]
fn touch_is_required_and_registered_handles_survive_process_restart() {
    let directory = TestDirectory::new().unwrap();
    let worker = ready(&directory);
    let channel = init(&worker);
    let data = [0x42; 64];
    let register = u2f_apdu(1, 0, &data);
    assert_eq!(hid(&worker, channel, 3, &register), [0x69, 0x85]);
    worker.set_input("touch-button", true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let registered = loop {
        let response = hid(&worker, channel, 3, &register);
        if response != [0x69, 0x85] {
            break response;
        }
        assert!(
            Instant::now() < deadline,
            "worker did not observe explicit touch"
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(&registered[registered.len() - 2..], &[0x90, 0]);
    assert_eq!(registered[0], 5);
    let length = registered[66] as usize;
    let handle = registered[67..67 + length].to_vec();
    worker.set_input("touch-button", false).unwrap();
    worker.shutdown().unwrap();
    let worker = ready(&directory);
    let channel = init(&worker);
    let mut authenticate = data.to_vec();
    authenticate.push(handle.len() as u8);
    authenticate.extend_from_slice(&handle);
    // Check-only recognizes the persisted wrapping key and still demands UP.
    assert_eq!(
        hid(&worker, channel, 3, &u2f_apdu(2, 7, &authenticate)),
        [0x69, 0x85]
    );
    assert_eq!(hid(&worker, channel, 3, &register), [0x69, 0x85]);
    worker.shutdown().unwrap();
}

#[test]
fn real_reconnect_input_ejects_and_creates_a_fresh_generation() {
    let directory = TestDirectory::new().unwrap();
    let mut worker = ready(&directory);
    worker.set_input("reconnect-button", true).unwrap();
    let absent = worker.receive().unwrap();
    assert_eq!(absent.kind, Kind::Configure);
    assert!(absent.body.is_empty());
    assert_eq!(absent.generation, 1);
    worker.quiesce(absent.request_id).unwrap();
    worker.set_input("reconnect-button", false).unwrap();
    worker.configure().unwrap();
    assert_eq!(worker.generation(), 2);
    worker.activate().unwrap();
    barrier(&mut worker);
    let channel = init(&worker);
    assert_eq!(hid(&worker, channel, 1, b"reinserted"), b"reinserted");
    worker.shutdown().unwrap();
}

#[test]
fn configuration_rejection_exits_the_real_worker() {
    let directory = TestDirectory::new().unwrap();
    let mut worker = launch(&directory);
    let configuration = worker.receive().unwrap();
    assert_eq!(configuration.kind, Kind::Configure);
    worker
        .send(
            &usb_gadget_harness::Record::new(
                Kind::ConfigurationRejected,
                0,
                configuration.request_id,
                b"test rejection".to_vec(),
            ),
            &[],
        )
        .unwrap();
    assert!(!worker.wait_for_exit().unwrap().success());
    assert!(worker.logs().contains("test rejection"));
}
