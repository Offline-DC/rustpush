//! Regression test for the `dumb` field mapping.
//!
//! `rom` is field 11 and `io_mac_address` is field 2 in OpenBubbles'
//! `mac_hw_info.proto`. They are DIFFERENT bytes on genuine hardware (verified on
//! a real MacBookPro16,2: f2 = 147dda3f5864, f11 = 8e04522f5881), and only field
//! 11 belongs in `X-Apple-I-ROM`. An earlier hand-rolled protobuf reader had these
//! two swapped, so every GSA request carried the MAC address as the ROM while the
//! NAC-signed validation data attested to the real one.
#![cfg(feature = "macos-remote-validation")]

use prost::Message;
use rustpush::macos_remote::{bbhwinfo, generate_udid, is_openbubbles_shaped_udid, MacOSConfigRemote};
use rustpush::OSConfig;

const IO_MAC: [u8; 6] = [0x14, 0x7d, 0xda, 0x3f, 0x58, 0x64];
const ROM: [u8; 6] = [0x8e, 0x04, 0x52, 0x2f, 0x58, 0x81];

fn dumb_body() -> Vec<u8> {
    let hw = bbhwinfo::HwInfo {
        inner: Some(bbhwinfo::hw_info::InnerHwInfo {
            product_name: "MacBookPro16,2".into(),
            io_mac_address: IO_MAC.to_vec(),
            platform_serial_number: "SERIALNUM123".into(),
            platform_uuid: "00000000-0000-0000-0000-000000000000".into(),
            os_build_num: "24D70".into(),
            rom: ROM.to_vec(),
            mlb: "MLB00000000000000".into(),
            ..Default::default()
        }),
        version: "15.3.1".into(),
        protocol_version: 1640,
        device_id: "00000000-0000-0000-0000-000000000000".into(),
        icloud_ua: "com.apple.iCloudHelper/282 CFNetwork/1494.0.7 Darwin/23.4.0".into(),
        aoskit_version: "com.apple.AOSKit/282".into(),
    };
    let mut body = b"OABS\0".to_vec();
    body.extend_from_slice(&hw.encode_to_vec());
    body
}

#[test]
fn rom_comes_from_field_11_not_io_mac_address() {
    let cfg = MacOSConfigRemote::from_dumb_body(&dumb_body()).expect("parse dumb");
    let rom: Vec<u8> = cfg.inner.rom.clone().into();
    assert_eq!(rom, ROM.to_vec(), "rom must be field 11");
    assert_ne!(rom, IO_MAC.to_vec(), "rom must NOT be io_mac_address (field 2)");
}

#[test]
fn gsa_rom_header_matches_openbubbles() {
    let cfg = MacOSConfigRemote::from_dumb_body(&dumb_body()).expect("parse dumb");
    let headers = cfg.get_gsa_hardware_headers();
    // OpenBubbles sends hex(field 11), lowercase.
    assert_eq!(headers.get("X-Apple-I-ROM").map(String::as_str), Some("8e04522f5881"));
}

#[test]
fn other_identity_fields_round_trip() {
    let cfg = MacOSConfigRemote::from_dumb_body(&dumb_body()).expect("parse dumb");
    assert_eq!(cfg.inner.product_name, "MacBookPro16,2");
    assert_eq!(cfg.inner.os_build_num, "24D70");
    assert_eq!(cfg.version, "15.3.1");
    assert_eq!(cfg.protocol_version, 1640);
    assert_eq!(cfg.get_serial_number(), "SERIALNUM123");
}

#[test]
fn truncated_body_is_rejected() {
    assert!(MacOSConfigRemote::from_dumb_body(b"OABS").is_err());
}

#[test]
fn missing_rom_is_rejected() {
    let mut hw = bbhwinfo::HwInfo::decode(&dumb_body()[5..]).unwrap();
    hw.inner.as_mut().unwrap().rom.clear();
    let mut body = b"OABS\0".to_vec();
    body.extend_from_slice(&hw.encode_to_vec());
    assert!(MacOSConfigRemote::from_dumb_body(&body).is_err());
}

/// The client UDID must have OpenBubbles' shape (32 random bytes, hex, uppercase
/// -> 64 hex chars) and must NOT be derived from the Mac's platform UUID. It
/// leaves as `X-Client-UDID` on every GSA request; a dashed UUID there is a
/// one-regex classifier separating this client from OpenBubbles.
#[test]
fn udid_is_openbubbles_shaped_and_not_the_platform_uuid() {
    let cfg = MacOSConfigRemote::from_dumb_body(&dumb_body()).expect("parse dumb");
    let udid = cfg.udid.clone().expect("udid");
    assert_eq!(udid.len(), 64, "OpenBubbles emits 32 bytes of hex");
    assert!(udid.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(udid, udid.to_uppercase(), "OpenBubbles uppercases it");
    assert!(is_openbubbles_shaped_udid(&udid));
    assert_ne!(udid, cfg.device_id, "udid must not reuse the platform UUID");
}

#[test]
fn generated_udids_are_distinct() {
    assert_ne!(generate_udid(), generate_udid());
}

/// The legacy value (a dashed platform UUID) must be recognised as NOT
/// OpenBubbles-shaped, so existing installs migrate exactly once.
#[test]
fn legacy_dashed_uuid_is_not_openbubbles_shaped() {
    assert!(!is_openbubbles_shaped_udid("00000000-0000-0000-0000-000000000000"));
    assert!(is_openbubbles_shaped_udid(&"AB".repeat(32)));
}

/// The runtime self-check must be able to see BOTH fields, and must report them
/// the right way round — that is what makes the ROM_CHECK log line proof rather
/// than an assertion.
#[test]
fn rom_and_io_mac_diagnostic_reports_both_fields() {
    let cfg = MacOSConfigRemote::from_dumb_body(&dumb_body()).expect("parse dumb");
    let (rom_hex, mac_hex) = cfg.rom_and_io_mac_hex().expect("diagnostic");
    assert_eq!(rom_hex, "8e04522f5881", "field 11 = rom");
    assert_eq!(mac_hex, "147dda3f5864", "field 2 = io_mac_address");
    assert_ne!(rom_hex, mac_hex);
    // And the header must carry the ROM, not the MAC.
    let headers = cfg.get_gsa_hardware_headers();
    assert_eq!(headers.get("X-Apple-I-ROM").map(String::as_str), Some(rom_hex.as_str()));
    assert_ne!(headers.get("X-Apple-I-ROM").map(String::as_str), Some(mac_hex.as_str()));
}
