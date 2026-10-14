// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use firm_carver::carve::{carve_and_extract, scan_carvable_streams, CarvedKind};
use firm_carver::nvram::*;
use std::fs;
use zeroize::Zeroize;

#[test]
fn test_broadcom_flsh_parsing_le_and_be() {
    let entries = [
        ("router_name", "Broadcom_AP"),
        ("lan_ipaddr", "192.168.1.1"),
        ("wl0_ssid", "Home_WiFi"),
    ];

    // Little-endian test
    let le_blob = build_synthetic_broadcom_flsh(&entries, Endianness::Little);
    let le_archive = NvramArchive::parse(&le_blob).expect("Failed to parse LE Broadcom FLSH");
    assert_eq!(le_archive.source_kind, NvramSourceKind::BroadcomFlsh);
    assert_eq!(le_archive.endianness, Some(Endianness::Little));
    assert_eq!(le_archive.entries.len(), 3);
    assert_eq!(le_archive.entries[0].key, "router_name");
    assert_eq!(le_archive.entries[0].value, "Broadcom_AP");

    // Big-endian test
    let be_blob = build_synthetic_broadcom_flsh(&entries, Endianness::Big);
    let be_archive = NvramArchive::parse(&be_blob).expect("Failed to parse BE Broadcom FLSH");
    assert_eq!(be_archive.source_kind, NvramSourceKind::BroadcomFlsh);
    assert_eq!(be_archive.endianness, Some(Endianness::Big));
    assert_eq!(be_archive.entries.len(), 3);
    assert_eq!(be_archive.entries[1].key, "lan_ipaddr");
    assert_eq!(be_archive.entries[1].value, "192.168.1.1");

    // Verify CRC8 / Checksum helpers
    let crc = compute_bcm_crc8(b"test_payload_123");
    let sum = compute_bcm_checksum8(b"test_payload_123");
    assert!(crc > 0);
    assert!(sum > 0);
}

#[test]
fn test_broadcom_packed_strings_scanning() {
    let entries = [
        ("boardtype", "0x0472"),
        ("boardrev", "0x10"),
        ("clkfreq", "200,100"),
        ("sromrev", "2"),
    ];
    let packed = build_synthetic_packed_strings(&entries);
    let tables = scan_packed_strings_tables(&packed, 3);
    assert_eq!(tables.len(), 1);
    let (off, len, pairs) = &tables[0];
    assert_eq!(*off, 0);
    assert!(*len > 0);
    assert_eq!(pairs.len(), 4);

    let archive = NvramArchive::parse_packed_strings(&packed).expect("Parse packed strings");
    assert_eq!(archive.source_kind, NvramSourceKind::BroadcomPackedStrings);
    assert_eq!(archive.entries.len(), 4);
    assert_eq!(archive.entries[2].key, "clkfreq");
    assert_eq!(archive.entries[2].value, "200,100");
}

#[test]
fn test_mediatek_dat_parsing() {
    let entries = [
        ("SSID1", "MediaTek_WLAN"),
        ("AuthMode", "WPA2PSK"),
        ("EncrypType", "AES"),
        ("WPAPSK1", "MySecretPresharedKey"),
        ("CountryCode", "KR"),
        ("BssidNum", "1"),
    ];
    let dat_bytes = build_synthetic_mediatek_dat(&entries);
    assert!(probe_mediatek_dat(&dat_bytes));

    let archive = NvramArchive::parse(&dat_bytes).expect("Parse MediaTek .dat");
    assert_eq!(archive.source_kind, NvramSourceKind::MediatekDat);
    // Includes _section=Default + 6 parameters
    assert!(archive
        .entries
        .iter()
        .any(|e| e.key == "SSID1" && e.value == "MediaTek_WLAN"));
    assert!(archive
        .entries
        .iter()
        .any(|e| e.key == "CountryCode" && e.value == "KR"));
}

#[test]
fn test_mediatek_eeprom_factory_partition() {
    let eeprom_blob = build_synthetic_mtk7628_factory();
    let archive = NvramArchive::parse(&eeprom_blob).expect("Parse MT7628 EEPROM");

    assert_eq!(archive.source_kind, NvramSourceKind::MediatekEeprom);
    assert_eq!(archive.chip_id, Some(MTK_CHIP_MT7628));
    assert_eq!(archive.mac_address.as_deref(), Some("00:0C:43:28:76:01"));
    assert!(archive
        .entries
        .iter()
        .any(|e| e.key == "chip_id" && e.value == "0x7628"));
    assert!(archive
        .entries
        .iter()
        .any(|e| e.key == "mac_wan" && e.value == "00:0C:43:28:76:02"));

    // Test RT2880 factory blob
    let rt2880_blob = build_synthetic_rt2880_factory();
    let rt_archive = NvramArchive::parse(&rt2880_blob).expect("Parse RT2880 EEPROM");
    assert_eq!(rt_archive.chip_id, Some(MTK_CHIP_RT2880));
    assert_eq!(rt_archive.mac_address.as_deref(), Some("00:0C:43:28:80:01"));

    // Test MT7620 factory blob
    let mt7620_blob = build_synthetic_mt7620_factory();
    let mt_archive = NvramArchive::parse(&mt7620_blob).expect("Parse MT7620 EEPROM");
    assert_eq!(mt_archive.chip_id, Some(MTK_CHIP_MT7620));
}

#[test]
fn test_nvram_security_audit_all_six_rules() {
    let (vuln_blob, _) = build_synthetic_vulnerable_nvram();
    let archive = NvramArchive::parse(&vuln_blob).expect("Parse vulnerable nvram");
    let report = archive.audit_nvram();

    // Verify all 6 security rules are triggered
    assert!(report.issues.iter().any(|i| i.rule_id == "NVRAM-WIFI-001"));
    assert!(report.issues.iter().any(|i| i.rule_id == "NVRAM-WIFI-002"));
    assert!(report.issues.iter().any(|i| i.rule_id == "NVRAM-WPS-001"));
    assert!(report.issues.iter().any(|i| i.rule_id == "NVRAM-CRED-001"));
    assert!(report.issues.iter().any(|i| i.rule_id == "NVRAM-FLAG-001"));
    assert!(report.issues.iter().any(|i| i.rule_id == "NVRAM-SVC-001"));

    // Check severities and summary
    assert!(report.summary.critical_count >= 2);
    assert!(report.summary.high_count >= 3);
    assert!(report.summary.medium_count >= 1);
    assert_eq!(report.summary.total_entries, archive.entries.len());

    // Verify specific finding recommendations
    let cred_issue = report
        .issues
        .iter()
        .find(|i| i.rule_id == "NVRAM-CRED-001")
        .expect("CRED issue");
    assert_eq!(cred_issue.severity, NvramSeverity::Critical);
    assert_eq!(cred_issue.category, NvramCategory::DefaultCredentials);
}

#[test]
fn test_nvram_hardened_clean_audit() {
    let hardened_blob = build_synthetic_hardened_nvram();
    let archive = NvramArchive::parse(&hardened_blob).expect("Parse hardened nvram");
    let report = archive.audit_nvram();

    assert_eq!(report.summary.critical_count, 0);
    assert_eq!(report.summary.high_count, 0);
    assert_eq!(report.issues.len(), 0);
}

#[test]
fn test_wps_pin_checksum_verification() {
    // 12345670 is a valid 8-digit WPS PIN
    assert!(verify_wps_pin_checksum("12345670"));

    // Test invalid checksum
    assert!(!verify_wps_pin_checksum("12345671"));
    assert!(!verify_wps_pin_checksum("1234567")); // 7 digits
    assert!(!verify_wps_pin_checksum("123456789")); // 9 digits
    assert!(!verify_wps_pin_checksum("abcdefgh")); // Non-numeric
}

#[test]
fn test_nvram_stream_carver_integration() {
    let mut firmware = vec![0x90u8; 1024]; // leading padding

    let bcm_offset = firmware.len();
    let (bcm_blob, _) = build_synthetic_vulnerable_nvram();
    firmware.extend_from_slice(&bcm_blob);

    firmware.resize(firmware.len() + 512, 0xFF); // flash gap

    let mtk_offset = firmware.len();
    let mtk_blob = build_synthetic_mtk7628_factory();
    firmware.extend_from_slice(&mtk_blob);

    firmware.resize(firmware.len() + 256, 0x00); // trailing padding

    // Stream carving detection
    let spans = scan_nvram_partitions(&firmware);
    assert!(spans.len() >= 2);
    assert_eq!(spans[0].offset, bcm_offset);
    assert_eq!(spans[0].kind, NvramSourceKind::BroadcomFlsh);
    assert_eq!(spans[1].offset, mtk_offset);
    assert_eq!(spans[1].kind, NvramSourceKind::MediatekEeprom);

    // Carve stream integration
    let segments = scan_carvable_streams(&firmware);
    let nvram_segs: Vec<_> = segments
        .into_iter()
        .filter(|s| s.kind == CarvedKind::Nvram)
        .collect();
    assert!(nvram_segs.len() >= 2);

    // Disk carving and manifest test
    let temp_dir = std::env::temp_dir().join(format!("fcarver_nvram_test_{}", std::process::id()));
    let manifest = carve_and_extract(&firmware, &temp_dir, "test_firmware.bin")
        .expect("Carve and extract nvram");
    assert!(manifest.carved_count >= 2);
    assert!(temp_dir.join("manifest.json").exists());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_nvram_zeroize_memory_safety() {
    let mut entry = NvramEntry {
        key: "http_passwd".to_string(),
        value: "SecretSuperPassword123".to_string(),
        source: NvramSourceKind::BroadcomFlsh,
        offset: 120,
    };
    entry.zeroize();
    assert!(entry.key.is_empty());
    assert!(entry.value.is_empty());
    assert_eq!(entry.offset, 0);

    let (blob, _) = build_synthetic_vulnerable_nvram();
    let mut archive = NvramArchive::parse(&blob).expect("Parse nvram");
    assert!(!archive.entries.is_empty());
    archive.zeroize();
    for e in &archive.entries {
        assert!(e.key.is_empty());
        assert!(e.value.is_empty());
    }
}

#[test]
fn test_nvram_corrupted_and_truncated_resilience() {
    // Empty buffer
    assert!(NvramArchive::parse(&[]).is_err());

    // 1-byte buffer
    assert!(NvramArchive::parse(&[0x46]).is_err());

    // Corrupted FLSH magic
    let bad_magic = [0x46, 0x4C, 0x53, 0x00];
    assert!(probe_nvram_at(&bad_magic, 0).is_none());

    // Random non-NVRAM bytes
    let random_noise = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    assert!(NvramArchive::parse(&random_noise).is_err());
}

#[test]
fn test_nvram_json_and_env_export_and_formatting() {
    let (blob, _) = build_synthetic_vulnerable_nvram();
    let archive = NvramArchive::parse(&blob).expect("Parse nvram");

    // JSON serialization
    let json_text = serde_json::to_string_pretty(&archive).expect("Serialize JSON");
    assert!(json_text.contains("BroadcomFlsh"));
    assert!(json_text.contains("wl0_ssid"));

    let report = archive.audit_nvram();
    let report_json = serde_json::to_string_pretty(&report).expect("Serialize audit report");
    assert!(report_json.contains("NVRAM-WIFI-001"));

    // Formatted text listings
    let listing = archive.format_listing();
    assert!(listing.contains("wl0_ssid"));

    let summary = archive.format_summary();
    assert!(summary.contains("Broadcom FLSH"));

    let audit_table = NvramArchive::format_audit_table(&report);
    assert!(audit_table.contains("NVRAM-WIFI-001"));
    assert!(audit_table.contains("CRITICAL"));

    // .env export test
    let env_file = std::env::temp_dir().join(format!("nvram_export_{}.env", std::process::id()));
    let count = archive
        .extract_to_env_file(&env_file)
        .expect("Extract to env file");
    assert_eq!(count, archive.entries.len());
    let env_content = fs::read_to_string(&env_file).expect("Read env file");
    assert!(env_content.contains("wl0_ssid=\"HomeRouter_2.4G\""));

    let _ = fs::remove_file(&env_file);
}
