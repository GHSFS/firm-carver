// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use firm_carver::cramfs::{
    build_synthetic_cramfs, probe_cramfs_at, scan_cramfs_partitions, CramFsArchive, CramFsFileType,
    Endianness, CRAMFS_MAGIC_BE, CRAMFS_MAGIC_LE,
};
use std::fs;

#[test]
fn test_cramfs_little_endian_superblock_and_tree() {
    let img = build_synthetic_cramfs(Endianness::Little, true);
    let archive = CramFsArchive::parse(&img).expect("Failed to parse LE CramFS image");

    assert_eq!(archive.superblock.magic, CRAMFS_MAGIC_LE);
    assert_eq!(archive.superblock.endianness, Endianness::Little);
    assert_eq!(archive.superblock.name, "CRAMFS_TEST_ROM");
    assert!(archive.superblock.size > 0);
    assert!(archive.entries.len() >= 5);

    let paths: Vec<&str> = archive.entries.iter().map(|e| e.path.as_str()).collect();
    assert!(paths.contains(&"/bin"));
    assert!(paths.contains(&"/etc"));
    assert!(paths.contains(&"/bin/sh"));
    assert!(paths.contains(&"/bin/busybox"));
    assert!(paths.contains(&"/etc/banner"));
}

#[test]
fn test_cramfs_big_endian_superblock_and_tree() {
    let img = build_synthetic_cramfs(Endianness::Big, false);
    let archive = CramFsArchive::parse(&img).expect("Failed to parse BE CramFS image");

    assert_eq!(archive.superblock.magic, CRAMFS_MAGIC_BE);
    assert_eq!(archive.superblock.endianness, Endianness::Big);
    assert_eq!(archive.superblock.name, "CRAMFS_TEST_ROM");

    let sh_entry = archive
        .entries
        .iter()
        .find(|e| e.path == "/bin/sh")
        .expect("Missing /bin/sh entry");
    assert_eq!(sh_entry.file_type, CramFsFileType::RegularFile);
}

#[test]
fn test_cramfs_zlib_file_decompression() {
    let img = build_synthetic_cramfs(Endianness::Little, true);
    let archive = CramFsArchive::parse(&img).expect("Failed to parse LE CramFS");

    let sh_bytes = archive
        .read_file_content(&img, "/bin/sh")
        .expect("Failed to read /bin/sh");
    let sh_str = String::from_utf8_lossy(&sh_bytes);
    assert!(sh_str.contains("FirmCarver synthetic shell"));

    let banner_bytes = archive
        .read_file_content(&img, "/etc/banner")
        .expect("Failed to read /etc/banner");
    let banner_str = String::from_utf8_lossy(&banner_bytes);
    assert!(banner_str.contains("Forensic Testing Banner"));
}

#[test]
fn test_cramfs_symlink_resolution_and_content() {
    let img = build_synthetic_cramfs(Endianness::Little, true);
    let archive = CramFsArchive::parse(&img).expect("Failed to parse LE CramFS");

    let busybox_entry = archive
        .entries
        .iter()
        .find(|e| e.path == "/bin/busybox")
        .expect("Missing /bin/busybox");

    assert_eq!(busybox_entry.file_type, CramFsFileType::Symlink);
    assert_eq!(busybox_entry.symlink_target.as_deref(), Some("sh"));
    assert!(!busybox_entry.is_dangling_symlink);
    assert!(!busybox_entry.is_path_traversal);
}

#[test]
fn test_cramfs_security_audit_path_traversal_symlink() {
    let img = build_synthetic_cramfs(Endianness::Little, true);
    let archive = CramFsArchive::parse(&img).expect("Failed to parse LE CramFS");

    let trav_entry = archive
        .entries
        .iter()
        .find(|e| e.path == "/bin/malicious_sym")
        .expect("Missing /bin/malicious_sym");

    assert_eq!(trav_entry.file_type, CramFsFileType::Symlink);
    assert_eq!(
        trav_entry.symlink_target.as_deref(),
        Some("../../etc/shadow")
    );
    assert!(trav_entry.is_path_traversal);

    let finding = archive
        .audit_report
        .findings
        .iter()
        .find(|f| f.rule_id == "CRAMFS-SYMLNK-001");
    assert!(finding.is_some(), "Expected CRAMFS-SYMLNK-001 finding");
    assert!(finding.unwrap().description.contains("../../etc/shadow"));
}

#[test]
fn test_cramfs_security_audit_dangling_symlink() {
    let img = build_synthetic_cramfs(Endianness::Little, true);
    let archive = CramFsArchive::parse(&img).expect("Failed to parse LE CramFS");

    let dang_entry = archive
        .entries
        .iter()
        .find(|e| e.path == "/bin/broken_sym")
        .expect("Missing /bin/broken_sym");

    assert_eq!(dang_entry.file_type, CramFsFileType::Symlink);
    assert!(dang_entry.is_dangling_symlink);

    let finding = archive
        .audit_report
        .findings
        .iter()
        .find(|f| f.rule_id == "CRAMFS-SYMLNK-002");
    assert!(finding.is_some(), "Expected CRAMFS-SYMLNK-002 finding");
}

#[test]
fn test_cramfs_security_audit_suid_binary() {
    let img = build_synthetic_cramfs(Endianness::Little, true);
    let archive = CramFsArchive::parse(&img).expect("Failed to parse LE CramFS");

    let suid_entry = archive
        .entries
        .iter()
        .find(|e| e.path == "/bin/suid_tool")
        .expect("Missing /bin/suid_tool");

    assert_eq!(suid_entry.mode & 0o4000, 0o4000);

    let finding = archive
        .audit_report
        .findings
        .iter()
        .find(|f| f.rule_id == "CRAMFS-PERM-001");
    assert!(finding.is_some(), "Expected CRAMFS-PERM-001 finding");
}

#[test]
fn test_cramfs_clean_hardened_audit() {
    let img = build_synthetic_cramfs(Endianness::Little, false);
    let archive = CramFsArchive::parse(&img).expect("Failed to parse clean CramFS");

    assert_eq!(archive.audit_report.critical, 0);
    assert_eq!(archive.audit_report.high, 0);
    assert_eq!(archive.summary.traversal_symlinks_count, 0);
    assert_eq!(archive.summary.dangling_symlinks_count, 0);
}

#[test]
fn test_cramfs_safe_disk_extraction() {
    let img = build_synthetic_cramfs(Endianness::Little, false);
    let archive = CramFsArchive::parse(&img).expect("Failed to parse CramFS");

    let temp_dir = std::env::temp_dir().join(format!("cramfs_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);

    let count = archive
        .extract_to_disk(&img, &temp_dir)
        .expect("Extraction failed");
    assert!(count >= 4);

    let extracted_sh = temp_dir.join("bin").join("sh");
    assert!(extracted_sh.exists(), "Extracted /bin/sh does not exist");
    let content = fs::read_to_string(&extracted_sh).expect("Failed to read extracted /bin/sh");
    assert!(content.contains("FirmCarver synthetic shell"));

    let extracted_banner = temp_dir.join("etc").join("banner");
    assert!(extracted_banner.exists(), "Extracted /etc/banner missing");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cramfs_raw_firmware_partition_carver() {
    let img = build_synthetic_cramfs(Endianness::Little, false);
    let mut blob = vec![0xFF; 1024];
    blob.extend_from_slice(&img);
    blob.extend_from_slice(&vec![0xEE; 512]);

    let span = probe_cramfs_at(&blob, 1024).expect("Probe failed at offset 1024");
    assert_eq!(span.offset, 1024);
    assert_eq!(span.endianness, Endianness::Little);
    assert_eq!(span.fs_name, "CRAMFS_TEST_ROM");
    assert!(span.recovered_entries >= 4);

    let all_spans = scan_cramfs_partitions(&blob);
    assert_eq!(all_spans.len(), 1);
    assert_eq!(all_spans[0].offset, 1024);
}

#[test]
fn test_cramfs_corrupted_and_truncated_resilience() {
    assert!(CramFsArchive::parse(&[]).is_err());
    assert!(CramFsArchive::parse(&[0x45, 0x3D, 0xCD, 0x28]).is_err());

    let mut corrupted = build_synthetic_cramfs(Endianness::Little, false);
    corrupted[0] = 0x00;
    assert!(CramFsArchive::parse(&corrupted).is_err());
}

#[test]
fn test_cramfs_listing_and_json_serialization() {
    let img = build_synthetic_cramfs(Endianness::Little, true);
    let archive = CramFsArchive::parse(&img).expect("Failed to parse CramFS");

    let listing = archive.format_listing();
    assert!(listing.contains("/bin/sh"));
    assert!(listing.contains("/etc/banner"));
    assert!(listing.contains("TRAVERSAL"));

    let summary = archive.format_summary();
    assert!(summary.contains("CramFS Filesystem"));

    let audit_table = archive.format_audit_table();
    assert!(audit_table.contains("CRAMFS-SYMLNK-001"));

    let json = serde_json::to_string_pretty(&archive).expect("JSON serialization failed");
    assert!(json.contains("CRAMFS_TEST_ROM"));
}
