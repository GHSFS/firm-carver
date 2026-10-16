// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use firm_carver::extfs::{
    build_synthetic_extfs, probe_extfs_at, scan_extfs_partitions, Endianness, ExtArchive,
    ExtFileType, ExtVersion, EXT_SUPER_MAGIC,
};

#[test]
fn test_ext2_little_endian_superblock_and_tree() {
    let img = build_synthetic_extfs(false, Endianness::Little, true);
    let archive = ExtArchive::parse(&img).expect("Failed to parse Ext2 LE image");

    assert_eq!(archive.superblock.magic, EXT_SUPER_MAGIC);
    assert_eq!(archive.superblock.version, ExtVersion::Ext2);
    assert_eq!(archive.superblock.endianness, Endianness::Little);
    assert_eq!(archive.superblock.block_size, 1024);
    assert_eq!(archive.superblock.volume_name, "ROOTFS_EMBEDDED");

    assert!(archive.summary.total_entries >= 6);
    assert!(archive.summary.regular_files >= 2);
    assert!(archive.summary.directories >= 3);

    // Verify presence of core paths
    let paths: Vec<&str> = archive.entries.iter().map(|e| e.path.as_str()).collect();
    assert!(paths.contains(&"/"));
    assert!(paths.contains(&"/bin"));
    assert!(paths.contains(&"/etc"));
    assert!(paths.contains(&"/etc/hostname"));
    assert!(paths.contains(&"/etc/shadow"));

    // Verify content of /etc/hostname
    let content = archive
        .read_file(&img, "/etc/hostname")
        .expect("Failed to read /etc/hostname");
    assert_eq!(content, b"router-gw01\n");
}

#[test]
fn test_ext2_big_endian_superblock_and_tree() {
    let img = build_synthetic_extfs(false, Endianness::Big, false);
    let archive = ExtArchive::parse(&img).expect("Failed to parse Ext2 BE image");

    assert_eq!(archive.superblock.magic, EXT_SUPER_MAGIC);
    assert_eq!(archive.superblock.endianness, Endianness::Big);
    assert_eq!(archive.superblock.version, ExtVersion::Ext2);

    let content = archive
        .read_file(&img, "/etc/hostname")
        .expect("Failed to read /etc/hostname on BE image");
    assert_eq!(content, b"router-gw01\n");
}

#[test]
fn test_ext4_extent_tree_file_reading() {
    let img = build_synthetic_extfs(true, Endianness::Little, true);
    let archive = ExtArchive::parse(&img).expect("Failed to parse Ext4 image");

    assert_eq!(archive.superblock.version, ExtVersion::Ext4);
    assert_eq!(archive.superblock.inode_size, 256);

    let hostname = archive
        .read_file(&img, "/etc/hostname")
        .expect("Failed to read /etc/hostname on Ext4");
    assert_eq!(hostname, b"router-gw01\n");

    let shadow = archive
        .read_file(&img, "/etc/shadow")
        .expect("Failed to read /etc/shadow on Ext4");
    assert!(shadow.starts_with(b"root:$6$rounds=5000$"));
}

#[test]
fn test_extfs_fast_inline_symlink() {
    let img = build_synthetic_extfs(false, Endianness::Little, true);
    let archive = ExtArchive::parse(&img).expect("Failed to parse image");

    let symlink_entry = archive
        .entries
        .iter()
        .find(|e| e.path == "/bin/sh_link")
        .expect("Missing /bin/sh_link");

    assert_eq!(symlink_entry.file_type, ExtFileType::Symlink);
    assert_eq!(
        symlink_entry.symlink_target.as_deref(),
        Some("../../etc/shadow")
    );
}

#[test]
fn test_extfs_security_audit_all_rules() {
    let img = build_synthetic_extfs(false, Endianness::Little, true);
    let archive = ExtArchive::parse(&img).expect("Failed to parse vulnerable image");

    let codes: Vec<&str> = archive
        .audit
        .findings
        .iter()
        .map(|f| f.code.as_str())
        .collect();

    // Verify detection of all expected vulnerability rules
    assert!(
        codes.contains(&"EXTFS-TRAV-001"),
        "Missing path traversal finding"
    );
    assert!(
        codes.contains(&"EXTFS-SYMLNK-001"),
        "Missing dangling symlink finding"
    );
    assert!(
        codes.contains(&"EXTFS-SYMLNK-002"),
        "Missing sensitive hardware symlink finding"
    );
    assert!(
        codes.contains(&"EXTFS-PERM-001"),
        "Missing SUID binary finding"
    );
    assert!(
        codes.contains(&"EXTFS-SHADOW-001"),
        "Missing shadow file finding"
    );

    // Verify severity counting
    assert!(archive.audit.critical_count >= 2); // TRAV-001 + SHADOW-001
    assert!(archive.audit.high_count >= 2); // SYMLNK-002 + PERM-001
    assert!(archive.audit.low_count >= 1); // SYMLNK-001
}

#[test]
fn test_extfs_hardened_clean_audit() {
    let img = build_synthetic_extfs(false, Endianness::Little, false);
    let archive = ExtArchive::parse(&img).expect("Failed to parse hardened image");

    let trav = archive
        .audit
        .findings
        .iter()
        .any(|f| f.code == "EXTFS-TRAV-001");
    let suid = archive
        .audit
        .findings
        .iter()
        .any(|f| f.code == "EXTFS-PERM-001");

    assert!(!trav, "Hardened image should not have path traversal");
    assert!(!suid, "Hardened image should not have SUID binary");
}

#[test]
fn test_extfs_safe_disk_extraction() {
    let img = build_synthetic_extfs(false, Endianness::Little, false);
    let archive = ExtArchive::parse(&img).expect("Failed to parse image");

    let temp_dir = std::env::temp_dir().join(format!("fcarver_ext_test_{}", std::process::id()));
    if temp_dir.exists() {
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    let count = archive
        .extract_to_disk(&img, &temp_dir)
        .expect("Extraction failed");
    assert!(count >= 4);

    let extracted_hostname = temp_dir.join("etc").join("hostname");
    assert!(extracted_hostname.exists());
    let data = std::fs::read(&extracted_hostname).expect("Read extracted file");
    assert_eq!(data, b"router-gw01\n");

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_extfs_raw_firmware_partition_carver() {
    let ext_fs = build_synthetic_extfs(false, Endianness::Little, false);

    // Embed in synthetic firmware blob with leading and trailing noise
    let mut blob = Vec::new();
    blob.resize(2048, 0x55); // 2048 bytes leading bootloader padding
    let embed_offset = blob.len();
    blob.extend_from_slice(&ext_fs);
    blob.resize(blob.len() + 4096, 0xAA); // trailing padding

    let span = probe_extfs_at(&blob, embed_offset).expect("Failed to probe embedded extfs");
    assert_eq!(span.offset, embed_offset);
    assert_eq!(span.block_size, 1024);
    assert_eq!(span.version, ExtVersion::Ext2);
    assert!(span.recovered_entries >= 4);

    let partitions = scan_extfs_partitions(&blob);
    assert_eq!(partitions.len(), 1);
    assert_eq!(partitions[0].offset, embed_offset);
}

#[test]
fn test_extfs_corrupted_and_truncated_resilience() {
    // Truncated buffer shorter than superblock
    let short_buf = vec![0u8; 500];
    assert!(ExtArchive::parse(&short_buf).is_err());

    // Bad magic bytes
    let mut bad_magic = build_synthetic_extfs(false, Endianness::Little, false);
    bad_magic[1024 + 0x38] = 0x00;
    bad_magic[1024 + 0x39] = 0x00;
    assert!(ExtArchive::parse(&bad_magic).is_err());

    // Bad block size (> 6)
    let mut bad_bs = build_synthetic_extfs(false, Endianness::Little, false);
    bad_bs[1024 + 0x18] = 0x0A;
    assert!(ExtArchive::parse(&bad_bs).is_err());
}

#[test]
fn test_extfs_listing_and_json_serialization() {
    let img = build_synthetic_extfs(false, Endianness::Little, true);
    let archive = ExtArchive::parse(&img).expect("Parse image");

    let listing = archive.format_listing();
    assert!(listing.contains("/etc/hostname"));
    assert!(listing.contains("/bin/su"));

    let summary = archive.format_summary();
    assert!(summary.contains("entries"));
    assert!(summary.contains("Findings"));

    let table = archive.format_audit_table();
    assert!(table.contains("EXTFS-TRAV-001"));
    assert!(table.contains("EXTFS-SHADOW-001"));

    let json_text = serde_json::to_string(&archive).expect("Serialize to JSON");
    let roundtrip: ExtArchive = serde_json::from_str(&json_text).expect("Deserialize JSON");
    assert_eq!(roundtrip.superblock.magic, EXT_SUPER_MAGIC);
    assert_eq!(roundtrip.entries.len(), archive.entries.len());
}
