// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use firm_carver::carve::{scan_carvable_streams, CarvedKind};
use firm_carver::jffs2::decompress::{compress_rtime, decompress_rtime};
use firm_carver::jffs2::{
    build_synthetic_jffs2, scan_jffs2_partitions, Endianness, Jffs2Archive, Jffs2Entry,
    Jffs2FileType,
};
use std::fs;

#[test]
fn test_jffs2_synthetic_little_endian_parsing() {
    let image = build_synthetic_jffs2(false);
    let archive = Jffs2Archive::parse(&image).expect("Failed to parse LE JFFS2 image");

    assert_eq!(archive.endianness, Endianness::Little);
    assert!(archive.cleanmarker_count >= 1);
    assert!(archive.entries.len() >= 6);

    let paths: Vec<&str> = archive.entries.iter().map(|e| e.path.as_str()).collect();
    assert!(paths.contains(&"/"));
    assert!(paths.contains(&"/etc"));
    assert!(paths.contains(&"/bin"));
    assert!(paths.contains(&"/etc/banner"));
    assert!(paths.contains(&"/etc/config"));
    assert!(paths.contains(&"/bin/busybox"));
    assert!(paths.contains(&"/bin/sh"));
    assert!(paths.contains(&"/etc/hosts"));

    let banner = archive
        .entries
        .iter()
        .find(|e| e.path == "/etc/banner")
        .expect("Missing /etc/banner");
    assert_eq!(banner.file_type, Jffs2FileType::Regular);
    assert!(banner.size > 0);
    let banner_text = String::from_utf8_lossy(&banner.data);
    assert!(banner_text.contains("FirmCarver JFFS2 Recovery Banner"));
}

#[test]
fn test_jffs2_synthetic_big_endian_parsing() {
    let image = build_synthetic_jffs2(true);
    let archive = Jffs2Archive::parse(&image).expect("Failed to parse BE JFFS2 image");

    assert_eq!(archive.endianness, Endianness::Big);
    assert!(archive.cleanmarker_count >= 1);

    let banner = archive
        .entries
        .iter()
        .find(|e| e.path == "/etc/banner")
        .expect("Missing /etc/banner");
    let banner_text = String::from_utf8_lossy(&banner.data);
    assert!(banner_text.contains("FirmCarver JFFS2 Recovery Banner"));
}

#[test]
fn test_jffs2_rtime_decompression_and_bounds_safety() {
    let source = b"AAAAABBBBBCCCCCDDDDDEEEEEFFFFFGGGGG0123456789";
    let compressed = compress_rtime(source).expect("Failed to compress RTIME");
    let decompressed =
        decompress_rtime(&compressed, source.len()).expect("Failed to decompress RTIME");
    assert_eq!(source.as_slice(), decompressed.as_slice());

    // Bounds safety: Truncated RTIME payload must return Err, never panic
    let truncated = &compressed[..compressed.len() / 2];
    assert!(decompress_rtime(truncated, source.len()).is_err());

    // Corrupted repeat exceeding destination length must return Err
    let malformed = vec![b'X', 250];
    assert!(decompress_rtime(&malformed, 10).is_err());
}

#[test]
fn test_jffs2_zlib_decompression() {
    let image = build_synthetic_jffs2(false);
    let archive = Jffs2Archive::parse(&image).expect("Failed to parse image");

    let busybox = archive
        .entries
        .iter()
        .find(|e| e.path == "/bin/busybox")
        .expect("Missing /bin/busybox");
    assert_eq!(busybox.file_type, Jffs2FileType::Regular);
    assert!(busybox.data.starts_with(b"\x7FELF"));
}

#[test]
fn test_jffs2_multi_chunk_inode_reassembly() {
    let image = build_synthetic_jffs2(false);
    let archive = Jffs2Archive::parse(&image).expect("Failed to parse image");

    let hosts = archive
        .entries
        .iter()
        .find(|e| e.path == "/etc/hosts")
        .expect("Missing /etc/hosts");
    let hosts_text = String::from_utf8_lossy(&hosts.data);
    assert!(hosts_text.contains("127.0.0.1 localhost"));
    assert!(hosts_text.contains("192.168.1.1 router.local"));
}

#[test]
fn test_jffs2_deletion_tombstone_filtering() {
    let image = build_synthetic_jffs2(false);
    let archive = Jffs2Archive::parse(&image).expect("Failed to parse image");

    let deleted = archive.entries.iter().find(|e| e.name == "temp_del");
    assert!(
        deleted.is_none(),
        "Deleted tombstone entry temp_del must not appear in active tree"
    );
}

#[test]
fn test_jffs2_symlink_target_extraction() {
    let image = build_synthetic_jffs2(false);
    let archive = Jffs2Archive::parse(&image).expect("Failed to parse image");

    let sh = archive
        .entries
        .iter()
        .find(|e| e.path == "/bin/sh")
        .expect("Missing /bin/sh");
    assert_eq!(sh.file_type, Jffs2FileType::Symlink);
    assert_eq!(sh.symlink_target.as_deref(), Some("/bin/busybox"));
}

#[test]
fn test_jffs2_path_traversal_extraction_defense() {
    let image = build_synthetic_jffs2(false);
    let mut archive = Jffs2Archive::parse(&image).expect("Failed to parse image");

    let temp_dir = std::env::temp_dir().join(format!("fcarver_test_jffs2_{}", std::process::id()));
    if temp_dir.exists() {
        fs::remove_dir_all(&temp_dir).ok();
    }

    // Normal extraction should succeed cleanly
    let count = archive
        .extract_to_disk(&temp_dir)
        .expect("Extraction to disk failed");
    assert!(count >= 5);
    assert!(temp_dir.join("etc").join("banner").exists());

    // Inject malicious path traversal entry
    archive.entries.push(Jffs2Entry {
        ino: 999,
        pino: 1,
        name: "escape".to_string(),
        path: "/../../malicious_file".to_string(),
        file_type: Jffs2FileType::Regular,
        mode: 0o100644,
        uid: 0,
        gid: 0,
        size: 4,
        mtime: 0,
        symlink_target: None,
        data: b"HACK".to_vec(),
    });

    let result = archive.extract_to_disk(&temp_dir);
    assert!(
        result.is_err(),
        "Extraction must reject path traversal attempt"
    );

    fs::remove_dir_all(&temp_dir).ok();
}

#[test]
fn test_jffs2_raw_firmware_partition_carving() {
    let jffs2_blob = build_synthetic_jffs2(false);
    let mut firmware = vec![0xAA; 0x2000]; // 8KB leading garbage
    let jffs2_offset = firmware.len();
    firmware.extend_from_slice(&jffs2_blob);
    firmware.extend_from_slice(&[0xBB; 0x1000]); // Trailing garbage

    let partitions = scan_jffs2_partitions(&firmware);
    assert_eq!(partitions.len(), 1);
    assert_eq!(partitions[0].offset, jffs2_offset);
    assert!(partitions[0].node_count >= 5);

    let carves = scan_carvable_streams(&firmware);
    let jffs_carve = carves.iter().find(|c| c.kind == CarvedKind::Jffs2);
    assert!(jffs_carve.is_some());
    assert_eq!(jffs_carve.unwrap().offset, jffs2_offset);
}

#[test]
fn test_jffs2_corrupted_and_empty_resilience() {
    assert!(Jffs2Archive::parse(&[]).is_err());
    assert!(Jffs2Archive::parse(&[0u8; 8]).is_err());
    assert!(Jffs2Archive::parse(&[0xFF; 64]).is_err());
    assert!(Jffs2Archive::parse(&[0x19, 0x85, 0x00, 0x00, 0x00]).is_err());
}

#[test]
fn test_jffs2_listing_and_summary_formatting() {
    let image = build_synthetic_jffs2(false);
    let archive = Jffs2Archive::parse(&image).expect("Failed to parse image");

    let listing = archive.format_listing();
    assert!(listing.contains("drwxr-xr-x"));
    assert!(listing.contains("-rw-r--r--"));
    assert!(listing.contains("/etc/banner"));
    assert!(listing.contains("-> /bin/busybox"));

    let summary = archive.format_summary();
    assert!(summary.contains("Endianness:"));
    assert!(summary.contains("Recovered:"));
}
