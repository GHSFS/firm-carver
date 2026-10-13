// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use firm_carver::carve::scan_carvable_streams;
use firm_carver::ubifs::{
    build_synthetic_ubi, build_synthetic_ubifs, extract_archive_to_disk, format_mode_string,
    parse_ec_header, parse_vid_header, parse_vtbl_record, scan_ubi_partitions, validate_safe_path,
    Endianness, UbiImage, UbifsArchive, UbifsFileType, UBI_EC_HDR_MAGIC, UBI_LAYOUT_VOLUME_ID,
    UBI_VID_HDR_MAGIC,
};
use std::collections::HashMap;
use std::fs;

#[test]
fn test_ubi_ec_and_vid_headers_parsing_and_crc() {
    let synthetic_ubi = build_synthetic_ubi(Endianness::Little);
    assert!(synthetic_ubi.len() >= 128 * 1024);

    // First PEB (EC header at offset 0)
    let ec = parse_ec_header(&synthetic_ubi[0..64]).expect("EC header should parse");
    assert_eq!(ec.magic, UBI_EC_HDR_MAGIC);
    assert_eq!(ec.version, 1);
    assert_eq!(ec.ec, 10);
    assert_eq!(ec.vid_hdr_offset, 512);
    assert_eq!(ec.data_offset, 2048);
    assert!(ec.crc_valid);

    // VID header at offset 512
    let vid = parse_vid_header(&synthetic_ubi[512..512 + 64]).expect("VID header should parse");
    assert_eq!(vid.magic, UBI_VID_HDR_MAGIC);
    assert_eq!(vid.version, 1);
    assert_eq!(vid.vol_id, UBI_LAYOUT_VOLUME_ID);
    assert_eq!(vid.lnum, 0);
    assert!(vid.crc_valid);

    // Corrupted EC header CRC
    let mut corrupt_ec = synthetic_ubi[0..64].to_vec();
    corrupt_ec[10] ^= 0xFF; // Modify byte in EC header
    let ec_corrupted = parse_ec_header(&corrupt_ec).expect("Should parse structure");
    assert!(
        !ec_corrupted.crc_valid,
        "Corrupted header must fail CRC validation"
    );
}

#[test]
fn test_ubi_volume_table_record_parsing() {
    let synthetic_ubi = build_synthetic_ubi(Endianness::Little);

    // In synthetic UBI, layout volume data starts at offset 2048
    let vtbl_slice = &synthetic_ubi[2048..2048 + 172];
    let vtbl = parse_vtbl_record(vtbl_slice).expect("VTBL record should parse");
    assert_eq!(vtbl.name, "rootfs");
    assert_eq!(vtbl.reserved_pebs, 16);
    assert!(vtbl.crc_valid);
}

#[test]
fn test_ubi_synthetic_image_full_parse() {
    let synthetic_ubi = build_synthetic_ubi(Endianness::Little);
    let ubi =
        UbiImage::parse(&synthetic_ubi, Some(128 * 1024)).expect("UbiImage parse should succeed");

    assert_eq!(ubi.peb_size, 128 * 1024);
    assert_eq!(ubi.pebs.len(), 3); // PEB 0, 1 (layout), PEB 2 (rootfs)

    let summaries = ubi.get_volume_summaries();
    assert!(!summaries.is_empty());
    let rootfs = summaries
        .iter()
        .find(|s| s.name == "rootfs")
        .expect("rootfs volume must be present");
    assert_eq!(rootfs.vol_id, 0);
    assert_eq!(rootfs.mapped_lebs, 1);

    let vol_data = ubi
        .assemble_volume_data(0)
        .expect("Assembled volume data must exist");
    assert!(!vol_data.is_empty());
}

#[test]
fn test_ubifs_synthetic_little_endian_tree_recovery() {
    let ubifs_blob = build_synthetic_ubifs(Endianness::Little);
    let archive = UbifsArchive::parse(&ubifs_blob).expect("UBIFS parse should succeed");

    assert_eq!(archive.endianness, Endianness::Little);
    assert!(!archive.is_ubi_container);

    let sb = archive
        .superblock
        .as_ref()
        .expect("Superblock must be present");
    assert_eq!(sb.fmt_version, 5);
    assert_eq!(sb.leb_cnt, 16);
    assert_eq!(sb.uuid, "12345678-9abc-def0-1122-334455667788");

    let mst = archive
        .master_node
        .as_ref()
        .expect("Master node must be present");
    assert_eq!(mst.cmt_no, 1);
    assert_eq!(mst.highest_inum, 10);
    assert_eq!(mst.total_used, 250000);

    // Verify directory tree entries
    let paths: Vec<&str> = archive.entries.iter().map(|e| e.path.as_str()).collect();
    assert!(paths.contains(&"/"));
    assert!(paths.contains(&"/bin"));
    assert!(paths.contains(&"/etc"));
    assert!(paths.contains(&"/bin/busybox"));
    assert!(paths.contains(&"/etc/passwd"));
    assert!(paths.contains(&"/bin/sh"));

    // Verify symlink target
    let sh_entry = archive
        .entries
        .iter()
        .find(|e| e.path == "/bin/sh")
        .expect("/bin/sh must exist");
    assert_eq!(sh_entry.file_type, UbifsFileType::Symlink);
    assert_eq!(sh_entry.symlink_target.as_deref(), Some("/bin/busybox"));

    // Verify summary formatting
    let summary = archive.format_summary();
    assert!(summary.contains("Standalone UBIFS Image"));
    assert!(summary.contains("Format v5"));
    assert!(summary.contains("Recovered Entries:"));
}

#[test]
fn test_ubifs_synthetic_big_endian_parsing() {
    let ubifs_blob_be = build_synthetic_ubifs(Endianness::Big);
    let archive = UbifsArchive::parse(&ubifs_blob_be).expect("UBIFS BE parse should succeed");

    assert_eq!(archive.endianness, Endianness::Big);

    let sb = archive
        .superblock
        .as_ref()
        .expect("Superblock must be present");
    assert_eq!(sb.fmt_version, 5);
    assert_eq!(sb.leb_cnt, 16);

    let mst = archive
        .master_node
        .as_ref()
        .expect("Master node must be present");
    assert_eq!(mst.highest_inum, 10);

    let paths: Vec<&str> = archive.entries.iter().map(|e| e.path.as_str()).collect();
    assert!(paths.contains(&"/bin/busybox"));
    assert!(paths.contains(&"/etc/passwd"));
}

#[test]
fn test_ubifs_mode_formatting_and_listing() {
    assert_eq!(
        format_mode_string(0o755, UbifsFileType::Directory),
        "drwxr-xr-x"
    );
    assert_eq!(
        format_mode_string(0o777, UbifsFileType::Symlink),
        "lrwxrwxrwx"
    );
    assert_eq!(
        format_mode_string(0o644, UbifsFileType::Regular),
        "-rw-r--r--"
    );

    let ubifs_blob = build_synthetic_ubifs(Endianness::Little);
    let archive = UbifsArchive::parse(&ubifs_blob).expect("UBIFS parse should succeed");
    let listing = archive.format_listing();

    assert!(listing.contains("drwxr-xr-x"));
    assert!(listing.contains("/bin/busybox"));
    assert!(listing.contains("-> /bin/busybox"));
}

#[test]
fn test_ubifs_path_traversal_defense() {
    let temp_dir = std::env::temp_dir().join(format!(
        "fcarver_ubifs_traversal_test_{}",
        std::process::id()
    ));
    fs::create_dir_all(&temp_dir).ok();
    let base = &temp_dir;

    assert!(validate_safe_path(base, "/etc/passwd").is_ok());
    assert!(validate_safe_path(base, "bin/sh").is_ok());

    // Path traversal attempts must be rejected
    assert!(validate_safe_path(base, "/../etc/shadow").is_err());
    assert!(validate_safe_path(base, "bin/../../etc/passwd").is_err());
    assert!(validate_safe_path(base, "../../root/.ssh/id_rsa").is_err());

    fs::remove_dir_all(&temp_dir).ok();
}

#[test]
fn test_ubifs_disk_extraction() {
    let temp_dir =
        std::env::temp_dir().join(format!("fcarver_ubifs_extract_test_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).ok();

    let ubifs_blob = build_synthetic_ubifs(Endianness::Little);
    let archive = UbifsArchive::parse(&ubifs_blob).expect("UBIFS parse should succeed");

    let mut contents = HashMap::new();
    contents.insert(5, b"root:x:0:0:root:/root:/bin/sh\n".to_vec());

    let extracted = extract_archive_to_disk(&archive.entries, &temp_dir, &contents)
        .expect("Extraction should succeed");
    assert!(extracted >= 5);

    let passwd_file = temp_dir.join("etc").join("passwd");
    assert!(passwd_file.exists());
    let text = fs::read_to_string(&passwd_file).expect("Read passwd file");
    assert!(text.contains("root:x:0:0"));

    fs::remove_dir_all(&temp_dir).ok();
}

#[test]
fn test_ubi_raw_firmware_stream_carving() {
    let mut raw_firmware = vec![0xCCu8; 4096]; // Padded firmware header
    let synthetic_ubi = build_synthetic_ubi(Endianness::Little);
    let ubi_offset = raw_firmware.len();
    raw_firmware.extend_from_slice(&synthetic_ubi);
    raw_firmware.extend_from_slice(&[0xAAu8; 8192]); // Trailing firmware blob

    let partitions = scan_ubi_partitions(&raw_firmware);
    assert_eq!(partitions.len(), 1);
    assert_eq!(partitions[0].offset, ubi_offset);
    assert_eq!(partitions[0].peb_size, 128 * 1024);
    assert!(partitions[0].volume_names.contains(&"rootfs".to_string()));

    let carved = scan_carvable_streams(&raw_firmware);
    let ubi_seg = carved
        .iter()
        .find(|s| s.kind == firm_carver::carve::CarvedKind::Ubi);
    assert!(
        ubi_seg.is_some(),
        "UBI partition must be identified by carve scanner"
    );
    assert_eq!(ubi_seg.unwrap().offset, ubi_offset);
}

#[test]
fn test_ubifs_corrupted_and_truncated_resilience() {
    // Empty data
    assert!(UbifsArchive::parse(&[]).is_err());
    assert!(parse_ec_header(&[]).is_none());
    assert!(parse_vid_header(&[]).is_none());
    assert!(parse_vtbl_record(&[]).is_none());

    // Truncated data
    let short_data = vec![0x55, 0x42, 0x49, 0x23];
    assert!(parse_ec_header(&short_data).is_none());

    // Corrupted magic
    let fake_data = vec![0xFF; 128];
    assert!(parse_ec_header(&fake_data).is_none());
    assert!(parse_vid_header(&fake_data).is_none());
}

#[test]
fn test_ubifs_json_serialization_roundtrip() {
    let synthetic_ubi = build_synthetic_ubi(Endianness::Little);
    let archive = UbifsArchive::parse(&synthetic_ubi).expect("UBI parse should succeed");

    let json_text = serde_json::to_string_pretty(&archive).expect("Serialize to JSON");
    assert!(json_text.contains("\"is_ubi_container\": true"));
    assert!(json_text.contains("\"rootfs\""));

    let deserialized: UbifsArchive =
        serde_json::from_str(&json_text).expect("Deserialize from JSON");
    assert_eq!(deserialized.is_ubi_container, archive.is_ubi_container);
    assert_eq!(deserialized.entries.len(), archive.entries.len());
}
