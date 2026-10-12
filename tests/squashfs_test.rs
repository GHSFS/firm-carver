// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use firm_carver::squashfs::superblock::{CompressionType, Endianness, SquashFsSuperblock};
use firm_carver::squashfs::{build_synthetic_squashfs, SquashFsArchive};

#[test]
fn test_squashfs_superblock_parse_little_endian() {
    let image = build_synthetic_squashfs(false);
    let sb = SquashFsSuperblock::parse(&image).expect("Failed to parse little-endian superblock");

    assert_eq!(sb.endianness, Endianness::Little);
    assert_eq!(sb.magic, 0x7371_7368);
    assert_eq!(sb.version_major, 4);
    assert_eq!(sb.version_minor, 0);
    assert_eq!(sb.block_size, 4096);
    assert_eq!(sb.block_log, 12);
    assert_eq!(sb.inode_count, 6);
    assert_eq!(sb.compression, CompressionType::Gzip);
    assert!(sb.uncompressed_inodes());
    assert!(!sb.uncompressed_data());
}

#[test]
fn test_squashfs_superblock_parse_big_endian() {
    let image = build_synthetic_squashfs(true);
    let sb = SquashFsSuperblock::parse(&image).expect("Failed to parse big-endian superblock");

    assert_eq!(sb.endianness, Endianness::Big);
    assert_eq!(sb.magic, 0x6873_7173);
    assert_eq!(sb.version_major, 4);
    assert_eq!(sb.version_minor, 0);
    assert_eq!(sb.block_size, 4096);
    assert_eq!(sb.block_log, 12);
    assert_eq!(sb.inode_count, 6);
}

#[test]
fn test_squashfs_full_directory_tree_extraction() {
    let image = build_synthetic_squashfs(false);
    let archive = SquashFsArchive::parse(&image).expect("Failed to parse SquashFS archive");

    assert_eq!(archive.superblock.inode_count, 6);
    assert_eq!(archive.entries.len(), 6);

    // Root directory
    let root = archive.find_entry("/").expect("Root '/' not found");
    assert_eq!(root.inode_type, "directory");
    assert_eq!(root.inode_number, 1);
    assert_eq!(root.mode, 0o755);

    // /bin directory
    let bin_dir = archive.find_entry("/bin").expect("'/bin' not found");
    assert_eq!(bin_dir.inode_type, "directory");
    assert_eq!(bin_dir.inode_number, 2);

    // /bin/busybox file
    let busybox = archive
        .find_entry("/bin/busybox")
        .expect("'/bin/busybox' not found");
    assert_eq!(busybox.inode_type, "file");
    assert_eq!(busybox.inode_number, 3);
    assert_eq!(busybox.file_size, 1_048_576);
    assert_eq!(busybox.mode, 0o755);

    // /bin/sh symlink -> "busybox"
    let sh = archive.find_entry("/bin/sh").expect("'/bin/sh' not found");
    assert_eq!(sh.inode_type, "symlink");
    assert_eq!(sh.inode_number, 4);
    assert_eq!(sh.symlink_target.as_deref(), Some("busybox"));

    // /etc directory
    let etc_dir = archive.find_entry("/etc").expect("'/etc' not found");
    assert_eq!(etc_dir.inode_type, "directory");
    assert_eq!(etc_dir.inode_number, 5);

    // /etc/shadow sensitive credential file
    let shadow = archive
        .find_entry("/etc/shadow")
        .expect("'/etc/shadow' not found");
    assert_eq!(shadow.inode_type, "file");
    assert_eq!(shadow.inode_number, 6);
    assert_eq!(shadow.file_size, 128);
    assert_eq!(shadow.mode, 0o600);
}

#[test]
fn test_squashfs_big_endian_directory_tree_extraction() {
    let image = build_synthetic_squashfs(true);
    let archive = SquashFsArchive::parse(&image).expect("Failed to parse BE archive");

    assert_eq!(archive.entries.len(), 6);
    let shadow = archive
        .find_entry("/etc/shadow")
        .expect("BE '/etc/shadow' not found");
    assert_eq!(shadow.inode_type, "file");
    assert_eq!(shadow.mode, 0o600);

    let sh = archive
        .find_entry("/bin/sh")
        .expect("BE '/bin/sh' not found");
    assert_eq!(sh.symlink_target.as_deref(), Some("busybox"));
}

#[test]
fn test_squashfs_format_listing() {
    let image = build_synthetic_squashfs(false);
    let archive = SquashFsArchive::parse(&image).unwrap();
    let listing = archive.format_listing();

    assert!(listing.contains("drwxr-xr-x"));
    assert!(listing.contains("-rwxr-xr-x"));
    assert!(listing.contains("/bin/busybox"));
    assert!(listing.contains("/bin/sh -> busybox"));
    assert!(listing.contains("/etc/shadow"));
}

#[test]
fn test_squashfs_invalid_inputs_and_bounds_guards() {
    // Underflow test: < 96 bytes
    let small_buf = vec![0u8; 40];
    assert!(SquashFsSuperblock::parse(&small_buf).is_err());

    // Bad magic
    let mut bad_magic = build_synthetic_squashfs(false);
    bad_magic[0] = 0xFF;
    assert!(SquashFsSuperblock::parse(&bad_magic).is_err());

    // Non-power of two block size
    let mut bad_block = build_synthetic_squashfs(false);
    bad_block[12..16].copy_from_slice(&5000u32.to_le_bytes());
    assert!(SquashFsSuperblock::parse(&bad_block).is_err());
}

#[test]
fn test_squashfs_embedded_stream_offset_parsing() {
    let raw_fs = build_synthetic_squashfs(false);
    let mut padded = Vec::new();
    padded.extend_from_slice(&[0xCC; 256]); // Padded bootloader offset
    padded.extend_from_slice(&raw_fs);

    // Parse at exact offset 256
    let archive = SquashFsArchive::parse(&padded[256..]).expect("Failed to parse at offset 256");
    assert_eq!(archive.entries.len(), 6);
    assert!(archive.find_entry("/etc/shadow").is_some());
}
