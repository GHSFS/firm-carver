// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use firm_carver::carve::{carve_and_extract, scan_carvable_streams, CarvedKind};
use firm_carver::image::{
    build_synthetic_firmware, scan_containers, ContainerKind, ContainerMetadata, FDT_MAGIC,
    UBOOT_MAGIC,
};
use std::fs;

#[test]
fn test_uboot_container_generation_and_inspection() {
    let payload = b"VMLINUX_EMBEDDED_KERNEL_DATA_TEST_STREAM";
    let fw = build_synthetic_firmware("uboot", payload).expect("Failed to build synthetic uImage");

    assert!(fw.len() >= 64 + payload.len());
    let containers = scan_containers(&fw);
    assert_eq!(containers.len(), 1);

    let c = &containers[0];
    assert_eq!(c.kind, ContainerKind::UBoot);
    assert_eq!(c.container_offset, 0);
    assert_eq!(c.payload_size, payload.len());

    if let ContainerMetadata::UBoot(u) = &c.metadata {
        assert_eq!(u.magic, UBOOT_MAGIC);
        assert!(u.header_crc_valid);
        assert_eq!(u.data_crc_valid, Some(true));
        assert_eq!(u.image_name, "Synthetic Linux Kernel");
    } else {
        panic!("Expected UBoot container metadata");
    }
}

#[test]
fn test_trx_container_generation_and_inspection() {
    let payload = b"BROADCOM_ROUTER_PARTITION_CHUNK_STREAM";
    let fw = build_synthetic_firmware("trx", payload).expect("Failed to build synthetic TRX");

    assert!(fw.len() >= 28 + payload.len());
    let containers = scan_containers(&fw);
    assert_eq!(containers.len(), 1);

    let c = &containers[0];
    assert_eq!(c.kind, ContainerKind::BroadcomTrx);
    if let ContainerMetadata::Trx(t) = &c.metadata {
        assert_eq!(t.magic, "HDR0");
        assert_eq!(t.total_length as usize, 28 + payload.len());
        assert_eq!(t.crc_valid, Some(true));
    } else {
        panic!("Expected TRX container metadata");
    }
}

#[test]
fn test_fdt_container_generation_and_inspection() {
    let payload = b"DEVICE_TREE_BLOB_STRUCTURE";
    let fw = build_synthetic_firmware("fdt", payload).expect("Failed to build synthetic FDT");

    let containers = scan_containers(&fw);
    assert_eq!(containers.len(), 1);
    let c = &containers[0];
    assert_eq!(c.kind, ContainerKind::DeviceTreeBlob);
    if let ContainerMetadata::Fdt(f) = &c.metadata {
        assert_eq!(f.magic, FDT_MAGIC);
        assert_eq!(f.version, 17);
    } else {
        panic!("Expected FDT container metadata");
    }
}

#[test]
fn test_squashfs_and_gzip_stream_carving() {
    let mut blob = Vec::new();
    blob.extend_from_slice(b"PREAMBLE_DATA_PAD_OFFSET_00000000");

    // Embed a SquashFS 4.0 superblock at offset blob.len()
    let sqsh_offset = blob.len();
    blob.extend_from_slice(&0x73717368u32.to_le_bytes()); // sqsh magic
    blob.extend_from_slice(&42u32.to_le_bytes()); // 42 inodes
    blob.extend_from_slice(&1_710_000_000u32.to_le_bytes()); // time
    blob.extend_from_slice(&131072u32.to_le_bytes()); // 128k block size
    blob.resize(sqsh_offset + 28, 0);
    blob.extend_from_slice(&4u16.to_le_bytes()); // major 4
    blob.extend_from_slice(&0u16.to_le_bytes()); // minor 0
    blob.resize(sqsh_offset + 40, 0);
    let sqsh_len = 256u64;
    blob.extend_from_slice(&sqsh_len.to_le_bytes()); // bytes_used
    blob.resize(sqsh_offset + sqsh_len as usize, 0x55);

    // Embed a Gzip archive right after
    let gz_offset = blob.len();
    blob.extend_from_slice(&[0x1F, 0x8B, 0x08, 0x00]); // gzip magic + deflate
    blob.extend_from_slice(&1_710_000_100u32.to_le_bytes()); // mtime
    blob.extend_from_slice(&[0x02, 0x03]); // xfl, os = unix
    blob.extend_from_slice(b"COMPRESSED_PAYLOAD_BYTES");

    let segments = scan_carvable_streams(&blob);
    assert_eq!(segments.len(), 2);

    assert_eq!(segments[0].kind, CarvedKind::SquashFs);
    assert_eq!(segments[0].offset, sqsh_offset);
    assert_eq!(segments[0].length, sqsh_len as usize);

    assert_eq!(segments[1].kind, CarvedKind::Gzip);
    assert_eq!(segments[1].offset, gz_offset);

    // Test extraction to directory
    let temp_dir = std::env::temp_dir().join(format!("fcarver_test_{}", std::process::id()));
    let manifest =
        carve_and_extract(&blob, &temp_dir, "test_firmware.bin").expect("Carve and extract failed");

    assert_eq!(manifest.carved_count, 2);
    assert!(temp_dir.join("manifest.json").exists());

    // Clean up temp directory
    let _ = fs::remove_dir_all(&temp_dir);
}
