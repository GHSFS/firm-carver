// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::manifest::{generate_attestation_manifest, AttestationManifest};
use crate::image::build_synthetic_firmware;
use crate::squashfs::build_synthetic_squashfs;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::Write;

/// Build a deterministic multi-stage firmware fixture suitable for integrity verification tests.
pub fn build_synthetic_attested_firmware() -> (Vec<u8>, AttestationManifest) {
    let mut blob = Vec::new();

    // 1. Stage 1: U-Boot container (with 64B header + synthetic payload)
    let uboot_payload = b"VMLINUX_INIT_STAGE_0";
    let uboot = build_synthetic_firmware("uboot", uboot_payload).expect("uboot build failed");
    blob.extend_from_slice(&uboot);

    // Padding between stages
    blob.extend_from_slice(&[0x00; 128]);

    // 2. Stage 2: Embedded Gzip compressed kernel payload
    let kernel_data = b"Linux version 5.15.0-mips (gcc version 11.2.0) #1 PREEMPT Mon Oct 12";
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(kernel_data).expect("gzip compression failed");
    let compressed_kernel = gz.finish().expect("gzip finish failed");
    blob.extend_from_slice(&compressed_kernel);

    // Padding
    blob.extend_from_slice(&[0xFF; 256]);

    // 3. Stage 3: Embedded little-endian SquashFS v4 filesystem
    let sqfs = build_synthetic_squashfs(true);
    blob.extend_from_slice(&sqfs);

    // Final padding
    blob.extend_from_slice(&[0x00; 64]);

    let manifest = generate_attestation_manifest("synthetic_firmware_v1.bin", &blob);
    (blob, manifest)
}

/// Helper function to deterministically tamper with a byte at the specified offset.
pub fn tamper_firmware_byte(original: &[u8], offset: usize) -> Vec<u8> {
    let mut tampered = original.to_vec();
    if offset < tampered.len() {
        tampered[offset] ^= 0xFF;
    }
    tampered
}

/// Helper function to truncate a firmware binary to simulate incomplete flash reads.
pub fn truncate_firmware(original: &[u8], new_len: usize) -> Vec<u8> {
    let len = new_len.min(original.len());
    original[..len].to_vec()
}
