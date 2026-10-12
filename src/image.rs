// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::error::{CarverError, Result};
use serde::{Deserialize, Serialize};

/// Standard IEEE 802.3 CRC32 calculation.
pub fn compute_crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if (crc & 1) != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

pub const UBOOT_MAGIC: u32 = 0x2705_1956;
pub const TRX_MAGIC_LE: u32 = 0x3030_4448; // "HDR0" in little-endian representation
pub const TRX_MAGIC_BYTES: &[u8; 4] = b"HDR0";
pub const FDT_MAGIC: u32 = 0xD00D_FEED;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ContainerKind {
    UBoot,
    BroadcomTrx,
    DeviceTreeBlob,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UBootDetails {
    pub magic: u32,
    pub header_crc: u32,
    pub timestamp: u32,
    pub data_size: u32,
    pub load_address: u32,
    pub entry_point: u32,
    pub data_crc: u32,
    pub os_type: u8,
    pub architecture: u8,
    pub image_type: u8,
    pub compression: u8,
    pub image_name: String,
    pub header_crc_valid: bool,
    pub data_crc_valid: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrxDetails {
    pub magic: String,
    pub total_length: u32,
    pub crc32: u32,
    pub version: u16,
    pub flags: u16,
    pub offsets: [u32; 3],
    pub crc_valid: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FdtDetails {
    pub magic: u32,
    pub total_size: u32,
    pub off_dt_struct: u32,
    pub off_dt_strings: u32,
    pub off_mem_rsvmap: u32,
    pub version: u32,
    pub last_comp_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "details")]
pub enum ContainerMetadata {
    UBoot(UBootDetails),
    Trx(TrxDetails),
    Fdt(FdtDetails),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredContainer {
    pub kind: ContainerKind,
    pub container_offset: usize,
    pub payload_offset: usize,
    pub payload_size: usize,
    pub metadata: ContainerMetadata,
}

pub fn parse_uboot_header(data: &[u8], offset: usize) -> Option<DiscoveredContainer> {
    if data.len() < offset + 64 {
        return None;
    }
    let slice = &data[offset..offset + 64];
    let magic = u32::from_be_bytes(slice[0..4].try_into().ok()?);
    if magic != UBOOT_MAGIC {
        return None;
    }

    let hcrc = u32::from_be_bytes(slice[4..8].try_into().ok()?);
    let time = u32::from_be_bytes(slice[8..12].try_into().ok()?);
    let size = u32::from_be_bytes(slice[12..16].try_into().ok()?);
    let load = u32::from_be_bytes(slice[16..20].try_into().ok()?);
    let ep = u32::from_be_bytes(slice[20..24].try_into().ok()?);
    let dcrc = u32::from_be_bytes(slice[24..28].try_into().ok()?);
    let os = slice[28];
    let arch = slice[29];
    let image_type = slice[30];
    let comp = slice[31];

    let name_raw = &slice[32..64];
    let name_end = name_raw.iter().position(|&c| c == 0).unwrap_or(32);
    let image_name = String::from_utf8_lossy(&name_raw[..name_end]).to_string();

    let mut zero_crc_header = [0u8; 64];
    zero_crc_header.copy_from_slice(slice);
    zero_crc_header[4..8].copy_from_slice(&[0, 0, 0, 0]);
    let calc_hcrc = compute_crc32(&zero_crc_header);
    let header_crc_valid = calc_hcrc == hcrc;

    let payload_offset = offset + 64;
    let payload_size = size as usize;
    let data_crc_valid = if data.len() >= payload_offset + payload_size {
        let calc_dcrc = compute_crc32(&data[payload_offset..payload_offset + payload_size]);
        Some(calc_dcrc == dcrc)
    } else {
        None
    };

    Some(DiscoveredContainer {
        kind: ContainerKind::UBoot,
        container_offset: offset,
        payload_offset,
        payload_size,
        metadata: ContainerMetadata::UBoot(UBootDetails {
            magic,
            header_crc: hcrc,
            timestamp: time,
            data_size: size,
            load_address: load,
            entry_point: ep,
            data_crc: dcrc,
            os_type: os,
            architecture: arch,
            image_type,
            compression: comp,
            image_name,
            header_crc_valid,
            data_crc_valid,
        }),
    })
}

pub fn parse_trx_header(data: &[u8], offset: usize) -> Option<DiscoveredContainer> {
    if data.len() < offset + 28 {
        return None;
    }
    let slice = &data[offset..offset + 28];
    if &slice[0..4] != TRX_MAGIC_BYTES {
        return None;
    }

    let len = u32::from_le_bytes(slice[4..8].try_into().ok()?);
    let crc = u32::from_le_bytes(slice[8..12].try_into().ok()?);
    let version_flags = u32::from_le_bytes(slice[12..16].try_into().ok()?);
    let version = (version_flags & 0xFFFF) as u16;
    let flags = (version_flags >> 16) as u16;

    let o0 = u32::from_le_bytes(slice[16..20].try_into().ok()?);
    let o1 = u32::from_le_bytes(slice[20..24].try_into().ok()?);
    let o2 = u32::from_le_bytes(slice[24..28].try_into().ok()?);

    let crc_valid = if data.len() >= offset + len as usize && len >= 12 {
        let payload_to_check = &data[offset + 12..offset + len as usize];
        Some(compute_crc32(payload_to_check) == crc)
    } else {
        None
    };

    let payload_offset = offset + (if o0 >= 28 { o0 as usize } else { 28 });
    let total_len = len as usize;
    let payload_size = total_len.saturating_sub(payload_offset - offset);

    Some(DiscoveredContainer {
        kind: ContainerKind::BroadcomTrx,
        container_offset: offset,
        payload_offset,
        payload_size,
        metadata: ContainerMetadata::Trx(TrxDetails {
            magic: "HDR0".to_string(),
            total_length: len,
            crc32: crc,
            version,
            flags,
            offsets: [o0, o1, o2],
            crc_valid,
        }),
    })
}

pub fn parse_fdt_header(data: &[u8], offset: usize) -> Option<DiscoveredContainer> {
    if data.len() < offset + 28 {
        return None;
    }
    let slice = &data[offset..offset + 28];
    let magic = u32::from_be_bytes(slice[0..4].try_into().ok()?);
    if magic != FDT_MAGIC {
        return None;
    }

    let totalsize = u32::from_be_bytes(slice[4..8].try_into().ok()?);
    let off_dt_struct = u32::from_be_bytes(slice[8..12].try_into().ok()?);
    let off_dt_strings = u32::from_be_bytes(slice[12..16].try_into().ok()?);
    let off_mem_rsvmap = u32::from_be_bytes(slice[16..20].try_into().ok()?);
    let version = u32::from_be_bytes(slice[20..24].try_into().ok()?);
    let last_comp_version = u32::from_be_bytes(slice[24..28].try_into().ok()?);

    Some(DiscoveredContainer {
        kind: ContainerKind::DeviceTreeBlob,
        container_offset: offset,
        payload_offset: offset + 28,
        payload_size: if totalsize >= 28 {
            totalsize as usize - 28
        } else {
            0
        },
        metadata: ContainerMetadata::Fdt(FdtDetails {
            magic,
            total_size: totalsize,
            off_dt_struct,
            off_dt_strings,
            off_mem_rsvmap,
            version,
            last_comp_version,
        }),
    })
}

/// Scans the entire binary blob for known container headers.
pub fn scan_containers(data: &[u8]) -> Vec<DiscoveredContainer> {
    let mut results = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if let Some(c) = parse_uboot_header(data, i) {
            results.push(c);
            i += 64;
            continue;
        }
        if let Some(c) = parse_trx_header(data, i) {
            results.push(c);
            i += 28;
            continue;
        }
        if let Some(c) = parse_fdt_header(data, i) {
            results.push(c);
            i += 28;
            continue;
        }
        i += 1;
    }
    results
}

/// Helper generating valid test firmware blobs deterministically.
pub fn build_synthetic_firmware(image_type: &str, payload: &[u8]) -> Result<Vec<u8>> {
    match image_type.to_lowercase().as_str() {
        "uboot" | "uimage" => {
            let mut blob = Vec::with_capacity(64 + payload.len());
            let mut header = [0u8; 64];
            header[0..4].copy_from_slice(&UBOOT_MAGIC.to_be_bytes());
            header[8..12].copy_from_slice(&1_700_000_000u32.to_be_bytes()); // deterministic time
            header[12..16].copy_from_slice(&(payload.len() as u32).to_be_bytes());
            header[16..20].copy_from_slice(&0x8000_0000u32.to_be_bytes()); // load
            header[20..24].copy_from_slice(&0x8000_0000u32.to_be_bytes()); // ep
            let dcrc = compute_crc32(payload);
            header[24..28].copy_from_slice(&dcrc.to_be_bytes());
            header[28] = 5; // Linux
            header[29] = 2; // ARM
            header[30] = 2; // Kernel
            header[31] = 1; // Gzip
            let name = b"Synthetic Linux Kernel";
            header[32..32 + name.len()].copy_from_slice(name);
            let hcrc = compute_crc32(&header);
            header[4..8].copy_from_slice(&hcrc.to_be_bytes());

            blob.extend_from_slice(&header);
            blob.extend_from_slice(payload);
            Ok(blob)
        }
        "trx" => {
            let total_len = (28 + payload.len()) as u32;
            let mut blob = Vec::with_capacity(total_len as usize);
            blob.extend_from_slice(TRX_MAGIC_BYTES);
            blob.extend_from_slice(&total_len.to_le_bytes());
            blob.extend_from_slice(&[0, 0, 0, 0]); // CRC placeholder at offset 8..12
            let version_flags = 1u32; // v1
            blob.extend_from_slice(&version_flags.to_le_bytes());
            blob.extend_from_slice(&28u32.to_le_bytes()); // offset 0
            blob.extend_from_slice(&0u32.to_le_bytes()); // offset 1
            blob.extend_from_slice(&0u32.to_le_bytes()); // offset 2
            blob.extend_from_slice(payload);

            let crc = compute_crc32(&blob[12..]);
            blob[8..12].copy_from_slice(&crc.to_le_bytes());
            Ok(blob)
        }
        "fdt" | "dtb" => {
            let total_len = (28 + payload.len()) as u32;
            let mut blob = Vec::with_capacity(total_len as usize);
            blob.extend_from_slice(&FDT_MAGIC.to_be_bytes());
            blob.extend_from_slice(&total_len.to_be_bytes());
            blob.extend_from_slice(&28u32.to_be_bytes()); // off_dt_struct
            blob.extend_from_slice(&28u32.to_be_bytes()); // off_dt_strings
            blob.extend_from_slice(&28u32.to_be_bytes()); // off_mem_rsvmap
            blob.extend_from_slice(&17u32.to_be_bytes()); // version 17
            blob.extend_from_slice(&16u32.to_be_bytes()); // last_comp_version
            blob.extend_from_slice(payload);
            Ok(blob)
        }
        _ => Err(CarverError::InvalidArgument(format!(
            "Unsupported synthetic firmware container type: {}. Available: uboot, trx, fdt",
            image_type
        ))),
    }
}
