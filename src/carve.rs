// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::error::{CarverError, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub const SQUASHFS_MAGIC_LE: u32 = 0x7371_7368; // "sqsh"
pub const SQUASHFS_MAGIC_BE: u32 = 0x6873_7173; // "hsqs"
pub const CRAMFS_MAGIC_LE: u32 = 0x28cd_3d45;
pub const CRAMFS_MAGIC_BE: u32 = 0x453d_cd28;
pub const XZ_MAGIC: [u8; 6] = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CarvedKind {
    SquashFs,
    CramFs,
    Gzip,
    Lzma,
    Xz,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarvedSegment {
    pub kind: CarvedKind,
    pub offset: usize,
    pub length: usize,
    pub description: String,
    pub endianness: String,
    pub attributes: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extracted_filename: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarveManifest {
    pub source_file: String,
    pub source_size: usize,
    pub carved_count: usize,
    pub segments: Vec<CarvedSegment>,
}

fn parse_squashfs_at(data: &[u8], offset: usize) -> Option<CarvedSegment> {
    if data.len() < offset + 96 {
        return None;
    }
    let slice = &data[offset..offset + 96];
    let magic_le = u32::from_le_bytes(slice[0..4].try_into().ok()?);
    let magic_be = u32::from_be_bytes(slice[0..4].try_into().ok()?);

    let (is_le, inodes, mkfs_time, block_size, major, minor, bytes_used) =
        if magic_le == SQUASHFS_MAGIC_LE {
            let inodes = u32::from_le_bytes(slice[4..8].try_into().ok()?);
            let time = u32::from_le_bytes(slice[8..12].try_into().ok()?);
            let blk = u32::from_le_bytes(slice[12..16].try_into().ok()?);
            let major = u16::from_le_bytes(slice[28..30].try_into().ok()?);
            let minor = u16::from_le_bytes(slice[30..32].try_into().ok()?);
            let bytes_used = u64::from_le_bytes(slice[40..48].try_into().ok()?);
            (true, inodes, time, blk, major, minor, bytes_used)
        } else if magic_be == SQUASHFS_MAGIC_BE {
            let inodes = u32::from_be_bytes(slice[4..8].try_into().ok()?);
            let time = u32::from_be_bytes(slice[8..12].try_into().ok()?);
            let blk = u32::from_be_bytes(slice[12..16].try_into().ok()?);
            let major = u16::from_be_bytes(slice[28..30].try_into().ok()?);
            let minor = u16::from_be_bytes(slice[30..32].try_into().ok()?);
            let bytes_used = u64::from_be_bytes(slice[40..48].try_into().ok()?);
            (false, inodes, time, blk, major, minor, bytes_used)
        } else {
            return None;
        };

    let calculated_len = if bytes_used > 0 && bytes_used <= (data.len() - offset) as u64 {
        bytes_used as usize
    } else {
        data.len() - offset
    };

    let recovered_entries = crate::squashfs::SquashFsArchive::parse(&data[offset..])
        .map(|a| a.entries.len())
        .ok();

    Some(CarvedSegment {
        kind: CarvedKind::SquashFs,
        offset,
        length: calculated_len,
        description: format!(
            "SquashFS filesystem (v{}.{}, {} inodes, block size {} bytes)",
            major, minor, inodes, block_size
        ),
        endianness: if is_le {
            "little-endian".to_string()
        } else {
            "big-endian".to_string()
        },
        attributes: serde_json::json!({
            "version": format!("{}.{}", major, minor),
            "inode_count": inodes,
            "creation_time": mkfs_time,
            "block_size": block_size,
            "bytes_used": bytes_used,
            "recovered_entries": recovered_entries,
        }),
        extracted_filename: None,
    })
}

fn parse_cramfs_at(data: &[u8], offset: usize) -> Option<CarvedSegment> {
    if data.len() < offset + 64 {
        return None;
    }
    let slice = &data[offset..offset + 64];
    let magic_le = u32::from_le_bytes(slice[0..4].try_into().ok()?);
    let magic_be = u32::from_be_bytes(slice[0..4].try_into().ok()?);

    let (is_le, size, flags) = if magic_le == CRAMFS_MAGIC_LE {
        let size = u32::from_le_bytes(slice[4..8].try_into().ok()?);
        let flags = u32::from_le_bytes(slice[8..12].try_into().ok()?);
        (true, size, flags)
    } else if magic_be == CRAMFS_MAGIC_BE {
        let size = u32::from_be_bytes(slice[4..8].try_into().ok()?);
        let flags = u32::from_be_bytes(slice[8..12].try_into().ok()?);
        (false, size, flags)
    } else {
        return None;
    };

    let calculated_len = if size > 0 && size as usize <= (data.len() - offset) {
        size as usize
    } else {
        data.len() - offset
    };

    Some(CarvedSegment {
        kind: CarvedKind::CramFs,
        offset,
        length: calculated_len,
        description: format!(
            "CramFS compressed ROM filesystem (size: {} bytes, flags: 0x{:08X})",
            size, flags
        ),
        endianness: if is_le {
            "little-endian".to_string()
        } else {
            "big-endian".to_string()
        },
        attributes: serde_json::json!({
            "size": size,
            "flags": flags,
        }),
        extracted_filename: None,
    })
}

fn parse_gzip_at(data: &[u8], offset: usize) -> Option<CarvedSegment> {
    if data.len() < offset + 10 {
        return None;
    }
    let slice = &data[offset..offset + 10];
    if slice[0] != 0x1F || slice[1] != 0x8B || slice[2] != 0x08 {
        return None;
    }

    let mtime = u32::from_le_bytes(slice[4..8].try_into().ok()?);
    let xfl = slice[8];
    let os = slice[9];

    // Estimate stream length or extract remaining capacity up to next boundary
    let length = data.len() - offset;

    Some(CarvedSegment {
        kind: CarvedKind::Gzip,
        offset,
        length,
        description: format!("Gzip compressed archive (mtime: {}, os: {})", mtime, os),
        endianness: "little-endian".to_string(),
        attributes: serde_json::json!({
            "mtime": mtime,
            "flags": slice[3],
            "extra_flags": xfl,
            "os": os,
        }),
        extracted_filename: None,
    })
}

fn parse_lzma_at(data: &[u8], offset: usize) -> Option<CarvedSegment> {
    if data.len() < offset + 13 {
        return None;
    }
    let slice = &data[offset..offset + 13];
    if slice[0] != 0x5D || slice[1] != 0x00 || slice[2] != 0x00 {
        return None;
    }

    let dict_size = u32::from_le_bytes(slice[1..5].try_into().ok()?);
    let uncomp_size = u64::from_le_bytes(slice[5..13].try_into().ok()?);

    Some(CarvedSegment {
        kind: CarvedKind::Lzma,
        offset,
        length: data.len() - offset,
        description: format!(
            "LZMA compressed data stream (dictionary size: {} bytes)",
            dict_size
        ),
        endianness: "little-endian".to_string(),
        attributes: serde_json::json!({
            "dict_size": dict_size,
            "uncompressed_size": uncomp_size,
        }),
        extracted_filename: None,
    })
}

fn parse_xz_at(data: &[u8], offset: usize) -> Option<CarvedSegment> {
    if data.len() < offset + 12 {
        return None;
    }
    if data[offset..offset + 6] != XZ_MAGIC {
        return None;
    }

    Some(CarvedSegment {
        kind: CarvedKind::Xz,
        offset,
        length: data.len() - offset,
        description: "XZ compressed container stream".to_string(),
        endianness: "little-endian".to_string(),
        attributes: serde_json::json!({ "format": "xz" }),
        extracted_filename: None,
    })
}

/// Scans the binary slice for all carvable compressed and filesystem streams.
pub fn scan_carvable_streams(data: &[u8]) -> Vec<CarvedSegment> {
    let mut segments = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if let Some(sq) = parse_squashfs_at(data, i) {
            let next_offset = sq.length.max(96);
            segments.push(sq);
            i += next_offset;
            continue;
        }
        if let Some(cr) = parse_cramfs_at(data, i) {
            let next_offset = cr.length.max(64);
            segments.push(cr);
            i += next_offset;
            continue;
        }
        if let Some(xz) = parse_xz_at(data, i) {
            segments.push(xz);
            i += 12;
            continue;
        }
        if let Some(gz) = parse_gzip_at(data, i) {
            segments.push(gz);
            i += 10;
            continue;
        }
        if let Some(lz) = parse_lzma_at(data, i) {
            segments.push(lz);
            i += 13;
            continue;
        }
        i += 1;
    }
    segments
}

/// Carves detected segments to disk, saves a manifest, and returns metadata.
pub fn carve_and_extract(data: &[u8], out_dir: &Path, source_file: &str) -> Result<CarveManifest> {
    if !out_dir.exists() {
        fs::create_dir_all(out_dir)
            .map_err(|e| CarverError::ExtractionFailed(format!("Failed to create dir: {}", e)))?;
    }

    let mut segments = scan_carvable_streams(data);
    for (idx, seg) in segments.iter_mut().enumerate() {
        let ext = match seg.kind {
            CarvedKind::SquashFs => "squashfs",
            CarvedKind::CramFs => "cramfs",
            CarvedKind::Gzip => "gz",
            CarvedKind::Lzma => "lzma",
            CarvedKind::Xz => "xz",
        };
        let file_name = format!("carved_{:08x}_{}.{}", seg.offset, idx, ext);
        let dest_path = out_dir.join(&file_name);

        let end = (seg.offset + seg.length).min(data.len());
        let chunk = &data[seg.offset..end];

        fs::write(&dest_path, chunk).map_err(|e| {
            CarverError::ExtractionFailed(format!("Failed to write {}: {}", file_name, e))
        })?;
        seg.extracted_filename = Some(file_name);
    }

    let manifest = CarveManifest {
        source_file: source_file.to_string(),
        source_size: data.len(),
        carved_count: segments.len(),
        segments,
    };

    let manifest_path = out_dir.join("manifest.json");
    let json_text = serde_json::to_string_pretty(&manifest)?;
    fs::write(&manifest_path, json_text)
        .map_err(|e| CarverError::ExtractionFailed(format!("Failed to save manifest: {}", e)))?;

    Ok(manifest)
}
