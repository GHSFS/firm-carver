// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::types::*;
use super::ubi::{detect_peb_size, parse_ec_header, UbiImage};
use crate::carve::{CarvedKind, CarvedSegment};

#[derive(Debug, Clone)]
pub struct UbiPartitionSpan {
    pub offset: usize,
    pub length: usize,
    pub peb_size: usize,
    pub peb_count: usize,
    pub volume_names: Vec<String>,
}

pub fn probe_ubi_at(data: &[u8], offset: usize) -> Option<UbiPartitionSpan> {
    if data.len() < offset + 64 {
        return None;
    }

    let first_ec = parse_ec_header(&data[offset..])?;
    if !first_ec.crc_valid {
        return None;
    }

    let peb_size = detect_peb_size(&data[offset..]).unwrap_or(128 * 1024);
    let mut peb_count = 0;
    let mut cur = offset;

    while cur + 64 <= data.len() {
        if let Some(ec) = parse_ec_header(&data[cur..]) {
            if ec.crc_valid {
                peb_count += 1;
                cur += peb_size;
                continue;
            }
        }
        break;
    }

    if peb_count == 0 {
        return None;
    }

    let span_len = (peb_count * peb_size).min(data.len() - offset);
    let mut volume_names = Vec::new();

    if let Ok(ubi) = UbiImage::parse(&data[offset..offset + span_len], Some(peb_size)) {
        for summary in ubi.get_volume_summaries() {
            volume_names.push(summary.name);
        }
    }

    Some(UbiPartitionSpan {
        offset,
        length: span_len,
        peb_size,
        peb_count,
        volume_names,
    })
}

pub fn scan_ubi_partitions(data: &[u8]) -> Vec<UbiPartitionSpan> {
    let mut partitions = Vec::new();
    let mut i = 0;

    while i + 64 <= data.len() {
        if &data[i..i + 4] == b"UBI#" {
            if let Some(span) = probe_ubi_at(data, i) {
                let next_step = span.length.max(64);
                partitions.push(span);
                i += next_step;
                continue;
            }
        }
        i += 4;
    }

    partitions
}

pub fn parse_ubi_segment_at(data: &[u8], offset: usize) -> Option<CarvedSegment> {
    let span = probe_ubi_at(data, offset)?;

    Some(CarvedSegment {
        kind: CarvedKind::Ubi,
        offset: span.offset,
        length: span.length,
        description: format!(
            "UBI Flash Volume Image ({} PEBs, PEB size: {} KB, volumes: {:?})",
            span.peb_count,
            span.peb_size / 1024,
            span.volume_names
        ),
        endianness: "big-endian".to_string(),
        attributes: serde_json::json!({
            "peb_size": span.peb_size,
            "peb_count": span.peb_count,
            "volumes": span.volume_names,
        }),
        extracted_filename: None,
    })
}

pub fn parse_ubifs_raw_segment_at(data: &[u8], offset: usize) -> Option<CarvedSegment> {
    if data.len() < offset + UBIFS_CH_SZ {
        return None;
    }

    let magic_le = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
    if magic_le != UBIFS_NODE_MAGIC_LE {
        return None;
    }

    let endian = super::node::detect_node_endianness(&data[offset..])?;
    let ch = super::node::parse_common_header(&data[offset..], endian)?;

    if ch.node_type == UbifsNodeType::Sb {
        let sb = super::node::parse_sb_node(&data[offset..], endian)?;
        let est_len = (sb.leb_size as usize * sb.leb_cnt as usize).min(data.len() - offset);
        return Some(CarvedSegment {
            kind: CarvedKind::Ubifs,
            offset,
            length: if est_len > 0 {
                est_len
            } else {
                ch.len as usize
            },
            description: format!(
                "UBIFS Superblock Node (format v{}, LEB size: {} bytes, LEB count: {}, UUID: {})",
                sb.fmt_version, sb.leb_size, sb.leb_cnt, sb.uuid
            ),
            endianness: match endian {
                Endianness::Little => "little-endian".to_string(),
                Endianness::Big => "big-endian".to_string(),
            },
            attributes: serde_json::json!({
                "fmt_version": sb.fmt_version,
                "leb_size": sb.leb_size,
                "leb_cnt": sb.leb_cnt,
                "uuid": sb.uuid,
            }),
            extracted_filename: None,
        });
    }

    None
}
