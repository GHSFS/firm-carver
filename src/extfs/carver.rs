// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::reconstruct::reconstruct_filesystem;
use super::superblock::{detect_endianness, parse_block_group_descriptors, parse_superblock};
use super::types::*;
use crate::carve::{CarvedKind, CarvedSegment};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtPartitionSpan {
    pub offset: usize,
    pub length: usize,
    pub version: ExtVersion,
    pub endianness: Endianness,
    pub volume_name: String,
    pub total_inodes: u32,
    pub total_blocks: u64,
    pub block_size: u32,
    pub recovered_entries: usize,
}

pub fn probe_extfs_at(data: &[u8], offset: usize) -> Option<ExtPartitionSpan> {
    if data.len() < offset + EXT_SUPERBLOCK_OFFSET + EXT_MIN_SUPERBLOCK_SIZE {
        return None;
    }

    let endianness = detect_endianness(data, offset)?;
    let sb = parse_superblock(data, offset).ok()?;
    let groups = parse_block_group_descriptors(data, offset, &sb).ok()?;

    let (entries, _) = reconstruct_filesystem(data, offset, &sb, &groups).ok()?;

    let calculated_len = (sb.blocks_count as usize).saturating_mul(sb.block_size as usize);
    let length = if calculated_len > 0 && offset + calculated_len <= data.len() {
        calculated_len
    } else {
        data.len() - offset
    };

    Some(ExtPartitionSpan {
        offset,
        length,
        version: sb.version,
        endianness,
        volume_name: sb.volume_name,
        total_inodes: sb.inodes_count,
        total_blocks: sb.blocks_count,
        block_size: sb.block_size,
        recovered_entries: entries.len(),
    })
}

pub fn scan_extfs_partitions(data: &[u8]) -> Vec<ExtPartitionSpan> {
    let mut spans = Vec::new();
    let mut i = 0;

    while i + EXT_SUPERBLOCK_OFFSET + 0x3A <= data.len() {
        if let Some(span) = probe_extfs_at(data, i) {
            let next_step = span.length.max(sb_step(&span));
            spans.push(span);
            i += next_step;
        } else {
            i += 512;
        }
    }

    spans
}

fn sb_step(span: &ExtPartitionSpan) -> usize {
    (span.block_size as usize).max(1024)
}

pub fn parse_extfs_segment_at(data: &[u8], offset: usize) -> Option<CarvedSegment> {
    let span = probe_extfs_at(data, offset)?;

    Some(CarvedSegment {
        kind: CarvedKind::ExtFs,
        offset,
        length: span.length,
        description: format!(
            "{} filesystem (volume: '{}', {} blocks of {} bytes, {} recovered entries)",
            span.version.as_str().to_uppercase(),
            span.volume_name,
            span.total_blocks,
            span.block_size,
            span.recovered_entries
        ),
        endianness: match span.endianness {
            Endianness::Little => "little-endian".to_string(),
            Endianness::Big => "big-endian".to_string(),
        },
        attributes: serde_json::json!({
            "version": span.version.as_str(),
            "volume_name": span.volume_name,
            "total_inodes": span.total_inodes,
            "total_blocks": span.total_blocks,
            "block_size": span.block_size,
            "recovered_entries": span.recovered_entries,
        }),
        extracted_filename: None,
    })
}
