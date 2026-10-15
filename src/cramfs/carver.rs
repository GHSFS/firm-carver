// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::reconstruct::walk_directory_tree;
use super::superblock::{detect_endianness, parse_superblock};
use super::types::{Endianness, CRAMFS_MAGIC_BE, CRAMFS_MAGIC_LE};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CramFsPartitionSpan {
    pub offset: usize,
    pub length: usize,
    pub endianness: Endianness,
    pub size_field: u32,
    pub flags: u32,
    pub fs_name: String,
    pub recovered_entries: usize,
}

pub fn probe_cramfs_at(data: &[u8], offset: usize) -> Option<CramFsPartitionSpan> {
    if data.len() < offset + 76 {
        return None;
    }
    let slice = &data[offset..];
    let endianness = detect_endianness(slice)?;

    let sb = parse_superblock(slice).ok()?;

    let calculated_len = if sb.size > 0 && (sb.size as usize) <= (data.len() - offset) {
        sb.size as usize
    } else {
        data.len() - offset
    };

    let recovered_entries = walk_directory_tree(&data[offset..offset + calculated_len], &sb)
        .map(|(entries, _)| entries.len())
        .unwrap_or(0);

    Some(CramFsPartitionSpan {
        offset,
        length: calculated_len,
        endianness,
        size_field: sb.size,
        flags: sb.flags,
        fs_name: sb.name,
        recovered_entries,
    })
}

pub fn scan_cramfs_partitions(data: &[u8]) -> Vec<CramFsPartitionSpan> {
    let mut spans = Vec::new();
    let mut offset = 0;

    while offset + 4 <= data.len() {
        let magic_le = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        let magic_be = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap());

        if magic_le == CRAMFS_MAGIC_LE || magic_be == CRAMFS_MAGIC_BE || magic_le == CRAMFS_MAGIC_BE
        {
            if let Some(span) = probe_cramfs_at(data, offset) {
                let skip = span.length.max(64);
                spans.push(span);
                offset += skip;
                continue;
            }
        }
        offset += 4;
    }

    spans
}
