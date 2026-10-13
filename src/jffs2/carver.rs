// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::carve::{CarvedKind, CarvedSegment};
use crate::jffs2::node::{detect_endianness, CommonNodeHeader};
use crate::jffs2::types::*;

/// Detected JFFS2 flash partition boundary and node statistics.
#[derive(Debug, Clone)]
pub struct Jffs2PartitionSpan {
    pub offset: usize,
    pub length: usize,
    pub endianness: Endianness,
    pub node_count: usize,
    pub cleanmarker_count: usize,
    pub dirent_count: usize,
    pub inode_count: usize,
}

/// Probes whether a valid JFFS2 partition stream starts at the specified offset.
pub fn probe_jffs2_at(data: &[u8], offset: usize) -> Option<Jffs2PartitionSpan> {
    if data.len() < offset + 12 {
        return None;
    }

    let endian = detect_endianness(&data[offset..])?;
    let header = CommonNodeHeader::parse(&data[offset..], endian)?;

    // Accept valid cleanmarker, dirent, or inode as entry point
    if header.nodetype != JFFS2_NODETYPE_CLEANMARKER
        && header.nodetype != JFFS2_NODETYPE_DIRENT
        && header.nodetype != JFFS2_NODETYPE_INODE
    {
        return None;
    }

    let mut cur = offset;
    let mut node_count = 0;
    let mut cleanmarker_count = 0;
    let mut dirent_count = 0;
    let mut inode_count = 0;

    // Follow node chain with 4-byte alignment
    while cur + 12 <= data.len() {
        if let Some(h) = CommonNodeHeader::parse(&data[cur..], endian) {
            node_count += 1;
            match h.nodetype {
                JFFS2_NODETYPE_CLEANMARKER => cleanmarker_count += 1,
                JFFS2_NODETYPE_DIRENT => dirent_count += 1,
                JFFS2_NODETYPE_INODE => inode_count += 1,
                _ => {}
            }
            let step = ((h.totlen as usize) + 3) & !3;
            if step == 0 {
                break;
            }
            cur += step;
        } else {
            // Check for empty/erased flash padding (0xFF or 0x00 up to boundary)
            let remaining = data.len() - cur;
            if remaining >= 4
                && (data[cur..cur + 4] == [0xFF; 4] || data[cur..cur + 4] == [0x00; 4])
            {
                // Advance past padding up to next aligned block or end
                let mut pad_end = cur;
                while pad_end < data.len() && (data[pad_end] == 0xFF || data[pad_end] == 0x00) {
                    pad_end += 1;
                }
                let aligned_pad = (pad_end + 3) & !3;
                if aligned_pad + 12 <= data.len()
                    && CommonNodeHeader::parse(&data[aligned_pad..], endian).is_some()
                {
                    cur = aligned_pad;
                    continue;
                }
            }
            break;
        }
    }

    if node_count >= 1 {
        let length = cur - offset;
        Some(Jffs2PartitionSpan {
            offset,
            length,
            endianness: endian,
            node_count,
            cleanmarker_count,
            dirent_count,
            inode_count,
        })
    } else {
        None
    }
}

/// Scans raw firmware buffer for all contiguous JFFS2 flash filesystem partitions.
pub fn scan_jffs2_partitions(data: &[u8]) -> Vec<Jffs2PartitionSpan> {
    let mut spans = Vec::new();
    let mut i = 0;
    while i + 12 <= data.len() {
        if let Some(span) = probe_jffs2_at(data, i) {
            let next_offset = span.length.max(12);
            spans.push(span);
            i += next_offset;
        } else {
            i += 4; // JFFS2 nodes are 4-byte aligned
        }
    }
    spans
}

/// Carves a JFFS2 segment for integration into the magic carver manifest.
pub fn parse_jffs2_segment_at(data: &[u8], offset: usize) -> Option<CarvedSegment> {
    let span = probe_jffs2_at(data, offset)?;
    let endian_str = match span.endianness {
        Endianness::Little => "little-endian",
        Endianness::Big => "big-endian",
    };

    Some(CarvedSegment {
        kind: CarvedKind::Jffs2,
        offset: span.offset,
        length: span.length,
        description: format!(
            "JFFS2 flash filesystem ({} nodes, {} dirents, {} inodes, {} cleanmarkers)",
            span.node_count, span.dirent_count, span.inode_count, span.cleanmarker_count
        ),
        endianness: endian_str.to_string(),
        attributes: serde_json::json!({
            "node_count": span.node_count,
            "dirent_count": span.dirent_count,
            "inode_count": span.inode_count,
            "cleanmarker_count": span.cleanmarker_count,
        }),
        extracted_filename: None,
    })
}
