// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::broadcom::{parse_broadcom_flsh, scan_packed_strings_tables};
use super::mediatek::{parse_mediatek_dat, parse_mediatek_eeprom, probe_mediatek_dat};
use super::types::{Endianness, NvramSourceKind};
use crate::carve::{CarvedKind, CarvedSegment};

/// Detected NVRAM partition span and metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NvramPartitionSpan {
    pub offset: usize,
    pub length: usize,
    pub kind: NvramSourceKind,
    pub entry_count: usize,
    pub details: String,
    pub endianness: Option<Endianness>,
}

/// Probes whether a valid NVRAM stream or table starts at the specified offset.
pub fn probe_nvram_at(data: &[u8], offset: usize) -> Option<NvramPartitionSpan> {
    if offset >= data.len() {
        return None;
    }
    let slice = &data[offset..];

    // 1. Broadcom FLSH header probe
    if slice.len() >= 20 {
        let magic = &slice[0..4];
        if magic == [0x46, 0x4C, 0x53, 0x48] || magic == [0x48, 0x53, 0x4C, 0x46] {
            if let Ok((hdr, entries)) = parse_broadcom_flsh(slice) {
                let length = if hdr.len > 0 && (hdr.len as usize) <= slice.len() {
                    hdr.len as usize
                } else {
                    slice.len()
                };
                return Some(NvramPartitionSpan {
                    offset,
                    length,
                    kind: NvramSourceKind::BroadcomFlsh,
                    entry_count: entries.len(),
                    details: format!(
                        "Broadcom FLSH NVRAM (v{}, {} entries, len {} B)",
                        hdr.version,
                        entries.len(),
                        length
                    ),
                    endianness: Some(hdr.endianness),
                });
            }
        }
    }

    // 2. MediaTek EEPROM probe
    if slice.len() >= 16 {
        if let Ok((eeprom, entries)) = parse_mediatek_eeprom(slice) {
            let length = slice.len().min(512);
            return Some(NvramPartitionSpan {
                offset,
                length,
                kind: NvramSourceKind::MediatekEeprom,
                entry_count: entries.len(),
                details: format!(
                    "MediaTek EEPROM ({}, MAC: {})",
                    eeprom.chip_name,
                    eeprom.mac_lan_string()
                ),
                endianness: Some(eeprom.endianness),
            });
        }
    }

    // 3. MediaTek .dat wireless config probe
    if probe_mediatek_dat(slice) {
        if let Ok(entries) = parse_mediatek_dat(slice) {
            if entries.len() >= 2 {
                // Find length of .dat text section
                let text_len = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
                let length = text_len.max(16);
                return Some(NvramPartitionSpan {
                    offset,
                    length,
                    kind: NvramSourceKind::MediatekDat,
                    entry_count: entries.len(),
                    details: format!("MediaTek .dat configuration ({} parameters)", entries.len()),
                    endianness: None,
                });
            }
        }
    }

    // 4. Packed null-delimited strings table probe (min 3 pairs)
    let tables = scan_packed_strings_tables(slice, 3);
    if let Some((tab_off, tab_len, tab_entries)) = tables.first() {
        if *tab_off == 0 {
            return Some(NvramPartitionSpan {
                offset,
                length: *tab_len,
                kind: NvramSourceKind::BroadcomPackedStrings,
                entry_count: tab_entries.len(),
                details: format!(
                    "Packed null-delimited strings table ({} pairs)",
                    tab_entries.len()
                ),
                endianness: None,
            });
        }
    }

    None
}

/// Scans raw firmware buffer for all identifiable NVRAM partitions.
pub fn scan_nvram_partitions(data: &[u8]) -> Vec<NvramPartitionSpan> {
    let mut spans = Vec::new();
    let mut idx = 0;

    while idx < data.len() {
        if let Some(span) = probe_nvram_at(data, idx) {
            let step = span.length.max(16);
            spans.push(span);
            idx += step;
        } else {
            // NVRAM headers in flash typically align to 4 or 16 bytes
            idx += 4;
        }
    }

    spans
}

/// Carves a detected NVRAM segment for integration into the magic carver manifest.
pub fn parse_nvram_segment_at(data: &[u8], offset: usize) -> Option<CarvedSegment> {
    let span = probe_nvram_at(data, offset)?;
    let endian_str = span
        .endianness
        .map(|e| e.as_str().to_string())
        .unwrap_or_else(|| "none".to_string());

    Some(CarvedSegment {
        kind: CarvedKind::Nvram,
        offset: span.offset,
        length: span.length,
        description: span.details,
        endianness: endian_str,
        attributes: serde_json::json!({
            "source_kind": span.kind.code(),
            "entry_count": span.entry_count,
        }),
        extracted_filename: None,
    })
}
