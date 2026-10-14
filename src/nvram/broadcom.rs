// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::types::{Endianness, NvramEntry, NvramSourceKind};
use crate::error::{CarverError, Result};

pub const BCM_NVRAM_MAGIC_LE: u32 = 0x4853_4C46; // "FLSH" in LE (0x46, 0x4C, 0x53, 0x48)
pub const BCM_NVRAM_MAGIC_BE: u32 = 0x464C_5348; // "FLSH" in BE
pub const BCM_NVRAM_HEADER_LEN: usize = 20;

/// Parsed Broadcom FLSH hardware NVRAM header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BroadcomNvramHeader {
    pub magic: u32,
    pub len: u32,
    pub crc8: u8,
    pub version: u8,
    pub flags: u16,
    pub config_refresh: u32,
    pub config_ncdl: u32,
    pub endianness: Endianness,
}

impl BroadcomNvramHeader {
    /// Parses a 20-byte Broadcom NVRAM header from the start of slice.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < BCM_NVRAM_HEADER_LEN {
            return None;
        }

        let magic_raw = &data[0..4];
        let (endianness, magic, len, crc_ver_flg, refresh, ncdl) =
            if magic_raw == [0x46, 0x4C, 0x53, 0x48] {
                // 'F', 'L', 'S', 'H'
                let magic = u32::from_le_bytes(magic_raw.try_into().ok()?);
                let len = u32::from_le_bytes(data[4..8].try_into().ok()?);
                let crc_ver_flg = u32::from_le_bytes(data[8..12].try_into().ok()?);
                let refresh = u32::from_le_bytes(data[12..16].try_into().ok()?);
                let ncdl = u32::from_le_bytes(data[16..20].try_into().ok()?);
                (Endianness::Little, magic, len, crc_ver_flg, refresh, ncdl)
            } else if magic_raw == [0x48, 0x53, 0x4C, 0x46] {
                // Big-endian 'H', 'S', 'L', 'F' byte pattern or BE u32
                let magic = u32::from_be_bytes(magic_raw.try_into().ok()?);
                let len = u32::from_be_bytes(data[4..8].try_into().ok()?);
                let crc_ver_flg = u32::from_be_bytes(data[8..12].try_into().ok()?);
                let refresh = u32::from_be_bytes(data[12..16].try_into().ok()?);
                let ncdl = u32::from_be_bytes(data[16..20].try_into().ok()?);
                (Endianness::Big, magic, len, crc_ver_flg, refresh, ncdl)
            } else {
                return None;
            };

        let crc8 = (crc_ver_flg & 0xFF) as u8;
        let version = ((crc_ver_flg >> 8) & 0xFF) as u8;
        let flags = ((crc_ver_flg >> 16) & 0xFFFF) as u16;

        Some(Self {
            magic,
            len,
            crc8,
            version,
            flags,
            config_refresh: refresh,
            config_ncdl: ncdl,
            endianness,
        })
    }
}

/// Computes Broadcom 8-bit CRC over NVRAM data payload.
pub fn compute_bcm_crc8(data: &[u8]) -> u8 {
    let mut crc: u8 = 0xFF;
    for &byte in data {
        crc ^= byte;
        for _ in 0..8 {
            if (crc & 0x80) != 0 {
                crc = (crc << 1) ^ 0x07;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// Computes 8-bit additive wrapping checksum.
pub fn compute_bcm_checksum8(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |acc, &b| acc.wrapping_add(b))
}

/// Parses null-terminated `key=value\0` pairs starting from `offset`.
pub fn parse_null_delimited_entries(
    data: &[u8],
    base_offset: usize,
    source: NvramSourceKind,
) -> Vec<NvramEntry> {
    let mut entries = Vec::new();
    let mut cursor = base_offset;
    let limit = data.len();

    while cursor < limit {
        // Broadcom double-null or flash unprogrammed 0xFF termination
        if data[cursor] == 0x00 || data[cursor] == 0xFF {
            // Check if next is also 0x00 or end of table
            if cursor + 1 < limit && (data[cursor + 1] == 0x00 || data[cursor + 1] == 0xFF) {
                break;
            }
            cursor += 1;
            continue;
        }

        // Find next null terminator
        let start = cursor;
        while cursor < limit && data[cursor] != 0x00 && data[cursor] != 0xFF {
            cursor += 1;
        }

        let slice = &data[start..cursor];
        if let Ok(text) = std::str::from_utf8(slice) {
            if let Some(pos) = text.find('=') {
                let key = text[..pos].trim().to_string();
                let value = text[pos + 1..].to_string();
                if !key.is_empty() && is_valid_nvram_key(&key) {
                    entries.push(NvramEntry {
                        key,
                        value,
                        source,
                        offset: start,
                    });
                }
            }
        }

        if cursor < limit && (data[cursor] == 0x00 || data[cursor] == 0xFF) {
            cursor += 1;
        }
    }

    entries
}

/// Validates whether a key matches typical embedded NVRAM naming conventions.
pub fn is_valid_nvram_key(key: &str) -> bool {
    if key.is_empty() || key.len() > 96 {
        return false;
    }
    key.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || c == '_'
            || c == '.'
            || c == '-'
            || c == ':'
            || c == '/'
            || c == '@'
    })
}

/// Parses a Broadcom FLSH image starting with header.
pub fn parse_broadcom_flsh(data: &[u8]) -> Result<(BroadcomNvramHeader, Vec<NvramEntry>)> {
    let header = BroadcomNvramHeader::parse(data).ok_or_else(|| {
        CarverError::Nvram("Missing or invalid Broadcom FLSH NVRAM magic header".to_string())
    })?;

    let effective_len = if header.len > 0 && (header.len as usize) <= data.len() {
        header.len as usize
    } else {
        data.len()
    };

    let entries = parse_null_delimited_entries(
        &data[..effective_len],
        BCM_NVRAM_HEADER_LEN,
        NvramSourceKind::BroadcomFlsh,
    );

    Ok((header, entries))
}

/// Scans raw binary buffer for contiguous packed null-delimited strings tables.
/// Requires at least `min_pairs` (typically 3) consecutive `key=value\0` pairs.
pub fn scan_packed_strings_tables(
    data: &[u8],
    min_pairs: usize,
) -> Vec<(usize, usize, Vec<NvramEntry>)> {
    let mut results = Vec::new();
    let mut idx = 0;

    while idx < data.len() {
        // Look for printable ASCII starting character
        if !data[idx].is_ascii_alphanumeric() && data[idx] != b'_' {
            idx += 1;
            continue;
        }

        // Try extracting sequence of key=value\0
        let seq_start = idx;
        let mut cur = idx;
        let mut found_pairs = Vec::new();

        while cur < data.len() {
            let item_start = cur;
            while cur < data.len() && data[cur] != 0 && data[cur] != 0xFF {
                cur += 1;
            }

            if cur >= data.len() {
                break;
            }

            let slice = &data[item_start..cur];
            if slice.is_empty() {
                break;
            }

            if let Ok(text) = std::str::from_utf8(slice) {
                if let Some(eq_pos) = text.find('=') {
                    let key = text[..eq_pos].trim();
                    let val = &text[eq_pos + 1..];
                    if !key.is_empty()
                        && is_valid_nvram_key(key)
                        && val.chars().all(|c| c.is_ascii() && !c.is_ascii_control())
                    {
                        found_pairs.push(NvramEntry {
                            key: key.to_string(),
                            value: val.to_string(),
                            source: NvramSourceKind::BroadcomPackedStrings,
                            offset: item_start,
                        });
                        cur += 1; // skip null
                        continue;
                    }
                }
            }
            break;
        }

        if found_pairs.len() >= min_pairs {
            let total_len = cur - seq_start;
            results.push((seq_start, total_len, found_pairs));
            idx = cur;
        } else {
            idx += 1;
        }
    }

    results
}
