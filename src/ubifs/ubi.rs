// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::types::*;
use crate::error::{CarverError, Result};
use crate::image::compute_crc32;
use std::collections::BTreeMap;

pub fn parse_ec_header(data: &[u8]) -> Option<EraseCounterHeader> {
    if data.len() < 64 {
        return None;
    }
    let magic = u32::from_be_bytes(data[0..4].try_into().ok()?);
    if magic != UBI_EC_HDR_MAGIC {
        return None;
    }
    let version = data[4];
    let ec = u64::from_be_bytes(data[8..16].try_into().ok()?);
    let vid_hdr_offset = u32::from_be_bytes(data[16..20].try_into().ok()?);
    let data_offset = u32::from_be_bytes(data[20..24].try_into().ok()?);
    let image_seq = u32::from_be_bytes(data[24..28].try_into().ok()?);
    let hdr_crc = u32::from_be_bytes(data[60..64].try_into().ok()?);

    let calculated_crc = compute_crc32(&data[0..60]);
    let crc_valid = calculated_crc == hdr_crc;

    Some(EraseCounterHeader {
        magic,
        version,
        ec,
        vid_hdr_offset,
        data_offset,
        image_seq,
        hdr_crc,
        crc_valid,
    })
}

pub fn parse_vid_header(data: &[u8]) -> Option<VolumeIdHeader> {
    if data.len() < 64 {
        return None;
    }
    let magic = u32::from_be_bytes(data[0..4].try_into().ok()?);
    if magic != UBI_VID_HDR_MAGIC {
        return None;
    }
    let version = data[4];
    let vol_type = UbiVolumeType::from(data[5]);
    let copy_flag = data[6];
    let compat = data[7];
    let vol_id = u32::from_be_bytes(data[8..12].try_into().ok()?);
    let lnum = u32::from_be_bytes(data[12..16].try_into().ok()?);
    let data_size = u32::from_be_bytes(data[20..24].try_into().ok()?);
    let used_ebs = u32::from_be_bytes(data[24..28].try_into().ok()?);
    let data_pad = u32::from_be_bytes(data[28..32].try_into().ok()?);
    let data_crc = u32::from_be_bytes(data[32..36].try_into().ok()?);
    let hdr_crc = u32::from_be_bytes(data[60..64].try_into().ok()?);

    let calculated_crc = compute_crc32(&data[0..60]);
    let crc_valid = calculated_crc == hdr_crc;

    Some(VolumeIdHeader {
        magic,
        version,
        vol_type,
        copy_flag,
        compat,
        vol_id,
        lnum,
        data_size,
        used_ebs,
        data_pad,
        data_crc,
        hdr_crc,
        crc_valid,
    })
}

pub fn parse_vtbl_record(data: &[u8]) -> Option<VolumeTableRecord> {
    if data.len() < UBI_VTBL_RECORD_SIZE {
        return None;
    }
    let reserved_pebs = u32::from_be_bytes(data[0..4].try_into().ok()?);
    if reserved_pebs == 0 {
        return None; // Empty record entry
    }
    let alignment = u32::from_be_bytes(data[4..8].try_into().ok()?);
    let data_pad = u32::from_be_bytes(data[8..12].try_into().ok()?);
    let vol_type = UbiVolumeType::from(data[12]);
    let upd_marker = data[13];
    let name_len = u16::from_be_bytes(data[14..16].try_into().ok()?);

    let raw_name = &data[16..144];
    let end_pos = (name_len as usize).min(127);
    let slice = &raw_name[..end_pos];
    let null_idx = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    let name = String::from_utf8_lossy(&slice[..null_idx]).to_string();

    let flags = data[144];
    let crc = u32::from_be_bytes(data[168..172].try_into().ok()?);
    let calculated_crc = compute_crc32(&data[0..UBI_VTBL_RECORD_SIZE_CRC]);
    let crc_valid = calculated_crc == crc;

    Some(VolumeTableRecord {
        reserved_pebs,
        alignment,
        data_pad,
        vol_type,
        upd_marker,
        name_len,
        name,
        flags,
        crc,
        crc_valid,
    })
}

#[derive(Debug, Clone)]
pub struct PhysicalEraseBlock {
    pub peb_index: usize,
    pub offset: usize,
    pub ec_hdr: EraseCounterHeader,
    pub vid_hdr: Option<VolumeIdHeader>,
    pub data_offset: usize,
    pub leb_data_len: usize,
}

#[derive(Debug, Clone)]
pub struct UbiImage {
    pub peb_size: usize,
    pub pebs: Vec<PhysicalEraseBlock>,
    pub volumes: BTreeMap<u32, VolumeTableRecord>,
    pub volume_lebs: BTreeMap<u32, BTreeMap<u32, Vec<u8>>>,
}

impl UbiImage {
    pub fn parse(data: &[u8], user_peb_size: Option<usize>) -> Result<Self> {
        if data.len() < 64 {
            return Err(CarverError::Ubifs(
                "Data too small for UBI header (less than 64 bytes)".into(),
            ));
        }

        let _first_ec = parse_ec_header(&data[0..64])
            .ok_or_else(|| CarverError::Ubifs("Invalid UBI EC magic (expected UBI#)".into()))?;

        let peb_size = if let Some(ps) = user_peb_size {
            if ps < 64 {
                return Err(CarverError::InvalidArgument(format!(
                    "PEB size {} is too small",
                    ps
                )));
            }
            ps
        } else {
            detect_peb_size(data).unwrap_or(128 * 1024)
        };

        let mut pebs = Vec::new();
        let mut peb_idx = 0;
        let mut cur_offset = 0;

        while cur_offset + 64 <= data.len() {
            if let Some(ec) = parse_ec_header(&data[cur_offset..]) {
                let vid_hdr_pos = cur_offset + ec.vid_hdr_offset as usize;
                let vid = if vid_hdr_pos + 64 <= data.len() {
                    parse_vid_header(&data[vid_hdr_pos..])
                } else {
                    None
                };

                let data_start = cur_offset + ec.data_offset as usize;
                let peb_end = (cur_offset + peb_size).min(data.len());
                let leb_data_len = peb_end.saturating_sub(data_start);

                pebs.push(PhysicalEraseBlock {
                    peb_index: peb_idx,
                    offset: cur_offset,
                    ec_hdr: ec,
                    vid_hdr: vid,
                    data_offset: data_start,
                    leb_data_len,
                });
            }
            cur_offset += peb_size;
            peb_idx += 1;
        }

        let mut volume_lebs: BTreeMap<u32, BTreeMap<u32, Vec<u8>>> = BTreeMap::new();
        for peb in &pebs {
            if let Some(vid) = &peb.vid_hdr {
                if peb.data_offset + peb.leb_data_len <= data.len() {
                    let chunk = &data[peb.data_offset..peb.data_offset + peb.leb_data_len];
                    volume_lebs
                        .entry(vid.vol_id)
                        .or_default()
                        .insert(vid.lnum, chunk.to_vec());
                }
            }
        }

        let mut volumes = BTreeMap::new();
        if let Some(layout_lebs) = volume_lebs.get(&UBI_LAYOUT_VOLUME_ID) {
            for leb_bytes in layout_lebs.values() {
                let mut vtbl_offset = 0;
                let mut vol_idx = 0;
                while vtbl_offset + UBI_VTBL_RECORD_SIZE <= leb_bytes.len()
                    && vol_idx < UBI_MAX_VOLUMES
                {
                    if let Some(rec) = parse_vtbl_record(&leb_bytes[vtbl_offset..]) {
                        volumes.insert(vol_idx as u32, rec);
                    }
                    vtbl_offset += UBI_VTBL_RECORD_SIZE;
                    vol_idx += 1;
                }
            }
        }

        Ok(Self {
            peb_size,
            pebs,
            volumes,
            volume_lebs,
        })
    }

    pub fn assemble_volume_data(&self, vol_id: u32) -> Option<Vec<u8>> {
        let lebs = self.volume_lebs.get(&vol_id)?;
        let mut buffer = Vec::new();
        for chunk in lebs.values() {
            buffer.extend_from_slice(chunk);
        }
        Some(buffer)
    }

    pub fn get_volume_summaries(&self) -> Vec<UbiVolumeInfo> {
        let mut summaries = Vec::new();
        for (&vol_id, lebs) in &self.volume_lebs {
            if vol_id == UBI_LAYOUT_VOLUME_ID {
                continue;
            }
            let total_bytes: usize = lebs.values().map(|v| v.len()).sum();
            let (name, vol_type, reserved_pebs) = if let Some(rec) = self.volumes.get(&vol_id) {
                (rec.name.clone(), rec.vol_type, rec.reserved_pebs)
            } else {
                (
                    format!("vol_{}", vol_id),
                    UbiVolumeType::Dynamic,
                    lebs.len() as u32,
                )
            };

            summaries.push(UbiVolumeInfo {
                vol_id,
                name,
                vol_type,
                reserved_pebs,
                mapped_lebs: lebs.len(),
                data_bytes: total_bytes,
            });
        }
        summaries
    }
}

pub fn detect_peb_size(data: &[u8]) -> Option<usize> {
    if data.len() < 128 {
        return None;
    }
    let mut ec_offsets = Vec::new();
    let scan_limit = data.len().min(1024 * 1024 * 4); // Scan up to 4MB for PEB spacing
    let mut i = 0;
    while i + 4 <= scan_limit {
        if &data[i..i + 4] == b"UBI#" {
            ec_offsets.push(i);
            if ec_offsets.len() >= 3 {
                break;
            }
            i += 64;
        } else {
            i += 4;
        }
    }

    if ec_offsets.len() >= 2 {
        let delta = ec_offsets[1] - ec_offsets[0];
        if delta.is_power_of_two() && delta >= 4096 {
            return Some(delta);
        }
    }

    // Default NAND block geometries
    for &candidate in &[
        128 * 1024,
        64 * 1024,
        256 * 1024,
        512 * 1024,
        16 * 1024,
        2048 * 1024,
    ] {
        if candidate < data.len()
            && &data[candidate..candidate + 4.min(data.len() - candidate)] == b"UBI#"
        {
            return Some(candidate);
        }
    }

    None
}
