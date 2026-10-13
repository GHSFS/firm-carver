// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

pub mod carver;
pub mod node;
pub mod reconstruct;
pub mod synth;
pub mod types;
pub mod ubi;

use crate::error::{CarverError, Result};
pub use carver::{
    parse_ubi_segment_at, parse_ubifs_raw_segment_at, probe_ubi_at, scan_ubi_partitions,
    UbiPartitionSpan,
};
pub use node::{
    detect_node_endianness, parse_common_header, parse_dent_node, parse_ino_node, parse_mst_node,
    parse_sb_node,
};
pub use reconstruct::{
    extract_archive_to_disk, format_listing, format_mode_string, validate_safe_path,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
pub use synth::{
    build_synthetic_dent_node, build_synthetic_ino_node, build_synthetic_mst_node,
    build_synthetic_sb_node, build_synthetic_ubi, build_synthetic_ubifs,
};
pub use types::*;
pub use ubi::{detect_peb_size, parse_ec_header, parse_vid_header, parse_vtbl_record, UbiImage};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UbifsArchive {
    pub is_ubi_container: bool,
    pub ubi_volumes: Vec<UbiVolumeInfo>,
    pub endianness: Endianness,
    pub superblock: Option<UbifsSuperblock>,
    pub master_node: Option<UbifsMasterNode>,
    pub entries: Vec<UbifsEntry>,
}

impl UbifsArchive {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 24 {
            return Err(CarverError::Ubifs("Payload too small for UBI/UBIFS".into()));
        }

        // Check if raw UBI container
        if data.len() >= 4 && &data[0..4] == b"UBI#" {
            return Self::parse_ubi_image(data, None);
        }

        // Otherwise parse directly as UBIFS volume
        Self::parse_ubifs_stream(data, false, Vec::new())
    }

    pub fn parse_ubi_image(data: &[u8], peb_size: Option<usize>) -> Result<Self> {
        let ubi = UbiImage::parse(data, peb_size)?;
        let ubi_volumes = ubi.get_volume_summaries();

        // Find the first data volume containing UBIFS nodes
        for vol in &ubi_volumes {
            if let Some(vol_data) = ubi.assemble_volume_data(vol.vol_id) {
                if vol_data.len() >= 24 {
                    if let Ok(archive) =
                        Self::parse_ubifs_stream(&vol_data, true, ubi_volumes.clone())
                    {
                        return Ok(archive);
                    }
                }
            }
        }

        // If no UBIFS volumes found inside UBI, return UBI container summary
        Ok(Self {
            is_ubi_container: true,
            ubi_volumes,
            endianness: Endianness::Little,
            superblock: None,
            master_node: None,
            entries: Vec::new(),
        })
    }

    pub fn parse_ubifs_stream(
        data: &[u8],
        is_ubi_container: bool,
        ubi_volumes: Vec<UbiVolumeInfo>,
    ) -> Result<Self> {
        let endian = detect_node_endianness(data).unwrap_or(Endianness::Little);

        let mut superblock = None;
        let mut master_node = None;
        let mut inodes = HashMap::new();
        let mut dentries = Vec::new();

        let mut offset = 0;
        while offset + UBIFS_CH_SZ <= data.len() {
            if let Some(ch) = parse_common_header(&data[offset..], endian) {
                let node_slice = &data[offset..offset + ch.len as usize];
                match ch.node_type {
                    UbifsNodeType::Sb => {
                        if superblock.is_none() {
                            superblock = parse_sb_node(node_slice, endian);
                        }
                    }
                    UbifsNodeType::Mst => {
                        if master_node.is_none() {
                            master_node = parse_mst_node(node_slice, endian);
                        }
                    }
                    UbifsNodeType::Ino => {
                        if let Some(ino) = parse_ino_node(node_slice, endian) {
                            inodes.insert(ino.inum, ino);
                        }
                    }
                    UbifsNodeType::Dent => {
                        if let Some(dent) = parse_dent_node(node_slice, endian) {
                            dentries.push(dent);
                        }
                    }
                    _ => {}
                }
                // Align to 8-byte boundary per UBIFS node alignment
                let aligned_len = (ch.len as usize + 7) & !7;
                offset += aligned_len.max(UBIFS_CH_SZ);
            } else {
                offset += 4;
            }
        }

        let entries = reconstruct::reconstruct_filesystem(&inodes, &dentries);

        Ok(Self {
            is_ubi_container,
            ubi_volumes,
            endianness: endian,
            superblock,
            master_node,
            entries,
        })
    }

    pub fn format_listing(&self) -> String {
        format_listing(&self.entries)
    }

    pub fn format_summary(&self) -> String {
        let mut out = String::new();
        if self.is_ubi_container {
            out.push_str("Container Format: UBI (Unsorted Block Images)\n");
            out.push_str(&format!("Discovered Volumes: {}\n", self.ubi_volumes.len()));
            for v in &self.ubi_volumes {
                out.push_str(&format!(
                    "  [Vol ID {:2}] {:<18} ({:?}, {} mapped LEBs, {} bytes)\n",
                    v.vol_id, v.name, v.vol_type, v.mapped_lebs, v.data_bytes
                ));
            }
        } else {
            out.push_str("Container Format: Standalone UBIFS Image\n");
        }

        out.push_str(&format!("Endianness:       {:?}\n", self.endianness));

        if let Some(sb) = &self.superblock {
            out.push_str(&format!(
                "UBIFS Superblock: Format v{}, LEB Size: {} B, LEBs: {}/{}, Default Compr: {:?}, UUID: {}\n",
                sb.fmt_version, sb.leb_size, sb.leb_cnt, sb.max_leb_cnt, sb.default_compr, sb.uuid
            ));
        }

        if let Some(mst) = &self.master_node {
            out.push_str(&format!(
                "UBIFS Master:     Commit #{}, Highest Inum: {}, Used: {} B, Free: {} B, Dirty: {} B\n",
                mst.cmt_no, mst.highest_inum, mst.total_used, mst.total_free, mst.total_dirty
            ));
        }

        out.push_str(&format!("Recovered Entries: {}", self.entries.len()));
        out
    }

    pub fn extract_to_disk(&self, dest_dir: &Path) -> Result<usize> {
        let empty_contents = HashMap::new();
        extract_archive_to_disk(&self.entries, dest_dir, &empty_contents)
    }
}
