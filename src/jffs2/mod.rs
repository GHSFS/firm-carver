// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

pub mod carver;
pub mod decompress;
pub mod node;
pub mod reconstruct;
pub mod synth;
pub mod types;

pub use carver::{
    parse_jffs2_segment_at, probe_jffs2_at, scan_jffs2_partitions, Jffs2PartitionSpan,
};
pub use decompress::{
    compress_rtime, compress_zlib, decompress_payload, decompress_rtime, decompress_zlib,
};
pub use node::{detect_endianness, CommonNodeHeader, RawDirent, RawInode};
pub use reconstruct::{extract_archive_to_disk, format_mode_string, reconstruct_filesystem};
pub use synth::build_synthetic_jffs2;
pub use types::*;

use crate::error::{CarverError, Result};
use std::path::Path;

impl Jffs2Archive {
    /// Parses a raw JFFS2 flash byte slice and reconstructs its directory tree and files.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 12 {
            return Err(CarverError::Jffs2(
                "Data slice too short for JFFS2".to_string(),
            ));
        }

        let endian = detect_endianness(data).ok_or_else(|| {
            CarverError::Jffs2("Unrecognized JFFS2 magic or header CRC".to_string())
        })?;

        let mut dirents = Vec::new();
        let mut inodes = Vec::new();
        let mut cleanmarker_count = 0;
        let mut cur = 0;

        while cur + 12 <= data.len() {
            if let Some(h) = CommonNodeHeader::parse(&data[cur..], endian) {
                let node_slice = &data[cur..cur + (h.totlen as usize).min(data.len() - cur)];
                match h.nodetype {
                    JFFS2_NODETYPE_CLEANMARKER => {
                        cleanmarker_count += 1;
                    }
                    JFFS2_NODETYPE_DIRENT => {
                        if let Ok(dirent) = RawDirent::parse(node_slice, h, endian) {
                            dirents.push(dirent);
                        }
                    }
                    JFFS2_NODETYPE_INODE => {
                        if let Ok(inode) = RawInode::parse(node_slice, h, endian) {
                            inodes.push(inode);
                        }
                    }
                    _ => {}
                }
                let step = ((h.totlen as usize) + 3) & !3;
                if step == 0 {
                    break;
                }
                cur += step;
            } else {
                // Advance 4 bytes if aligned padding or junk
                cur += 4;
            }
        }

        if dirents.is_empty() && inodes.is_empty() && cleanmarker_count == 0 {
            return Err(CarverError::Jffs2(
                "No valid JFFS2 nodes found in slice".to_string(),
            ));
        }

        reconstruct_filesystem(dirents, inodes, cleanmarker_count, endian, cur)
    }

    /// Formats the reconstructed filesystem tree as an aligned UNIX `ls -la` table.
    pub fn format_listing(&self) -> String {
        let mut out = String::new();
        for e in &self.entries {
            let mode_str = format_mode_string(e.mode, e.file_type);
            let suffix = match &e.symlink_target {
                Some(target) => format!(" -> {}", target),
                None => String::new(),
            };
            out.push_str(&format!(
                "{:<10} {:4} {:4} {:8} {:5} {}{}\n",
                mode_str, e.uid, e.gid, e.size, e.ino, e.path, suffix
            ));
        }
        out
    }

    /// Formats a high-level summary report of the parsed JFFS2 flash filesystem.
    pub fn format_summary(&self) -> String {
        let mut dir_count = 0;
        let mut file_count = 0;
        let mut symlink_count = 0;
        let mut total_size = 0u64;

        for e in &self.entries {
            match e.file_type {
                Jffs2FileType::Directory => dir_count += 1,
                Jffs2FileType::Regular => {
                    file_count += 1;
                    total_size += e.size;
                }
                Jffs2FileType::Symlink => symlink_count += 1,
                _ => {}
            }
        }

        format!(
            "Endianness:     {:?}\n\
             Cleanmarkers:   {}\n\
             Inode Nodes:    {}\n\
             Dirent Nodes:   {}\n\
             Recovered:      {} entries ({} dirs, {} files, {} symlinks)\n\
             Total Payload:  {} bytes",
            self.endianness,
            self.cleanmarker_count,
            self.inode_node_count,
            self.dirent_node_count,
            self.entries.len(),
            dir_count,
            file_count,
            symlink_count,
            total_size
        )
    }

    /// Safely extracts all files, directories, and symlinks to disk.
    pub fn extract_to_disk(&self, out_dir: &Path) -> Result<usize> {
        extract_archive_to_disk(self, out_dir)
    }
}
