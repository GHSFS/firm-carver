// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

pub mod carver;
pub mod decompress;
pub mod reconstruct;
pub mod rules;
pub mod superblock;
pub mod synth;
pub mod types;

pub use carver::{probe_cramfs_at, scan_cramfs_partitions, CramFsPartitionSpan};
pub use decompress::{
    decompress_file_blocks, decompress_symlink_target, CRAMFS_BLOCK_SIZE,
    CRAMFS_MAX_UNCOMPRESSED_FILE_SIZE,
};
pub use reconstruct::{extract_archive_to_disk, format_mode_string, walk_directory_tree};
pub use rules::CramFsRuleEngine;
pub use superblock::{detect_endianness, pack_inode, parse_superblock, unpack_inode};
pub use synth::build_synthetic_cramfs;
pub use types::{
    CramFsAuditFinding, CramFsAuditReport, CramFsEntry, CramFsFileType, CramFsInfo, CramFsInode,
    CramFsSeverity, CramFsSummary, CramFsSuperblock, Endianness, CRAMFS_MAGIC_BE, CRAMFS_MAGIC_LE,
    CRAMFS_SIGNATURE,
};

use crate::error::{CarverError, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CramFsArchive {
    pub superblock: CramFsSuperblock,
    pub entries: Vec<CramFsEntry>,
    pub summary: CramFsSummary,
    pub audit_report: CramFsAuditReport,
}

impl CramFsArchive {
    pub fn parse(data: &[u8]) -> Result<Self> {
        Self::parse_at(data, 0)
    }

    pub fn parse_at(data: &[u8], offset: usize) -> Result<Self> {
        if offset >= data.len() {
            return Err(CarverError::CramFs(format!(
                "Offset 0x{:X} exceeds data length {}",
                offset,
                data.len()
            )));
        }

        let slice = &data[offset..];
        let superblock = parse_superblock(slice)?;
        let (entries, summary) = walk_directory_tree(slice, &superblock)?;
        let audit_report = CramFsRuleEngine::audit(&superblock, &entries);

        Ok(Self {
            superblock,
            entries,
            summary,
            audit_report,
        })
    }

    pub fn read_file_content(&self, data: &[u8], target_path: &str) -> Result<Vec<u8>> {
        let normalized = if target_path.starts_with('/') {
            target_path.to_string()
        } else {
            format!("/{}", target_path)
        };

        for entry in &self.entries {
            if entry.path == normalized {
                if entry.file_type != CramFsFileType::RegularFile {
                    return Err(CarverError::CramFs(format!(
                        "Entry '{}' is not a regular file",
                        target_path
                    )));
                }

                return decompress_file_blocks(
                    data,
                    entry.payload_offset,
                    entry.size,
                    self.superblock.endianness,
                    self.superblock.flags,
                );
            }
        }

        Err(CarverError::CramFs(format!(
            "File '{}' not found in CramFS archive",
            target_path
        )))
    }

    pub fn extract_to_disk(&self, data: &[u8], out_dir: &Path) -> Result<usize> {
        extract_archive_to_disk(data, &self.entries, &self.superblock, out_dir)
    }

    pub fn format_listing(&self) -> String {
        let mut out = String::new();
        for entry in &self.entries {
            let mode_str = format_mode_string(entry.mode);
            let target_str = match &entry.symlink_target {
                Some(t) => {
                    let mut flags = Vec::new();
                    if entry.is_path_traversal {
                        flags.push("TRAVERSAL");
                    }
                    if entry.is_dangling_symlink {
                        flags.push("DANGLING");
                    }
                    if flags.is_empty() {
                        format!(" -> {}", t)
                    } else {
                        format!(" -> {} [{}]", t, flags.join(", "))
                    }
                }
                None => String::new(),
            };

            out.push_str(&format!(
                "{} {:4} {:4} {:8} 0x{:06X} {}{}\n",
                mode_str, entry.uid, entry.gid, entry.size, entry.offset, entry.path, target_str
            ));
        }
        out
    }

    pub fn format_summary(&self) -> String {
        format!(
            "CramFS Filesystem: '{}' (v2, {:?})\n\
             Total Entries:    {} (Dirs: {}, Files: {}, Symlinks: {}, Nodes: {})\n\
             Uncompressed:     {} bytes\n\
             Security Audit:   {} issues ({} Critical, {} High, {} Medium, {} Low)\n\
             SUID Binaries:    {}\n\
             Symlink Anomalies: {} traversal, {} dangling",
            self.superblock.name,
            self.superblock.endianness,
            self.summary.total_entries,
            self.summary.directories,
            self.summary.regular_files,
            self.summary.symlinks,
            self.summary.special_nodes,
            self.summary.total_uncompressed_bytes,
            self.audit_report.total_findings,
            self.audit_report.critical,
            self.audit_report.high,
            self.audit_report.medium,
            self.audit_report.low,
            self.summary.suid_files_count,
            self.summary.traversal_symlinks_count,
            self.summary.dangling_symlinks_count,
        )
    }

    pub fn format_audit_table(&self) -> String {
        let mut out = String::new();
        out.push_str("SEVERITY | RULE ID          | PATH                   | DESCRIPTION\n");
        out.push_str("---------+------------------+------------------------+----------------------------------------\n");
        for f in &self.audit_report.findings {
            out.push_str(&format!(
                "{:<8} | {:<16} | {:<22} | {}\n",
                f.severity.as_str(),
                f.rule_id,
                f.path,
                f.description
            ));
        }
        out
    }
}
