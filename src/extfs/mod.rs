// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

pub mod carver;
pub mod inode;
pub mod reconstruct;
pub mod rules;
pub mod superblock;
pub mod synth;
pub mod types;

pub use carver::{parse_extfs_segment_at, probe_extfs_at, scan_extfs_partitions, ExtPartitionSpan};
pub use inode::{format_mode_string, parse_inode, read_inode_content, resolve_inode_blocks};
pub use reconstruct::{extract_archive_to_disk, reconstruct_filesystem, validate_safe_path};
pub use rules::ExtRuleEngine;
pub use superblock::{detect_endianness, parse_block_group_descriptors, parse_superblock};
pub use synth::build_synthetic_extfs;
pub use types::*;

use crate::error::{CarverError, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtArchive {
    pub offset: usize,
    pub superblock: ExtSuperblock,
    pub groups: Vec<BlockGroupDescriptor>,
    pub entries: Vec<ExtEntry>,
    pub summary: ExtSummary,
    pub audit: ExtAuditReport,
}

impl ExtArchive {
    /// Parses an Ext2/Ext3/Ext4 filesystem image starting at offset 0.
    pub fn parse(data: &[u8]) -> Result<Self> {
        Self::parse_at(data, 0)
    }

    /// Parses an Ext2/Ext3/Ext4 filesystem image starting at the specified byte offset.
    pub fn parse_at(data: &[u8], offset: usize) -> Result<Self> {
        let sb = parse_superblock(data, offset)?;
        let groups = parse_block_group_descriptors(data, offset, &sb)?;
        let (entries, summary) = reconstruct_filesystem(data, offset, &sb, &groups)?;
        let audit = ExtRuleEngine::audit(&sb, &entries);

        Ok(Self {
            offset,
            superblock: sb,
            groups,
            entries,
            summary,
            audit,
        })
    }

    /// Extracts all files and directories to the specified directory on disk.
    pub fn extract_to_disk(&self, data: &[u8], dest_dir: &Path) -> Result<usize> {
        extract_archive_to_disk(
            data,
            self.offset,
            &self.superblock,
            &self.groups,
            &self.entries,
            dest_dir,
        )
    }

    /// Reads raw file payload bytes for a specific archive entry by path.
    pub fn read_file(&self, data: &[u8], path: &str) -> Result<Vec<u8>> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.path == path)
            .ok_or_else(|| {
                CarverError::ExtFs(format!("File path '{}' not found in archive", path))
            })?;

        let inode = parse_inode(data, self.offset, &self.superblock, &self.groups, entry.ino)?;
        read_inode_content(data, self.offset, &self.superblock, &self.groups, &inode)
    }

    /// Formats a UNIX `ls -la` style file tree listing string.
    pub fn format_listing(&self) -> String {
        let mut out = String::new();
        for e in &self.entries {
            let mode_str = format_mode_string(e.mode, e.file_type);
            let target_str = match &e.symlink_target {
                Some(t) => format!(" -> {}", t),
                None => String::new(),
            };
            out.push_str(&format!(
                "{:<10} {:>4} {:>4} {:>8} Ino {:<5} {}{}\n",
                mode_str, e.uid, e.gid, e.size, e.ino, e.path, target_str
            ));
        }
        out
    }

    /// Formats an audit summary table string.
    pub fn format_summary(&self) -> String {
        format!(
            "Total: {} entries ({} files, {} dirs, {} symlinks, {} special, {} bytes) | Findings: {} ({} Crit, {} High, {} Med, {} Low)",
            self.summary.total_entries,
            self.summary.regular_files,
            self.summary.directories,
            self.summary.symlinks,
            self.summary.special_files,
            self.summary.total_bytes,
            self.audit.total_findings,
            self.audit.critical_count,
            self.audit.high_count,
            self.audit.medium_count,
            self.audit.low_count,
        )
    }

    /// Formats structured security audit findings into a clean ASCII table.
    pub fn format_audit_table(&self) -> String {
        if self.audit.findings.is_empty() {
            return "No security anomalies or permission vulnerabilities detected.\n".to_string();
        }

        let mut out = String::new();
        out.push_str("Sev      Code            Ino   Path                            Message\n");
        out.push_str("---------------------------------------------------------------------------------------------------\n");
        for f in &self.audit.findings {
            out.push_str(&format!(
                "{:<8} {:<15} {:<5} {:<31} {}\n",
                f.severity.as_str(),
                f.code,
                f.inode,
                f.path,
                f.message
            ));
        }
        out
    }
}
