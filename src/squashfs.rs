// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

pub mod inode;
pub mod metadata;
pub mod superblock;
pub mod synth;

pub use inode::*;
pub use metadata::*;
pub use superblock::*;
pub use synth::*;

use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Extracted metadata entry representing a file, directory, or symlink in a SquashFS filesystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SquashFsEntry {
    pub path: String,
    pub name: String,
    pub inode_number: u32,
    pub inode_type: String,
    pub mode: u16,
    pub uid_idx: u16,
    pub gid_idx: u16,
    pub mtime: u32,
    pub file_size: u64,
    pub symlink_target: Option<String>,
}

/// In-memory representation of an unpacked SquashFS archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SquashFsArchive {
    pub superblock: SquashFsSuperblock,
    pub entries: Vec<SquashFsEntry>,
}

struct DirQueueItem {
    parent_path: String,
    start_block: u32,
    offset: u16,
    file_size: u32,
}

impl SquashFsArchive {
    /// Parses a complete SquashFS v4 image from a byte slice, exploring all directories and inodes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let superblock = SquashFsSuperblock::parse(data)?;
        let mut reader = MetadataReader::new(data, superblock.endianness, superblock.compression);

        let root_disk_offset =
            (superblock.inode_table_start + superblock.root_block_offset()) as usize;
        let root_in_block = superblock.root_offset_in_block();
        let root_inode = ParsedInode::parse(&mut reader, root_disk_offset, root_in_block)?;

        let mut entries = Vec::new();
        let mut visited_inodes = HashSet::new();

        let root_dir_info = match &root_inode.data {
            InodeData::Directory {
                file_size,
                start_block,
                offset,
                ..
            } => {
                entries.push(SquashFsEntry {
                    path: "/".to_string(),
                    name: "".to_string(),
                    inode_number: root_inode.header.inode_number,
                    inode_type: "directory".to_string(),
                    mode: root_inode.header.mode,
                    uid_idx: root_inode.header.uid_idx,
                    gid_idx: root_inode.header.gid_idx,
                    mtime: root_inode.header.mtime,
                    file_size: *file_size as u64,
                    symlink_target: None,
                });
                visited_inodes.insert(root_inode.header.inode_number);
                Some((*start_block, *offset, *file_size))
            }
            _ => None,
        };

        let mut queue = Vec::new();
        if let Some((start_block, offset, file_size)) = root_dir_info {
            queue.push(DirQueueItem {
                parent_path: "/".to_string(),
                start_block,
                offset,
                file_size,
            });
        }

        while let Some(item) = queue.pop() {
            let dir_records = parse_directory_records(
                &mut reader,
                superblock.directory_table_start as usize,
                item.start_block,
                item.offset,
                item.file_size,
            )?;

            for (hdr, entry) in dir_records {
                let target_disk_offset =
                    (superblock.inode_table_start + hdr.start_block as u64) as usize;
                let target_in_block = entry.offset as usize;

                let target_inode =
                    match ParsedInode::parse(&mut reader, target_disk_offset, target_in_block) {
                        Ok(inode) => inode,
                        Err(_) => continue,
                    };

                let path = if item.parent_path == "/" {
                    format!("/{}", entry.name)
                } else {
                    format!("{}/{}", item.parent_path, entry.name)
                };

                let (type_str, size, symlink_target, dir_recurse) = match &target_inode.data {
                    InodeData::Directory {
                        file_size,
                        start_block,
                        offset,
                        ..
                    } => (
                        "directory".to_string(),
                        *file_size as u64,
                        None,
                        Some((*start_block, *offset, *file_size)),
                    ),
                    InodeData::File { file_size, .. } => {
                        ("file".to_string(), *file_size, None, None)
                    }
                    InodeData::Symlink { target_path, .. } => (
                        "symlink".to_string(),
                        target_path.len() as u64,
                        Some(target_path.clone()),
                        None,
                    ),
                    InodeData::Device { .. } => ("device".to_string(), 0, None, None),
                    InodeData::Ipc { .. } => ("fifo".to_string(), 0, None, None),
                };

                entries.push(SquashFsEntry {
                    path: path.clone(),
                    name: entry.name,
                    inode_number: target_inode.header.inode_number,
                    inode_type: type_str,
                    mode: target_inode.header.mode,
                    uid_idx: target_inode.header.uid_idx,
                    gid_idx: target_inode.header.gid_idx,
                    mtime: target_inode.header.mtime,
                    file_size: size,
                    symlink_target,
                });

                if let Some((start_block, offset, file_size)) = dir_recurse {
                    if visited_inodes.insert(target_inode.header.inode_number) {
                        queue.push(DirQueueItem {
                            parent_path: path,
                            start_block,
                            offset,
                            file_size,
                        });
                    }
                }
            }
        }

        Ok(Self {
            superblock,
            entries,
        })
    }

    /// Finds a metadata entry by its exact absolute path.
    pub fn find_entry(&self, path: &str) -> Option<&SquashFsEntry> {
        self.entries.iter().find(|e| e.path == path)
    }

    /// Formats a UNIX `ls -la` style listing for all extracted entries.
    pub fn format_listing(&self) -> String {
        let mut out = String::new();
        for e in &self.entries {
            let type_char = match e.inode_type.as_str() {
                "directory" => 'd',
                "symlink" => 'l',
                "device" => 'c',
                "fifo" => 'p',
                _ => '-',
            };
            let mode_str = format_mode(type_char, e.mode);
            let symlink_suffix = match &e.symlink_target {
                Some(target) => format!(" -> {}", target),
                None => String::new(),
            };
            out.push_str(&format!(
                "{} {:4} {:4} {:8} {} {}{}\n",
                mode_str, e.uid_idx, e.gid_idx, e.file_size, e.inode_number, e.path, symlink_suffix
            ));
        }
        out
    }
}

fn format_mode(type_char: char, mode: u16) -> String {
    let r = |m: u16, shift: u16| if (m >> shift) & 4 != 0 { 'r' } else { '-' };
    let w = |m: u16, shift: u16| if (m >> shift) & 2 != 0 { 'w' } else { '-' };
    let x = |m: u16, shift: u16| if (m >> shift) & 1 != 0 { 'x' } else { '-' };

    format!(
        "{}{}{}{}{}{}{}{}{}{}",
        type_char,
        r(mode, 6),
        w(mode, 6),
        x(mode, 6),
        r(mode, 3),
        w(mode, 3),
        x(mode, 3),
        r(mode, 0),
        w(mode, 0),
        x(mode, 0)
    )
}
