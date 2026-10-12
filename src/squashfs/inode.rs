// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::metadata::MetadataReader;
use crate::error::{CarverError, Result};
use serde::{Deserialize, Serialize};

pub const SQUASHFS_DIR_TYPE: u16 = 1;
pub const SQUASHFS_FILE_TYPE: u16 = 2;
pub const SQUASHFS_SYMLINK_TYPE: u16 = 3;
pub const SQUASHFS_BLKDEV_TYPE: u16 = 4;
pub const SQUASHFS_CHRDEV_TYPE: u16 = 5;
pub const SQUASHFS_FIFO_TYPE: u16 = 6;
pub const SQUASHFS_SOCKET_TYPE: u16 = 7;
pub const SQUASHFS_LDIR_TYPE: u16 = 8;
pub const SQUASHFS_LFILE_TYPE: u16 = 9;
pub const SQUASHFS_LSYMLINK_TYPE: u16 = 10;
pub const SQUASHFS_LBLKDEV_TYPE: u16 = 11;
pub const SQUASHFS_LCHRDEV_TYPE: u16 = 12;
pub const SQUASHFS_LFIFO_TYPE: u16 = 13;
pub const SQUASHFS_LSOCKET_TYPE: u16 = 14;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommonInodeHeader {
    pub inode_type: u16,
    pub mode: u16,
    pub uid_idx: u16,
    pub gid_idx: u16,
    pub mtime: u32,
    pub inode_number: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InodeData {
    Directory {
        start_block: u32,
        nlink: u32,
        file_size: u32,
        offset: u16,
        parent_inode: u32,
    },
    File {
        blocks_start: u64,
        fragment_block_index: u32,
        fragment_offset: u32,
        file_size: u64,
    },
    Symlink {
        nlink: u32,
        target_path: String,
    },
    Device {
        nlink: u32,
        rdev: u32,
    },
    Ipc {
        nlink: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedInode {
    pub header: CommonInodeHeader,
    pub data: InodeData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryHeader {
    pub count: u32,
    pub start_block: u32,
    pub inode_number: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryEntry {
    pub offset: u16,
    pub inode_offset: i16,
    pub entry_type: u16,
    pub name: String,
}

impl ParsedInode {
    pub fn parse(
        reader: &mut MetadataReader,
        disk_offset: usize,
        in_block_offset: usize,
    ) -> Result<Self> {
        let inode_type = reader.read_u16(disk_offset, in_block_offset)?;
        let mode = reader.read_u16(disk_offset, in_block_offset + 2)?;
        let uid_idx = reader.read_u16(disk_offset, in_block_offset + 4)?;
        let gid_idx = reader.read_u16(disk_offset, in_block_offset + 6)?;
        let mtime = reader.read_u32(disk_offset, in_block_offset + 8)?;
        let inode_number = reader.read_u32(disk_offset, in_block_offset + 12)?;

        let header = CommonInodeHeader {
            inode_type,
            mode,
            uid_idx,
            gid_idx,
            mtime,
            inode_number,
        };

        let data = match inode_type {
            SQUASHFS_DIR_TYPE => {
                let start_block = reader.read_u32(disk_offset, in_block_offset + 16)?;
                let nlink = reader.read_u32(disk_offset, in_block_offset + 20)?;
                let file_size = reader.read_u16(disk_offset, in_block_offset + 24)? as u32;
                let offset = reader.read_u16(disk_offset, in_block_offset + 26)?;
                let parent_inode = reader.read_u32(disk_offset, in_block_offset + 28)?;
                InodeData::Directory {
                    start_block,
                    nlink,
                    file_size,
                    offset,
                    parent_inode,
                }
            }
            SQUASHFS_LDIR_TYPE => {
                let nlink = reader.read_u32(disk_offset, in_block_offset + 16)?;
                let file_size = reader.read_u32(disk_offset, in_block_offset + 20)?;
                let start_block = reader.read_u32(disk_offset, in_block_offset + 24)?;
                let parent_inode = reader.read_u32(disk_offset, in_block_offset + 28)?;
                let offset = reader.read_u16(disk_offset, in_block_offset + 34)?;
                InodeData::Directory {
                    start_block,
                    nlink,
                    file_size,
                    offset,
                    parent_inode,
                }
            }
            SQUASHFS_FILE_TYPE => {
                let blocks_start = reader.read_u32(disk_offset, in_block_offset + 16)? as u64;
                let fragment_block_index = reader.read_u32(disk_offset, in_block_offset + 20)?;
                let fragment_offset = reader.read_u32(disk_offset, in_block_offset + 24)?;
                let file_size = reader.read_u32(disk_offset, in_block_offset + 28)? as u64;
                InodeData::File {
                    blocks_start,
                    fragment_block_index,
                    fragment_offset,
                    file_size,
                }
            }
            SQUASHFS_LFILE_TYPE => {
                let blocks_start = reader.read_u64(disk_offset, in_block_offset + 16)?;
                let file_size = reader.read_u64(disk_offset, in_block_offset + 24)?;
                let fragment_block_index = reader.read_u32(disk_offset, in_block_offset + 44)?;
                let fragment_offset = reader.read_u32(disk_offset, in_block_offset + 48)?;
                InodeData::File {
                    blocks_start,
                    fragment_block_index,
                    fragment_offset,
                    file_size,
                }
            }
            SQUASHFS_SYMLINK_TYPE | SQUASHFS_LSYMLINK_TYPE => {
                let nlink = reader.read_u32(disk_offset, in_block_offset + 16)?;
                let target_size = reader.read_u32(disk_offset, in_block_offset + 20)? as usize;
                let target_bytes =
                    reader.read_bytes(disk_offset, in_block_offset + 24, target_size)?;
                let target_path = String::from_utf8_lossy(&target_bytes).to_string();
                InodeData::Symlink { nlink, target_path }
            }
            SQUASHFS_BLKDEV_TYPE
            | SQUASHFS_CHRDEV_TYPE
            | SQUASHFS_LBLKDEV_TYPE
            | SQUASHFS_LCHRDEV_TYPE => {
                let nlink = reader.read_u32(disk_offset, in_block_offset + 16)?;
                let rdev = reader.read_u32(disk_offset, in_block_offset + 20)?;
                InodeData::Device { nlink, rdev }
            }
            SQUASHFS_FIFO_TYPE
            | SQUASHFS_SOCKET_TYPE
            | SQUASHFS_LFIFO_TYPE
            | SQUASHFS_LSOCKET_TYPE => {
                let nlink = reader.read_u32(disk_offset, in_block_offset + 16)?;
                InodeData::Ipc { nlink }
            }
            other => {
                return Err(CarverError::SquashFs(format!(
                    "Unrecognized inode type {} at 0x{:08X}+{}",
                    other, disk_offset, in_block_offset
                )));
            }
        };

        Ok(Self { header, data })
    }
}

pub fn parse_directory_records(
    reader: &mut MetadataReader,
    dir_table_base: usize,
    start_block: u32,
    offset_in_block: u16,
    file_size: u32,
) -> Result<Vec<(DirectoryHeader, DirectoryEntry)>> {
    let mut entries = Vec::new();
    let total_bytes_to_read = if file_size >= 3 {
        (file_size - 3) as usize
    } else {
        file_size as usize
    };

    if total_bytes_to_read == 0 {
        return Ok(entries);
    }

    let disk_offset = dir_table_base + start_block as usize;
    let mut in_block = offset_in_block as usize;
    let mut bytes_consumed = 0;

    while bytes_consumed < total_bytes_to_read {
        if bytes_consumed + 12 > total_bytes_to_read {
            break;
        }

        let count_raw = reader.read_u32(disk_offset, in_block)?;
        let start_block_val = reader.read_u32(disk_offset, in_block + 4)?;
        let inode_number_val = reader.read_u32(disk_offset, in_block + 8)?;

        let header = DirectoryHeader {
            count: count_raw + 1,
            start_block: start_block_val,
            inode_number: inode_number_val,
        };

        in_block += 12;
        bytes_consumed += 12;

        for _ in 0..header.count {
            if bytes_consumed + 8 > total_bytes_to_read {
                break;
            }

            let entry_offset = reader.read_u16(disk_offset, in_block)?;
            let inode_offset = reader.read_i16(disk_offset, in_block + 2)?;
            let entry_type = reader.read_u16(disk_offset, in_block + 4)?;
            let name_size = reader.read_u16(disk_offset, in_block + 6)? as usize + 1;

            in_block += 8;
            bytes_consumed += 8;

            let name_bytes = reader.read_bytes(disk_offset, in_block, name_size)?;
            let name = String::from_utf8_lossy(&name_bytes).to_string();

            in_block += name_size;
            bytes_consumed += name_size;

            entries.push((
                header.clone(),
                DirectoryEntry {
                    offset: entry_offset,
                    inode_offset,
                    entry_type,
                    name,
                },
            ));
        }
    }

    Ok(entries)
}
