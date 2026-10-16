// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub const EXT_SUPER_MAGIC: u16 = 0xEF53;
pub const EXT_SUPERBLOCK_OFFSET: usize = 1024;
pub const EXT_MIN_SUPERBLOCK_SIZE: usize = 1024;

// Feature Compat Flags
pub const EXT3_FEATURE_COMPAT_HAS_JOURNAL: u32 = 0x0004;
pub const EXT2_FEATURE_COMPAT_EXT_ATTR: u32 = 0x0008;
pub const EXT2_FEATURE_COMPAT_RESIZE_INO: u32 = 0x0010;
pub const EXT2_FEATURE_COMPAT_DIR_INDEX: u32 = 0x0020;

// Feature Incompat Flags
pub const EXT2_FEATURE_INCOMPAT_FILETYPE: u32 = 0x0002;
pub const EXT3_FEATURE_INCOMPAT_RECOVER: u32 = 0x0004;
pub const EXT4_FEATURE_INCOMPAT_EXTENTS: u32 = 0x0040;
pub const EXT4_FEATURE_INCOMPAT_64BIT: u32 = 0x0080;
pub const EXT4_FEATURE_INCOMPAT_FLEX_BG: u32 = 0x0200;

// Feature Read-Only Compat Flags
pub const EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER: u32 = 0x0001;
pub const EXT2_FEATURE_RO_COMPAT_LARGE_FILE: u32 = 0x0002;
pub const EXT4_FEATURE_RO_COMPAT_HUGE_FILE: u32 = 0x0008;
pub const EXT4_FEATURE_RO_COMPAT_METADATA_CSUM: u32 = 0x0400;

// Inode flags
pub const EXT4_EXTENTS_FL: u32 = 0x0008_0000;
pub const EXT4_EXTENT_HEADER_MAGIC: u16 = 0xF30A;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExtVersion {
    Ext2,
    Ext3,
    Ext4,
}

impl ExtVersion {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ext2 => "ext2",
            Self::Ext3 => "ext3",
            Self::Ext4 => "ext4",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExtFileType {
    Unknown,
    RegularFile,
    Directory,
    CharDevice,
    BlockDevice,
    Fifo,
    Socket,
    Symlink,
}

impl ExtFileType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::RegularFile => "file",
            Self::Directory => "dir",
            Self::CharDevice => "chardev",
            Self::BlockDevice => "blockdev",
            Self::Fifo => "fifo",
            Self::Socket => "socket",
            Self::Symlink => "symlink",
        }
    }

    pub fn from_mode(mode: u16) -> Self {
        match mode & 0xF000 {
            0x8000 => Self::RegularFile,
            0x4000 => Self::Directory,
            0xA000 => Self::Symlink,
            0x6000 => Self::BlockDevice,
            0x2000 => Self::CharDevice,
            0x1000 => Self::Fifo,
            0xC000 => Self::Socket,
            _ => Self::Unknown,
        }
    }

    pub fn from_dir_type(dtype: u8) -> Self {
        match dtype {
            1 => Self::RegularFile,
            2 => Self::Directory,
            3 => Self::CharDevice,
            4 => Self::BlockDevice,
            5 => Self::Fifo,
            6 => Self::Socket,
            7 => Self::Symlink,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtSuperblock {
    pub inodes_count: u32,
    pub blocks_count: u64,
    pub free_blocks_count: u64,
    pub free_inodes_count: u32,
    pub first_data_block: u32,
    pub block_size: u32,
    pub cluster_size: u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub mtime: u32,
    pub wtime: u32,
    pub magic: u16,
    pub state: u16,
    pub rev_level: u32,
    pub first_ino: u32,
    pub inode_size: u16,
    pub feature_compat: u32,
    pub feature_incompat: u32,
    pub feature_ro_compat: u32,
    pub uuid: String,
    pub volume_name: String,
    pub last_mounted: String,
    pub desc_size: u16,
    pub version: ExtVersion,
    pub endianness: Endianness,
    pub block_group_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockGroupDescriptor {
    pub bg_index: usize,
    pub block_bitmap: u64,
    pub inode_bitmap: u64,
    pub inode_table: u64,
    pub free_blocks_count: u32,
    pub free_inodes_count: u32,
    pub used_dirs_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtInode {
    pub ino: u32,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime: u32,
    pub ctime: u32,
    pub mtime: u32,
    pub dtime: u32,
    pub links_count: u16,
    pub blocks_count: u64,
    pub flags: u32,
    pub direct_blocks: [u32; 12],
    pub single_indirect: u32,
    pub double_indirect: u32,
    pub triple_indirect: u32,
    pub is_extent: bool,
    pub file_type: ExtFileType,
    pub symlink_target: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtEntry {
    pub ino: u32,
    pub path: String,
    pub name: String,
    pub parent_ino: u32,
    pub file_type: ExtFileType,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub symlink_target: Option<String>,
    pub mtime: u32,
}

impl Zeroize for ExtEntry {
    fn zeroize(&mut self) {
        self.path.zeroize();
        self.name.zeroize();
        if let Some(target) = &mut self.symlink_target {
            target.zeroize();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtSummary {
    pub total_entries: usize,
    pub regular_files: usize,
    pub directories: usize,
    pub symlinks: usize,
    pub special_files: usize,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExtSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl ExtSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "CRITICAL",
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
            Self::Info => "INFO",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtAuditFinding {
    pub code: String,
    pub severity: ExtSeverity,
    pub path: String,
    pub inode: u32,
    pub message: String,
    pub detail: Option<String>,
}

impl Zeroize for ExtAuditFinding {
    fn zeroize(&mut self) {
        self.code.zeroize();
        self.path.zeroize();
        self.message.zeroize();
        if let Some(d) = &mut self.detail {
            d.zeroize();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtAuditReport {
    pub timestamp: u64,
    pub filesystem_version: String,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub findings: Vec<ExtAuditFinding>,
}

impl Zeroize for ExtAuditReport {
    fn zeroize(&mut self) {
        for f in &mut self.findings {
            f.zeroize();
        }
    }
}
