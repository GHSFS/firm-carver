// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use serde::{Deserialize, Serialize};

pub const CRAMFS_MAGIC: u32 = 0x28cd_3d45;
pub const CRAMFS_MAGIC_LE: u32 = 0x28cd_3d45;
pub const CRAMFS_MAGIC_BE: u32 = 0x28cd_3d45;
pub const CRAMFS_SIGNATURE: &[u8] = b"Compressed ROMFS";

pub const CRAMFS_FLAG_FSID_VERSION_2: u32 = 0x0000_0001;
pub const CRAMFS_FLAG_SORTED_DIRS: u32 = 0x0000_0002;
pub const CRAMFS_FLAG_HOLES: u32 = 0x0000_0100;
pub const CRAMFS_FLAG_WRONG_SIGNATURE: u32 = 0x0000_0200;
pub const CRAMFS_FLAG_SHIFTED_ROOT_OFFSET: u32 = 0x0000_0400;
pub const CRAMFS_FLAG_EXT_BLOCK_POINTERS: u32 = 0x0000_0800;

pub const CRAMFS_BLK_FLAG_UNCOMPRESSED: u32 = 0x8000_0000;
pub const CRAMFS_BLK_FLAG_DIRECT_PTR: u32 = 0x4000_0000;

pub const S_IFMT: u16 = 0o170000;
pub const S_IFSOCK: u16 = 0o140000;
pub const S_IFLNK: u16 = 0o120000;
pub const S_IFREG: u16 = 0o100000;
pub const S_IFBLK: u16 = 0o060000;
pub const S_IFDIR: u16 = 0o040000;
pub const S_IFCHR: u16 = 0o020000;
pub const S_IFIFO: u16 = 0o010000;

pub const S_ISUID: u16 = 0o004000;
pub const S_ISGID: u16 = 0o002000;
pub const S_ISVTX: u16 = 0o001000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CramFsFileType {
    Directory,
    RegularFile,
    Symlink,
    BlockDevice,
    CharDevice,
    Fifo,
    Socket,
    Unknown,
}

impl CramFsFileType {
    pub fn from_mode(mode: u16) -> Self {
        match mode & S_IFMT {
            S_IFDIR => Self::Directory,
            S_IFREG => Self::RegularFile,
            S_IFLNK => Self::Symlink,
            S_IFBLK => Self::BlockDevice,
            S_IFCHR => Self::CharDevice,
            S_IFIFO => Self::Fifo,
            S_IFSOCK => Self::Socket,
            _ => Self::Unknown,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Directory => "directory",
            Self::RegularFile => "regular",
            Self::Symlink => "symlink",
            Self::BlockDevice => "block_dev",
            Self::CharDevice => "char_dev",
            Self::Fifo => "fifo",
            Self::Socket => "socket",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CramFsInfo {
    pub crc: u32,
    pub edition: u32,
    pub blocks: u32,
    pub files: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CramFsInode {
    pub mode: u16,
    pub uid: u16,
    pub size: u32,
    pub gid: u8,
    pub namelen: u8,
    pub offset: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CramFsSuperblock {
    pub magic: u32,
    pub size: u32,
    pub flags: u32,
    pub future: u32,
    pub signature: String,
    pub fsid: CramFsInfo,
    pub name: String,
    pub root: CramFsInode,
    pub endianness: Endianness,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CramFsEntry {
    pub path: String,
    pub name: String,
    pub file_type: CramFsFileType,
    pub mode: u16,
    pub uid: u16,
    pub gid: u8,
    pub size: usize,
    pub offset: usize,
    pub payload_offset: usize,
    pub symlink_target: Option<String>,
    pub is_dangling_symlink: bool,
    pub is_path_traversal: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CramFsSummary {
    pub total_entries: usize,
    pub directories: usize,
    pub regular_files: usize,
    pub symlinks: usize,
    pub special_nodes: usize,
    pub total_uncompressed_bytes: usize,
    pub dangling_symlinks_count: usize,
    pub traversal_symlinks_count: usize,
    pub suid_files_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CramFsSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl CramFsSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CramFsAuditFinding {
    pub rule_id: String,
    pub severity: CramFsSeverity,
    pub title: String,
    pub description: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CramFsAuditReport {
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub findings: Vec<CramFsAuditFinding>,
}
