// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use serde::{Deserialize, Serialize};

/// Standard JFFS2 magic bitmask (0x1985).
pub const JFFS2_MAGIC_BITMASK: u16 = 0x1985;

/// JFFS2 node types defined in Linux kernel include/uapi/linux/jffs2.h.
pub const JFFS2_NODETYPE_DIRENT: u16 = 0xE001;
pub const JFFS2_NODETYPE_INODE: u16 = 0xE002;
pub const JFFS2_NODETYPE_CLEANMARKER: u16 = 0x2003;
pub const JFFS2_NODETYPE_PADDING: u16 = 0x2004;
pub const JFFS2_NODETYPE_SUMMARY: u16 = 0x2006;

/// JFFS2 compression algorithms.
pub const JFFS2_COMPR_NONE: u8 = 0x00;
pub const JFFS2_COMPR_ZERO: u8 = 0x01;
pub const JFFS2_COMPR_RTIME: u8 = 0x02;
pub const JFFS2_COMPR_RUBINMIPS: u8 = 0x03;
pub const JFFS2_COMPR_COPY: u8 = 0x04;
pub const JFFS2_COMPR_DYNRUBIN: u8 = 0x05;
pub const JFFS2_COMPR_ZLIB: u8 = 0x06;
pub const JFFS2_COMPR_LZO: u8 = 0x07;

/// Endianness of the JFFS2 flash filesystem image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Endianness {
    Little,
    Big,
}

/// JFFS2 directory entry file type (POSIX d_type).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Jffs2FileType {
    Regular,
    Directory,
    Symlink,
    Fifo,
    Socket,
    BlockDevice,
    CharDevice,
    Unknown,
}

impl Jffs2FileType {
    pub fn from_raw(val: u8, mode: u32) -> Self {
        match val {
            1 => Self::Fifo,
            2 => Self::CharDevice,
            4 => Self::Directory,
            6 => Self::BlockDevice,
            8 => Self::Regular,
            10 => Self::Symlink,
            12 => Self::Socket,
            _ => {
                // Infer from POSIX mode if d_type is DT_UNKNOWN
                let fmt = mode & 0o170000;
                match fmt {
                    0o010000 => Self::Fifo,
                    0o020000 => Self::CharDevice,
                    0o040000 => Self::Directory,
                    0o060000 => Self::BlockDevice,
                    0o100000 => Self::Regular,
                    0o120000 => Self::Symlink,
                    0o140000 => Self::Socket,
                    _ => Self::Unknown,
                }
            }
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Regular => "file",
            Self::Directory => "directory",
            Self::Symlink => "symlink",
            Self::Fifo => "fifo",
            Self::Socket => "socket",
            Self::BlockDevice => "block_dev",
            Self::CharDevice => "char_dev",
            Self::Unknown => "unknown",
        }
    }
}

/// Reconstructed filesystem entry from parsed JFFS2 nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jffs2Entry {
    pub ino: u32,
    pub pino: u32,
    pub name: String,
    pub path: String,
    pub file_type: Jffs2FileType,
    pub mode: u32,
    pub uid: u16,
    pub gid: u16,
    pub size: u64,
    pub mtime: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symlink_target: Option<String>,
    #[serde(skip)]
    pub data: Vec<u8>,
}

/// Fully parsed and reconstructed JFFS2 flash filesystem archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jffs2Archive {
    pub endianness: Endianness,
    pub cleanmarker_count: usize,
    pub inode_node_count: usize,
    pub dirent_node_count: usize,
    pub total_bytes_carved: usize,
    pub entries: Vec<Jffs2Entry>,
}
