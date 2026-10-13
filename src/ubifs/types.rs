// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use serde::{Deserialize, Serialize};

pub const UBI_EC_HDR_MAGIC: u32 = 0x5542_4923; // "UBI#"
pub const UBI_VID_HDR_MAGIC: u32 = 0x5542_4921; // "UBI!"
pub const UBI_LAYOUT_VOLUME_ID: u32 = 0x7FFF_FFFF;
pub const UBI_MAX_VOLUMES: usize = 128;
pub const UBI_VTBL_RECORD_SIZE: usize = 172;
pub const UBI_VTBL_RECORD_SIZE_CRC: usize = 168;

pub const UBIFS_NODE_MAGIC_LE: u32 = 0x0610_1831;
pub const UBIFS_NODE_MAGIC_BE: u32 = 0x3118_1006;
pub const UBIFS_CH_SZ: usize = 24;
pub const UBIFS_MAX_KEY_LEN: usize = 16;
pub const UBIFS_ROOT_INO: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UbiVolumeType {
    Dynamic = 1,
    Static = 2,
    Unknown = 255,
}

impl From<u8> for UbiVolumeType {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::Dynamic,
            2 => Self::Static,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UbifsNodeType {
    Ino = 0,
    Data = 1,
    Dent = 2,
    Xent = 3,
    Trun = 4,
    Pad = 5,
    Sb = 6,
    Mst = 7,
    Ref = 8,
    Idx = 9,
    Cs = 10,
    Orph = 11,
    Unknown = 255,
}

impl From<u8> for UbifsNodeType {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Ino,
            1 => Self::Data,
            2 => Self::Dent,
            3 => Self::Xent,
            4 => Self::Trun,
            5 => Self::Pad,
            6 => Self::Sb,
            7 => Self::Mst,
            8 => Self::Ref,
            9 => Self::Idx,
            10 => Self::Cs,
            11 => Self::Orph,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UbifsCompressionType {
    None = 0,
    Lzo = 1,
    Zlib = 2,
    Unknown = 255,
}

impl From<u16> for UbifsCompressionType {
    fn from(v: u16) -> Self {
        match v {
            0 => Self::None,
            1 => Self::Lzo,
            2 => Self::Zlib,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UbifsFileType {
    Regular = 1,
    Directory = 2,
    Symlink = 3,
    BlockDevice = 4,
    CharDevice = 5,
    Fifo = 6,
    Socket = 7,
    Unknown = 255,
}

impl From<u8> for UbifsFileType {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::Regular,
            2 => Self::Directory,
            3 => Self::Symlink,
            4 => Self::BlockDevice,
            5 => Self::CharDevice,
            6 => Self::Fifo,
            7 => Self::Socket,
            _ => Self::Unknown,
        }
    }
}

impl UbifsFileType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Regular => "file",
            Self::Directory => "directory",
            Self::Symlink => "symlink",
            Self::BlockDevice => "block_dev",
            Self::CharDevice => "char_dev",
            Self::Fifo => "fifo",
            Self::Socket => "socket",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EraseCounterHeader {
    pub magic: u32,
    pub version: u8,
    pub ec: u64,
    pub vid_hdr_offset: u32,
    pub data_offset: u32,
    pub image_seq: u32,
    pub hdr_crc: u32,
    pub crc_valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeIdHeader {
    pub magic: u32,
    pub version: u8,
    pub vol_type: UbiVolumeType,
    pub copy_flag: u8,
    pub compat: u8,
    pub vol_id: u32,
    pub lnum: u32,
    pub data_size: u32,
    pub used_ebs: u32,
    pub data_pad: u32,
    pub data_crc: u32,
    pub hdr_crc: u32,
    pub crc_valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeTableRecord {
    pub reserved_pebs: u32,
    pub alignment: u32,
    pub data_pad: u32,
    pub vol_type: UbiVolumeType,
    pub upd_marker: u8,
    pub name_len: u16,
    pub name: String,
    pub flags: u8,
    pub crc: u32,
    pub crc_valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UbifsCommonHeader {
    pub magic: u32,
    pub crc: u32,
    pub sqnum: u64,
    pub len: u32,
    pub node_type: UbifsNodeType,
    pub group_type: u8,
    pub crc_valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UbifsSuperblock {
    pub key_hash: u8,
    pub key_fmt: u8,
    pub flags: u32,
    pub min_io_size: u32,
    pub leb_size: u32,
    pub leb_cnt: u32,
    pub max_leb_cnt: u32,
    pub max_bud_bytes: u64,
    pub log_lebs: u32,
    pub lpt_lebs: u32,
    pub orph_lebs: u32,
    pub jhead_cnt: u32,
    pub fanout: u32,
    pub lsave_cnt: u32,
    pub fmt_version: u32,
    pub default_compr: UbifsCompressionType,
    pub rp_size: u64,
    pub time_gran: u32,
    pub uuid: String,
    pub ro_compat_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UbifsMasterNode {
    pub highest_inum: u64,
    pub cmt_no: u64,
    pub flags: u32,
    pub log_lnum: u32,
    pub root_lnum: u32,
    pub root_offs: u32,
    pub root_len: u32,
    pub gc_lnum: u32,
    pub ihead_lnum: u32,
    pub ihead_offs: u32,
    pub index_size: u64,
    pub total_free: u64,
    pub total_dirty: u64,
    pub total_used: u64,
    pub total_dead: u64,
    pub total_dark: u64,
    pub leb_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UbifsInode {
    pub inum: u64,
    pub creat_sqnum: u64,
    pub size: u64,
    pub atime_sec: u64,
    pub ctime_sec: u64,
    pub mtime_sec: u64,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub flags: u32,
    pub data_len: u32,
    pub compr_type: UbifsCompressionType,
    pub symlink_target: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UbifsDent {
    pub inum: u64,
    pub parent_inum: u64,
    pub target_type: UbifsFileType,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UbifsEntry {
    pub inum: u64,
    pub parent_inum: u64,
    pub path: String,
    pub name: String,
    pub file_type: UbifsFileType,
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime_sec: u64,
    pub symlink_target: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UbiVolumeInfo {
    pub vol_id: u32,
    pub name: String,
    pub vol_type: UbiVolumeType,
    pub reserved_pebs: u32,
    pub mapped_lebs: usize,
    pub data_bytes: usize,
}
