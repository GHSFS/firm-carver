// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::error::{CarverError, Result};
use serde::{Deserialize, Serialize};

pub const SQUASHFS_MAGIC_LE: u32 = 0x7371_7368; // "sqsh"
pub const SQUASHFS_MAGIC_BE: u32 = 0x6873_7173; // "hsqs"
pub const SUPERBLOCK_SIZE: usize = 96;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompressionType {
    Gzip,
    Lzma,
    Lzo,
    Xz,
    Lz4,
    Zstd,
    Unknown(u16),
}

impl From<u16> for CompressionType {
    fn from(val: u16) -> Self {
        match val {
            1 => Self::Gzip,
            2 => Self::Lzma,
            3 => Self::Lzo,
            4 => Self::Xz,
            5 => Self::Lz4,
            6 => Self::Zstd,
            other => Self::Unknown(other),
        }
    }
}

impl CompressionType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Gzip => "GZIP (Deflate)",
            Self::Lzma => "LZMA",
            Self::Lzo => "LZO",
            Self::Xz => "XZ",
            Self::Lz4 => "LZ4",
            Self::Zstd => "ZSTD",
            Self::Unknown(_) => "Unknown",
        }
    }
}

/// SquashFS v4.0 Superblock structure (96 bytes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SquashFsSuperblock {
    pub magic: u32,
    pub endianness: Endianness,
    pub inode_count: u32,
    pub modification_time: u32,
    pub block_size: u32,
    pub fragment_count: u32,
    pub compression: CompressionType,
    pub block_log: u16,
    pub flags: u16,
    pub id_count: u16,
    pub version_major: u16,
    pub version_minor: u16,
    pub root_inode_ref: u64,
    pub bytes_used: u64,
    pub id_table_start: u64,
    pub xattr_id_table_start: u64,
    pub inode_table_start: u64,
    pub directory_table_start: u64,
    pub fragment_table_start: u64,
    pub lookup_table_start: u64,
}

impl SquashFsSuperblock {
    /// Parses and validates a 96-byte SquashFS v4.0 superblock from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < SUPERBLOCK_SIZE {
            return Err(CarverError::SquashFs(format!(
                "Superblock buffer underflow: {} bytes (required {})",
                data.len(),
                SUPERBLOCK_SIZE
            )));
        }

        let magic_raw = &data[0..4];
        let (endianness, magic) = if magic_raw == [0x73, 0x71, 0x73, 0x68] {
            (Endianness::Little, SQUASHFS_MAGIC_LE)
        } else if magic_raw == [0x68, 0x73, 0x71, 0x73] {
            (Endianness::Big, SQUASHFS_MAGIC_BE)
        } else {
            return Err(CarverError::InvalidImage(format!(
                "Invalid SquashFS magic: 0x{:02X}{:02X}{:02X}{:02X}",
                magic_raw[0], magic_raw[1], magic_raw[2], magic_raw[3]
            )));
        };

        let read_u16 = |offset: usize| -> Result<u16> {
            let bytes: [u8; 2] = data[offset..offset + 2]
                .try_into()
                .map_err(|_| CarverError::SquashFs("Offset out of bounds".to_string()))?;
            Ok(match endianness {
                Endianness::Little => u16::from_le_bytes(bytes),
                Endianness::Big => u16::from_be_bytes(bytes),
            })
        };

        let read_u32 = |offset: usize| -> Result<u32> {
            let bytes: [u8; 4] = data[offset..offset + 4]
                .try_into()
                .map_err(|_| CarverError::SquashFs("Offset out of bounds".to_string()))?;
            Ok(match endianness {
                Endianness::Little => u32::from_le_bytes(bytes),
                Endianness::Big => u32::from_be_bytes(bytes),
            })
        };

        let read_u64 = |offset: usize| -> Result<u64> {
            let bytes: [u8; 8] = data[offset..offset + 8]
                .try_into()
                .map_err(|_| CarverError::SquashFs("Offset out of bounds".to_string()))?;
            Ok(match endianness {
                Endianness::Little => u64::from_le_bytes(bytes),
                Endianness::Big => u64::from_be_bytes(bytes),
            })
        };

        let inode_count = read_u32(4)?;
        let modification_time = read_u32(8)?;
        let block_size = read_u32(12)?;
        let fragment_count = read_u32(16)?;
        let compression_val = read_u16(20)?;
        let block_log = read_u16(22)?;
        let flags = read_u16(24)?;
        let id_count = read_u16(26)?;
        let version_major = read_u16(28)?;
        let version_minor = read_u16(30)?;
        let root_inode_ref = read_u64(32)?;
        let bytes_used = read_u64(40)?;
        let id_table_start = read_u64(48)?;
        let xattr_id_table_start = read_u64(56)?;
        let inode_table_start = read_u64(64)?;
        let directory_table_start = read_u64(72)?;
        let fragment_table_start = read_u64(80)?;
        let lookup_table_start = read_u64(88)?;

        if version_major != 4 || version_minor != 0 {
            return Err(CarverError::SquashFs(format!(
                "Unsupported SquashFS version: {}.{} (only v4.0 is supported)",
                version_major, version_minor
            )));
        }

        if !(4096..=1_048_576).contains(&block_size) || !block_size.is_power_of_two() {
            return Err(CarverError::SquashFs(format!(
                "Invalid block size: {} (must be power of two between 4K and 1M)",
                block_size
            )));
        }

        if (1u32 << block_log) != block_size {
            return Err(CarverError::SquashFs(format!(
                "Block log {} does not match block size {}",
                block_log, block_size
            )));
        }

        Ok(Self {
            magic,
            endianness,
            inode_count,
            modification_time,
            block_size,
            fragment_count,
            compression: CompressionType::from(compression_val),
            block_log,
            flags,
            id_count,
            version_major,
            version_minor,
            root_inode_ref,
            bytes_used,
            id_table_start,
            xattr_id_table_start,
            inode_table_start,
            directory_table_start,
            fragment_table_start,
            lookup_table_start,
        })
    }

    /// Offset in bytes from `inode_table_start` to the metadata block holding the root inode.
    pub fn root_block_offset(&self) -> u64 {
        (self.root_inode_ref >> 16) & 0x0000_FFFF_FFFF_FFFF
    }

    /// Offset in bytes within the decompressed metadata block where the root inode starts.
    pub fn root_offset_in_block(&self) -> usize {
        (self.root_inode_ref & 0xFFFF) as usize
    }

    pub fn uncompressed_inodes(&self) -> bool {
        (self.flags & 0x0001) != 0
    }

    pub fn uncompressed_data(&self) -> bool {
        (self.flags & 0x0002) != 0
    }

    pub fn uncompressed_fragments(&self) -> bool {
        (self.flags & 0x0004) != 0
    }

    pub fn no_fragments(&self) -> bool {
        (self.flags & 0x0008) != 0
    }
}
