// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::types::*;
use crate::error::{CarverError, Result};

pub fn detect_endianness(data: &[u8], offset: usize) -> Option<Endianness> {
    let sb_start = offset + EXT_SUPERBLOCK_OFFSET;
    if data.len() < sb_start + 0x3A {
        return None;
    }
    let magic_bytes = &data[sb_start + 0x38..sb_start + 0x3A];
    if magic_bytes == [0x53, 0xEF] {
        Some(Endianness::Little)
    } else if magic_bytes == [0xEF, 0x53] {
        Some(Endianness::Big)
    } else {
        None
    }
}

pub fn read_u16(data: &[u8], offset: usize, endian: Endianness) -> Result<u16> {
    if offset + 2 > data.len() {
        return Err(CarverError::ExtFs(format!(
            "Buffer underflow reading u16 at offset 0x{:X}",
            offset
        )));
    }
    let bytes: [u8; 2] = data[offset..offset + 2].try_into().unwrap();
    match endian {
        Endianness::Little => Ok(u16::from_le_bytes(bytes)),
        Endianness::Big => Ok(u16::from_be_bytes(bytes)),
    }
}

pub fn read_u32(data: &[u8], offset: usize, endian: Endianness) -> Result<u32> {
    if offset + 4 > data.len() {
        return Err(CarverError::ExtFs(format!(
            "Buffer underflow reading u32 at offset 0x{:X}",
            offset
        )));
    }
    let bytes: [u8; 4] = data[offset..offset + 4].try_into().unwrap();
    match endian {
        Endianness::Little => Ok(u32::from_le_bytes(bytes)),
        Endianness::Big => Ok(u32::from_be_bytes(bytes)),
    }
}

pub fn parse_superblock(data: &[u8], offset: usize) -> Result<ExtSuperblock> {
    let sb_start = offset + EXT_SUPERBLOCK_OFFSET;
    if data.len() < sb_start + EXT_MIN_SUPERBLOCK_SIZE {
        return Err(CarverError::ExtFs(format!(
            "Buffer length {} too short for ext superblock at offset {}",
            data.len(),
            offset
        )));
    }

    let endianness = detect_endianness(data, offset).ok_or_else(|| {
        CarverError::ExtFs(format!(
            "Invalid Ext superblock magic at offset 0x{:X}",
            sb_start + 0x38
        ))
    })?;

    let inodes_count = read_u32(data, sb_start, endianness)?;
    let blocks_count_lo = read_u32(data, sb_start + 0x04, endianness)?;
    let free_blocks_count_lo = read_u32(data, sb_start + 0x0C, endianness)?;
    let free_inodes_count = read_u32(data, sb_start + 0x10, endianness)?;
    let first_data_block = read_u32(data, sb_start + 0x14, endianness)?;
    let s_log_block_size = read_u32(data, sb_start + 0x18, endianness)?;
    let s_log_cluster_size = read_u32(data, sb_start + 0x1C, endianness)?;
    let blocks_per_group = read_u32(data, sb_start + 0x20, endianness)?;
    let inodes_per_group = read_u32(data, sb_start + 0x28, endianness)?;
    let mtime = read_u32(data, sb_start + 0x2C, endianness)?;
    let wtime = read_u32(data, sb_start + 0x30, endianness)?;
    let magic = read_u16(data, sb_start + 0x38, endianness)?;
    let state = read_u16(data, sb_start + 0x3A, endianness)?;
    let rev_level = read_u32(data, sb_start + 0x4C, endianness)?;

    if s_log_block_size > 6 {
        return Err(CarverError::ExtFs(format!(
            "Invalid s_log_block_size {} (must be <= 6)",
            s_log_block_size
        )));
    }
    let block_size = 1024u32
        .checked_shl(s_log_block_size)
        .ok_or_else(|| CarverError::ExtFs("Block size overflow".to_string()))?;

    if blocks_per_group == 0 || inodes_per_group == 0 {
        return Err(CarverError::ExtFs(
            "Corrupt superblock: blocks_per_group or inodes_per_group is 0".to_string(),
        ));
    }

    let (
        first_ino,
        inode_size,
        feat_compat,
        feat_incompat,
        feat_ro_compat,
        desc_size,
        blocks_count_hi,
        free_blocks_hi,
    ) = if rev_level >= 1 {
        let first_ino = read_u32(data, sb_start + 0x54, endianness)?;
        let inode_size = read_u16(data, sb_start + 0x58, endianness)?;
        let fc = read_u32(data, sb_start + 0x5C, endianness)?;
        let fi = read_u32(data, sb_start + 0x60, endianness)?;
        let fr = read_u32(data, sb_start + 0x64, endianness)?;
        let ds = read_u16(data, sb_start + 0xFE, endianness).unwrap_or(32);
        let ds = if ds == 0 { 32 } else { ds };

        let (b_hi, fb_hi) = if fi & EXT4_FEATURE_INCOMPAT_64BIT != 0 {
            let b = read_u32(data, sb_start + 0x150, endianness).unwrap_or(0);
            let fb = read_u32(data, sb_start + 0x154, endianness).unwrap_or(0);
            (b as u64, fb as u64)
        } else {
            (0, 0)
        };

        (first_ino, inode_size, fc, fi, fr, ds, b_hi, fb_hi)
    } else {
        (11, 128, 0, 0, 0, 32, 0, 0)
    };

    let inode_size = if inode_size == 0 { 128 } else { inode_size };
    let blocks_count = (blocks_count_hi << 32) | (blocks_count_lo as u64);
    let free_blocks_count = (free_blocks_hi << 32) | (free_blocks_count_lo as u64);

    let block_group_count = blocks_count.div_ceil(blocks_per_group as u64) as usize;

    let version = if feat_incompat
        & (EXT4_FEATURE_INCOMPAT_EXTENTS
            | EXT4_FEATURE_INCOMPAT_64BIT
            | EXT4_FEATURE_INCOMPAT_FLEX_BG)
        != 0
    {
        ExtVersion::Ext4
    } else if feat_compat & EXT3_FEATURE_COMPAT_HAS_JOURNAL != 0 {
        ExtVersion::Ext3
    } else {
        ExtVersion::Ext2
    };

    let uuid_bytes = &data[sb_start + 0x68..sb_start + 0x78];
    let uuid = format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        uuid_bytes[0], uuid_bytes[1], uuid_bytes[2], uuid_bytes[3],
        uuid_bytes[4], uuid_bytes[5], uuid_bytes[6], uuid_bytes[7],
        uuid_bytes[8], uuid_bytes[9], uuid_bytes[10], uuid_bytes[11],
        uuid_bytes[12], uuid_bytes[13], uuid_bytes[14], uuid_bytes[15]
    );

    let vol_name_raw = &data[sb_start + 0x78..sb_start + 0x88];
    let volume_name = String::from_utf8_lossy(vol_name_raw)
        .trim_end_matches('\0')
        .trim()
        .to_string();

    let last_mounted_raw = &data[sb_start + 0x88..sb_start + 0xC8];
    let last_mounted = String::from_utf8_lossy(last_mounted_raw)
        .trim_end_matches('\0')
        .trim()
        .to_string();

    Ok(ExtSuperblock {
        inodes_count,
        blocks_count,
        free_blocks_count,
        free_inodes_count,
        first_data_block,
        block_size,
        cluster_size: 1024u32
            .checked_shl(s_log_cluster_size)
            .unwrap_or(block_size),
        blocks_per_group,
        inodes_per_group,
        mtime,
        wtime,
        magic,
        state,
        rev_level,
        first_ino,
        inode_size,
        feature_compat: feat_compat,
        feature_incompat: feat_incompat,
        feature_ro_compat: feat_ro_compat,
        uuid,
        volume_name,
        last_mounted,
        desc_size,
        version,
        endianness,
        block_group_count,
    })
}

pub fn parse_block_group_descriptors(
    data: &[u8],
    offset: usize,
    sb: &ExtSuperblock,
) -> Result<Vec<BlockGroupDescriptor>> {
    let gdt_block = if sb.block_size == 1024 { 2 } else { 1 };
    let gdt_start = offset + (gdt_block as usize) * (sb.block_size as usize);
    let desc_size = sb.desc_size as usize;
    let is_64bit = sb.feature_incompat & EXT4_FEATURE_INCOMPAT_64BIT != 0;

    let mut descriptors = Vec::with_capacity(sb.block_group_count);

    for i in 0..sb.block_group_count {
        let entry_off = gdt_start + i * desc_size;
        if entry_off + 32 > data.len() {
            break;
        }

        let block_bitmap_lo = read_u32(data, entry_off, sb.endianness)?;
        let inode_bitmap_lo = read_u32(data, entry_off + 0x04, sb.endianness)?;
        let inode_table_lo = read_u32(data, entry_off + 0x08, sb.endianness)?;
        let free_blocks = read_u16(data, entry_off + 0x0C, sb.endianness)? as u32;
        let free_inodes = read_u16(data, entry_off + 0x0E, sb.endianness)? as u32;
        let used_dirs = read_u16(data, entry_off + 0x10, sb.endianness)? as u32;

        let (block_bitmap_hi, inode_bitmap_hi, inode_table_hi) =
            if is_64bit && desc_size >= 64 && entry_off + 64 <= data.len() {
                let bb_hi = read_u32(data, entry_off + 0x20, sb.endianness).unwrap_or(0);
                let ib_hi = read_u32(data, entry_off + 0x24, sb.endianness).unwrap_or(0);
                let it_hi = read_u32(data, entry_off + 0x28, sb.endianness).unwrap_or(0);
                (bb_hi as u64, ib_hi as u64, it_hi as u64)
            } else {
                (0, 0, 0)
            };

        let block_bitmap = (block_bitmap_hi << 32) | (block_bitmap_lo as u64);
        let inode_bitmap = (inode_bitmap_hi << 32) | (inode_bitmap_lo as u64);
        let inode_table = (inode_table_hi << 32) | (inode_table_lo as u64);

        descriptors.push(BlockGroupDescriptor {
            bg_index: i,
            block_bitmap,
            inode_bitmap,
            inode_table,
            free_blocks_count: free_blocks,
            free_inodes_count: free_inodes,
            used_dirs_count: used_dirs,
        });
    }

    Ok(descriptors)
}
