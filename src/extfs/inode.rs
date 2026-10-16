// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::superblock::{read_u16, read_u32};
use super::types::*;
use crate::error::{CarverError, Result};

pub const MAX_EXT_FILE_READ_BYTES: usize = 64 * 1024 * 1024; // 64 MiB safety ceiling

pub fn parse_inode(
    data: &[u8],
    base_offset: usize,
    sb: &ExtSuperblock,
    groups: &[BlockGroupDescriptor],
    ino: u32,
) -> Result<ExtInode> {
    if ino == 0 || ino > sb.inodes_count {
        return Err(CarverError::ExtFs(format!(
            "Invalid inode number {} (total inodes: {})",
            ino, sb.inodes_count
        )));
    }

    let group_idx = ((ino - 1) / sb.inodes_per_group) as usize;
    let index_in_group = ((ino - 1) % sb.inodes_per_group) as usize;

    let bg = groups.get(group_idx).ok_or_else(|| {
        CarverError::ExtFs(format!(
            "Block group index {} out of range for inode {}",
            group_idx, ino
        ))
    })?;

    let itable_byte_offset = base_offset
        + (bg.inode_table as usize) * (sb.block_size as usize)
        + index_in_group * (sb.inode_size as usize);

    if itable_byte_offset + 128 > data.len() {
        return Err(CarverError::ExtFs(format!(
            "Inode table offset 0x{:X} exceeds image length {}",
            itable_byte_offset,
            data.len()
        )));
    }

    let mode = read_u16(data, itable_byte_offset, sb.endianness)?;
    let uid_lo = read_u16(data, itable_byte_offset + 0x02, sb.endianness)? as u32;
    let size_lo = read_u32(data, itable_byte_offset + 0x04, sb.endianness)?;
    let atime = read_u32(data, itable_byte_offset + 0x08, sb.endianness)?;
    let ctime = read_u32(data, itable_byte_offset + 0x0C, sb.endianness)?;
    let mtime = read_u32(data, itable_byte_offset + 0x10, sb.endianness)?;
    let dtime = read_u32(data, itable_byte_offset + 0x14, sb.endianness)?;
    let gid_lo = read_u16(data, itable_byte_offset + 0x18, sb.endianness)? as u32;
    let links_count = read_u16(data, itable_byte_offset + 0x1A, sb.endianness)?;
    let blocks_lo = read_u32(data, itable_byte_offset + 0x1C, sb.endianness)? as u64;
    let flags = read_u32(data, itable_byte_offset + 0x20, sb.endianness)?;

    let (uid_hi, gid_hi, size_hi) =
        if sb.inode_size >= 128 && itable_byte_offset + 128 <= data.len() {
            let osd2_uid_hi =
                read_u16(data, itable_byte_offset + 0x78, sb.endianness).unwrap_or(0) as u32;
            let osd2_gid_hi =
                read_u16(data, itable_byte_offset + 0x7A, sb.endianness).unwrap_or(0) as u32;
            let s_hi = if (mode & 0xF000) == 0x8000 {
                read_u32(data, itable_byte_offset + 0x6C, sb.endianness).unwrap_or(0) as u64
            } else {
                0
            };
            (osd2_uid_hi, osd2_gid_hi, s_hi)
        } else {
            (0, 0, 0)
        };

    let uid = (uid_hi << 16) | uid_lo;
    let gid = (gid_hi << 16) | gid_lo;
    let size = (size_hi << 32) | (size_lo as u64);

    let file_type = ExtFileType::from_mode(mode);
    let is_extent = (flags & EXT4_EXTENTS_FL) != 0;

    let mut direct_blocks = [0u32; 12];
    let mut single_indirect = 0u32;
    let mut double_indirect = 0u32;
    let mut triple_indirect = 0u32;
    let mut symlink_target = None;

    let iblock_off = itable_byte_offset + 0x28;

    if file_type == ExtFileType::Symlink && size <= 60 && blocks_lo == 0 {
        // Fast symlink: target is stored directly inside i_block
        let target_len = (size as usize).min(60);
        if iblock_off + target_len <= data.len() {
            let target_bytes = &data[iblock_off..iblock_off + target_len];
            symlink_target = Some(
                String::from_utf8_lossy(target_bytes)
                    .trim_end_matches('\0')
                    .to_string(),
            );
        }
    } else if !is_extent {
        for (idx, blk) in direct_blocks.iter_mut().enumerate() {
            *blk = read_u32(data, iblock_off + idx * 4, sb.endianness)?;
        }
        single_indirect = read_u32(data, iblock_off + 12 * 4, sb.endianness)?;
        double_indirect = read_u32(data, iblock_off + 13 * 4, sb.endianness)?;
        triple_indirect = read_u32(data, iblock_off + 14 * 4, sb.endianness)?;
    }

    Ok(ExtInode {
        ino,
        mode,
        uid,
        gid,
        size,
        atime,
        ctime,
        mtime,
        dtime,
        links_count,
        blocks_count: blocks_lo,
        flags,
        direct_blocks,
        single_indirect,
        double_indirect,
        triple_indirect,
        is_extent,
        file_type,
        symlink_target,
    })
}

/// Collects physical block numbers occupied by an inode (supporting Ext2/3 direct/indirect and Ext4 extents).
pub fn resolve_inode_blocks(
    data: &[u8],
    base_offset: usize,
    sb: &ExtSuperblock,
    inode: &ExtInode,
    itable_byte_offset: usize,
) -> Result<Vec<u64>> {
    let mut blocks = Vec::new();
    let block_size = sb.block_size as usize;

    if inode.is_extent {
        // Ext4 Extent Tree resolution
        let iblock_off = itable_byte_offset + 0x28;
        if iblock_off + 12 <= data.len() {
            parse_extent_tree_level(data, base_offset, sb, iblock_off, 0, &mut blocks)?;
        }
    } else {
        // Traditional Ext2/Ext3 direct and indirect blocks
        for &blk in &inode.direct_blocks {
            if blk != 0 {
                blocks.push(blk as u64);
            }
        }
        if inode.single_indirect != 0 {
            let ind_off = base_offset + (inode.single_indirect as usize) * block_size;
            if ind_off + block_size <= data.len() {
                let count = block_size / 4;
                for i in 0..count {
                    let b = read_u32(data, ind_off + i * 4, sb.endianness)?;
                    if b != 0 {
                        blocks.push(b as u64);
                    }
                }
            }
        }
        if inode.double_indirect != 0 {
            let dind_off = base_offset + (inode.double_indirect as usize) * block_size;
            if dind_off + block_size <= data.len() {
                let count = block_size / 4;
                for i in 0..count {
                    let s = read_u32(data, dind_off + i * 4, sb.endianness)?;
                    if s != 0 {
                        let ind_off = base_offset + (s as usize) * block_size;
                        if ind_off + block_size <= data.len() {
                            for j in 0..count {
                                let b = read_u32(data, ind_off + j * 4, sb.endianness)?;
                                if b != 0 {
                                    blocks.push(b as u64);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(blocks)
}

fn parse_extent_tree_level(
    data: &[u8],
    base_offset: usize,
    sb: &ExtSuperblock,
    header_offset: usize,
    depth_guard: usize,
    out_blocks: &mut Vec<u64>,
) -> Result<()> {
    if depth_guard > 5 || header_offset + 12 > data.len() {
        return Ok(());
    }

    let magic = read_u16(data, header_offset, sb.endianness)?;
    if magic != EXT4_EXTENT_HEADER_MAGIC {
        return Ok(());
    }

    let entries = read_u16(data, header_offset + 0x02, sb.endianness)? as usize;
    let depth = read_u16(data, header_offset + 0x06, sb.endianness)? as usize;

    let max_entries = (sb.block_size as usize - 12) / 12;
    let entries = entries.min(max_entries);

    if depth == 0 {
        // Leaf nodes: extent structures
        for i in 0..entries {
            let ext_off = header_offset + 12 + i * 12;
            if ext_off + 12 > data.len() {
                break;
            }
            let len = read_u16(data, ext_off + 0x04, sb.endianness)? as u64;
            // Uninitialized preallocated extents have len > 32768 (len - 32768)
            let actual_len = if len > 32768 { len - 32768 } else { len };
            let start_hi = read_u16(data, ext_off + 0x06, sb.endianness)? as u64;
            let start_lo = read_u32(data, ext_off + 0x08, sb.endianness)? as u64;
            let start_pblk = (start_hi << 32) | start_lo;

            for b in 0..actual_len {
                out_blocks.push(start_pblk + b);
            }
        }
    } else {
        // Index nodes: recurse to child blocks
        for i in 0..entries {
            let idx_off = header_offset + 12 + i * 12;
            if idx_off + 12 > data.len() {
                break;
            }
            let leaf_hi = read_u16(data, idx_off + 0x06, sb.endianness)? as u64;
            let leaf_lo = read_u32(data, idx_off + 0x08, sb.endianness)? as u64;
            let child_pblk = (leaf_hi << 32) | leaf_lo;

            let child_offset = base_offset + (child_pblk as usize) * (sb.block_size as usize);
            parse_extent_tree_level(
                data,
                base_offset,
                sb,
                child_offset,
                depth_guard + 1,
                out_blocks,
            )?;
        }
    }

    Ok(())
}

/// Reads the payload bytes of an inode up to its logical size (with safety ceiling).
pub fn read_inode_content(
    data: &[u8],
    base_offset: usize,
    sb: &ExtSuperblock,
    groups: &[BlockGroupDescriptor],
    inode: &ExtInode,
) -> Result<Vec<u8>> {
    if inode.file_type == ExtFileType::Symlink {
        if let Some(target) = &inode.symlink_target {
            return Ok(target.as_bytes().to_vec());
        }
    }

    if inode.size == 0 {
        return Ok(Vec::new());
    }

    let read_size = (inode.size as usize).min(MAX_EXT_FILE_READ_BYTES);
    let group_idx = ((inode.ino - 1) / sb.inodes_per_group) as usize;
    let index_in_group = ((inode.ino - 1) % sb.inodes_per_group) as usize;

    let bg = groups
        .get(group_idx)
        .ok_or_else(|| CarverError::ExtFs(format!("Group index {} out of range", group_idx)))?;

    let itable_byte_offset = base_offset
        + (bg.inode_table as usize) * (sb.block_size as usize)
        + index_in_group * (sb.inode_size as usize);

    let blocks = resolve_inode_blocks(data, base_offset, sb, inode, itable_byte_offset)?;
    let block_size = sb.block_size as usize;

    let mut content = Vec::with_capacity(read_size);
    let mut remaining = read_size;

    for &blk in &blocks {
        if remaining == 0 {
            break;
        }
        let blk_off = base_offset + (blk as usize) * block_size;
        let to_read = remaining.min(block_size);
        if blk_off + to_read <= data.len() {
            content.extend_from_slice(&data[blk_off..blk_off + to_read]);
        } else if blk_off < data.len() {
            let available = data.len() - blk_off;
            let take = available.min(to_read);
            content.extend_from_slice(&data[blk_off..blk_off + take]);
            content.resize(content.len() + (to_read - take), 0);
        } else {
            content.resize(content.len() + to_read, 0);
        }
        remaining -= to_read;
    }

    Ok(content)
}

pub fn format_mode_string(mode: u16, file_type: ExtFileType) -> String {
    let type_char = match file_type {
        ExtFileType::Directory => 'd',
        ExtFileType::RegularFile => '-',
        ExtFileType::Symlink => 'l',
        ExtFileType::CharDevice => 'c',
        ExtFileType::BlockDevice => 'b',
        ExtFileType::Fifo => 'p',
        ExtFileType::Socket => 's',
        ExtFileType::Unknown => '?',
    };

    let r1 = if mode & 0o400 != 0 { 'r' } else { '-' };
    let w1 = if mode & 0o200 != 0 { 'w' } else { '-' };
    let x1 = match (mode & 0o100 != 0, mode & 0o4000 != 0) {
        (true, true) => 's',
        (false, true) => 'S',
        (true, false) => 'x',
        (false, false) => '-',
    };

    let r2 = if mode & 0o040 != 0 { 'r' } else { '-' };
    let w2 = if mode & 0o020 != 0 { 'w' } else { '-' };
    let x2 = match (mode & 0o010 != 0, mode & 0o2000 != 0) {
        (true, true) => 's',
        (false, true) => 'S',
        (true, false) => 'x',
        (false, false) => '-',
    };

    let r3 = if mode & 0o004 != 0 { 'r' } else { '-' };
    let w3 = if mode & 0o002 != 0 { 'w' } else { '-' };
    let x3 = match (mode & 0o001 != 0, mode & 0o1000 != 0) {
        (true, true) => 't',
        (false, true) => 'T',
        (true, false) => 'x',
        (false, false) => '-',
    };

    format!(
        "{}{}{}{}{}{}{}{}{}{}",
        type_char, r1, w1, x1, r2, w2, x2, r3, w3, x3
    )
}
