// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::types::{CramFsInfo, CramFsInode, CramFsSuperblock, Endianness, CRAMFS_MAGIC};
use crate::error::{CarverError, Result};

pub const CRAMFS_SUPERBLOCK_MIN_LEN: usize = 76;

pub fn detect_endianness(data: &[u8]) -> Option<Endianness> {
    if data.len() < 4 {
        return None;
    }
    let magic_le = u32::from_le_bytes(data[0..4].try_into().ok()?);
    let magic_be = u32::from_be_bytes(data[0..4].try_into().ok()?);

    if magic_le == CRAMFS_MAGIC {
        Some(Endianness::Little)
    } else if magic_be == CRAMFS_MAGIC {
        Some(Endianness::Big)
    } else {
        None
    }
}

pub fn unpack_inode(slice: &[u8], endian: Endianness) -> Result<CramFsInode> {
    if slice.len() < 12 {
        return Err(CarverError::CramFs(
            "Inode slice too short (< 12 bytes)".to_string(),
        ));
    }

    match endian {
        Endianness::Little => {
            let w0 = u32::from_le_bytes(slice[0..4].try_into().unwrap());
            let w1 = u32::from_le_bytes(slice[4..8].try_into().unwrap());
            let w2 = u32::from_le_bytes(slice[8..12].try_into().unwrap());

            let mode = (w0 & 0xFFFF) as u16;
            let uid = ((w0 >> 16) & 0xFFFF) as u16;
            let size = w1 & 0x00FF_FFFF;
            let gid = ((w1 >> 24) & 0xFF) as u8;
            let namelen = (w2 & 0x3F) as u8;
            let offset = w2 >> 6;

            Ok(CramFsInode {
                mode,
                uid,
                size,
                gid,
                namelen,
                offset,
            })
        }
        Endianness::Big => {
            let w0 = u32::from_be_bytes(slice[0..4].try_into().unwrap());
            let w1 = u32::from_be_bytes(slice[4..8].try_into().unwrap());
            let w2 = u32::from_be_bytes(slice[8..12].try_into().unwrap());

            let mode = ((w0 >> 16) & 0xFFFF) as u16;
            let uid = (w0 & 0xFFFF) as u16;
            let size = (w1 >> 8) & 0x00FF_FFFF;
            let gid = (w1 & 0xFF) as u8;
            let namelen = ((w2 >> 26) & 0x3F) as u8;
            let offset = w2 & 0x03FF_FFFF;

            Ok(CramFsInode {
                mode,
                uid,
                size,
                gid,
                namelen,
                offset,
            })
        }
    }
}

pub fn pack_inode(inode: &CramFsInode, endian: Endianness) -> [u8; 12] {
    let mut buf = [0u8; 12];
    match endian {
        Endianness::Little => {
            let w0 = (inode.mode as u32) | ((inode.uid as u32) << 16);
            let w1 = (inode.size & 0x00FF_FFFF) | ((inode.gid as u32) << 24);
            let w2 = ((inode.namelen as u32) & 0x3F) | (inode.offset << 6);
            buf[0..4].copy_from_slice(&w0.to_le_bytes());
            buf[4..8].copy_from_slice(&w1.to_le_bytes());
            buf[8..12].copy_from_slice(&w2.to_le_bytes());
        }
        Endianness::Big => {
            let w0 = ((inode.mode as u32) << 16) | (inode.uid as u32);
            let w1 = ((inode.size & 0x00FF_FFFF) << 8) | (inode.gid as u32);
            let w2 = (((inode.namelen as u32) & 0x3F) << 26) | (inode.offset & 0x03FF_FFFF);
            buf[0..4].copy_from_slice(&w0.to_be_bytes());
            buf[4..8].copy_from_slice(&w1.to_be_bytes());
            buf[8..12].copy_from_slice(&w2.to_be_bytes());
        }
    }
    buf
}

pub fn parse_superblock(data: &[u8]) -> Result<CramFsSuperblock> {
    if data.len() < CRAMFS_SUPERBLOCK_MIN_LEN {
        return Err(CarverError::CramFs(format!(
            "Data too small for CramFS superblock: {} bytes (required {})",
            data.len(),
            CRAMFS_SUPERBLOCK_MIN_LEN
        )));
    }

    let endianness = detect_endianness(data).ok_or_else(|| {
        CarverError::InvalidImage(format!(
            "Invalid CramFS magic: 0x{:02X}{:02X}{:02X}{:02X}",
            data[0], data[1], data[2], data[3]
        ))
    })?;

    let (magic, size, flags, future, crc, edition, blocks, files) = match endianness {
        Endianness::Little => (
            u32::from_le_bytes(data[0..4].try_into().unwrap()),
            u32::from_le_bytes(data[4..8].try_into().unwrap()),
            u32::from_le_bytes(data[8..12].try_into().unwrap()),
            u32::from_le_bytes(data[12..16].try_into().unwrap()),
            u32::from_le_bytes(data[32..36].try_into().unwrap()),
            u32::from_le_bytes(data[36..40].try_into().unwrap()),
            u32::from_le_bytes(data[40..44].try_into().unwrap()),
            u32::from_le_bytes(data[44..48].try_into().unwrap()),
        ),
        Endianness::Big => (
            u32::from_be_bytes(data[0..4].try_into().unwrap()),
            u32::from_be_bytes(data[4..8].try_into().unwrap()),
            u32::from_be_bytes(data[8..12].try_into().unwrap()),
            u32::from_be_bytes(data[12..16].try_into().unwrap()),
            u32::from_be_bytes(data[32..36].try_into().unwrap()),
            u32::from_be_bytes(data[36..40].try_into().unwrap()),
            u32::from_be_bytes(data[40..44].try_into().unwrap()),
            u32::from_be_bytes(data[44..48].try_into().unwrap()),
        ),
    };

    let sig_bytes = &data[16..32];
    let signature =
        String::from_utf8_lossy(sig_bytes.split(|&b| b == 0).next().unwrap_or(sig_bytes))
            .to_string();

    let name_bytes = &data[48..64];
    let name = String::from_utf8_lossy(name_bytes.split(|&b| b == 0).next().unwrap_or(name_bytes))
        .to_string();

    let root = unpack_inode(&data[64..76], endianness)?;

    Ok(CramFsSuperblock {
        magic,
        size,
        flags,
        future,
        signature,
        fsid: CramFsInfo {
            crc,
            edition,
            blocks,
            files,
        },
        name,
        root,
        endianness,
    })
}
