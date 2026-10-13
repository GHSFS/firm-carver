// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::error::{CarverError, Result};
use crate::image::compute_crc32;
use crate::jffs2::types::*;

#[inline]
pub fn read_u16(slice: &[u8], endian: Endianness) -> u16 {
    match endian {
        Endianness::Little => u16::from_le_bytes([slice[0], slice[1]]),
        Endianness::Big => u16::from_be_bytes([slice[0], slice[1]]),
    }
}

#[inline]
pub fn read_u32(slice: &[u8], endian: Endianness) -> u32 {
    match endian {
        Endianness::Little => u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]),
        Endianness::Big => u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]),
    }
}

/// Detects the endianness of a potential JFFS2 node stream.
pub fn detect_endianness(slice: &[u8]) -> Option<Endianness> {
    if slice.len() < 12 {
        return None;
    }
    // Check Little-Endian magic: [0x85, 0x19]
    if slice[0] == 0x85 && slice[1] == 0x19 {
        let hdr_crc = read_u32(&slice[8..12], Endianness::Little);
        if compute_crc32(&slice[0..8]) == hdr_crc {
            return Some(Endianness::Little);
        }
    }
    // Check Big-Endian magic: [0x19, 0x85]
    if slice[0] == 0x19 && slice[1] == 0x85 {
        let hdr_crc = read_u32(&slice[8..12], Endianness::Big);
        if compute_crc32(&slice[0..8]) == hdr_crc {
            return Some(Endianness::Big);
        }
    }
    None
}

/// Common header present in every JFFS2 on-flash node (12 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommonNodeHeader {
    pub magic: u16,
    pub nodetype: u16,
    pub totlen: u32,
    pub hdr_crc: u32,
}

impl CommonNodeHeader {
    pub fn parse(slice: &[u8], endian: Endianness) -> Option<Self> {
        if slice.len() < 12 {
            return None;
        }
        let magic = read_u16(&slice[0..2], endian);
        if magic != JFFS2_MAGIC_BITMASK {
            return None;
        }
        let nodetype = read_u16(&slice[2..4], endian);
        let totlen = read_u32(&slice[4..8], endian);
        let hdr_crc = read_u32(&slice[8..12], endian);

        if compute_crc32(&slice[0..8]) != hdr_crc {
            return None;
        }
        if totlen < 12 {
            return None;
        }

        Some(Self {
            magic,
            nodetype,
            totlen,
            hdr_crc,
        })
    }
}

/// Raw on-flash JFFS2 directory entry node (`struct jffs2_raw_dirent`).
#[derive(Debug, Clone)]
pub struct RawDirent {
    pub header: CommonNodeHeader,
    pub pino: u32,
    pub version: u32,
    pub ino: u32,
    pub mctime: u32,
    pub nsize: u8,
    pub file_type: u8,
    pub unused: u16,
    pub node_crc: u32,
    pub name_crc: u32,
    pub name: String,
}

impl RawDirent {
    pub fn parse(slice: &[u8], header: CommonNodeHeader, endian: Endianness) -> Result<Self> {
        if slice.len() < 40 {
            return Err(CarverError::Jffs2(
                "Truncated JFFS2 dirent header".to_string(),
            ));
        }
        let pino = read_u32(&slice[12..16], endian);
        let version = read_u32(&slice[16..20], endian);
        let ino = read_u32(&slice[20..24], endian);
        let mctime = read_u32(&slice[24..28], endian);
        let nsize = slice[28];
        let file_type = slice[29];
        let unused = read_u16(&slice[30..32], endian);
        let node_crc = read_u32(&slice[32..36], endian);
        let name_crc = read_u32(&slice[36..40], endian);

        // Verify node CRC across bytes 0..32
        let expected_node_crc = compute_crc32(&slice[0..32]);
        if node_crc != expected_node_crc {
            return Err(CarverError::Jffs2(format!(
                "JFFS2 dirent node CRC mismatch: expected 0x{:08X}, got 0x{:08X}",
                expected_node_crc, node_crc
            )));
        }

        let name_end = 40 + nsize as usize;
        if slice.len() < name_end {
            return Err(CarverError::Jffs2(
                "Truncated JFFS2 dirent name payload".to_string(),
            ));
        }

        let name_bytes = &slice[40..name_end];
        let expected_name_crc = compute_crc32(name_bytes);
        if name_crc != expected_name_crc {
            return Err(CarverError::Jffs2(format!(
                "JFFS2 dirent name CRC mismatch: expected 0x{:08X}, got 0x{:08X}",
                expected_name_crc, name_crc
            )));
        }

        let name = String::from_utf8_lossy(name_bytes).to_string();

        Ok(Self {
            header,
            pino,
            version,
            ino,
            mctime,
            nsize,
            file_type,
            unused,
            node_crc,
            name_crc,
            name,
        })
    }
}

/// Raw on-flash JFFS2 inode data node (`struct jffs2_raw_inode`).
#[derive(Debug, Clone)]
pub struct RawInode {
    pub header: CommonNodeHeader,
    pub ino: u32,
    pub version: u32,
    pub mode: u32,
    pub uid: u16,
    pub gid: u16,
    pub isize: u32,
    pub atime: u32,
    pub mtime: u32,
    pub ctime: u32,
    pub offset: u32,
    pub csize: u32,
    pub dsize: u32,
    pub compr: u8,
    pub usercompr: u8,
    pub flags: u16,
    pub data_crc: u32,
    pub node_crc: u32,
    pub payload: Vec<u8>,
}

impl RawInode {
    pub fn parse(slice: &[u8], header: CommonNodeHeader, endian: Endianness) -> Result<Self> {
        if slice.len() < 68 {
            return Err(CarverError::Jffs2(
                "Truncated JFFS2 inode header".to_string(),
            ));
        }
        let ino = read_u32(&slice[12..16], endian);
        let version = read_u32(&slice[16..20], endian);
        let mode = read_u32(&slice[20..24], endian);
        let uid = read_u16(&slice[24..26], endian);
        let gid = read_u16(&slice[26..28], endian);
        let isize = read_u32(&slice[28..32], endian);
        let atime = read_u32(&slice[32..36], endian);
        let mtime = read_u32(&slice[36..40], endian);
        let ctime = read_u32(&slice[40..44], endian);
        let offset = read_u32(&slice[44..48], endian);
        let csize = read_u32(&slice[48..52], endian);
        let dsize = read_u32(&slice[52..56], endian);
        let compr = slice[56];
        let usercompr = slice[57];
        let flags = read_u16(&slice[58..60], endian);
        let data_crc = read_u32(&slice[60..64], endian);
        let node_crc = read_u32(&slice[64..68], endian);

        // Verify node CRC across bytes 0..60 (all fields prior to data_crc and node_crc)
        let expected_node_crc = compute_crc32(&slice[0..60]);
        if node_crc != expected_node_crc {
            return Err(CarverError::Jffs2(format!(
                "JFFS2 inode node CRC mismatch: expected 0x{:08X}, got 0x{:08X}",
                expected_node_crc, node_crc
            )));
        }

        let payload_end = 68 + csize as usize;
        if slice.len() < payload_end {
            return Err(CarverError::Jffs2(
                "Truncated JFFS2 inode payload chunk".to_string(),
            ));
        }

        let payload_bytes = &slice[68..payload_end];
        if csize > 0 {
            let expected_data_crc = compute_crc32(payload_bytes);
            if data_crc != expected_data_crc {
                return Err(CarverError::Jffs2(format!(
                    "JFFS2 inode data CRC mismatch: expected 0x{:08X}, got 0x{:08X}",
                    expected_data_crc, data_crc
                )));
            }
        }

        Ok(Self {
            header,
            ino,
            version,
            mode,
            uid,
            gid,
            isize,
            atime,
            mtime,
            ctime,
            offset,
            csize,
            dsize,
            compr,
            usercompr,
            flags,
            data_crc,
            node_crc,
            payload: payload_bytes.to_vec(),
        })
    }
}

/// Representation of any parsed JFFS2 node.
#[derive(Debug, Clone)]
pub enum ParsedNode {
    Cleanmarker(CommonNodeHeader),
    Padding(CommonNodeHeader),
    Dirent(RawDirent),
    Inode(RawInode),
    Unknown(CommonNodeHeader),
}
