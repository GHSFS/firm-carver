// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::types::*;
use crate::image::compute_crc32;

pub fn detect_node_endianness(data: &[u8]) -> Option<Endianness> {
    if data.len() < 4 {
        return None;
    }
    let magic_le = u32::from_le_bytes(data[0..4].try_into().ok()?);
    let magic_be = u32::from_be_bytes(data[0..4].try_into().ok()?);

    if magic_le == UBIFS_NODE_MAGIC_LE {
        Some(Endianness::Little)
    } else if magic_be == UBIFS_NODE_MAGIC_LE || magic_le == UBIFS_NODE_MAGIC_BE {
        Some(Endianness::Big)
    } else {
        None
    }
}

pub fn parse_common_header(data: &[u8], endian: Endianness) -> Option<UbifsCommonHeader> {
    if data.len() < UBIFS_CH_SZ {
        return None;
    }
    let (magic, crc, sqnum, len) = match endian {
        Endianness::Little => {
            let magic = u32::from_le_bytes(data[0..4].try_into().ok()?);
            let crc = u32::from_le_bytes(data[4..8].try_into().ok()?);
            let sqnum = u64::from_le_bytes(data[8..16].try_into().ok()?);
            let len = u32::from_le_bytes(data[16..20].try_into().ok()?);
            (magic, crc, sqnum, len)
        }
        Endianness::Big => {
            let magic = u32::from_be_bytes(data[0..4].try_into().ok()?);
            let crc = u32::from_be_bytes(data[4..8].try_into().ok()?);
            let sqnum = u64::from_be_bytes(data[8..16].try_into().ok()?);
            let len = u32::from_be_bytes(data[16..20].try_into().ok()?);
            (magic, crc, sqnum, len)
        }
    };

    if magic != UBIFS_NODE_MAGIC_LE {
        return None;
    }
    if (len as usize) < UBIFS_CH_SZ || (len as usize) > data.len() {
        return None;
    }

    let node_type = UbifsNodeType::from(data[20]);
    let group_type = data[21];

    let calculated_crc = compute_crc32(&data[8..len as usize]);
    let crc_valid = calculated_crc == crc;

    Some(UbifsCommonHeader {
        magic,
        crc,
        sqnum,
        len,
        node_type,
        group_type,
        crc_valid,
    })
}

pub fn parse_sb_node(data: &[u8], endian: Endianness) -> Option<UbifsSuperblock> {
    let ch = parse_common_header(data, endian)?;
    if ch.node_type != UbifsNodeType::Sb || (ch.len as usize) < 120 {
        return None;
    }

    let p = &data[UBIFS_CH_SZ..];
    let key_hash = p[2];
    let key_fmt = p[3];

    let (flags, min_io_size, leb_size, leb_cnt, max_leb_cnt, max_bud_bytes) = match endian {
        Endianness::Little => (
            u32::from_le_bytes(p[4..8].try_into().ok()?),
            u32::from_le_bytes(p[8..12].try_into().ok()?),
            u32::from_le_bytes(p[12..16].try_into().ok()?),
            u32::from_le_bytes(p[16..20].try_into().ok()?),
            u32::from_le_bytes(p[20..24].try_into().ok()?),
            u64::from_le_bytes(p[24..32].try_into().ok()?),
        ),
        Endianness::Big => (
            u32::from_be_bytes(p[4..8].try_into().ok()?),
            u32::from_be_bytes(p[8..12].try_into().ok()?),
            u32::from_be_bytes(p[12..16].try_into().ok()?),
            u32::from_be_bytes(p[16..20].try_into().ok()?),
            u32::from_be_bytes(p[20..24].try_into().ok()?),
            u64::from_be_bytes(p[24..32].try_into().ok()?),
        ),
    };

    let (log_lebs, lpt_lebs, orph_lebs, jhead_cnt, fanout, lsave_cnt, fmt_version, default_compr) =
        match endian {
            Endianness::Little => (
                u32::from_le_bytes(p[44..48].try_into().ok()?),
                u32::from_le_bytes(p[48..52].try_into().ok()?),
                u32::from_le_bytes(p[52..56].try_into().ok()?),
                u32::from_le_bytes(p[56..60].try_into().ok()?),
                u32::from_le_bytes(p[60..64].try_into().ok()?),
                u32::from_le_bytes(p[64..68].try_into().ok()?),
                u32::from_le_bytes(p[68..72].try_into().ok()?),
                UbifsCompressionType::from(u16::from_le_bytes(p[72..74].try_into().ok()?)),
            ),
            Endianness::Big => (
                u32::from_be_bytes(p[44..48].try_into().ok()?),
                u32::from_be_bytes(p[48..52].try_into().ok()?),
                u32::from_be_bytes(p[52..56].try_into().ok()?),
                u32::from_be_bytes(p[56..60].try_into().ok()?),
                u32::from_be_bytes(p[60..64].try_into().ok()?),
                u32::from_be_bytes(p[64..68].try_into().ok()?),
                u32::from_be_bytes(p[68..72].try_into().ok()?),
                UbifsCompressionType::from(u16::from_be_bytes(p[72..74].try_into().ok()?)),
            ),
        };

    let (rp_size, time_gran) = match endian {
        Endianness::Little => (
            u64::from_le_bytes(p[76..84].try_into().ok()?),
            u32::from_le_bytes(p[84..88].try_into().ok()?),
        ),
        Endianness::Big => (
            u64::from_be_bytes(p[76..84].try_into().ok()?),
            u32::from_be_bytes(p[84..88].try_into().ok()?),
        ),
    };

    let raw_uuid = &p[88..104];
    let uuid = format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        raw_uuid[0], raw_uuid[1], raw_uuid[2], raw_uuid[3],
        raw_uuid[4], raw_uuid[5],
        raw_uuid[6], raw_uuid[7],
        raw_uuid[8], raw_uuid[9],
        raw_uuid[10], raw_uuid[11], raw_uuid[12], raw_uuid[13], raw_uuid[14], raw_uuid[15]
    );

    let ro_compat_version = match endian {
        Endianness::Little => u32::from_le_bytes(p[104..108].try_into().ok()?),
        Endianness::Big => u32::from_be_bytes(p[104..108].try_into().ok()?),
    };

    Some(UbifsSuperblock {
        key_hash,
        key_fmt,
        flags,
        min_io_size,
        leb_size,
        leb_cnt,
        max_leb_cnt,
        max_bud_bytes,
        log_lebs,
        lpt_lebs,
        orph_lebs,
        jhead_cnt,
        fanout,
        lsave_cnt,
        fmt_version,
        default_compr,
        rp_size,
        time_gran,
        uuid,
        ro_compat_version,
    })
}

pub fn parse_mst_node(data: &[u8], endian: Endianness) -> Option<UbifsMasterNode> {
    let ch = parse_common_header(data, endian)?;
    if ch.node_type != UbifsNodeType::Mst || (ch.len as usize) < 140 {
        return None;
    }

    let p = &data[UBIFS_CH_SZ..];
    let (
        highest_inum,
        cmt_no,
        flags,
        log_lnum,
        root_lnum,
        root_offs,
        root_len,
        gc_lnum,
        ihead_lnum,
        ihead_offs,
    ) = match endian {
        Endianness::Little => (
            u64::from_le_bytes(p[0..8].try_into().ok()?),
            u64::from_le_bytes(p[8..16].try_into().ok()?),
            u32::from_le_bytes(p[16..20].try_into().ok()?),
            u32::from_le_bytes(p[20..24].try_into().ok()?),
            u32::from_le_bytes(p[24..28].try_into().ok()?),
            u32::from_le_bytes(p[28..32].try_into().ok()?),
            u32::from_le_bytes(p[32..36].try_into().ok()?),
            u32::from_le_bytes(p[36..40].try_into().ok()?),
            u32::from_le_bytes(p[40..44].try_into().ok()?),
            u32::from_le_bytes(p[44..48].try_into().ok()?),
        ),
        Endianness::Big => (
            u64::from_be_bytes(p[0..8].try_into().ok()?),
            u64::from_be_bytes(p[8..16].try_into().ok()?),
            u32::from_be_bytes(p[16..20].try_into().ok()?),
            u32::from_be_bytes(p[20..24].try_into().ok()?),
            u32::from_be_bytes(p[24..28].try_into().ok()?),
            u32::from_be_bytes(p[28..32].try_into().ok()?),
            u32::from_be_bytes(p[32..36].try_into().ok()?),
            u32::from_be_bytes(p[36..40].try_into().ok()?),
            u32::from_be_bytes(p[40..44].try_into().ok()?),
            u32::from_be_bytes(p[44..48].try_into().ok()?),
        ),
    };

    let (index_size, total_free, total_dirty, total_used, total_dead, total_dark) = match endian {
        Endianness::Little => (
            u64::from_le_bytes(p[48..56].try_into().ok()?),
            u64::from_le_bytes(p[56..64].try_into().ok()?),
            u64::from_le_bytes(p[64..72].try_into().ok()?),
            u64::from_le_bytes(p[72..80].try_into().ok()?),
            u64::from_le_bytes(p[80..88].try_into().ok()?),
            u64::from_le_bytes(p[88..96].try_into().ok()?),
        ),
        Endianness::Big => (
            u64::from_be_bytes(p[48..56].try_into().ok()?),
            u64::from_be_bytes(p[56..64].try_into().ok()?),
            u64::from_be_bytes(p[64..72].try_into().ok()?),
            u64::from_be_bytes(p[72..80].try_into().ok()?),
            u64::from_be_bytes(p[80..88].try_into().ok()?),
            u64::from_be_bytes(p[88..96].try_into().ok()?),
        ),
    };

    let leb_size = match endian {
        Endianness::Little => u32::from_le_bytes(p[148..152].try_into().ok()?),
        Endianness::Big => u32::from_be_bytes(p[148..152].try_into().ok()?),
    };

    Some(UbifsMasterNode {
        highest_inum,
        cmt_no,
        flags,
        log_lnum,
        root_lnum,
        root_offs,
        root_len,
        gc_lnum,
        ihead_lnum,
        ihead_offs,
        index_size,
        total_free,
        total_dirty,
        total_used,
        total_dead,
        total_dark,
        leb_size,
    })
}

pub fn parse_ino_node(data: &[u8], endian: Endianness) -> Option<UbifsInode> {
    let ch = parse_common_header(data, endian)?;
    if ch.node_type != UbifsNodeType::Ino || (ch.len as usize) < 140 {
        return None;
    }

    let p = &data[UBIFS_CH_SZ..];
    let inum = match endian {
        Endianness::Little => u32::from_le_bytes(p[0..4].try_into().ok()?) as u64,
        Endianness::Big => u32::from_be_bytes(p[0..4].try_into().ok()?) as u64,
    };

    let ip = &p[UBIFS_MAX_KEY_LEN..];
    let (creat_sqnum, size, atime_sec, ctime_sec, mtime_sec) = match endian {
        Endianness::Little => (
            u64::from_le_bytes(ip[0..8].try_into().ok()?),
            u64::from_le_bytes(ip[8..16].try_into().ok()?),
            u64::from_le_bytes(ip[16..24].try_into().ok()?),
            u64::from_le_bytes(ip[24..32].try_into().ok()?),
            u64::from_le_bytes(ip[32..40].try_into().ok()?),
        ),
        Endianness::Big => (
            u64::from_be_bytes(ip[0..8].try_into().ok()?),
            u64::from_be_bytes(ip[8..16].try_into().ok()?),
            u64::from_be_bytes(ip[16..24].try_into().ok()?),
            u64::from_be_bytes(ip[24..32].try_into().ok()?),
            u64::from_be_bytes(ip[32..40].try_into().ok()?),
        ),
    };

    let (nlink, uid, gid, mode, flags, data_len) = match endian {
        Endianness::Little => (
            u32::from_le_bytes(ip[52..56].try_into().ok()?),
            u32::from_le_bytes(ip[56..60].try_into().ok()?),
            u32::from_le_bytes(ip[60..64].try_into().ok()?),
            u32::from_le_bytes(ip[64..68].try_into().ok()?),
            u32::from_le_bytes(ip[68..72].try_into().ok()?),
            u32::from_le_bytes(ip[72..76].try_into().ok()?),
        ),
        Endianness::Big => (
            u32::from_be_bytes(ip[52..56].try_into().ok()?),
            u32::from_be_bytes(ip[56..60].try_into().ok()?),
            u32::from_be_bytes(ip[60..64].try_into().ok()?),
            u32::from_be_bytes(ip[64..68].try_into().ok()?),
            u32::from_be_bytes(ip[68..72].try_into().ok()?),
            u32::from_be_bytes(ip[72..76].try_into().ok()?),
        ),
    };

    let compr_type = match endian {
        Endianness::Little => {
            UbifsCompressionType::from(u16::from_le_bytes(ip[92..94].try_into().ok()?))
        }
        Endianness::Big => {
            UbifsCompressionType::from(u16::from_be_bytes(ip[92..94].try_into().ok()?))
        }
    };

    let symlink_target = if data_len > 0 && ip.len() >= 116 + data_len as usize {
        let sym_slice = &ip[116..116 + data_len as usize];
        let null_pos = sym_slice
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(sym_slice.len());
        Some(String::from_utf8_lossy(&sym_slice[..null_pos]).to_string())
    } else {
        None
    };

    Some(UbifsInode {
        inum,
        creat_sqnum,
        size,
        atime_sec,
        ctime_sec,
        mtime_sec,
        nlink,
        uid,
        gid,
        mode,
        flags,
        data_len,
        compr_type,
        symlink_target,
    })
}

pub fn parse_dent_node(data: &[u8], endian: Endianness) -> Option<UbifsDent> {
    let ch = parse_common_header(data, endian)?;
    if ch.node_type != UbifsNodeType::Dent || (ch.len as usize) < 56 {
        return None;
    }

    let p = &data[UBIFS_CH_SZ..];
    let parent_inum = match endian {
        Endianness::Little => u32::from_le_bytes(p[0..4].try_into().ok()?) as u64,
        Endianness::Big => u32::from_be_bytes(p[0..4].try_into().ok()?) as u64,
    };

    let dp = &p[UBIFS_MAX_KEY_LEN..];
    let inum = match endian {
        Endianness::Little => u64::from_le_bytes(dp[0..8].try_into().ok()?),
        Endianness::Big => u64::from_be_bytes(dp[0..8].try_into().ok()?),
    };

    let target_type = UbifsFileType::from(dp[9]);
    let nlen = match endian {
        Endianness::Little => u16::from_le_bytes(dp[10..12].try_into().ok()?) as usize,
        Endianness::Big => u16::from_be_bytes(dp[10..12].try_into().ok()?) as usize,
    };

    if dp.len() < 16 + nlen {
        return None;
    }
    let name_bytes = &dp[16..16 + nlen];
    let null_pos = name_bytes.iter().position(|&b| b == 0).unwrap_or(nlen);
    let name = String::from_utf8_lossy(&name_bytes[..null_pos]).to_string();

    Some(UbifsDent {
        inum,
        parent_inum,
        target_type,
        name,
    })
}
