// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::image::compute_crc32;
use crate::jffs2::decompress::{compress_rtime, compress_zlib};
use crate::jffs2::types::*;

/// Serializes a common 12-byte JFFS2 node header with valid header CRC.
pub fn build_node_header(nodetype: u16, totlen: u32, endian: Endianness) -> [u8; 12] {
    let mut buf = [0u8; 12];
    match endian {
        Endianness::Little => {
            buf[0..2].copy_from_slice(&JFFS2_MAGIC_BITMASK.to_le_bytes());
            buf[2..4].copy_from_slice(&nodetype.to_le_bytes());
            buf[4..8].copy_from_slice(&totlen.to_le_bytes());
        }
        Endianness::Big => {
            buf[0..2].copy_from_slice(&JFFS2_MAGIC_BITMASK.to_be_bytes());
            buf[2..4].copy_from_slice(&nodetype.to_be_bytes());
            buf[4..8].copy_from_slice(&totlen.to_be_bytes());
        }
    }
    let hdr_crc = compute_crc32(&buf[0..8]);
    match endian {
        Endianness::Little => buf[8..12].copy_from_slice(&hdr_crc.to_le_bytes()),
        Endianness::Big => buf[8..12].copy_from_slice(&hdr_crc.to_be_bytes()),
    }
    buf
}

/// Serializes a standard 12-byte cleanmarker node.
pub fn build_cleanmarker(endian: Endianness) -> Vec<u8> {
    build_node_header(JFFS2_NODETYPE_CLEANMARKER, 12, endian).to_vec()
}

/// Serializes a JFFS2 directory entry node (`jffs2_raw_dirent`).
pub fn build_raw_dirent(
    pino: u32,
    version: u32,
    ino: u32,
    mctime: u32,
    file_type: u8,
    name: &str,
    endian: Endianness,
) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    let nsize = name_bytes.len() as u8;
    let totlen = 40 + nsize as u32;

    let mut buf = Vec::with_capacity(totlen as usize);
    let hdr = build_node_header(JFFS2_NODETYPE_DIRENT, totlen, endian);
    buf.extend_from_slice(&hdr);

    // Fields 12..32: pino, version, ino, mctime, nsize, type, unused
    match endian {
        Endianness::Little => {
            buf.extend_from_slice(&pino.to_le_bytes());
            buf.extend_from_slice(&version.to_le_bytes());
            buf.extend_from_slice(&ino.to_le_bytes());
            buf.extend_from_slice(&mctime.to_le_bytes());
        }
        Endianness::Big => {
            buf.extend_from_slice(&pino.to_be_bytes());
            buf.extend_from_slice(&version.to_be_bytes());
            buf.extend_from_slice(&ino.to_be_bytes());
            buf.extend_from_slice(&mctime.to_be_bytes());
        }
    }
    buf.push(nsize);
    buf.push(file_type);
    buf.extend_from_slice(&[0u8, 0u8]); // unused

    // node_crc across bytes 0..32
    let node_crc = compute_crc32(&buf[0..32]);
    let name_crc = compute_crc32(name_bytes);

    match endian {
        Endianness::Little => {
            buf.extend_from_slice(&node_crc.to_le_bytes());
            buf.extend_from_slice(&name_crc.to_le_bytes());
        }
        Endianness::Big => {
            buf.extend_from_slice(&node_crc.to_be_bytes());
            buf.extend_from_slice(&name_crc.to_be_bytes());
        }
    }
    buf.extend_from_slice(name_bytes);

    // Pad to 4-byte boundary
    while buf.len() % 4 != 0 {
        buf.push(0xFF);
    }
    buf
}

/// Serializes a JFFS2 raw inode data node (`jffs2_raw_inode`).
#[allow(clippy::too_many_arguments)]
pub fn build_raw_inode(
    ino: u32,
    version: u32,
    mode: u32,
    uid: u16,
    gid: u16,
    isize: u32,
    mtime: u32,
    offset: u32,
    dsize: u32,
    compr: u8,
    payload: &[u8],
    endian: Endianness,
) -> Vec<u8> {
    let csize = payload.len() as u32;
    let totlen = 68 + csize;

    let mut buf = Vec::with_capacity(totlen as usize);
    let hdr = build_node_header(JFFS2_NODETYPE_INODE, totlen, endian);
    buf.extend_from_slice(&hdr);

    // Fields 12..60: ino, version, mode, uid, gid, isize, atime, mtime, ctime, offset, csize, dsize, compr, usercompr, flags
    match endian {
        Endianness::Little => {
            buf.extend_from_slice(&ino.to_le_bytes());
            buf.extend_from_slice(&version.to_le_bytes());
            buf.extend_from_slice(&mode.to_le_bytes());
            buf.extend_from_slice(&uid.to_le_bytes());
            buf.extend_from_slice(&gid.to_le_bytes());
            buf.extend_from_slice(&isize.to_le_bytes());
            buf.extend_from_slice(&mtime.to_le_bytes()); // atime
            buf.extend_from_slice(&mtime.to_le_bytes()); // mtime
            buf.extend_from_slice(&mtime.to_le_bytes()); // ctime
            buf.extend_from_slice(&offset.to_le_bytes());
            buf.extend_from_slice(&csize.to_le_bytes());
            buf.extend_from_slice(&dsize.to_le_bytes());
        }
        Endianness::Big => {
            buf.extend_from_slice(&ino.to_be_bytes());
            buf.extend_from_slice(&version.to_be_bytes());
            buf.extend_from_slice(&mode.to_be_bytes());
            buf.extend_from_slice(&uid.to_be_bytes());
            buf.extend_from_slice(&gid.to_be_bytes());
            buf.extend_from_slice(&isize.to_be_bytes());
            buf.extend_from_slice(&mtime.to_be_bytes());
            buf.extend_from_slice(&mtime.to_be_bytes());
            buf.extend_from_slice(&mtime.to_be_bytes());
            buf.extend_from_slice(&offset.to_be_bytes());
            buf.extend_from_slice(&csize.to_be_bytes());
            buf.extend_from_slice(&dsize.to_be_bytes());
        }
    }
    buf.push(compr);
    buf.push(0); // usercompr
    buf.extend_from_slice(&[0u8, 0u8]); // flags

    let data_crc = if csize > 0 { compute_crc32(payload) } else { 0 };
    let node_crc = compute_crc32(&buf[0..60]);

    match endian {
        Endianness::Little => {
            buf.extend_from_slice(&data_crc.to_le_bytes());
            buf.extend_from_slice(&node_crc.to_le_bytes());
        }
        Endianness::Big => {
            buf.extend_from_slice(&data_crc.to_be_bytes());
            buf.extend_from_slice(&node_crc.to_be_bytes());
        }
    }
    buf.extend_from_slice(payload);

    // Pad to 4-byte boundary
    while buf.len() % 4 != 0 {
        buf.push(0xFF);
    }
    buf
}

/// Builds a deterministic, valid synthetic JFFS2 flash filesystem image.
pub fn build_synthetic_jffs2(big_endian: bool) -> Vec<u8> {
    let endian = if big_endian {
        Endianness::Big
    } else {
        Endianness::Little
    };
    let mut image = Vec::new();
    let now = 1_700_000_000u32;

    // 1. Initial Eraseblock cleanmarker
    image.extend_from_slice(&build_cleanmarker(endian));

    // 2. Root directory inode (ino 1)
    image.extend_from_slice(&build_raw_inode(
        1,
        1,
        0o040755,
        0,
        0,
        0,
        now,
        0,
        0,
        JFFS2_COMPR_NONE,
        &[],
        endian,
    ));

    // 3. /etc directory (pino 1 -> ino 2)
    image.extend_from_slice(&build_raw_dirent(1, 1, 2, now, 4, "etc", endian));
    image.extend_from_slice(&build_raw_inode(
        2,
        1,
        0o040755,
        0,
        0,
        0,
        now,
        0,
        0,
        JFFS2_COMPR_NONE,
        &[],
        endian,
    ));

    // 4. /bin directory (pino 1 -> ino 3)
    image.extend_from_slice(&build_raw_dirent(1, 1, 3, now, 4, "bin", endian));
    image.extend_from_slice(&build_raw_inode(
        3,
        1,
        0o040755,
        0,
        0,
        0,
        now,
        0,
        0,
        JFFS2_COMPR_NONE,
        &[],
        endian,
    ));

    // 5. /etc/banner (uncompressed file, ino 10)
    let banner_data = b"FirmCarver JFFS2 Recovery Banner\nRouterOS Linux 5.15\n";
    image.extend_from_slice(&build_raw_dirent(2, 1, 10, now, 8, "banner", endian));
    image.extend_from_slice(&build_raw_inode(
        10,
        1,
        0o100644,
        0,
        0,
        banner_data.len() as u32,
        now,
        0,
        banner_data.len() as u32,
        JFFS2_COMPR_NONE,
        banner_data,
        endian,
    ));

    // 6. /etc/config (RTIME compressed file, ino 11)
    let config_plain =
        b"config system 'main'\n    option hostname 'RouterX'\n    option timezone 'UTC'\n";
    let config_rtime = compress_rtime(config_plain).unwrap_or_else(|| config_plain.to_vec());
    image.extend_from_slice(&build_raw_dirent(2, 1, 11, now, 8, "config", endian));
    image.extend_from_slice(&build_raw_inode(
        11,
        1,
        0o100600,
        0,
        0,
        config_plain.len() as u32,
        now,
        0,
        config_plain.len() as u32,
        JFFS2_COMPR_RTIME,
        &config_rtime,
        endian,
    ));

    // 7. /bin/busybox (ZLIB compressed executable, ino 12)
    let busybox_plain = b"\x7FELF\x01\x01\x01\x00BusyBox Embedded Multi-Call Binary v1.36.1";
    let busybox_zlib = compress_zlib(busybox_plain).unwrap_or_else(|_| busybox_plain.to_vec());
    image.extend_from_slice(&build_raw_dirent(3, 1, 12, now, 8, "busybox", endian));
    image.extend_from_slice(&build_raw_inode(
        12,
        1,
        0o100755,
        0,
        0,
        busybox_plain.len() as u32,
        now,
        0,
        busybox_plain.len() as u32,
        JFFS2_COMPR_ZLIB,
        &busybox_zlib,
        endian,
    ));

    // 8. /bin/sh (symlink pointing to /bin/busybox, ino 13)
    let symlink_dest = b"/bin/busybox";
    image.extend_from_slice(&build_raw_dirent(3, 1, 13, now, 10, "sh", endian));
    image.extend_from_slice(&build_raw_inode(
        13,
        1,
        0o120777,
        0,
        0,
        symlink_dest.len() as u32,
        now,
        0,
        symlink_dest.len() as u32,
        JFFS2_COMPR_NONE,
        symlink_dest,
        endian,
    ));

    // 9. Multi-chunk file: /etc/hosts (ino 14)
    let chunk1 = b"127.0.0.1 localhost\n";
    let chunk2 = b"192.168.1.1 router.local\n";
    let total_hosts_len = (chunk1.len() + chunk2.len()) as u32;
    image.extend_from_slice(&build_raw_dirent(2, 1, 14, now, 8, "hosts", endian));
    image.extend_from_slice(&build_raw_inode(
        14,
        1,
        0o100644,
        0,
        0,
        total_hosts_len,
        now,
        0,
        chunk1.len() as u32,
        JFFS2_COMPR_NONE,
        chunk1,
        endian,
    ));
    image.extend_from_slice(&build_raw_inode(
        14,
        2,
        0o100644,
        0,
        0,
        total_hosts_len,
        now,
        chunk1.len() as u32,
        chunk2.len() as u32,
        JFFS2_COMPR_NONE,
        chunk2,
        endian,
    ));

    // 10. Deletion tombstone test vector: /etc/temp_del (pino 2, ino 20 v1, then ino 0 v2)
    image.extend_from_slice(&build_raw_dirent(2, 1, 20, now, 8, "temp_del", endian));
    image.extend_from_slice(&build_raw_dirent(2, 2, 0, now, 8, "temp_del", endian)); // Tombstone

    image
}
