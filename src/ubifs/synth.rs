// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::types::*;
use crate::image::compute_crc32;

pub fn build_ubifs_node_header(
    node_type: UbifsNodeType,
    sqnum: u64,
    payload: &[u8],
    endian: Endianness,
) -> Vec<u8> {
    let full_len = (UBIFS_CH_SZ + payload.len()) as u32;
    let mut header = vec![0u8; UBIFS_CH_SZ];

    match endian {
        Endianness::Little => {
            header[0..4].copy_from_slice(&UBIFS_NODE_MAGIC_LE.to_le_bytes());
            header[8..16].copy_from_slice(&sqnum.to_le_bytes());
            header[16..20].copy_from_slice(&full_len.to_le_bytes());
        }
        Endianness::Big => {
            header[0..4].copy_from_slice(&UBIFS_NODE_MAGIC_LE.to_be_bytes());
            header[8..16].copy_from_slice(&sqnum.to_be_bytes());
            header[16..20].copy_from_slice(&full_len.to_be_bytes());
        }
    }
    header[20] = node_type as u8;
    header[21] = 0; // group_type

    let mut full_node = header;
    full_node.extend_from_slice(payload);

    // Compute CRC over bytes 8..full_len
    let crc = compute_crc32(&full_node[8..]);
    match endian {
        Endianness::Little => {
            full_node[4..8].copy_from_slice(&crc.to_le_bytes());
        }
        Endianness::Big => {
            full_node[4..8].copy_from_slice(&crc.to_be_bytes());
        }
    }

    // Pad on-flash node representation to 8-byte boundary per UBIFS specification
    let aligned_len = (full_node.len() + 7) & !7;
    full_node.resize(aligned_len, 0);

    full_node
}

pub fn build_synthetic_sb_node(leb_size: u32, leb_cnt: u32, endian: Endianness) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&[0, 0, 0, 0]); // padding(2), key_hash, key_fmt
    match endian {
        Endianness::Little => {
            payload.extend_from_slice(&0u32.to_le_bytes()); // flags
            payload.extend_from_slice(&2048u32.to_le_bytes()); // min_io_size
            payload.extend_from_slice(&leb_size.to_le_bytes()); // leb_size
            payload.extend_from_slice(&leb_cnt.to_le_bytes()); // leb_cnt
            payload.extend_from_slice(&(leb_cnt * 2).to_le_bytes()); // max_leb_cnt
            payload.extend_from_slice(&0x100000u64.to_le_bytes()); // max_bud_bytes
            payload.extend_from_slice(&0x400000000u64.to_le_bytes()); // max_bytes_per_inode
            payload.extend_from_slice(&0u32.to_le_bytes()); // boot_lebs
            payload.extend_from_slice(&4u32.to_le_bytes()); // log_lebs
            payload.extend_from_slice(&2u32.to_le_bytes()); // lpt_lebs
            payload.extend_from_slice(&1u32.to_le_bytes()); // orph_lebs
            payload.extend_from_slice(&1u32.to_le_bytes()); // jhead_cnt
            payload.extend_from_slice(&8u32.to_le_bytes()); // fanout
            payload.extend_from_slice(&12u32.to_le_bytes()); // lsave_cnt
            payload.extend_from_slice(&5u32.to_le_bytes()); // fmt_version (5)
            payload.extend_from_slice(&(UbifsCompressionType::Lzo as u16).to_le_bytes()); // default_compr
            payload.extend_from_slice(&[0, 0]); // padding1
            payload.extend_from_slice(&0u64.to_le_bytes()); // rp_size
            payload.extend_from_slice(&1000000000u32.to_le_bytes()); // time_gran
            payload.extend_from_slice(&[
                0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                0x77, 0x88,
            ]); // uuid
            payload.extend_from_slice(&0u32.to_le_bytes()); // ro_compat_version
            payload.extend_from_slice(&0u32.to_le_bytes()); // hmac_algo
        }
        Endianness::Big => {
            payload.extend_from_slice(&0u32.to_be_bytes()); // flags
            payload.extend_from_slice(&2048u32.to_be_bytes()); // min_io_size
            payload.extend_from_slice(&leb_size.to_be_bytes()); // leb_size
            payload.extend_from_slice(&leb_cnt.to_be_bytes()); // leb_cnt
            payload.extend_from_slice(&(leb_cnt * 2).to_be_bytes()); // max_leb_cnt
            payload.extend_from_slice(&0x100000u64.to_be_bytes()); // max_bud_bytes
            payload.extend_from_slice(&0x400000000u64.to_be_bytes()); // max_bytes_per_inode
            payload.extend_from_slice(&0u32.to_be_bytes()); // boot_lebs
            payload.extend_from_slice(&4u32.to_be_bytes()); // log_lebs
            payload.extend_from_slice(&2u32.to_be_bytes()); // lpt_lebs
            payload.extend_from_slice(&1u32.to_be_bytes()); // orph_lebs
            payload.extend_from_slice(&1u32.to_be_bytes()); // jhead_cnt
            payload.extend_from_slice(&8u32.to_be_bytes()); // fanout
            payload.extend_from_slice(&12u32.to_be_bytes()); // lsave_cnt
            payload.extend_from_slice(&5u32.to_be_bytes()); // fmt_version (5)
            payload.extend_from_slice(&(UbifsCompressionType::Lzo as u16).to_be_bytes()); // default_compr
            payload.extend_from_slice(&[0, 0]); // padding1
            payload.extend_from_slice(&0u64.to_be_bytes()); // rp_size
            payload.extend_from_slice(&1000000000u32.to_be_bytes()); // time_gran
            payload.extend_from_slice(&[
                0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                0x77, 0x88,
            ]); // uuid
            payload.extend_from_slice(&0u32.to_be_bytes()); // ro_compat_version
            payload.extend_from_slice(&0u32.to_be_bytes()); // hmac_algo
        }
    }

    build_ubifs_node_header(UbifsNodeType::Sb, 1, &payload, endian)
}

pub fn build_synthetic_mst_node(leb_size: u32, endian: Endianness) -> Vec<u8> {
    let mut payload = Vec::new();
    match endian {
        Endianness::Little => {
            payload.extend_from_slice(&10u64.to_le_bytes()); // highest_inum
            payload.extend_from_slice(&1u64.to_le_bytes()); // cmt_no
            payload.extend_from_slice(&0u32.to_le_bytes()); // flags
            payload.extend_from_slice(&4u32.to_le_bytes()); // log_lnum
            payload.extend_from_slice(&5u32.to_le_bytes()); // root_lnum
            payload.extend_from_slice(&0u32.to_le_bytes()); // root_offs
            payload.extend_from_slice(&64u32.to_le_bytes()); // root_len
            payload.extend_from_slice(&6u32.to_le_bytes()); // gc_lnum
            payload.extend_from_slice(&7u32.to_le_bytes()); // ihead_lnum
            payload.extend_from_slice(&0u32.to_le_bytes()); // ihead_offs
            payload.extend_from_slice(&4096u64.to_le_bytes()); // index_size
            payload.extend_from_slice(&1000000u64.to_le_bytes()); // total_free
            payload.extend_from_slice(&50000u64.to_le_bytes()); // total_dirty
            payload.extend_from_slice(&250000u64.to_le_bytes()); // total_used
            payload.extend_from_slice(&0u64.to_le_bytes()); // total_dead
            payload.extend_from_slice(&0u64.to_le_bytes()); // total_dark
            payload.resize(148, 0);
            payload.extend_from_slice(&leb_size.to_le_bytes()); // leb_size
        }
        Endianness::Big => {
            payload.extend_from_slice(&10u64.to_be_bytes()); // highest_inum
            payload.extend_from_slice(&1u64.to_be_bytes()); // cmt_no
            payload.extend_from_slice(&0u32.to_be_bytes()); // flags
            payload.extend_from_slice(&4u32.to_be_bytes()); // log_lnum
            payload.extend_from_slice(&5u32.to_be_bytes()); // root_lnum
            payload.extend_from_slice(&0u32.to_be_bytes()); // root_offs
            payload.extend_from_slice(&64u32.to_be_bytes()); // root_len
            payload.extend_from_slice(&6u32.to_be_bytes()); // gc_lnum
            payload.extend_from_slice(&7u32.to_be_bytes()); // ihead_lnum
            payload.extend_from_slice(&0u32.to_be_bytes()); // ihead_offs
            payload.extend_from_slice(&4096u64.to_be_bytes()); // index_size
            payload.extend_from_slice(&1000000u64.to_be_bytes()); // total_free
            payload.extend_from_slice(&50000u64.to_be_bytes()); // total_dirty
            payload.extend_from_slice(&250000u64.to_be_bytes()); // total_used
            payload.extend_from_slice(&0u64.to_be_bytes()); // total_dead
            payload.extend_from_slice(&0u64.to_be_bytes()); // total_dark
            payload.resize(148, 0);
            payload.extend_from_slice(&leb_size.to_be_bytes()); // leb_size
        }
    }

    build_ubifs_node_header(UbifsNodeType::Mst, 2, &payload, endian)
}

pub fn build_synthetic_ino_node(
    inum: u64,
    size: u64,
    mode: u32,
    symlink_target: Option<&str>,
    endian: Endianness,
) -> Vec<u8> {
    let mut payload = Vec::new();
    // Key (16 bytes)
    match endian {
        Endianness::Little => payload.extend_from_slice(&(inum as u32).to_le_bytes()),
        Endianness::Big => payload.extend_from_slice(&(inum as u32).to_be_bytes()),
    }
    payload.resize(UBIFS_MAX_KEY_LEN, 0);

    let sym_bytes = symlink_target.map(|s| s.as_bytes()).unwrap_or(&[]);
    let data_len = sym_bytes.len() as u32;

    match endian {
        Endianness::Little => {
            payload.extend_from_slice(&1u64.to_le_bytes()); // creat_sqnum
            payload.extend_from_slice(&size.to_le_bytes()); // size
            payload.extend_from_slice(&1700000000u64.to_le_bytes()); // atime_sec
            payload.extend_from_slice(&1700000000u64.to_le_bytes()); // ctime_sec
            payload.extend_from_slice(&1700000000u64.to_le_bytes()); // mtime_sec
            payload.extend_from_slice(&0u32.to_le_bytes()); // atime_nsec
            payload.extend_from_slice(&0u32.to_le_bytes()); // ctime_nsec
            payload.extend_from_slice(&0u32.to_le_bytes()); // mtime_nsec
            payload.extend_from_slice(&1u32.to_le_bytes()); // nlink
            payload.extend_from_slice(&0u32.to_le_bytes()); // uid
            payload.extend_from_slice(&0u32.to_le_bytes()); // gid
            payload.extend_from_slice(&mode.to_le_bytes()); // mode
            payload.extend_from_slice(&0u32.to_le_bytes()); // flags
            payload.extend_from_slice(&data_len.to_le_bytes()); // data_len
            payload.extend_from_slice(&0u32.to_le_bytes()); // xattr_cnt
            payload.extend_from_slice(&0u32.to_le_bytes()); // xattr_size
            payload.extend_from_slice(&[0; 4]); // padding1
            payload.extend_from_slice(&0u32.to_le_bytes()); // xattr_names
            payload.extend_from_slice(&0u16.to_le_bytes()); // compr_type
            payload.extend_from_slice(&[0; 22]); // padding2
        }
        Endianness::Big => {
            payload.extend_from_slice(&1u64.to_be_bytes()); // creat_sqnum
            payload.extend_from_slice(&size.to_be_bytes()); // size
            payload.extend_from_slice(&1700000000u64.to_be_bytes()); // atime_sec
            payload.extend_from_slice(&1700000000u64.to_be_bytes()); // ctime_sec
            payload.extend_from_slice(&1700000000u64.to_be_bytes()); // mtime_sec
            payload.extend_from_slice(&0u32.to_be_bytes()); // atime_nsec
            payload.extend_from_slice(&0u32.to_be_bytes()); // ctime_nsec
            payload.extend_from_slice(&0u32.to_be_bytes()); // mtime_nsec
            payload.extend_from_slice(&1u32.to_be_bytes()); // nlink
            payload.extend_from_slice(&0u32.to_be_bytes()); // uid
            payload.extend_from_slice(&0u32.to_be_bytes()); // gid
            payload.extend_from_slice(&mode.to_be_bytes()); // mode
            payload.extend_from_slice(&0u32.to_be_bytes()); // flags
            payload.extend_from_slice(&data_len.to_be_bytes()); // data_len
            payload.extend_from_slice(&0u32.to_be_bytes()); // xattr_cnt
            payload.extend_from_slice(&0u32.to_be_bytes()); // xattr_size
            payload.extend_from_slice(&[0; 4]); // padding1
            payload.extend_from_slice(&0u32.to_be_bytes()); // xattr_names
            payload.extend_from_slice(&0u16.to_be_bytes()); // compr_type
            payload.extend_from_slice(&[0; 22]); // padding2
        }
    }

    if !sym_bytes.is_empty() {
        payload.extend_from_slice(sym_bytes);
        payload.push(0);
    }

    build_ubifs_node_header(UbifsNodeType::Ino, inum + 10, &payload, endian)
}

pub fn build_synthetic_dent_node(
    parent_inum: u64,
    child_inum: u64,
    file_type: UbifsFileType,
    name: &str,
    endian: Endianness,
) -> Vec<u8> {
    let mut payload = Vec::new();
    match endian {
        Endianness::Little => payload.extend_from_slice(&(parent_inum as u32).to_le_bytes()),
        Endianness::Big => payload.extend_from_slice(&(parent_inum as u32).to_be_bytes()),
    }
    payload.resize(UBIFS_MAX_KEY_LEN, 0);

    match endian {
        Endianness::Little => {
            payload.extend_from_slice(&child_inum.to_le_bytes()); // inum
            payload.push(0); // padding1
            payload.push(file_type as u8); // type
            payload.extend_from_slice(&(name.len() as u16).to_le_bytes()); // nlen
            payload.extend_from_slice(&0u32.to_le_bytes()); // cookie
        }
        Endianness::Big => {
            payload.extend_from_slice(&child_inum.to_be_bytes()); // inum
            payload.push(0); // padding1
            payload.push(file_type as u8); // type
            payload.extend_from_slice(&(name.len() as u16).to_be_bytes()); // nlen
            payload.extend_from_slice(&0u32.to_be_bytes()); // cookie
        }
    }

    payload.extend_from_slice(name.as_bytes());
    payload.push(0);

    build_ubifs_node_header(UbifsNodeType::Dent, child_inum + 50, &payload, endian)
}

pub fn build_synthetic_ubifs(endian: Endianness) -> Vec<u8> {
    let mut stream = Vec::new();
    let leb_size = 126976u32; // Standard 128K PEB - 2 pages (124 KiB)

    // 1. Superblock node
    stream.extend_from_slice(&build_synthetic_sb_node(leb_size, 16, endian));
    // 2. Master node
    stream.extend_from_slice(&build_synthetic_mst_node(leb_size, endian));

    // 3. Root directory inode (inum = 1)
    stream.extend_from_slice(&build_synthetic_ino_node(
        UBIFS_ROOT_INO,
        0,
        0o755,
        None,
        endian,
    ));

    // 4. Subdirectories: /bin (inum = 2), /etc (inum = 3)
    stream.extend_from_slice(&build_synthetic_dent_node(
        UBIFS_ROOT_INO,
        2,
        UbifsFileType::Directory,
        "bin",
        endian,
    ));
    stream.extend_from_slice(&build_synthetic_ino_node(2, 0, 0o755, None, endian));

    stream.extend_from_slice(&build_synthetic_dent_node(
        UBIFS_ROOT_INO,
        3,
        UbifsFileType::Directory,
        "etc",
        endian,
    ));
    stream.extend_from_slice(&build_synthetic_ino_node(3, 0, 0o755, None, endian));

    // 5. Files: /bin/busybox (inum = 4, reg), /etc/passwd (inum = 5, reg), /bin/sh (inum = 6, symlink -> /bin/busybox)
    stream.extend_from_slice(&build_synthetic_dent_node(
        2,
        4,
        UbifsFileType::Regular,
        "busybox",
        endian,
    ));
    stream.extend_from_slice(&build_synthetic_ino_node(4, 512, 0o755, None, endian));

    stream.extend_from_slice(&build_synthetic_dent_node(
        3,
        5,
        UbifsFileType::Regular,
        "passwd",
        endian,
    ));
    stream.extend_from_slice(&build_synthetic_ino_node(5, 64, 0o644, None, endian));

    stream.extend_from_slice(&build_synthetic_dent_node(
        2,
        6,
        UbifsFileType::Symlink,
        "sh",
        endian,
    ));
    stream.extend_from_slice(&build_synthetic_ino_node(
        6,
        12,
        0o777,
        Some("/bin/busybox"),
        endian,
    ));

    stream
}

pub fn build_synthetic_ubi(endian: Endianness) -> Vec<u8> {
    let peb_size = 128 * 1024; // 128 KiB PEB
    let vid_hdr_offset = 512u32;
    let data_offset = 2048u32;
    let leb_size = (peb_size - data_offset as usize) as u32;

    let mut flash_image = Vec::new();

    let build_peb = |ec: u64, vol_id: u32, lnum: u32, payload: &[u8]| -> Vec<u8> {
        let mut peb = vec![0xFFu8; peb_size];

        // EC header
        peb[0..4].copy_from_slice(&UBI_EC_HDR_MAGIC.to_be_bytes());
        peb[4] = 1; // version
        peb[8..16].copy_from_slice(&ec.to_be_bytes());
        peb[16..20].copy_from_slice(&vid_hdr_offset.to_be_bytes());
        peb[20..24].copy_from_slice(&data_offset.to_be_bytes());
        peb[24..28].copy_from_slice(&1u32.to_be_bytes()); // image_seq
        let ec_crc = compute_crc32(&peb[0..60]);
        peb[60..64].copy_from_slice(&ec_crc.to_be_bytes());

        // VID header
        let vid_pos = vid_hdr_offset as usize;
        peb[vid_pos..vid_pos + 4].copy_from_slice(&UBI_VID_HDR_MAGIC.to_be_bytes());
        peb[vid_pos + 4] = 1; // version
        peb[vid_pos + 5] = 1; // vol_type: dynamic
        peb[vid_pos + 8..vid_pos + 12].copy_from_slice(&vol_id.to_be_bytes());
        peb[vid_pos + 12..vid_pos + 16].copy_from_slice(&lnum.to_be_bytes());
        peb[vid_pos + 20..vid_pos + 24].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        let vid_crc = compute_crc32(&peb[vid_pos..vid_pos + 60]);
        peb[vid_pos + 60..vid_pos + 64].copy_from_slice(&vid_crc.to_be_bytes());

        // Data payload
        let dpos = data_offset as usize;
        if !payload.is_empty() {
            let copy_len = payload.len().min(peb_size - dpos);
            peb[dpos..dpos + copy_len].copy_from_slice(&payload[..copy_len]);
        }

        peb
    };

    // Layout volume payload (contains 1 volume table record for "rootfs")
    let mut vtbl_payload = vec![0u8; leb_size as usize];
    vtbl_payload[0..4].copy_from_slice(&16u32.to_be_bytes()); // reserved_pebs
    vtbl_payload[4..8].copy_from_slice(&1u32.to_be_bytes()); // alignment
    vtbl_payload[8..12].copy_from_slice(&0u32.to_be_bytes()); // data_pad
    vtbl_payload[12] = 1; // vol_type: dynamic
    vtbl_payload[13] = 0; // upd_marker
    let name = "rootfs";
    vtbl_payload[14..16].copy_from_slice(&(name.len() as u16).to_be_bytes());
    vtbl_payload[16..16 + name.len()].copy_from_slice(name.as_bytes());
    let vtbl_crc = compute_crc32(&vtbl_payload[0..UBI_VTBL_RECORD_SIZE_CRC]);
    vtbl_payload[168..172].copy_from_slice(&vtbl_crc.to_be_bytes());

    // PEB 0: Layout volume
    flash_image.extend_from_slice(&build_peb(10, UBI_LAYOUT_VOLUME_ID, 0, &vtbl_payload));
    // PEB 1: Layout volume mirror
    flash_image.extend_from_slice(&build_peb(11, UBI_LAYOUT_VOLUME_ID, 1, &vtbl_payload));

    // UBIFS nodes payload for rootfs volume
    let ubifs_data = build_synthetic_ubifs(endian);

    // PEB 2: rootfs LEB 0
    flash_image.extend_from_slice(&build_peb(15, 0, 0, &ubifs_data));

    flash_image
}
