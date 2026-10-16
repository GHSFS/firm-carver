// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::types::*;

pub fn write_u16(buf: &mut [u8], offset: usize, val: u16, endian: Endianness) {
    let bytes = match endian {
        Endianness::Little => val.to_le_bytes(),
        Endianness::Big => val.to_be_bytes(),
    };
    buf[offset..offset + 2].copy_from_slice(&bytes);
}

pub fn write_u32(buf: &mut [u8], offset: usize, val: u32, endian: Endianness) {
    let bytes = match endian {
        Endianness::Little => val.to_le_bytes(),
        Endianness::Big => val.to_be_bytes(),
    };
    buf[offset..offset + 4].copy_from_slice(&bytes);
}

#[allow(clippy::too_many_arguments)]
fn write_synth_inode(
    image: &mut [u8],
    itable_off: usize,
    isize: usize,
    is_ext4: bool,
    endian: Endianness,
    ino: u32,
    mode: u16,
    uid: u32,
    size: u32,
    data_blocks: &[u32],
    is_fast_symlink: bool,
    symlink_target: Option<&str>,
) {
    let node_off = itable_off + ((ino - 1) as usize) * isize;
    write_u16(image, node_off, mode, endian);
    write_u16(image, node_off + 0x02, uid as u16, endian);
    write_u32(image, node_off + 0x04, size, endian);
    write_u32(image, node_off + 0x08, 1_700_000_000, endian); // atime
    write_u32(image, node_off + 0x0C, 1_700_000_000, endian); // ctime
    write_u32(image, node_off + 0x10, 1_700_000_000, endian); // mtime
    write_u16(image, node_off + 0x18, 0, endian); // gid
    write_u16(image, node_off + 0x1A, 1, endian); // links_count
    let blocks_count = if is_fast_symlink {
        0
    } else {
        size.div_ceil(512)
    };
    write_u32(image, node_off + 0x1C, blocks_count, endian);

    let iblock_off = node_off + 0x28;
    if is_fast_symlink {
        if let Some(target) = symlink_target {
            let bytes = target.as_bytes();
            image[iblock_off..iblock_off + bytes.len()].copy_from_slice(bytes);
        }
    } else if is_ext4 && !data_blocks.is_empty() {
        // Write Ext4 Extent Tree Header (12 bytes)
        write_u32(image, node_off + 0x20, EXT4_EXTENTS_FL, endian);
        write_u16(image, iblock_off, EXT4_EXTENT_HEADER_MAGIC, endian);
        write_u16(image, iblock_off + 0x02, 1, endian); // entries = 1
        write_u16(image, iblock_off + 0x04, 4, endian); // max = 4
        write_u16(image, iblock_off + 0x06, 0, endian); // depth = 0
        write_u32(image, iblock_off + 0x08, 0, endian); // generation

        // Write 1 Extent record (12 bytes)
        let ext_rec_off = iblock_off + 12;
        write_u32(image, ext_rec_off, 0, endian); // ee_block
        write_u16(image, ext_rec_off + 0x04, data_blocks.len() as u16, endian); // ee_len
        write_u16(image, ext_rec_off + 0x06, 0, endian); // start_hi
        write_u32(image, ext_rec_off + 0x08, data_blocks[0], endian); // start_lo
    } else {
        for (idx, &blk) in data_blocks.iter().enumerate().take(12) {
            write_u32(image, iblock_off + idx * 4, blk, endian);
        }
    }
}

fn write_dir_block(
    image: &mut [u8],
    block_size: usize,
    endian: Endianness,
    blk: u32,
    entries: &[(u32, u8, &str)],
) {
    let blk_off = (blk as usize) * block_size;
    let mut cur = blk_off;
    let total_entries = entries.len();

    for (idx, &(ino, dtype, name)) in entries.iter().enumerate() {
        let name_bytes = name.as_bytes();
        let name_len = name_bytes.len() as u8;
        let entry_len = 8 + ((name_len as usize + 3) & !3);
        let is_last = idx == total_entries - 1;
        let rec_len = if is_last {
            (blk_off + block_size - cur) as u16
        } else {
            entry_len as u16
        };

        write_u32(image, cur, ino, endian);
        write_u16(image, cur + 0x04, rec_len, endian);
        image[cur + 0x06] = name_len;
        image[cur + 0x07] = dtype;
        image[cur + 0x08..cur + 0x08 + name_bytes.len()].copy_from_slice(name_bytes);

        cur += rec_len as usize;
    }
}

/// Builds a deterministic synthetic Ext2 or Ext4 image for unit and integration testing.
pub fn build_synthetic_extfs(
    is_ext4: bool,
    endian: Endianness,
    include_vulnerabilities: bool,
) -> Vec<u8> {
    let block_size = 1024usize;
    let total_blocks = 64usize;
    let total_size = total_blocks * block_size;
    let mut image = vec![0u8; total_size];

    let inodes_count = 32u32;
    let blocks_per_group = 64u32;
    let inodes_per_group = 32u32;
    let inode_size = if is_ext4 { 256u16 } else { 128u16 };

    // --- Block 1: Superblock (offset 1024..2048) ---
    let sb_off = 1024;
    write_u32(&mut image, sb_off, inodes_count, endian);
    write_u32(&mut image, sb_off + 0x04, total_blocks as u32, endian);
    write_u32(&mut image, sb_off + 0x08, 0, endian); // r_blocks_count
    write_u32(
        &mut image,
        sb_off + 0x0C,
        (total_blocks - 16) as u32,
        endian,
    ); // free_blocks
    write_u32(&mut image, sb_off + 0x10, inodes_count - 10, endian); // free_inodes
    write_u32(&mut image, sb_off + 0x14, 1, endian); // first_data_block (1 for 1KB blocks)
    write_u32(&mut image, sb_off + 0x18, 0, endian); // s_log_block_size (0 -> 1024 B)
    write_u32(&mut image, sb_off + 0x1C, 0, endian); // s_log_cluster_size
    write_u32(&mut image, sb_off + 0x20, blocks_per_group, endian);
    write_u32(&mut image, sb_off + 0x24, blocks_per_group, endian);
    write_u32(&mut image, sb_off + 0x28, inodes_per_group, endian);
    write_u32(&mut image, sb_off + 0x2C, 1_700_000_000, endian); // mtime
    write_u32(&mut image, sb_off + 0x30, 1_700_000_000, endian); // wtime
    write_u16(&mut image, sb_off + 0x38, EXT_SUPER_MAGIC, endian);
    write_u16(&mut image, sb_off + 0x3A, 1, endian); // state: cleanly unmounted
    write_u32(&mut image, sb_off + 0x4C, 1, endian); // rev_level: dynamic
    write_u32(&mut image, sb_off + 0x54, 11, endian); // first_ino
    write_u16(&mut image, sb_off + 0x58, inode_size, endian);

    let feat_compat = if is_ext4 {
        EXT3_FEATURE_COMPAT_HAS_JOURNAL
    } else {
        0
    };
    let feat_incompat = if is_ext4 {
        EXT2_FEATURE_INCOMPAT_FILETYPE | EXT4_FEATURE_INCOMPAT_EXTENTS
    } else {
        EXT2_FEATURE_INCOMPAT_FILETYPE
    };
    let feat_ro_compat = EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER;

    write_u32(&mut image, sb_off + 0x5C, feat_compat, endian);
    write_u32(&mut image, sb_off + 0x60, feat_incompat, endian);
    write_u32(&mut image, sb_off + 0x64, feat_ro_compat, endian);

    // UUID
    image[sb_off + 0x68..sb_off + 0x78].copy_from_slice(&[
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08,
    ]);

    // Volume name
    let vol_name = b"ROOTFS_EMBEDDED\0";
    image[sb_off + 0x78..sb_off + 0x78 + vol_name.len()].copy_from_slice(vol_name);

    // --- Block 2: Block Group Descriptors (offset 2048..3072) ---
    let gdt_off = 2 * block_size;
    let block_bitmap_blk = 3u32;
    let inode_bitmap_blk = 4u32;
    let inode_table_blk = 5u32;

    write_u32(&mut image, gdt_off, block_bitmap_blk, endian);
    write_u32(&mut image, gdt_off + 0x04, inode_bitmap_blk, endian);
    write_u32(&mut image, gdt_off + 0x08, inode_table_blk, endian);
    write_u16(&mut image, gdt_off + 0x0C, 48, endian); // free_blocks
    write_u16(&mut image, gdt_off + 0x0E, 22, endian); // free_inodes
    write_u16(&mut image, gdt_off + 0x10, 3, endian); // used_dirs

    // --- Inode Table layout (Blocks 5..12) ---
    let itable_off = (inode_table_blk as usize) * block_size;
    let isize = inode_size as usize;

    // --- Inode 2: Root Directory (/) ---
    let root_data_blk = 13u32;
    write_synth_inode(
        &mut image,
        itable_off,
        isize,
        is_ext4,
        endian,
        2,
        0o040755,
        0,
        block_size as u32,
        &[root_data_blk],
        false,
        None,
    );

    // --- Inode 11: /bin directory ---
    let bin_data_blk = 14u32;
    write_synth_inode(
        &mut image,
        itable_off,
        isize,
        is_ext4,
        endian,
        11,
        0o040755,
        0,
        block_size as u32,
        &[bin_data_blk],
        false,
        None,
    );

    // --- Inode 12: /etc directory ---
    let etc_data_blk = 15u32;
    write_synth_inode(
        &mut image,
        itable_off,
        isize,
        is_ext4,
        endian,
        12,
        0o040755,
        0,
        block_size as u32,
        &[etc_data_blk],
        false,
        None,
    );

    // Write Root Directory Entries in Block 13
    write_dir_block(
        &mut image,
        block_size,
        endian,
        root_data_blk,
        &[(2, 2, "."), (2, 2, ".."), (11, 2, "bin"), (12, 2, "etc")],
    );

    // --- Inode 13: /etc/hostname file ---
    let hostname_content = b"router-gw01\n";
    let hostname_blk = 16u32;
    let h_off = (hostname_blk as usize) * block_size;
    image[h_off..h_off + hostname_content.len()].copy_from_slice(hostname_content);
    write_synth_inode(
        &mut image,
        itable_off,
        isize,
        is_ext4,
        endian,
        13,
        0o100644,
        0,
        hostname_content.len() as u32,
        &[hostname_blk],
        false,
        None,
    );

    // --- Inode 14: /etc/shadow file ---
    let shadow_content = b"root:$6$rounds=5000$saltsalt$h4sh3dH4sh:19500:0:99999:7:::\n";
    let shadow_blk = 17u32;
    let s_off = (shadow_blk as usize) * block_size;
    image[s_off..s_off + shadow_content.len()].copy_from_slice(shadow_content);
    write_synth_inode(
        &mut image,
        itable_off,
        isize,
        is_ext4,
        endian,
        14,
        0o100600,
        0,
        shadow_content.len() as u32,
        &[shadow_blk],
        false,
        None,
    );

    // Write /etc Directory Entries in Block 15
    write_dir_block(
        &mut image,
        block_size,
        endian,
        etc_data_blk,
        &[
            (12, 2, "."),
            (2, 2, ".."),
            (13, 1, "hostname"),
            (14, 1, "shadow"),
        ],
    );

    if include_vulnerabilities {
        // --- Inode 15: SUID Binary /bin/su (mode 0o104755) ---
        let su_content = b"\x7FELF_MOCK_SUID_EXECUTABLE";
        let su_blk = 18u32;
        let su_off = (su_blk as usize) * block_size;
        image[su_off..su_off + su_content.len()].copy_from_slice(su_content);
        write_synth_inode(
            &mut image,
            itable_off,
            isize,
            is_ext4,
            endian,
            15,
            0o104755,
            0,
            su_content.len() as u32,
            &[su_blk],
            false,
            None,
        );

        // --- Inode 16: Path Traversal Symlink /bin/sh_link -> ../../etc/shadow ---
        let trav_target = "../../etc/shadow";
        write_synth_inode(
            &mut image,
            itable_off,
            isize,
            is_ext4,
            endian,
            16,
            0o120777,
            0,
            trav_target.len() as u32,
            &[],
            true,
            Some(trav_target),
        );

        // --- Inode 17: Dangling Symlink /bin/dangling -> /var/run/dangling ---
        let dang_target = "/var/run/dangling";
        write_synth_inode(
            &mut image,
            itable_off,
            isize,
            is_ext4,
            endian,
            17,
            0o120777,
            0,
            dang_target.len() as u32,
            &[],
            true,
            Some(dang_target),
        );

        // --- Inode 18: Sensitive Symlink /bin/raw_flash -> /dev/mtdblock0 ---
        let sens_target = "/dev/mtdblock0";
        write_synth_inode(
            &mut image,
            itable_off,
            isize,
            is_ext4,
            endian,
            18,
            0o120777,
            0,
            sens_target.len() as u32,
            &[],
            true,
            Some(sens_target),
        );

        // Write /bin Directory Entries in Block 14
        write_dir_block(
            &mut image,
            block_size,
            endian,
            bin_data_blk,
            &[
                (11, 2, "."),
                (2, 2, ".."),
                (15, 1, "su"),
                (16, 7, "sh_link"),
                (17, 7, "dangling"),
                (18, 7, "raw_flash"),
            ],
        );
    } else {
        // Hardened /bin directory: simple non-suid busybox
        let busybox_content = b"\x7FELF_MOCK_CLEAN_EXECUTABLE";
        let bb_blk = 18u32;
        let bb_off = (bb_blk as usize) * block_size;
        image[bb_off..bb_off + busybox_content.len()].copy_from_slice(busybox_content);
        write_synth_inode(
            &mut image,
            itable_off,
            isize,
            is_ext4,
            endian,
            15,
            0o100755,
            0,
            busybox_content.len() as u32,
            &[bb_blk],
            false,
            None,
        );

        write_dir_block(
            &mut image,
            block_size,
            endian,
            bin_data_blk,
            &[(11, 2, "."), (2, 2, ".."), (15, 1, "busybox")],
        );
    }

    image
}
