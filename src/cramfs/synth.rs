// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::superblock::pack_inode;
use super::types::{
    CramFsInode, Endianness, CRAMFS_FLAG_FSID_VERSION_2, CRAMFS_MAGIC, CRAMFS_SIGNATURE, S_IFDIR,
    S_IFLNK, S_IFREG, S_ISUID,
};
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::Write;

pub fn build_synthetic_cramfs(endian: Endianness, include_vulns: bool) -> Vec<u8> {
    let mut image = Vec::with_capacity(4096);

    // 1. Reserve 0..512 for Superblock, and 512..1024 for Root Directory Table
    image.resize(1024, 0);

    // 2. Prepare file data and compressed chunks
    let sh_content = b"#!/bin/sh\necho 'FirmCarver synthetic shell'\n";
    let sh_compressed = compress_zlib(sh_content);

    let banner_content = b"FirmCarver CramFS Forensic Testing Banner 2026\n";
    let banner_compressed = compress_zlib(banner_content);

    let sym_target_sh = b"sh";
    let sym_compressed_sh = compress_zlib(sym_target_sh);

    let sym_target_trav = b"../../etc/shadow";
    let sym_compressed_trav = compress_zlib(sym_target_trav);

    let sym_target_dang = b"missing_target_file";
    let sym_compressed_dang = compress_zlib(sym_target_dang);

    let suid_content = b"\x7FELF\x01\x01\x01\x00synthetic-suid-binary";
    let suid_compressed = compress_zlib(suid_content);

    // 3. Write data payloads at aligned offsets (starting at 1024)
    // Payload for /bin/sh
    let sh_data_offset = align_up(image.len(), 4);
    image.resize(sh_data_offset, 0);
    let sh_blk_end = (sh_data_offset + 4 + sh_compressed.len()) as u32;
    write_u32_endian(&mut image, sh_blk_end, endian);
    image.extend_from_slice(&sh_compressed);

    // Payload for /bin/busybox symlink -> sh
    let sym_sh_offset = align_up(image.len(), 4);
    image.resize(sym_sh_offset, 0);
    let sym_sh_blk_end = (sym_sh_offset + 4 + sym_compressed_sh.len()) as u32;
    write_u32_endian(&mut image, sym_sh_blk_end, endian);
    image.extend_from_slice(&sym_compressed_sh);

    // Payload for /etc/banner
    let banner_data_offset = align_up(image.len(), 4);
    image.resize(banner_data_offset, 0);
    let banner_blk_end = (banner_data_offset + 4 + banner_compressed.len()) as u32;
    write_u32_endian(&mut image, banner_blk_end, endian);
    image.extend_from_slice(&banner_compressed);

    // Vulnerable payloads if requested
    let mut sym_trav_offset = 0;
    let mut sym_dang_offset = 0;
    let mut suid_data_offset = 0;

    if include_vulns {
        // Traversal symlink
        sym_trav_offset = align_up(image.len(), 4);
        image.resize(sym_trav_offset, 0);
        let trav_blk_end = (sym_trav_offset + 4 + sym_compressed_trav.len()) as u32;
        write_u32_endian(&mut image, trav_blk_end, endian);
        image.extend_from_slice(&sym_compressed_trav);

        // Dangling symlink
        sym_dang_offset = align_up(image.len(), 4);
        image.resize(sym_dang_offset, 0);
        let dang_blk_end = (sym_dang_offset + 4 + sym_compressed_dang.len()) as u32;
        write_u32_endian(&mut image, dang_blk_end, endian);
        image.extend_from_slice(&sym_compressed_dang);

        // SUID binary
        suid_data_offset = align_up(image.len(), 4);
        image.resize(suid_data_offset, 0);
        let suid_blk_end = (suid_data_offset + 4 + suid_compressed.len()) as u32;
        write_u32_endian(&mut image, suid_blk_end, endian);
        image.extend_from_slice(&suid_compressed);
    }

    // 4. Build subdirectories: /bin directory table
    let bin_dir_offset = align_up(image.len(), 4);
    image.resize(bin_dir_offset, 0);

    // Entry 1 in /bin: "sh"
    append_dirent(
        &mut image,
        "sh",
        CramFsInode {
            mode: S_IFREG | 0o755,
            uid: 0,
            size: sh_content.len() as u32,
            gid: 0,
            namelen: 0, // will be computed in append_dirent
            offset: (sh_data_offset >> 2) as u32,
        },
        endian,
    );

    // Entry 2 in /bin: "busybox"
    append_dirent(
        &mut image,
        "busybox",
        CramFsInode {
            mode: S_IFLNK | 0o777,
            uid: 0,
            size: sym_target_sh.len() as u32,
            gid: 0,
            namelen: 0,
            offset: (sym_sh_offset >> 2) as u32,
        },
        endian,
    );

    if include_vulns {
        append_dirent(
            &mut image,
            "malicious_sym",
            CramFsInode {
                mode: S_IFLNK | 0o777,
                uid: 0,
                size: sym_target_trav.len() as u32,
                gid: 0,
                namelen: 0,
                offset: (sym_trav_offset >> 2) as u32,
            },
            endian,
        );

        append_dirent(
            &mut image,
            "broken_sym",
            CramFsInode {
                mode: S_IFLNK | 0o777,
                uid: 0,
                size: sym_target_dang.len() as u32,
                gid: 0,
                namelen: 0,
                offset: (sym_dang_offset >> 2) as u32,
            },
            endian,
        );

        append_dirent(
            &mut image,
            "suid_tool",
            CramFsInode {
                mode: S_IFREG | S_ISUID | 0o755,
                uid: 0,
                size: suid_content.len() as u32,
                gid: 0,
                namelen: 0,
                offset: (suid_data_offset >> 2) as u32,
            },
            endian,
        );
    }
    let bin_dir_len = image.len() - bin_dir_offset;

    // 5. Build /etc directory table
    let etc_dir_offset = align_up(image.len(), 4);
    image.resize(etc_dir_offset, 0);

    append_dirent(
        &mut image,
        "banner",
        CramFsInode {
            mode: S_IFREG | 0o644,
            uid: 0,
            size: banner_content.len() as u32,
            gid: 0,
            namelen: 0,
            offset: (banner_data_offset >> 2) as u32,
        },
        endian,
    );
    let etc_dir_len = image.len() - etc_dir_offset;

    // 6. Build root directory table (at reserved offset 512)
    let root_dir_offset = 512;
    let mut root_table = Vec::new();

    append_dirent(
        &mut root_table,
        "bin",
        CramFsInode {
            mode: S_IFDIR | 0o755,
            uid: 0,
            size: bin_dir_len as u32,
            gid: 0,
            namelen: 0,
            offset: (bin_dir_offset >> 2) as u32,
        },
        endian,
    );

    append_dirent(
        &mut root_table,
        "etc",
        CramFsInode {
            mode: S_IFDIR | 0o755,
            uid: 0,
            size: etc_dir_len as u32,
            gid: 0,
            namelen: 0,
            offset: (etc_dir_offset >> 2) as u32,
        },
        endian,
    );

    let root_len = root_table.len();
    image[root_dir_offset..root_dir_offset + root_len].copy_from_slice(&root_table);

    // 7. Write Superblock at offset 0
    let total_size = image.len() as u32;

    let root_inode = CramFsInode {
        mode: S_IFDIR | 0o755,
        uid: 0,
        size: root_len as u32,
        gid: 0,
        namelen: 0,
        offset: (root_dir_offset >> 2) as u32,
    };

    let root_bytes = pack_inode(&root_inode, endian);

    match endian {
        Endianness::Little => {
            image[0..4].copy_from_slice(&CRAMFS_MAGIC.to_le_bytes());
            image[4..8].copy_from_slice(&total_size.to_le_bytes());
            image[8..12].copy_from_slice(&CRAMFS_FLAG_FSID_VERSION_2.to_le_bytes());
            image[12..16].copy_from_slice(&0u32.to_le_bytes()); // future
            image[32..36].copy_from_slice(&0x12345678u32.to_le_bytes()); // crc
            image[36..40].copy_from_slice(&1u32.to_le_bytes()); // edition
            image[40..44].copy_from_slice(&8u32.to_le_bytes()); // blocks
            image[44..48].copy_from_slice(&6u32.to_le_bytes()); // files
        }
        Endianness::Big => {
            image[0..4].copy_from_slice(&CRAMFS_MAGIC.to_be_bytes());
            image[4..8].copy_from_slice(&total_size.to_be_bytes());
            image[8..12].copy_from_slice(&CRAMFS_FLAG_FSID_VERSION_2.to_be_bytes());
            image[12..16].copy_from_slice(&0u32.to_be_bytes());
            image[32..36].copy_from_slice(&0x12345678u32.to_be_bytes());
            image[36..40].copy_from_slice(&1u32.to_be_bytes());
            image[40..44].copy_from_slice(&8u32.to_be_bytes());
            image[44..48].copy_from_slice(&6u32.to_be_bytes());
        }
    }

    image[16..32].copy_from_slice(CRAMFS_SIGNATURE);
    let vol_name = b"CRAMFS_TEST_ROM";
    image[48..48 + vol_name.len()].copy_from_slice(vol_name);
    image[64..76].copy_from_slice(&root_bytes);

    image
}

fn append_dirent(dest: &mut Vec<u8>, name: &str, mut inode: CramFsInode, endian: Endianness) {
    let name_bytes = name.as_bytes();
    let namelen_words = name_bytes.len().div_ceil(4);
    inode.namelen = namelen_words as u8;

    let inode_bytes = pack_inode(&inode, endian);
    dest.extend_from_slice(&inode_bytes);

    let aligned_namelen = namelen_words * 4;
    let start = dest.len();
    dest.resize(start + aligned_namelen, 0);
    dest[start..start + name_bytes.len()].copy_from_slice(name_bytes);
}

fn compress_zlib(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn align_up(val: usize, align: usize) -> usize {
    (val + align - 1) & !(align - 1)
}

fn write_u32_endian(dest: &mut Vec<u8>, val: u32, endian: Endianness) {
    match endian {
        Endianness::Little => dest.extend_from_slice(&val.to_le_bytes()),
        Endianness::Big => dest.extend_from_slice(&val.to_be_bytes()),
    }
}
