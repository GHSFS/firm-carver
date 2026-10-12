// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::inode::*;
use super::superblock::SUPERBLOCK_SIZE;

/// Helper to serialize integer values respecting endianness.
struct EndianWriter {
    big_endian: bool,
}

impl EndianWriter {
    fn new(big_endian: bool) -> Self {
        Self { big_endian }
    }

    fn write_u16(&self, buf: &mut Vec<u8>, val: u16) {
        if self.big_endian {
            buf.extend_from_slice(&val.to_be_bytes());
        } else {
            buf.extend_from_slice(&val.to_le_bytes());
        }
    }

    fn write_i16(&self, buf: &mut Vec<u8>, val: i16) {
        if self.big_endian {
            buf.extend_from_slice(&val.to_be_bytes());
        } else {
            buf.extend_from_slice(&val.to_le_bytes());
        }
    }

    fn write_u32(&self, buf: &mut Vec<u8>, val: u32) {
        if self.big_endian {
            buf.extend_from_slice(&val.to_be_bytes());
        } else {
            buf.extend_from_slice(&val.to_le_bytes());
        }
    }

    fn write_u64(&self, buf: &mut Vec<u8>, val: u64) {
        if self.big_endian {
            buf.extend_from_slice(&val.to_be_bytes());
        } else {
            buf.extend_from_slice(&val.to_le_bytes());
        }
    }
}

/// Builds a deterministic, well-formed synthetic SquashFS v4.0 image for tests and simulations.
pub fn build_synthetic_squashfs(big_endian: bool) -> Vec<u8> {
    let ew = EndianWriter::new(big_endian);

    // 1. Prepare raw directory block contents
    let mut dir_raw = Vec::new();

    // Entry lengths:
    // Root dir has 2 entries: "bin" (entry_type=1) and "etc" (entry_type=1)
    // /bin dir has 2 entries: "busybox" (entry_type=2) and "sh" (entry_type=3)
    // /etc dir has 1 entry: "shadow" (entry_type=2)

    let root_dir_offset = dir_raw.len() as u16;
    // Directory Header for Root: count = 1 (2 entries: count_field = count - 1 = 1)
    ew.write_u32(&mut dir_raw, 1); // count = 1 (meaning 2 entries)
    ew.write_u32(&mut dir_raw, 0); // start_block = 0
    ew.write_u32(&mut dir_raw, 1); // base inode_number = 1

    // Entry 1: "bin" -> inode 2
    // offset will be set to inode 2's offset in inode block
    let bin_entry_offset_pos = dir_raw.len();
    ew.write_u16(&mut dir_raw, 0); // placeholder for inode 2 offset
    ew.write_i16(&mut dir_raw, 1); // inode_offset = 2 - 1 = 1
    ew.write_u16(&mut dir_raw, SQUASHFS_DIR_TYPE);
    ew.write_u16(&mut dir_raw, 3 - 1); // "bin" len - 1
    dir_raw.extend_from_slice(b"bin");

    // Entry 2: "etc" -> inode 5
    let etc_entry_offset_pos = dir_raw.len();
    ew.write_u16(&mut dir_raw, 0); // placeholder for inode 5 offset
    ew.write_i16(&mut dir_raw, 4); // inode_offset = 5 - 1 = 4
    ew.write_u16(&mut dir_raw, SQUASHFS_DIR_TYPE);
    ew.write_u16(&mut dir_raw, 3 - 1); // "etc" len - 1
    dir_raw.extend_from_slice(b"etc");

    let root_dir_size = (dir_raw.len() - root_dir_offset as usize) as u32 + 3;

    // /bin directory entries
    let bin_dir_offset = dir_raw.len() as u16;
    ew.write_u32(&mut dir_raw, 1); // count = 1 (2 entries)
    ew.write_u32(&mut dir_raw, 0); // start_block = 0
    ew.write_u32(&mut dir_raw, 1); // base inode = 1

    // Entry 1: "busybox" -> inode 3
    let busybox_entry_offset_pos = dir_raw.len();
    ew.write_u16(&mut dir_raw, 0); // placeholder for inode 3 offset
    ew.write_i16(&mut dir_raw, 2); // 3 - 1 = 2
    ew.write_u16(&mut dir_raw, SQUASHFS_FILE_TYPE);
    ew.write_u16(&mut dir_raw, 7 - 1); // "busybox"
    dir_raw.extend_from_slice(b"busybox");

    // Entry 2: "sh" -> inode 4
    let sh_entry_offset_pos = dir_raw.len();
    ew.write_u16(&mut dir_raw, 0); // placeholder for inode 4 offset
    ew.write_i16(&mut dir_raw, 3); // 4 - 1 = 3
    ew.write_u16(&mut dir_raw, SQUASHFS_SYMLINK_TYPE);
    ew.write_u16(&mut dir_raw, 2 - 1); // "sh"
    dir_raw.extend_from_slice(b"sh");

    let bin_dir_size = (dir_raw.len() - bin_dir_offset as usize) as u32 + 3;

    // /etc directory entries
    let etc_dir_offset = dir_raw.len() as u16;
    ew.write_u32(&mut dir_raw, 0); // count = 0 (1 entry)
    ew.write_u32(&mut dir_raw, 0); // start_block = 0
    ew.write_u32(&mut dir_raw, 1); // base inode = 1

    // Entry 1: "shadow" -> inode 6
    let shadow_entry_offset_pos = dir_raw.len();
    ew.write_u16(&mut dir_raw, 0); // placeholder for inode 6 offset
    ew.write_i16(&mut dir_raw, 5); // 6 - 1 = 5
    ew.write_u16(&mut dir_raw, SQUASHFS_FILE_TYPE);
    ew.write_u16(&mut dir_raw, 6 - 1); // "shadow"
    dir_raw.extend_from_slice(b"shadow");

    let etc_dir_size = (dir_raw.len() - etc_dir_offset as usize) as u32 + 3;

    // 2. Prepare raw inode block contents
    let mut inode_raw = Vec::new();

    // Inode 1: Root directory
    let root_inode_offset = inode_raw.len() as u16;
    ew.write_u16(&mut inode_raw, SQUASHFS_DIR_TYPE);
    ew.write_u16(&mut inode_raw, 0o755); // mode
    ew.write_u16(&mut inode_raw, 0); // uid_idx
    ew.write_u16(&mut inode_raw, 0); // gid_idx
    ew.write_u32(&mut inode_raw, 1_700_000_000); // mtime
    ew.write_u32(&mut inode_raw, 1); // inode_number 1
    ew.write_u32(&mut inode_raw, 0); // start_block in dir table
    ew.write_u32(&mut inode_raw, 2); // nlink
    ew.write_u16(&mut inode_raw, root_dir_size as u16);
    ew.write_u16(&mut inode_raw, root_dir_offset);
    ew.write_u32(&mut inode_raw, 1); // parent_inode 1

    // Inode 2: /bin directory
    let bin_inode_offset = inode_raw.len() as u16;
    ew.write_u16(&mut inode_raw, SQUASHFS_DIR_TYPE);
    ew.write_u16(&mut inode_raw, 0o755);
    ew.write_u16(&mut inode_raw, 0);
    ew.write_u16(&mut inode_raw, 0);
    ew.write_u32(&mut inode_raw, 1_700_000_000);
    ew.write_u32(&mut inode_raw, 2);
    ew.write_u32(&mut inode_raw, 0);
    ew.write_u32(&mut inode_raw, 2);
    ew.write_u16(&mut inode_raw, bin_dir_size as u16);
    ew.write_u16(&mut inode_raw, bin_dir_offset);
    ew.write_u32(&mut inode_raw, 1);

    // Inode 3: /bin/busybox (File)
    let busybox_inode_offset = inode_raw.len() as u16;
    ew.write_u16(&mut inode_raw, SQUASHFS_FILE_TYPE);
    ew.write_u16(&mut inode_raw, 0o755);
    ew.write_u16(&mut inode_raw, 0);
    ew.write_u16(&mut inode_raw, 0);
    ew.write_u32(&mut inode_raw, 1_700_000_000);
    ew.write_u32(&mut inode_raw, 3);
    ew.write_u32(&mut inode_raw, 0); // blocks_start
    ew.write_u32(&mut inode_raw, 0xFFFF_FFFF); // fragment_block_index
    ew.write_u32(&mut inode_raw, 0);
    ew.write_u32(&mut inode_raw, 1_048_576); // file_size 1MB

    // Inode 4: /bin/sh (Symlink -> "busybox")
    let sh_inode_offset = inode_raw.len() as u16;
    ew.write_u16(&mut inode_raw, SQUASHFS_SYMLINK_TYPE);
    ew.write_u16(&mut inode_raw, 0o777);
    ew.write_u16(&mut inode_raw, 0);
    ew.write_u16(&mut inode_raw, 0);
    ew.write_u32(&mut inode_raw, 1_700_000_000);
    ew.write_u32(&mut inode_raw, 4);
    ew.write_u32(&mut inode_raw, 1); // nlink
    ew.write_u32(&mut inode_raw, 7); // target_size
    inode_raw.extend_from_slice(b"busybox");

    // Inode 5: /etc directory
    let etc_inode_offset = inode_raw.len() as u16;
    ew.write_u16(&mut inode_raw, SQUASHFS_DIR_TYPE);
    ew.write_u16(&mut inode_raw, 0o755);
    ew.write_u16(&mut inode_raw, 0);
    ew.write_u16(&mut inode_raw, 0);
    ew.write_u32(&mut inode_raw, 1_700_000_000);
    ew.write_u32(&mut inode_raw, 5);
    ew.write_u32(&mut inode_raw, 0);
    ew.write_u32(&mut inode_raw, 2);
    ew.write_u16(&mut inode_raw, etc_dir_size as u16);
    ew.write_u16(&mut inode_raw, etc_dir_offset);
    ew.write_u32(&mut inode_raw, 1);

    // Inode 6: /etc/shadow (File)
    let shadow_inode_offset = inode_raw.len() as u16;
    ew.write_u16(&mut inode_raw, SQUASHFS_FILE_TYPE);
    ew.write_u16(&mut inode_raw, 0o600); // 0600 mode
    ew.write_u16(&mut inode_raw, 0);
    ew.write_u16(&mut inode_raw, 0);
    ew.write_u32(&mut inode_raw, 1_700_000_000);
    ew.write_u32(&mut inode_raw, 6);
    ew.write_u32(&mut inode_raw, 0);
    ew.write_u32(&mut inode_raw, 0xFFFF_FFFF);
    ew.write_u32(&mut inode_raw, 0);
    ew.write_u32(&mut inode_raw, 128); // 128 bytes

    // Now backfill directory entries with exact inode offsets in dir_raw!
    let patch_u16 = |buf: &mut [u8], pos: usize, val: u16| {
        let b = if big_endian {
            val.to_be_bytes()
        } else {
            val.to_le_bytes()
        };
        buf[pos..pos + 2].copy_from_slice(&b);
    };

    patch_u16(&mut dir_raw, bin_entry_offset_pos, bin_inode_offset);
    patch_u16(&mut dir_raw, etc_entry_offset_pos, etc_inode_offset);
    patch_u16(&mut dir_raw, busybox_entry_offset_pos, busybox_inode_offset);
    patch_u16(&mut dir_raw, sh_entry_offset_pos, sh_inode_offset);
    patch_u16(&mut dir_raw, shadow_entry_offset_pos, shadow_inode_offset);

    // 3. Assemble filesystem image with Uncompressed Metadata block headers (0x8000 | length)
    let mut image = vec![0u8; SUPERBLOCK_SIZE];

    let inode_table_start = image.len() as u64;
    // Inode table metadata block header:
    ew.write_u16(&mut image, 0x8000 | (inode_raw.len() as u16));
    image.extend_from_slice(&inode_raw);

    let directory_table_start = image.len() as u64;
    // Directory table metadata block header:
    ew.write_u16(&mut image, 0x8000 | (dir_raw.len() as u16));
    image.extend_from_slice(&dir_raw);

    let fragment_table_start = image.len() as u64;
    let id_table_start = image.len() as u64;
    let bytes_used = image.len() as u64;

    // 4. Fill Superblock (96 bytes)
    let magic_bytes = if big_endian {
        [0x68, 0x73, 0x71, 0x73]
    } else {
        [0x73, 0x71, 0x73, 0x68]
    };
    let root_inode_ref = root_inode_offset as u64;

    let mut sb = Vec::with_capacity(SUPERBLOCK_SIZE);
    sb.extend_from_slice(&magic_bytes);
    ew.write_u32(&mut sb, 6); // 6 inodes
    ew.write_u32(&mut sb, 1_700_000_000); // mkfs_time
    ew.write_u32(&mut sb, 4096); // block_size
    ew.write_u32(&mut sb, 0); // fragment_count
    ew.write_u16(&mut sb, 1); // compression = Gzip
    ew.write_u16(&mut sb, 12); // block_log = 12 (4096 = 1 << 12)
    ew.write_u16(&mut sb, 0x0001); // flags = uncompressed_inodes
    ew.write_u16(&mut sb, 1); // id_count = 1
    ew.write_u16(&mut sb, 4); // major 4
    ew.write_u16(&mut sb, 0); // minor 0
    ew.write_u64(&mut sb, root_inode_ref);
    ew.write_u64(&mut sb, bytes_used);
    ew.write_u64(&mut sb, id_table_start);
    ew.write_u64(&mut sb, 0xFFFF_FFFF_FFFF_FFFF); // no xattrs
    ew.write_u64(&mut sb, inode_table_start);
    ew.write_u64(&mut sb, directory_table_start);
    ew.write_u64(&mut sb, fragment_table_start);
    ew.write_u64(&mut sb, 0xFFFF_FFFF_FFFF_FFFF); // no lookup table

    image[0..SUPERBLOCK_SIZE].copy_from_slice(&sb);
    image
}
