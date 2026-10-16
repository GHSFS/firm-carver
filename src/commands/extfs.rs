// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::common::{read_firmware_file, validate_offset};
use firm_carver::cli::ExtfsArgs;
use firm_carver::error::Result;
use firm_carver::extfs::{detect_endianness, ExtArchive, EXT_SUPERBLOCK_OFFSET, EXT_SUPER_MAGIC};
use zeroize::Zeroize;

pub fn handle_extfs(args: ExtfsArgs) -> Result<()> {
    let mut data = read_firmware_file(&args.file)?;

    let start_offset = if let Some(off) = args.offset {
        off
    } else {
        find_extfs_magic(&data).unwrap_or(0)
    };

    validate_offset(start_offset, data.len())?;

    let archive = ExtArchive::parse_at(&data, start_offset)?;

    if let Some(dest_dir) = &args.extract {
        let extracted = archive.extract_to_disk(&data, dest_dir)?;
        if !args.json {
            println!(
                "Extracted {} files and directories to '{}'",
                extracted,
                dest_dir.display()
            );
        }
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&archive)?);
    } else if args.audit {
        println!("=== FirmCarver Ext2/Ext3/Ext4 Security Audit ===");
        println!("Target Image:     {}", args.file.display());
        println!(
            "Filesystem Type:  {}",
            archive.superblock.version.as_str().to_uppercase()
        );
        println!("Volume Label:     '{}'", archive.superblock.volume_name);
        println!(
            "Offset / Endian:  0x{:08X} / {:?}",
            start_offset, archive.superblock.endianness
        );
        println!("Audit Summary:    {}\n", archive.format_summary());
        print!("{}", archive.format_audit_table());
    } else if args.list {
        println!("=== FirmCarver Ext2/Ext3/Ext4 File Tree Listing ===");
        println!("Target Image:     {}", args.file.display());
        println!(
            "Filesystem Type:  {}",
            archive.superblock.version.as_str().to_uppercase()
        );
        println!("Volume Label:     '{}'", archive.superblock.volume_name);
        println!(
            "Offset / Endian:  0x{:08X} / {:?}",
            start_offset, archive.superblock.endianness
        );
        println!(
            "Total Blocks:     {} (block size: {} bytes)\n",
            archive.superblock.blocks_count, archive.superblock.block_size
        );
        println!("Mode         UID  GID      Size Inode Path");
        println!(
            "--------------------------------------------------------------------------------"
        );
        print!("{}", archive.format_listing());
    } else {
        println!("=== FirmCarver Ext2/Ext3/Ext4 Filesystem Inspector ===");
        println!("Target Image:     {}", args.file.display());
        println!(
            "Filesystem Type:  {}",
            archive.superblock.version.as_str().to_uppercase()
        );
        println!("Volume Label:     '{}'", archive.superblock.volume_name);
        println!("Filesystem UUID:  {}", archive.superblock.uuid);
        println!(
            "Offset / Endian:  0x{:08X} / {:?}",
            start_offset, archive.superblock.endianness
        );
        println!(
            "Block Geometry:   {} blocks, {} inodes (block size: {} bytes)",
            archive.superblock.blocks_count,
            archive.superblock.inodes_count,
            archive.superblock.block_size
        );
        println!(
            "Recovered Tree:   {} entries ({} files, {} dirs, {} symlinks)\n",
            archive.summary.total_entries,
            archive.summary.regular_files,
            archive.summary.directories,
            archive.summary.symlinks
        );

        println!("Sample Recovered Files & Directories:");
        for e in archive.entries.iter().take(15) {
            let target_info = match &e.symlink_target {
                Some(t) => format!(" -> {}", t),
                None => String::new(),
            };
            println!(
                "  [{:>10}] {:<30} (size: {:6} B){}",
                e.file_type.as_str(),
                e.path,
                e.size,
                target_info
            );
        }
        if archive.entries.len() > 15 {
            println!(
                "  ... and {} more entries. Use --list for full listing or --audit for security check.",
                archive.entries.len() - 15
            );
        }
    }

    data.zeroize();
    Ok(())
}

fn find_extfs_magic(data: &[u8]) -> Option<usize> {
    if data.len() < EXT_SUPERBLOCK_OFFSET + 0x3A {
        return None;
    }
    let mut i = 0;
    while i + EXT_SUPERBLOCK_OFFSET + 0x3A <= data.len() {
        if detect_endianness(data, i).is_some() {
            let sb_magic_off = i + EXT_SUPERBLOCK_OFFSET + 0x38;
            let magic_le =
                u16::from_le_bytes(data[sb_magic_off..sb_magic_off + 2].try_into().unwrap());
            let magic_be =
                u16::from_be_bytes(data[sb_magic_off..sb_magic_off + 2].try_into().unwrap());
            if magic_le == EXT_SUPER_MAGIC || magic_be == EXT_SUPER_MAGIC {
                return Some(i);
            }
        }
        i += 512;
    }
    None
}
