// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::common::{find_magic_or_default, read_firmware_file, validate_offset};
use firm_carver::cli::SquashfsArgs;
use firm_carver::error::Result;
use firm_carver::squashfs::SquashFsArchive;
use zeroize::Zeroize;

pub fn handle_squashfs(args: SquashfsArgs) -> Result<()> {
    let mut data = read_firmware_file(&args.file)?;
    let magics: [&[u8]; 2] = [b"sqsh", b"hsqs"];
    let start_offset = find_magic_or_default(&data, args.offset, &magics);
    validate_offset(start_offset, data.len())?;

    let archive = SquashFsArchive::parse(&data[start_offset..])?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&archive)?);
    } else if args.list {
        println!("=== FirmCarver SquashFS v4 File Listing ===");
        println!(
            "Archive Source: {} (offset 0x{:08X})",
            args.file.display(),
            start_offset
        );
        println!("Inodes:         {}", archive.superblock.inode_count);
        println!(
            "Compression:    {}\n",
            archive.superblock.compression.name()
        );
        println!("Permissions  UID  GID     Size Inode Path");
        println!("---------------------------------------------------------------");
        print!("{}", archive.format_listing());
    } else {
        println!("=== FirmCarver SquashFS v4 Filesystem Inspector ===");
        println!("Target Image:     {}", args.file.display());
        println!(
            "Offset / Endian:  0x{:08X} / {:?}",
            start_offset, archive.superblock.endianness
        );
        println!(
            "Version / Comp:   v{}.{} / {}",
            archive.superblock.version_major,
            archive.superblock.version_minor,
            archive.superblock.compression.name()
        );
        println!(
            "Block / Inodes:   {} bytes / {} nodes",
            archive.superblock.block_size, archive.superblock.inode_count
        );
        println!(
            "Bytes Used / Rec: {} bytes / {} entries\n",
            archive.superblock.bytes_used,
            archive.entries.len()
        );
        println!("Sample Recovered Files & Directories:");
        for e in archive.entries.iter().take(15) {
            let suffix = match &e.symlink_target {
                Some(t) => format!(" -> {}", t),
                None => String::new(),
            };
            println!(
                "  [{:>9}] {:<28} (size: {:6} B){}",
                e.inode_type, e.path, e.file_size, suffix
            );
        }
        if archive.entries.len() > 15 {
            println!(
                "  ... and {} more entries. Use --list for full listing or --json.",
                archive.entries.len() - 15
            );
        }
    }
    data.zeroize();
    Ok(())
}
