// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::common::{read_firmware_file, validate_offset};
use firm_carver::cli::CramfsArgs;
use firm_carver::cramfs::{CramFsArchive, CRAMFS_MAGIC_BE, CRAMFS_MAGIC_LE};
use firm_carver::error::Result;
use zeroize::Zeroize;

pub fn handle_cramfs(args: CramfsArgs) -> Result<()> {
    let mut data = read_firmware_file(&args.file)?;

    let start_offset = if let Some(off) = args.offset {
        off
    } else {
        find_cramfs_magic(&data).unwrap_or(0)
    };

    validate_offset(start_offset, data.len())?;

    let archive = CramFsArchive::parse_at(&data, start_offset)?;

    if let Some(dest_dir) = &args.extract {
        let extracted = archive.extract_to_disk(&data[start_offset..], dest_dir)?;
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
        println!("=== FirmCarver CramFS Security Audit ===");
        println!("Target Image:     {}", args.file.display());
        println!("Filesystem Name:  '{}'", archive.superblock.name);
        println!(
            "Offset / Endian:  0x{:08X} / {:?}",
            start_offset, archive.superblock.endianness
        );
        println!("Audit Summary:    {}\n", archive.format_summary());
        print!("{}", archive.format_audit_table());
    } else if args.list {
        println!("=== FirmCarver CramFS File Tree Listing ===");
        println!("Target Image:     {}", args.file.display());
        println!("Filesystem Name:  '{}'", archive.superblock.name);
        println!(
            "Offset / Endian:  0x{:08X} / {:?}",
            start_offset, archive.superblock.endianness
        );
        println!("Total Size:       {} bytes\n", archive.superblock.size);
        println!("Mode         UID  GID      Size   Offset Path");
        println!("----------------------------------------------------------------------");
        print!("{}", archive.format_listing());
    } else {
        println!("=== FirmCarver CramFS Compressed ROM Filesystem Inspector ===");
        println!("Target Image:     {}", args.file.display());
        println!("Filesystem Name:  '{}'", archive.superblock.name);
        println!(
            "Offset / Endian:  0x{:08X} / {:?}",
            start_offset, archive.superblock.endianness
        );
        println!("Total Size:       {} bytes", archive.superblock.size);
        println!("Feature Flags:    0x{:08X}", archive.superblock.flags);
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

fn find_cramfs_magic(data: &[u8]) -> Option<usize> {
    if data.len() < 4 {
        return None;
    }
    let mut i = 0;
    while i + 4 <= data.len() {
        let magic_le = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
        let magic_be = u32::from_be_bytes(data[i..i + 4].try_into().unwrap());
        if magic_le == CRAMFS_MAGIC_LE || magic_be == CRAMFS_MAGIC_BE || magic_le == CRAMFS_MAGIC_BE
        {
            return Some(i);
        }
        i += 4;
    }
    None
}
