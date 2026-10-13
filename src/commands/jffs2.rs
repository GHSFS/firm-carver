// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::common::{read_firmware_file, validate_offset};
use firm_carver::cli::Jffs2Args;
use firm_carver::error::Result;
use firm_carver::jffs2::{scan_jffs2_partitions, Jffs2Archive};
use zeroize::Zeroize;

pub fn handle_jffs2(args: Jffs2Args) -> Result<()> {
    let mut data = read_firmware_file(&args.file)?;

    let start_offset = if let Some(off) = args.offset {
        validate_offset(off, data.len())?;
        off
    } else {
        // Auto-scan for JFFS2 partition or default to 0
        let partitions = scan_jffs2_partitions(&data);
        if let Some(first) = partitions.first() {
            first.offset
        } else {
            0
        }
    };
    validate_offset(start_offset, data.len())?;

    let archive = Jffs2Archive::parse(&data[start_offset..])?;

    if let Some(out_dir) = &args.extract {
        let extracted = archive.extract_to_disk(out_dir)?;
        println!("=== FirmCarver JFFS2 Flash Filesystem Extractor ===");
        println!("Archive Source:     {}", args.file.display());
        println!("Extracted Entries:  {} entries", extracted);
        println!("Destination:        {}", out_dir.display());
    } else if args.json {
        println!("{}", serde_json::to_string_pretty(&archive)?);
    } else if args.list {
        println!("=== FirmCarver JFFS2 Flash Filesystem File Listing ===");
        println!(
            "Archive Source: {} (offset 0x{:08X})",
            args.file.display(),
            start_offset
        );
        println!("Endianness:     {:?}", archive.endianness);
        println!("Total Entries:  {}\n", archive.entries.len());
        println!("Permissions  UID  GID     Size Inode Path");
        println!("---------------------------------------------------------------");
        print!("{}", archive.format_listing());
    } else {
        println!("=== FirmCarver JFFS2 Flash Filesystem Inspector ===");
        println!("Target Image:     {}", args.file.display());
        println!("Partition Offset: 0x{:08X}", start_offset);
        println!("{}", archive.format_summary());
        println!("\nSample Recovered Files & Directories:");
        for e in archive.entries.iter().take(15) {
            let suffix = match &e.symlink_target {
                Some(t) => format!(" -> {}", t),
                None => String::new(),
            };
            println!(
                "  [{:>9}] {:<28} (size: {:6} B){}",
                e.file_type.as_str(),
                e.path,
                e.size,
                suffix
            );
        }
        if archive.entries.len() > 15 {
            println!(
                "  ... and {} more entries. Use --list for full listing, --extract <dir>, or --json.",
                archive.entries.len() - 15
            );
        }
    }

    data.zeroize();
    Ok(())
}
