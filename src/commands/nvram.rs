// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::common::{read_firmware_file, validate_offset};
use firm_carver::cli::NvramArgs;
use firm_carver::error::{CarverError, Result};
use firm_carver::nvram::{scan_nvram_partitions, NvramArchive};
use zeroize::Zeroize;

pub fn handle_nvram(args: NvramArgs) -> Result<()> {
    let mut data = read_firmware_file(&args.file)?;

    let start_offset = if let Some(off) = args.offset {
        validate_offset(off, data.len())?;
        off
    } else {
        let partitions = scan_nvram_partitions(&data);
        if let Some(first) = partitions.first() {
            first.offset
        } else {
            0
        }
    };
    validate_offset(start_offset, data.len())?;

    let slice = &data[start_offset..];
    let mut archive = match args.format.to_ascii_lowercase().as_str() {
        "broadcom" | "bcm-flsh" => NvramArchive::parse_broadcom(slice)?,
        "bcm-packed" | "packed" => NvramArchive::parse_packed_strings(slice)?,
        "mediatek" | "mtk" | "mtk-dat" | "mtk-eeprom" => NvramArchive::parse_mediatek(slice)?,
        "auto" => NvramArchive::parse(slice)?,
        other => {
            return Err(CarverError::InvalidArgument(format!(
                "Unsupported NVRAM format filter: '{}'. Expected auto, broadcom, bcm-flsh, bcm-packed, mediatek, mtk-dat, mtk-eeprom.",
                other
            )))
        }
    };

    if let Some(out_path) = &args.extract {
        let count = archive.extract_to_env_file(out_path)?;
        println!("=== FirmCarver NVRAM Parameter Extractor ===");
        println!("Firmware Source:    {}", args.file.display());
        println!("Extracted Entries:  {} variables", count);
        println!("Output .env File:   {}", out_path.display());
    } else if args.json {
        if args.audit {
            let report = archive.audit_nvram();
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            println!("{}", serde_json::to_string_pretty(&archive)?);
        }
    } else if args.audit {
        let report = archive.audit_nvram();
        print!("{}", NvramArchive::format_audit_table(&report));
    } else if args.list {
        println!("=== FirmCarver NVRAM Parameter Listing ===");
        println!(
            "Source Image:   {} (offset 0x{:08X})",
            args.file.display(),
            start_offset
        );
        print!("{}", archive.format_summary());
        println!("---------------------------------------------------------------");
        print!("{}", archive.format_listing());
    } else {
        println!("=== FirmCarver NVRAM Partition Inspector ===");
        println!("Target Image:     {}", args.file.display());
        println!("Partition Offset: 0x{:08X}", start_offset);
        print!("{}", archive.format_summary());
        println!("\nSample Recovered Parameters:");
        for e in archive.entries.iter().take(15) {
            println!("  {:<28} = {}", e.key, e.value);
        }
        if archive.entries.len() > 15 {
            println!(
                "  ... and {} more parameters. Use --list, --audit, --extract <file.env>, or --json.",
                archive.entries.len() - 15
            );
        }
    }

    archive.zeroize();
    data.zeroize();
    Ok(())
}
