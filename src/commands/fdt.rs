// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::common::{find_magic_or_default, read_firmware_file, validate_offset};
use firm_carver::cli::FdtArgs;
use firm_carver::error::Result;
use firm_carver::fdt::FdtArchive;
use zeroize::Zeroize;

pub fn handle_fdt(args: FdtArgs) -> Result<()> {
    let mut data = read_firmware_file(&args.file)?;
    let magics: [&[u8]; 1] = [&[0xD0, 0x0D, 0xFE, 0xED]];
    let start_offset = find_magic_or_default(&data, args.offset, &magics);
    validate_offset(start_offset, data.len())?;

    let archive = FdtArchive::parse(&data[start_offset..])?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&archive)?);
    } else if args.dts {
        print!("{}", archive.format_dts());
    } else if args.hardware {
        print!("{}", archive.format_hardware_summary());
    } else {
        println!("=== FirmCarver Device Tree Blob (FDT) Inspector ===");
        println!(
            "Target Image:     {} (offset 0x{:08X})",
            args.file.display(),
            start_offset
        );
        println!(
            "Total Size / Ver: {} bytes / v{}",
            archive.header.totalsize, archive.header.version
        );
        println!("Reservations:     {} entries\n", archive.mem_rsvmap.len());
        print!("{}", archive.format_hardware_summary());
        println!("\nHint: Run with --dts for full disassembler output or --json.");
    }
    data.zeroize();
    Ok(())
}
