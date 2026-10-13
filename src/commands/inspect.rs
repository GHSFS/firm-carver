// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::common::read_firmware_file;
use firm_carver::cli::InspectArgs;
use firm_carver::error::Result;
use firm_carver::image::{scan_containers, ContainerMetadata};
use zeroize::Zeroize;

pub fn handle_inspect(args: InspectArgs) -> Result<()> {
    let mut data = read_firmware_file(&args.file)?;
    let containers = scan_containers(&data);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&containers)?);
    } else {
        println!("=== FirmCarver Container Inspector ===");
        println!("Target Image: {}", args.file.display());
        println!("Total Size:   {} bytes", data.len());
        println!("Containers:   {} found\n", containers.len());

        if containers.is_empty() {
            println!("No standard U-Boot, TRX, or FDT container headers detected.");
            println!("Hint: The file might be a raw partition, unpadded stream, or custom header.");
        }

        for (idx, c) in containers.iter().enumerate() {
            println!(
                "Container #{:02} at offset 0x{:08X}:",
                idx + 1,
                c.container_offset
            );
            match &c.metadata {
                ContainerMetadata::UBoot(u) => {
                    println!("  Type:         U-Boot uImage (Magic 0x{:08X})", u.magic);
                    println!("  Image Name:   \"{}\"", u.image_name);
                    println!(
                        "  Data Size:    {} bytes (0x{:X})",
                        u.data_size, u.data_size
                    );
                    println!(
                        "  Load / Entry: 0x{:08X} / 0x{:08X}",
                        u.load_address, u.entry_point
                    );
                    println!(
                        "  OS / Arch:    OS {} / Arch {} (Compression: Type {})",
                        u.os_type, u.architecture, u.compression
                    );
                    println!(
                        "  Header CRC:   0x{:08X} (Valid: {})",
                        u.header_crc, u.header_crc_valid
                    );
                    if let Some(valid) = u.data_crc_valid {
                        println!("  Data CRC:     0x{:08X} (Valid: {})", u.data_crc, valid);
                    }
                }
                ContainerMetadata::Trx(t) => {
                    println!(
                        "  Type:         Broadcom TRX Header (Magic \"{}\")",
                        t.magic
                    );
                    println!(
                        "  Length / Ver: {} bytes / v{} (Flags: 0x{:04X})",
                        t.total_length, t.version, t.flags
                    );
                    println!(
                        "  Offsets:      [0x{:X}, 0x{:X}, 0x{:X}]",
                        t.offsets[0], t.offsets[1], t.offsets[2]
                    );
                    if let Some(valid) = t.crc_valid {
                        println!("  Header CRC32: 0x{:08X} (Valid: {})", t.crc32, valid);
                    }
                }
                ContainerMetadata::Fdt(f) => {
                    println!(
                        "  Type:         Device Tree Blob FDT (Magic 0x{:08X})",
                        f.magic
                    );
                    println!("  Size / Ver:   {} bytes / v{}", f.total_size, f.version);
                    println!(
                        "  Offsets:      struct 0x{:08X}, strings 0x{:08X}",
                        f.off_dt_struct, f.off_dt_strings
                    );
                }
            }
            println!();
        }
    }
    data.zeroize();
    Ok(())
}
