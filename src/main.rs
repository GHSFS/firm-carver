// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use clap::Parser;
use firm_carver::cli::{Cli, Commands};
use firm_carver::error::{CarverError, Result};
use firm_carver::image::{build_synthetic_firmware, scan_containers, ContainerMetadata};
use firm_carver::{carve_and_extract, scan_vulnerabilities, VulnSeverity};
use std::fs;
use std::process;
use zeroize::Zeroize;

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Inspect(args) => {
            let mut data = fs::read(&args.file).map_err(|e| {
                CarverError::Io(std::io::Error::new(
                    e.kind(),
                    format!("Failed to read {}: {}", args.file.display(), e),
                ))
            })?;

            let containers = scan_containers(&data);

            if args.json {
                let json_output = serde_json::to_string_pretty(&containers)?;
                println!("{}", json_output);
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
                            println!("  Load Address: 0x{:08X}", u.load_address);
                            println!("  Entry Point:  0x{:08X}", u.entry_point);
                            println!("  OS / Arch:    OS {} / Arch {}", u.os_type, u.architecture);
                            println!("  Compression:  Type {}", u.compression);
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
                            println!("  Total Length: {} bytes", t.total_length);
                            println!("  Version:      {}", t.version);
                            println!("  Flags:        0x{:04X}", t.flags);
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
                            println!("  Total Size:   {} bytes", f.total_size);
                            println!("  FDT Version:  {}", f.version);
                            println!("  Struct Offset:0x{:08X}", f.off_dt_struct);
                            println!("  Strings Offset:0x{:08X}", f.off_dt_strings);
                        }
                    }
                    println!();
                }
            }
            data.zeroize();
        }

        Commands::Carve(args) => {
            let mut data = fs::read(&args.file).map_err(|e| {
                CarverError::Io(std::io::Error::new(
                    e.kind(),
                    format!("Failed to read {}: {}", args.file.display(), e),
                ))
            })?;

            let manifest = carve_and_extract(&data, &args.out, &args.file.to_string_lossy())?;

            if args.json {
                let json_output = serde_json::to_string_pretty(&manifest)?;
                println!("{}", json_output);
            } else {
                println!("=== FirmCarver Magic Stream Carving Engine ===");
                println!("Source File:      {}", args.file.display());
                println!("Output Directory: {}", args.out.display());
                println!("Carved Segments:  {}\n", manifest.carved_count);

                for (idx, seg) in manifest.segments.iter().enumerate() {
                    let file_str = seg.extracted_filename.as_deref().unwrap_or("none");
                    println!(
                        "[{:02}] Offset: 0x{:08X} | Length: {:8} bytes | File: {}",
                        idx + 1,
                        seg.offset,
                        seg.length,
                        file_str
                    );
                    println!("     Info: {}", seg.description);
                }
                println!(
                    "\nExtraction complete. Manifest saved to {}/manifest.json",
                    args.out.display()
                );
            }
            data.zeroize();
        }

        Commands::Audit(args) => {
            let mut data = fs::read(&args.file).map_err(|e| {
                CarverError::Io(std::io::Error::new(
                    e.kind(),
                    format!("Failed to read {}: {}", args.file.display(), e),
                ))
            })?;

            let report = scan_vulnerabilities(&data, &args.file.to_string_lossy());

            if args.json {
                let json_output = serde_json::to_string_pretty(&report)?;
                println!("{}", json_output);
            } else {
                println!("=== FirmCarver Static Vulnerability & Backdoor Audit ===");
                println!("Target File:   {}", report.target_file);
                println!("Scanned Size:  {} bytes", report.target_size);
                println!("Total Findings:{}", report.total_findings);
                println!(
                    "Severity:      Critical: {} | High: {} | Medium: {} | Low: {}\n",
                    report.critical_count, report.high_count, report.medium_count, report.low_count
                );

                if report.findings.is_empty() {
                    println!("No obvious static backdoors, private keys, or default shadow credentials found.");
                } else {
                    for (idx, f) in report.findings.iter().enumerate() {
                        let sev_label = match f.severity {
                            VulnSeverity::Critical => "[CRITICAL]",
                            VulnSeverity::High => "[HIGH]    ",
                            VulnSeverity::Medium => "[MEDIUM]  ",
                            VulnSeverity::Low => "[LOW]     ",
                        };
                        println!("#{:02} {} {} - {}", idx + 1, sev_label, f.id, f.title);
                        println!("     Offset:      0x{:08X}", f.offset);
                        println!("     Evidence:    \"{}\"", f.evidence);
                        println!("     Description: {}", f.description);
                        println!("     Remedy:      {}", f.remediation);
                        println!();
                    }
                }
            }
            data.zeroize();
        }

        Commands::SynthFw(args) => {
            // Embed a tiny mock rootfs payload containing a SquashFS superblock signature
            let mut sample_payload = Vec::new();
            sample_payload.extend_from_slice(b"BOOTLOADER_INIT_ROUTINE");
            // Add a synthetic squashfs superblock inside the payload
            sample_payload.extend_from_slice(&0x73717368u32.to_le_bytes()); // sqsh magic
            sample_payload.extend_from_slice(&12u32.to_le_bytes()); // 12 inodes
            sample_payload.extend_from_slice(&1_700_000_000u32.to_le_bytes()); // time
            sample_payload.extend_from_slice(&4096u32.to_le_bytes()); // 4k block size
            sample_payload.resize(64, 0); // pad to 64 bytes
            sample_payload.extend_from_slice(&4u16.to_le_bytes()); // major 4
            sample_payload.extend_from_slice(&0u16.to_le_bytes()); // minor 0
            sample_payload.resize(80, 0);
            sample_payload.extend_from_slice(&128u64.to_le_bytes()); // bytes_used = 128
            sample_payload.resize(128, 0xAA); // fill payload

            let synthetic_blob = build_synthetic_firmware(&args.fw_type, &sample_payload)?;

            fs::write(&args.output, &synthetic_blob).map_err(|e| {
                CarverError::Io(std::io::Error::new(
                    e.kind(),
                    format!("Failed to write {}: {}", args.output.display(), e),
                ))
            })?;

            println!("=== FirmCarver Synthetic Firmware Generator ===");
            println!("Container Type: {}", args.fw_type);
            println!("Output File:    {}", args.output.display());
            println!("Total Size:     {} bytes", synthetic_blob.len());
            println!("Synthetic firmware image generated successfully.");
        }
    }

    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("[Error] fcarver failed: {}", err);
        process::exit(1);
    }
}
