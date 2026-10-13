// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use clap::Parser;
use firm_carver::arch_detect::{
    build_synthetic_shellcode, format_arch_report, ArchDetector, Architecture, ShellcodeVariant,
};
use firm_carver::cli::{Cli, Commands};
use firm_carver::error::{CarverError, Result};
use firm_carver::fdt::{build_synthetic_fdt, FdtArchive};
use firm_carver::image::{build_synthetic_firmware, scan_containers, ContainerMetadata};
use firm_carver::squashfs::{build_synthetic_squashfs, SquashFsArchive};
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

        Commands::Squashfs(args) => {
            let mut data = fs::read(&args.file).map_err(|e| {
                CarverError::Io(std::io::Error::new(
                    e.kind(),
                    format!("Failed to read {}: {}", args.file.display(), e),
                ))
            })?;

            let start_offset = if let Some(off) = args.offset {
                off
            } else {
                let mut found = None;
                for i in 0..data.len().saturating_sub(4) {
                    let slice = &data[i..i + 4];
                    if slice == [0x73, 0x71, 0x73, 0x68] || slice == [0x68, 0x73, 0x71, 0x73] {
                        found = Some(i);
                        break;
                    }
                }
                found.unwrap_or(0)
            };

            if start_offset >= data.len() {
                return Err(CarverError::InvalidArgument(format!(
                    "Offset 0x{:08X} exceeds file size {} bytes",
                    start_offset,
                    data.len()
                )));
            }

            let archive = SquashFsArchive::parse(&data[start_offset..])?;

            if args.json {
                let json_output = serde_json::to_string_pretty(&archive)?;
                println!("{}", json_output);
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
                println!("Filesystem Offset:0x{:08X}", start_offset);
                println!("Endianness:       {:?}", archive.superblock.endianness);
                println!(
                    "Version:          v{}.{}",
                    archive.superblock.version_major, archive.superblock.version_minor
                );
                println!(
                    "Compression:      {}",
                    archive.superblock.compression.name()
                );
                println!("Block Size:       {} bytes", archive.superblock.block_size);
                println!("Inodes Count:     {}", archive.superblock.inode_count);
                println!("Bytes Used:       {} bytes", archive.superblock.bytes_used);
                println!("Recovered Entries:{}", archive.entries.len());
                println!();
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
        }

        Commands::Fdt(args) => {
            let mut data = fs::read(&args.file).map_err(|e| {
                CarverError::Io(std::io::Error::new(
                    e.kind(),
                    format!("Failed to read {}: {}", args.file.display(), e),
                ))
            })?;

            let start_offset = if let Some(off) = args.offset {
                off
            } else {
                let mut found = None;
                for i in 0..data.len().saturating_sub(4) {
                    if data[i..i + 4] == [0xD0, 0x0D, 0xFE, 0xED] {
                        found = Some(i);
                        break;
                    }
                }
                found.unwrap_or(0)
            };

            if start_offset >= data.len() {
                return Err(CarverError::InvalidArgument(format!(
                    "Offset 0x{:08X} exceeds file size {} bytes",
                    start_offset,
                    data.len()
                )));
            }

            let archive = FdtArchive::parse(&data[start_offset..])?;

            if args.json {
                let json_output = serde_json::to_string_pretty(&archive)?;
                println!("{}", json_output);
            } else if args.dts {
                print!("{}", archive.format_dts());
            } else if args.hardware {
                print!("{}", archive.format_hardware_summary());
            } else {
                println!("=== FirmCarver Device Tree Blob (FDT) Inspector ===");
                println!("Target Image:     {}", args.file.display());
                println!("FDT Offset:       0x{:08X}", start_offset);
                println!("Total Size:       {} bytes", archive.header.totalsize);
                println!("Version:          v{}", archive.header.version);
                println!("Struct Offset:    0x{:08X}", archive.header.off_dt_struct);
                println!("Strings Offset:   0x{:08X}", archive.header.off_dt_strings);
                println!("Memreserve Offset:0x{:08X}", archive.header.off_mem_rsvmap);
                println!("Reservations:     {}", archive.mem_rsvmap.len());
                println!();
                print!("{}", archive.format_hardware_summary());
                println!();
                println!("Hint: Run with --dts for full disassembler output or --json.");
            }
            data.zeroize();
        }

        Commands::ArchDetect(args) => {
            let mut data = fs::read(&args.file).map_err(|e| {
                CarverError::Io(std::io::Error::new(
                    e.kind(),
                    format!("Failed to read {}: {}", args.file.display(), e),
                ))
            })?;

            if args.offset >= data.len() {
                return Err(CarverError::InvalidArgument(format!(
                    "Offset 0x{:08X} exceeds file size {} bytes",
                    args.offset,
                    data.len()
                )));
            }

            let slice = &data[args.offset..];
            let chunk_len = if let Some(len) = args.length {
                len.min(slice.len())
            } else {
                slice.len()
            };
            let analyze_slice = &slice[..chunk_len];

            let detector = ArchDetector {
                min_confidence: args.min_confidence,
            };
            let report = detector.analyze(analyze_slice, &args.file.to_string_lossy(), args.offset);

            if args.json {
                let json_output = serde_json::to_string_pretty(&report)?;
                println!("{}", json_output);
            } else {
                print!("{}", format_arch_report(&report));
            }
            data.zeroize();
        }

        Commands::SynthFw(args) => {
            let synthetic_blob = match args.fw_type.as_str() {
                "squashfs" => build_synthetic_squashfs(false),
                "fdt" | "dtb" => build_synthetic_fdt(),
                "shellcode-mips" | "mips" => {
                    build_synthetic_shellcode(Architecture::MipsEb, ShellcodeVariant::ExecveSh)
                }
                "shellcode-arm" | "arm" => {
                    build_synthetic_shellcode(Architecture::ArmV7, ShellcodeVariant::ExecveSh)
                }
                "shellcode-aarch64" | "aarch64" | "arm64" => {
                    build_synthetic_shellcode(Architecture::AArch64, ShellcodeVariant::ExecveSh)
                }
                "shellcode-riscv" | "riscv" => {
                    build_synthetic_shellcode(Architecture::RiscV32, ShellcodeVariant::ExecveSh)
                }
                "shellcode-sled" => {
                    build_synthetic_shellcode(Architecture::ArmV7, ShellcodeVariant::NopSled)
                }
                _ => {
                    let mut sample_payload = Vec::new();
                    sample_payload.extend_from_slice(b"BOOTLOADER_INIT_ROUTINE");
                    sample_payload.extend_from_slice(&0x73717368u32.to_le_bytes());
                    sample_payload.extend_from_slice(&12u32.to_le_bytes());
                    sample_payload.extend_from_slice(&1_700_000_000u32.to_le_bytes());
                    sample_payload.extend_from_slice(&4096u32.to_le_bytes());
                    sample_payload.resize(64, 0);
                    sample_payload.extend_from_slice(&4u16.to_le_bytes());
                    sample_payload.extend_from_slice(&0u16.to_le_bytes());
                    sample_payload.resize(80, 0);
                    sample_payload.extend_from_slice(&128u64.to_le_bytes());
                    sample_payload.resize(128, 0xAA);
                    build_synthetic_firmware(&args.fw_type, &sample_payload)?
                }
            };

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
