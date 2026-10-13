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
use firm_carver::integrity::{
    build_synthetic_attested_firmware, format_integrity_report, format_verification_report,
    generate_attestation_manifest, verify_attestation, AttestationManifest, HashAlgorithm,
};
use firm_carver::slicer::{
    analyze_and_slice, build_synthetic_sliced_firmware, extract_sliced_partitions,
    format_slicer_report, SlicerConfig,
};
use firm_carver::squashfs::{build_synthetic_squashfs, SquashFsArchive};
use firm_carver::{carve_and_extract, scan_vulnerabilities, VulnSeverity};
use std::fs;
use std::path::Path;
use std::process;
use zeroize::Zeroize;

fn read_firmware_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| {
        CarverError::Io(std::io::Error::new(
            e.kind(),
            format!("Failed to read {}: {}", path.display(), e),
        ))
    })
}

fn find_magic_or_default(data: &[u8], offset: Option<usize>, magics: &[&[u8]]) -> usize {
    if let Some(off) = offset {
        return off;
    }
    for i in 0..data.len().saturating_sub(4) {
        if magics.iter().any(|m| data[i..].starts_with(m)) {
            return i;
        }
    }
    0
}

fn validate_offset(offset: usize, len: usize) -> Result<()> {
    if offset >= len {
        Err(CarverError::InvalidArgument(format!(
            "Offset 0x{:08X} exceeds file size {} bytes",
            offset, len
        )))
    } else {
        Ok(())
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Inspect(args) => {
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
            let mut data = read_firmware_file(&args.file)?;
            let manifest = carve_and_extract(&data, &args.out, &args.file.to_string_lossy())?;

            if args.json {
                println!("{}", serde_json::to_string_pretty(&manifest)?);
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
            let mut data = read_firmware_file(&args.file)?;
            let report = scan_vulnerabilities(&data, &args.file.to_string_lossy());

            if args.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
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
                println!("\nHint: Run with --dts for full disassembler output or --json.");
            }
            data.zeroize();
        }

        Commands::ArchDetect(args) => {
            let mut data = read_firmware_file(&args.file)?;
            validate_offset(args.offset, data.len())?;

            let slice = &data[args.offset..];
            let chunk_len = args.length.unwrap_or(slice.len()).min(slice.len());
            let analyze_slice = &slice[..chunk_len];

            let detector = ArchDetector {
                min_confidence: args.min_confidence,
            };
            let report = detector.analyze(analyze_slice, &args.file.to_string_lossy(), args.offset);

            if args.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print!("{}", format_arch_report(&report));
            }
            data.zeroize();
        }

        Commands::Slice(args) => {
            let mut data = read_firmware_file(&args.file)?;
            let config = SlicerConfig {
                window_size: args.window,
                step_size: args.step,
                threshold: args.threshold,
            };
            let report = analyze_and_slice(&data, &args.file.to_string_lossy(), &config);

            if let Some(out_dir) = &args.out {
                let written = extract_sliced_partitions(&data, &report.partitions, out_dir)?;
                if !args.json {
                    println!(
                        "Extracted {} partition files into: {}\n",
                        written.len(),
                        out_dir.display()
                    );
                }
            }

            if args.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print!("{}", format_slicer_report(&report, args.plot));
            }
            data.zeroize();
        }

        Commands::Integrity(args) => {
            let mut data = read_firmware_file(&args.file)?;
            let algo = args
                .algo
                .parse::<HashAlgorithm>()
                .map_err(CarverError::InvalidArgument)?;

            if let Some(verify_manifest_path) = &args.verify {
                let manifest = AttestationManifest::from_file(verify_manifest_path)?;
                let report = verify_attestation(&data, &manifest);

                if args.json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    print!("{}", format_verification_report(&report));
                }

                data.zeroize();
                if !report.overall_valid {
                    return Err(CarverError::Integrity(
                        "Attestation verification failed: cryptographic integrity mismatch detected"
                            .to_string(),
                    ));
                }
            } else {
                let target_name = args.file.file_name().unwrap_or_default().to_string_lossy();
                let manifest = generate_attestation_manifest(&target_name, &data);

                if let Some(out_path) = &args.out {
                    manifest.save_to_file(out_path)?;
                    if !args.json {
                        println!("Wrote attestation manifest to: {}\n", out_path.display());
                    }
                }

                if args.json {
                    println!("{}", serde_json::to_string_pretty(&manifest)?);
                } else {
                    print!("{}", format_integrity_report(&manifest, algo));
                }
                data.zeroize();
            }
        }

        Commands::SynthFw(args) => {
            let synthetic_blob = match args.fw_type.as_str() {
                "squashfs" => build_synthetic_squashfs(false),
                "fdt" | "dtb" => build_synthetic_fdt(),
                "multi-stage" | "sliced" | "stages" => build_synthetic_sliced_firmware(),
                "integrity" | "attested" | "attestation" => {
                    let (blob, _) = build_synthetic_attested_firmware();
                    blob
                }
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
