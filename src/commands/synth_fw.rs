// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use firm_carver::arch_detect::{build_synthetic_shellcode, Architecture, ShellcodeVariant};
use firm_carver::cert_audit::CertSynth;
use firm_carver::cgi_audit::CgiSynth;
use firm_carver::cli::SynthFwArgs;
use firm_carver::error::{CarverError, Result};
use firm_carver::fdt::build_synthetic_fdt;
use firm_carver::image::build_synthetic_firmware;
use firm_carver::integrity::build_synthetic_attested_firmware;
use firm_carver::slicer::build_synthetic_sliced_firmware;
use firm_carver::squashfs::build_synthetic_squashfs;
use std::fs;

pub fn handle_synth_fw(args: SynthFwArgs) -> Result<()> {
    if args.fw_type == "cgi-tree" || args.fw_type == "cgi" || args.fw_type == "www" {
        let created = CgiSynth::write_synthetic_web_tree_to_disk(&args.output)?;
        println!("=== FirmCarver Synthetic Web Tree Generator ===");
        println!("Destination:    {}", args.output.display());
        println!("Files Created:  {}", created.len());
        println!("Synthetic router /www management tree generated successfully.");
        return Ok(());
    }

    if args.fw_type == "cert-store" || args.fw_type == "certs" {
        let created = CertSynth::write_synthetic_cert_store(&args.output)?;
        println!("=== FirmCarver Synthetic Certificate Store Generator ===");
        println!("Destination:    {}", args.output.display());
        println!("Files Created:  {}", created.len());
        println!("Synthetic certificate store generated successfully.");
        return Ok(());
    }

    let synthetic_blob = match args.fw_type.as_str() {
        "ubi" => firm_carver::ubifs::build_synthetic_ubi(firm_carver::ubifs::Endianness::Little),
        "ubi-be" => firm_carver::ubifs::build_synthetic_ubi(firm_carver::ubifs::Endianness::Big),
        "ubifs" => {
            firm_carver::ubifs::build_synthetic_ubifs(firm_carver::ubifs::Endianness::Little)
        }
        "ubifs-be" => {
            firm_carver::ubifs::build_synthetic_ubifs(firm_carver::ubifs::Endianness::Big)
        }
        "jffs2" => firm_carver::jffs2::build_synthetic_jffs2(false),
        "jffs2-be" => firm_carver::jffs2::build_synthetic_jffs2(true),
        "nvram-bcm" | "nvram-flsh" => {
            let (blob, _) = firm_carver::nvram::build_synthetic_vulnerable_nvram();
            blob
        }
        "nvram-mtk" | "nvram-eeprom" => firm_carver::nvram::build_synthetic_mtk7628_factory(),
        "nvram-dat" => {
            let entries = [
                ("SSID1", "MediaTek_AP"),
                ("WPAPSK1", "12345678"),
                ("AuthMode", "WPA2PSK"),
                ("EncrypType", "AES"),
                ("CountryCode", "US"),
                ("BssidNum", "1"),
            ];
            firm_carver::nvram::build_synthetic_mediatek_dat(&entries)
        }
        "cert-blob" => CertSynth::build_synthetic_firmware_cert_blob(),
        "squashfs" => build_synthetic_squashfs(false),
        "fdt" | "dtb" => build_synthetic_fdt(),
        "multi-stage" | "sliced" | "stages" => build_synthetic_sliced_firmware(),
        "integrity" | "attested" | "attestation" => {
            let (blob, _) = build_synthetic_attested_firmware();
            blob
        }
        "domain-vuln" => {
            firm_carver::domain_audit::DomainSynth::build_synthetic_vulnerable_buffer()
        }
        "domain-hardened" => {
            firm_carver::domain_audit::DomainSynth::build_synthetic_hardened_buffer()
        }
        "vuln-cgi" => CgiSynth::build_synthetic_firmware_with_cgi(),
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
    Ok(())
}
