// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "fcarver",
    version = env!("CARGO_PKG_VERSION"),
    author = "GHSFS",
    about = "Zero-dependency IoT and embedded firmware unpacker, multi-format magic carver, and static vulnerability auditing engine in pure Rust."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Inspect firmware container headers (U-Boot, TRX, FDT)
    Inspect(InspectArgs),
    /// Carve embedded filesystems (SquashFS, CramFS) and compressed streams
    Carve(CarveArgs),
    /// Audit firmware blob for embedded private keys, credentials, and backdoors
    Audit(AuditArgs),
    /// Extract directory tree and inode metadata from SquashFS v4 filesystems
    Squashfs(SquashfsArgs),
    /// Disassemble Flattened Device Tree (FDT/DTB) and map peripheral hardware
    Fdt(FdtArgs),
    /// Detect CPU instruction set architecture and scan for shellcode payloads
    ArchDetect(ArchDetectArgs),
    /// Generate a deterministic synthetic firmware blob for testing and analysis
    SynthFw(SynthFwArgs),
}

#[derive(Args, Debug)]
pub struct InspectArgs {
    /// Path to firmware binary file
    pub file: PathBuf,
    /// Output results in structured JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct CarveArgs {
    /// Path to firmware binary file
    pub file: PathBuf,
    /// Destination directory for carved segments
    #[arg(short, long)]
    pub out: PathBuf,
    /// Output extraction manifest in structured JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct AuditArgs {
    /// Path to firmware binary file
    pub file: PathBuf,
    /// Output vulnerability audit report in structured JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct SquashfsArgs {
    /// Path to firmware binary or extracted SquashFS image
    pub file: PathBuf,
    /// Byte offset where SquashFS filesystem begins (default: auto-scan or 0)
    #[arg(short, long)]
    pub offset: Option<usize>,
    /// Output extracted filesystem metadata in structured JSON format
    #[arg(long)]
    pub json: bool,
    /// List detailed file tree with permissions, sizes, and timestamps
    #[arg(short, long)]
    pub list: bool,
}

#[derive(Args, Debug)]
pub struct FdtArgs {
    /// Path to DTB file or firmware containing embedded FDT
    pub file: PathBuf,
    /// Byte offset where FDT begins (default: auto-scan or 0)
    #[arg(short, long)]
    pub offset: Option<usize>,
    /// Disassemble full tree into human-readable DTS (Device Tree Source) syntax
    #[arg(long)]
    pub dts: bool,
    /// Extract and summarize peripheral hardware (UART, Flash, Ethernet, Memory, CPU)
    #[arg(long)]
    pub hardware: bool,
    /// Output results in structured JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct ArchDetectArgs {
    /// Path to firmware binary file or extracted code chunk
    pub file: PathBuf,
    /// Byte offset where code chunk begins (default: 0)
    #[arg(short, long, default_value_t = 0)]
    pub offset: usize,
    /// Maximum length in bytes to analyze (default: 65536 or full file)
    #[arg(short, long)]
    pub length: Option<usize>,
    /// Minimum confidence threshold for architecture identification (0.0 to 1.0, default: 0.30)
    #[arg(long, default_value_t = 0.30)]
    pub min_confidence: f64,
    /// Disassemble sample instructions at start offset
    #[arg(long)]
    pub disasm: bool,
    /// Output audit report in structured JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct SynthFwArgs {
    /// Path to write synthetic firmware blob
    pub output: PathBuf,
    /// Container or code type: uboot, trx, fdt, squashfs, shellcode-mips, shellcode-arm, shellcode-aarch64, shellcode-riscv (default: uboot)
    #[arg(short = 't', long = "type", default_value = "uboot")]
    pub fw_type: String,
}
