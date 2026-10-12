// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "fcarver",
    version = "0.1.0",
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
pub struct SynthFwArgs {
    /// Path to write synthetic firmware blob
    pub output: PathBuf,
    /// Container type: uboot, trx, fdt (default: uboot)
    #[arg(short = 't', long = "type", default_value = "uboot")]
    pub fw_type: String,
}
