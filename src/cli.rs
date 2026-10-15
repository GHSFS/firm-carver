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
    /// Parse, walk directory trees, resolve symlinks, and audit CramFS compressed filesystems
    Cramfs(CramfsArgs),
    /// Carve, parse, and reconstruct JFFS2 flash filesystem directory trees and nodes
    Jffs2(Jffs2Args),
    /// Parse UBI volume headers, LEB mappings, and extract UBIFS directory trees and nodes
    Ubifs(UbifsArgs),
    /// Disassemble Flattened Device Tree (FDT/DTB) and map peripheral hardware
    Fdt(FdtArgs),
    /// Detect CPU instruction set architecture and scan for shellcode payloads
    ArchDetect(ArchDetectArgs),
    /// Slice firmware into bootloader, kernel, and filesystem partitions via Shannon entropy
    Slice(SliceArgs),
    /// Generate or verify cryptographic hash digests (SHA-256, SHA-512, BLAKE3) and integrity attestations
    Integrity(IntegrityArgs),
    /// Audit embedded /www directory tree or CGI scripts for command injection and unauthenticated routes
    CgiAudit(CgiAuditArgs),
    /// Audit TLS certificates, root CA stores, weak signature algos, and leaked private keys
    CertAudit(CertAuditArgs),
    /// Extract, carve, and audit Broadcom and MediaTek NVRAM tables and parameters
    Nvram(NvramArgs),
    /// Audit firmware or directories for embedded URLs, IPv4/IPv6 endpoints, and telemetry domains
    DomainAudit(DomainAuditArgs),
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
pub struct CramfsArgs {
    /// Path to firmware binary or extracted CramFS image
    pub file: PathBuf,
    /// Byte offset where CramFS filesystem begins (default: auto-scan or 0)
    #[arg(short, long)]
    pub offset: Option<usize>,
    /// Destination directory to safely extract recovered files and symlinks
    #[arg(short, long)]
    pub extract: Option<PathBuf>,
    /// Run security posture audit on directory records and symlinks
    #[arg(short, long)]
    pub audit: bool,
    /// Output extracted filesystem metadata in structured JSON format
    #[arg(long)]
    pub json: bool,
    /// List detailed file tree with permissions, sizes, and symlink targets
    #[arg(short, long)]
    pub list: bool,
}

#[derive(Args, Debug)]
pub struct Jffs2Args {
    /// Path to firmware binary or extracted JFFS2 flash dump
    pub file: PathBuf,
    /// Byte offset where JFFS2 filesystem begins (default: auto-scan or 0)
    #[arg(short, long)]
    pub offset: Option<usize>,
    /// Destination directory to extract reconstructed files and directory tree
    #[arg(short, long)]
    pub extract: Option<PathBuf>,
    /// Output extracted filesystem metadata in structured JSON format
    #[arg(long)]
    pub json: bool,
    /// List detailed file tree with permissions, sizes, and timestamps
    #[arg(short, long)]
    pub list: bool,
}

#[derive(Args, Debug)]
pub struct UbifsArgs {
    /// Path to firmware binary or extracted UBI/UBIFS flash dump
    pub file: PathBuf,
    /// Byte offset where UBI or UBIFS begins (default: auto-scan or 0)
    #[arg(short, long)]
    pub offset: Option<usize>,
    /// Physical Eraseblock (PEB) size in bytes for raw UBI scanning (default: auto-detect)
    #[arg(short, long)]
    pub peb_size: Option<usize>,
    /// Destination directory to extract reconstructed files and directory tree
    #[arg(short, long)]
    pub extract: Option<PathBuf>,
    /// Output extracted volume and filesystem metadata in structured JSON format
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
pub struct SliceArgs {
    /// Path to firmware binary file
    pub file: PathBuf,
    /// Destination directory for sliced partition files (optional)
    #[arg(short, long)]
    pub out: Option<PathBuf>,
    /// Window size in bytes for sliding entropy calculation (default: 512)
    #[arg(short, long, default_value_t = 512)]
    pub window: usize,
    /// Step stride in bytes between consecutive windows (default: 256)
    #[arg(short, long, default_value_t = 256)]
    pub step: usize,
    /// Delta entropy threshold for inflection point detection (default: 0.80)
    #[arg(short, long, default_value_t = 0.80)]
    pub threshold: f64,
    /// Display ASCII entropy curve in terminal
    #[arg(long)]
    pub plot: bool,
    /// Output results in structured JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct IntegrityArgs {
    /// Path to firmware binary file
    pub file: PathBuf,
    /// Destination path to export verifiable attestation manifest JSON
    #[arg(short, long)]
    pub out: Option<PathBuf>,
    /// Verify firmware against an existing attestation manifest JSON file
    #[arg(long)]
    pub verify: Option<PathBuf>,
    /// Cryptographic algorithm filter: sha256, sha512, blake3, all (default: all)
    #[arg(short, long, default_value = "all")]
    pub algo: String,
    /// Output results in structured JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct CgiAuditArgs {
    /// Path to web directory (e.g. /www or /cgi-bin) or individual CGI script file
    pub target: PathBuf,
    /// Destination path to export JSON audit report
    #[arg(short, long)]
    pub out: Option<PathBuf>,
    /// Minimum severity filter: critical, high, medium, low, info (default: low)
    #[arg(short, long, default_value = "low")]
    pub min_severity: String,
    /// Output audit findings in structured JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct CertAuditArgs {
    /// Path to certificate file, PEM bundle, directory, or firmware binary
    pub file: PathBuf,
    /// Destination path to export JSON audit report
    #[arg(short, long)]
    pub out: Option<PathBuf>,
    /// Minimum severity filter: critical, high, medium, low, info (default: low)
    #[arg(short, long, default_value = "low")]
    pub min_severity: String,
    /// Reference audit date (RFC 3339 date string like 2026-10-13 or seconds since epoch)
    #[arg(short, long)]
    pub reference_date: Option<String>,
    /// Output audit findings in structured JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct NvramArgs {
    /// Path to firmware binary or extracted NVRAM partition dump
    pub file: PathBuf,
    /// Byte offset where NVRAM begins (default: auto-scan or 0)
    #[arg(short, long)]
    pub offset: Option<usize>,
    /// Format filter: auto, broadcom, bcm-flsh, bcm-packed, mediatek, mtk-dat, mtk-eeprom (default: auto)
    #[arg(short = 'f', long = "format", default_value = "auto")]
    pub format: String,
    /// Destination path to export extracted parameters as .env file
    #[arg(short, long)]
    pub extract: Option<PathBuf>,
    /// Run security posture audit on extracted NVRAM parameters
    #[arg(short, long)]
    pub audit: bool,
    /// Output results in structured JSON format
    #[arg(long)]
    pub json: bool,
    /// List all extracted key-value pairs
    #[arg(short, long)]
    pub list: bool,
}

#[derive(Args, Debug)]
pub struct DomainAuditArgs {
    /// Path to firmware binary, extracted filesystem directory, or configuration file
    pub target: PathBuf,
    /// Byte offset where analysis begins in binary mode (default: 0)
    #[arg(short, long)]
    pub offset: Option<usize>,
    /// Minimum severity filter: critical, high, medium, low, info (default: low)
    #[arg(short, long, default_value = "low")]
    pub min_severity: String,
    /// Filter endpoint kind: url, ipv4, ipv6, domain, all (default: all)
    #[arg(short, long, default_value = "all")]
    pub filter: String,
    /// Minimum printable string length when scanning binary blobs (default: 4)
    #[arg(long, default_value_t = 4)]
    pub min_len: usize,
    /// Exclude RFC 1918 private IP addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    #[arg(long)]
    pub no_private: bool,
    /// Destination path to export JSON audit report
    #[arg(short, long)]
    pub out: Option<PathBuf>,
    /// Output audit findings in structured JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct SynthFwArgs {
    /// Path to write synthetic firmware blob or directory
    pub output: PathBuf,
    /// Container or code type: uboot, trx, fdt, squashfs, cramfs, cramfs-be, multi-stage, shellcode-mips, shellcode-arm, shellcode-aarch64, shellcode-riscv, integrity, cgi-tree, vuln-cgi, cert-store, cert-blob, nvram-bcm, nvram-mtk, nvram-dat, domain-vuln, domain-hardened (default: uboot)
    #[arg(short = 't', long = "type", default_value = "uboot")]
    pub fw_type: String,
}
