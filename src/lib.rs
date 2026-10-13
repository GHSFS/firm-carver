// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

pub mod arch_detect;
pub mod carve;
pub mod cert_audit;
pub mod cgi_audit;
pub mod cli;
pub mod error;
pub mod fdt;
pub mod image;
pub mod integrity;
pub mod slicer;
pub mod squashfs;
pub mod vuln_scan;

pub use arch_detect::{
    build_synthetic_shellcode, detect_shellcode_patterns, disassemble_chunk, format_arch_report,
    ArchAuditReport, ArchDetector, ArchScore, Architecture, DecodedInsn, ShellcodeCategory,
    ShellcodeFinding, ShellcodeSeverity, ShellcodeVariant,
};
pub use carve::{
    carve_and_extract, scan_carvable_streams, CarveManifest, CarvedKind, CarvedSegment,
};
pub use cert_audit::{
    audit_cert_buffer, audit_cert_path, format_cert_report, CertAuditConfig, CertAuditReport,
    CertFinding, CertIssueKind, CertRuleEngine, CertScanner, CertSeverity, CertSynth,
    ParsedCertificate,
};
pub use cgi_audit::{
    audit_web_path, format_cgi_report, CgiAuditConfig, CgiAuditReport, CgiFinding, CgiRuleEngine,
    CgiScanner, CgiSeverity, CgiSynth, CgiVulnCategory,
};
pub use error::{CarverError, Result};
pub use fdt::{
    build_synthetic_fdt, CpuCore, FdtArchive, FdtHeader, FdtNode, FdtProperty, FdtReserveEntry,
    FlashPartition, MemoryRange, NetworkInterface, PeripheralMap, UartConsole, FDT_MAGIC,
};
pub use image::{
    build_synthetic_firmware, compute_crc32, scan_containers, ContainerKind, ContainerMetadata,
    DiscoveredContainer,
};
pub use integrity::{
    build_synthetic_attested_firmware, compute_blake3, compute_sha256, compute_sha512,
    constant_time_eq_str, format_integrity_report, format_verification_report,
    generate_attestation_manifest, tamper_firmware_byte, truncate_firmware, verify_attestation,
    AttestationManifest, DigestBundle, DigestMismatch, FindingStatus, HashAlgorithm,
    PartitionAttestation, VerificationFinding, VerificationReport,
};
pub use slicer::{
    analyze_and_slice, build_synthetic_sliced_firmware, compute_entropy_profile, detect_boundaries,
    extract_sliced_partitions, format_slicer_report, render_ascii_entropy_plot, shannon_entropy,
    slice_into_partitions, EntropyProfile, EntropyWindow, InflectionType, RegionKind,
    SliceBoundary, SlicedPartition, SlicerConfig, SlicerReport,
};
pub use squashfs::{build_synthetic_squashfs, SquashFsArchive, SquashFsEntry, SquashFsSuperblock};
pub use vuln_scan::{
    scan_vulnerabilities, VulnAuditReport, VulnCategory, VulnFinding, VulnSeverity,
};
