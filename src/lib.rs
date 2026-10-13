// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

pub mod arch_detect;
pub mod carve;
pub mod cli;
pub mod error;
pub mod fdt;
pub mod image;
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
pub use error::{CarverError, Result};
pub use fdt::{
    build_synthetic_fdt, CpuCore, FdtArchive, FdtHeader, FdtNode, FdtProperty, FdtReserveEntry,
    FlashPartition, MemoryRange, NetworkInterface, PeripheralMap, UartConsole, FDT_MAGIC,
};
pub use image::{
    build_synthetic_firmware, compute_crc32, scan_containers, ContainerKind, ContainerMetadata,
    DiscoveredContainer,
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
