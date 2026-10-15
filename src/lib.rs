// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

pub mod arch_detect;
pub mod carve;
pub mod cert_audit;
pub mod cgi_audit;
pub mod cli;
pub mod cramfs;
pub mod domain_audit;
pub mod error;
pub mod fdt;
pub mod image;
pub mod integrity;
pub mod jffs2;
pub mod nvram;
pub mod slicer;
pub mod squashfs;
pub mod ubifs;
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
pub use cramfs::{
    build_synthetic_cramfs, probe_cramfs_at, scan_cramfs_partitions, walk_directory_tree,
    CramFsArchive, CramFsAuditFinding, CramFsAuditReport, CramFsEntry, CramFsFileType,
    CramFsPartitionSpan, CramFsRuleEngine, CramFsSeverity, CramFsSummary, CramFsSuperblock,
    CRAMFS_MAGIC_BE, CRAMFS_MAGIC_LE,
};
pub use domain_audit::{
    audit_domain_buffer, audit_domain_path, format_domain_report, DomainAuditConfig,
    DomainAuditReport, DomainAuditSummary, DomainCategory, DomainIssueCode, DomainRuleEngine,
    DomainScanner, DomainSecurityIssue, DomainSeverity, DomainSynth, EndpointFinding, EndpointKind,
    IpScope, UrlScheme,
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
pub use jffs2::{
    build_synthetic_jffs2, extract_archive_to_disk, format_mode_string, scan_jffs2_partitions,
    CommonNodeHeader, Endianness, Jffs2Archive, Jffs2Entry, Jffs2FileType, Jffs2PartitionSpan,
    RawDirent, RawInode,
};
pub use nvram::{
    build_synthetic_broadcom_flsh, build_synthetic_hardened_nvram, build_synthetic_mediatek_dat,
    build_synthetic_mediatek_eeprom, build_synthetic_mt7620_factory,
    build_synthetic_mtk7628_factory, build_synthetic_packed_strings,
    build_synthetic_rt2880_factory, build_synthetic_vulnerable_nvram, compute_bcm_checksum8,
    compute_bcm_crc8, format_mac, parse_broadcom_flsh, parse_mediatek_dat, parse_mediatek_eeprom,
    parse_null_delimited_entries, parse_nvram_segment_at, probe_mediatek_dat, probe_nvram_at,
    scan_nvram_partitions, scan_packed_strings_tables, verify_wps_pin_checksum,
    BroadcomNvramHeader, MediaTekEepromHeader, NvramArchive, NvramAuditReport, NvramCategory,
    NvramEntry, NvramPartitionSpan, NvramRuleEngine, NvramSecurityIssue, NvramSeverity,
    NvramSourceKind, NvramSummary, BCM_NVRAM_HEADER_LEN, BCM_NVRAM_MAGIC_BE, BCM_NVRAM_MAGIC_LE,
    MTK_CHIP_MT7603, MTK_CHIP_MT7612, MTK_CHIP_MT7615, MTK_CHIP_MT7620, MTK_CHIP_MT7621,
    MTK_CHIP_MT7628, MTK_CHIP_MT7915, MTK_CHIP_RT2880, MTK_CHIP_RT3052, MTK_CHIP_RT3883,
};
pub use slicer::{
    analyze_and_slice, build_synthetic_sliced_firmware, compute_entropy_profile, detect_boundaries,
    extract_sliced_partitions, format_slicer_report, render_ascii_entropy_plot, shannon_entropy,
    slice_into_partitions, EntropyProfile, EntropyWindow, InflectionType, RegionKind,
    SliceBoundary, SlicedPartition, SlicerConfig, SlicerReport,
};
pub use squashfs::{build_synthetic_squashfs, SquashFsArchive, SquashFsEntry, SquashFsSuperblock};
pub use ubifs::{
    build_synthetic_ubi, build_synthetic_ubifs, scan_ubi_partitions, EraseCounterHeader, UbiImage,
    UbiPartitionSpan, UbiVolumeInfo, UbiVolumeType, UbifsArchive, UbifsDent, UbifsEntry,
    UbifsFileType, UbifsInode, UbifsMasterNode, UbifsNodeType, UbifsSuperblock,
    UBIFS_NODE_MAGIC_LE, UBI_EC_HDR_MAGIC, UBI_LAYOUT_VOLUME_ID, UBI_VID_HDR_MAGIC,
};
pub use vuln_scan::{
    scan_vulnerabilities, VulnAuditReport, VulnCategory, VulnFinding, VulnSeverity,
};
