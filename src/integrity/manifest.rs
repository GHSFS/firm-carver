// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::digest::{DigestBundle, DigestMismatch};
use crate::carve::scan_carvable_streams;
use crate::error::{CarverError, Result};
use crate::image::{scan_containers, ContainerMetadata};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Attestation entry for a specific container header, filesystem, or carved payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionAttestation {
    /// Human-readable descriptor of the partition or container segment
    pub name: String,
    /// Partition category (e.g., "container_header", "container_payload", "carved_stream")
    pub category: String,
    /// Byte offset where partition starts within the container
    pub offset: u64,
    /// Exact byte size of the partition
    pub size: u64,
    /// Cryptographic digest bundle across this partition slice
    pub digests: DigestBundle,
}

/// Cryptographically verifiable attestation manifest covering entire image and partitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationManifest {
    /// Schema format version
    pub schema_version: String,
    /// Reference name or filename of target firmware image
    pub target_file: String,
    /// Total image file length in bytes
    pub file_size: u64,
    /// Cryptographic digests over the entire firmware binary file
    pub file_digests: DigestBundle,
    /// Individual attestation records for discovered containers and partitions
    pub partitions: Vec<PartitionAttestation>,
}

impl AttestationManifest {
    /// Load an attestation manifest from a JSON file on disk.
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path).map_err(|e| {
            CarverError::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to read manifest {}: {}", path.display(), e),
            ))
        })?;
        serde_json::from_str(&content).map_err(|e| {
            CarverError::Integrity(format!(
                "Failed to parse manifest JSON {}: {}",
                path.display(),
                e
            ))
        })
    }

    /// Save the attestation manifest as formatted JSON to a destination path.
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let json_str = self.to_json_pretty()?;
        fs::write(path, json_str).map_err(|e| {
            CarverError::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to write manifest {}: {}", path.display(), e),
            ))
        })
    }

    /// Serialize manifest into human-readable formatted JSON string.
    pub fn to_json_pretty(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| CarverError::Integrity(format!("JSON serialization failed: {}", e)))
    }
}

/// Status classification of an individual attestation verification check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    /// Computed digests strictly match the expected manifest digests
    Valid,
    /// Computed digests differ from the manifest (indicates modification or tampering)
    HashMismatch,
    /// Partition offset and size exceed current binary file boundaries
    OutOfBounds,
    /// Total file length does not match manifest
    FileLengthMismatch,
}

/// Detailed verification finding for a single partition or container header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationFinding {
    /// Partition or container label
    pub name: String,
    /// Category classification
    pub category: String,
    /// Starting byte offset in image
    pub offset: u64,
    /// Declared size in bytes
    pub size: u64,
    /// Outcome status of the verification check
    pub status: FindingStatus,
    /// List of algorithm mismatches if hash comparison failed
    pub mismatches: Vec<DigestMismatch>,
    /// Human-readable explanation of outcome
    pub message: String,
}

/// Comprehensive verification report detailing attestation validity across the binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReport {
    /// True if file-level and all partition-level digests strictly match
    pub overall_valid: bool,
    /// True if full binary file SHA-256, SHA-512, and BLAKE3 digests match
    pub file_digests_match: bool,
    /// Total partitions evaluated
    pub total_partitions: usize,
    /// Number of partitions that successfully verified
    pub passed_partitions: usize,
    /// Number of partitions that failed verification
    pub failed_partitions: usize,
    /// Individual findings for each checked partition
    pub findings: Vec<VerificationFinding>,
}

impl VerificationReport {
    /// Serialize report into formatted JSON string.
    pub fn to_json_pretty(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| CarverError::Integrity(format!("JSON serialization failed: {}", e)))
    }
}

/// Generate a complete attestation manifest from raw firmware image bytes.
pub fn generate_attestation_manifest(target_name: &str, data: &[u8]) -> AttestationManifest {
    let file_digests = DigestBundle::compute(data);
    let mut partitions = Vec::new();

    // 1. Scan container headers (U-Boot, TRX, FDT)
    let containers = scan_containers(data);
    for (i, c) in containers.iter().enumerate() {
        let base_off = c.container_offset as u64;
        match &c.metadata {
            ContainerMetadata::UBoot(u) => {
                let header_len = 64u64.min(data.len().saturating_sub(c.container_offset) as u64);
                if header_len > 0 {
                    let slice = &data[c.container_offset..c.container_offset + header_len as usize];
                    partitions.push(PartitionAttestation {
                        name: format!("uboot_header_{}", i + 1),
                        category: "container_header".to_string(),
                        offset: base_off,
                        size: header_len,
                        digests: DigestBundle::compute(slice),
                    });
                }
                if u.data_size > 0 {
                    let payload_off = c.container_offset + 64;
                    let payload_len =
                        (u.data_size as usize).min(data.len().saturating_sub(payload_off));
                    if payload_len > 0 {
                        let slice = &data[payload_off..payload_off + payload_len];
                        partitions.push(PartitionAttestation {
                            name: format!("uboot_payload_{}", i + 1),
                            category: "container_payload".to_string(),
                            offset: payload_off as u64,
                            size: payload_len as u64,
                            digests: DigestBundle::compute(slice),
                        });
                    }
                }
            }
            ContainerMetadata::Trx(t) => {
                let header_len = 28u64.min(data.len().saturating_sub(c.container_offset) as u64);
                if header_len > 0 {
                    let slice = &data[c.container_offset..c.container_offset + header_len as usize];
                    partitions.push(PartitionAttestation {
                        name: format!("trx_header_{}", i + 1),
                        category: "container_header".to_string(),
                        offset: base_off,
                        size: header_len,
                        digests: DigestBundle::compute(slice),
                    });
                }
                if t.total_length > 28 {
                    let total_trx_len = (t.total_length as usize)
                        .min(data.len().saturating_sub(c.container_offset));
                    let slice = &data[c.container_offset..c.container_offset + total_trx_len];
                    partitions.push(PartitionAttestation {
                        name: format!("trx_body_{}", i + 1),
                        category: "container_body".to_string(),
                        offset: base_off,
                        size: total_trx_len as u64,
                        digests: DigestBundle::compute(slice),
                    });
                }
            }
            ContainerMetadata::Fdt(f) => {
                let fdt_len =
                    (f.total_size as usize).min(data.len().saturating_sub(c.container_offset));
                if fdt_len > 0 {
                    let slice = &data[c.container_offset..c.container_offset + fdt_len];
                    partitions.push(PartitionAttestation {
                        name: format!("fdt_blob_{}", i + 1),
                        category: "container_blob".to_string(),
                        offset: base_off,
                        size: fdt_len as u64,
                        digests: DigestBundle::compute(slice),
                    });
                }
            }
        }
    }

    // 2. Scan carvable streams (SquashFS, CramFS, Gzip, LZMA, XZ)
    let carvable = scan_carvable_streams(data);
    for (i, stream) in carvable.iter().enumerate() {
        let stream_off = stream.offset;
        let stream_len = stream.length.min(data.len().saturating_sub(stream_off));
        if stream_len > 0 {
            let slice = &data[stream_off..stream_off + stream_len];
            let kind_label = format!("{:?}", stream.kind).to_lowercase();
            partitions.push(PartitionAttestation {
                name: format!("{}_stream_{}", kind_label, i + 1),
                category: "carved_stream".to_string(),
                offset: stream_off as u64,
                size: stream_len as u64,
                digests: DigestBundle::compute(slice),
            });
        }
    }

    // Deduplicate partitions by (offset, size)
    partitions.sort_by_key(|p| (p.offset, p.size));
    partitions.dedup_by(|a, b| a.offset == b.offset && a.size == b.size);

    AttestationManifest {
        schema_version: "1.0.0".to_string(),
        target_file: target_name.to_string(),
        file_size: data.len() as u64,
        file_digests,
        partitions,
    }
}

/// Verify a firmware image binary against a previously emitted attestation manifest.
pub fn verify_attestation(data: &[u8], manifest: &AttestationManifest) -> VerificationReport {
    let mut findings = Vec::new();
    let mut passed = 0;
    let mut failed = 0;

    // 1. Verify whole file length and digests
    let actual_file_digests = DigestBundle::compute(data);
    let file_digests_match = actual_file_digests.matches(&manifest.file_digests);

    if data.len() as u64 != manifest.file_size {
        findings.push(VerificationFinding {
            name: "entire_firmware_file".to_string(),
            category: "file_container".to_string(),
            offset: 0,
            size: data.len() as u64,
            status: FindingStatus::FileLengthMismatch,
            mismatches: Vec::new(),
            message: format!(
                "File size mismatch: expected {} bytes, found {} bytes",
                manifest.file_size,
                data.len()
            ),
        });
        failed += 1;
    } else if !file_digests_match {
        let mismatches = actual_file_digests.diff_mismatches(&manifest.file_digests);
        findings.push(VerificationFinding {
            name: "entire_firmware_file".to_string(),
            category: "file_container".to_string(),
            offset: 0,
            size: data.len() as u64,
            status: FindingStatus::HashMismatch,
            mismatches,
            message: "Whole-file cryptographic digests do not match manifest".to_string(),
        });
        failed += 1;
    } else {
        findings.push(VerificationFinding {
            name: "entire_firmware_file".to_string(),
            category: "file_container".to_string(),
            offset: 0,
            size: data.len() as u64,
            status: FindingStatus::Valid,
            mismatches: Vec::new(),
            message: "Whole-file cryptographic digests strictly verified".to_string(),
        });
        passed += 1;
    }

    // 2. Verify individual partitions
    for part in &manifest.partitions {
        let start = part.offset as usize;
        let end = (part.offset + part.size) as usize;

        if start >= data.len() || end > data.len() {
            findings.push(VerificationFinding {
                name: part.name.clone(),
                category: part.category.clone(),
                offset: part.offset,
                size: part.size,
                status: FindingStatus::OutOfBounds,
                mismatches: Vec::new(),
                message: format!(
                    "Partition bounds [0x{:08X}..0x{:08X}] exceed binary size {} bytes",
                    start,
                    end,
                    data.len()
                ),
            });
            failed += 1;
            continue;
        }

        let slice = &data[start..end];
        let actual_digests = DigestBundle::compute(slice);

        if actual_digests.matches(&part.digests) {
            findings.push(VerificationFinding {
                name: part.name.clone(),
                category: part.category.clone(),
                offset: part.offset,
                size: part.size,
                status: FindingStatus::Valid,
                mismatches: Vec::new(),
                message: "Cryptographic digests strictly match".to_string(),
            });
            passed += 1;
        } else {
            let mismatches = actual_digests.diff_mismatches(&part.digests);
            findings.push(VerificationFinding {
                name: part.name.clone(),
                category: part.category.clone(),
                offset: part.offset,
                size: part.size,
                status: FindingStatus::HashMismatch,
                mismatches,
                message: "Partition content modified or corrupted".to_string(),
            });
            failed += 1;
        }
    }

    let overall_valid = failed == 0 && file_digests_match;

    VerificationReport {
        overall_valid,
        file_digests_match,
        total_partitions: manifest.partitions.len(),
        passed_partitions: passed,
        failed_partitions: failed,
        findings,
    }
}
