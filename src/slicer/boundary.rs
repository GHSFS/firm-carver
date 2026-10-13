// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::error::{CarverError, Result};
use crate::slicer::entropy::{shannon_entropy, EntropyProfile};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Categorization of firmware binary regions based on Shannon entropy and payload characteristics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegionKind {
    /// Zero-fill (0x00) or erased flash blocks (0xFF), entropy < 1.2
    Padding,
    /// Plaintext ASCII, strings, configuration tables, sparse structures (1.2 .. 4.5)
    TextOrData,
    /// Uncompressed bootloader machine code, relocatable vectors (4.5 .. 7.1)
    Bootloader,
    /// Compressed Linux kernel, initramfs, or SquashFS/CramFS payloads (7.1 .. 7.92)
    CompressedKernel,
    /// High-entropy encrypted blocks, ciphertext, or near-random secrets (>= 7.92)
    EncryptedOrRandom,
    /// Unclassified or empty region
    Unknown,
}

impl RegionKind {
    /// Classifies an entropy value (0.0 to 8.0 bits/byte) into a firmware region kind.
    pub fn from_entropy(entropy: f64) -> Self {
        if entropy < 1.2 {
            Self::Padding
        } else if entropy < 4.8 {
            Self::TextOrData
        } else if entropy < 6.8 {
            Self::Bootloader
        } else if entropy < 7.92 {
            Self::CompressedKernel
        } else {
            Self::EncryptedOrRandom
        }
    }

    /// User-friendly display name of the region.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Padding => "Padding / Erased Flash",
            Self::TextOrData => "Plaintext / Config Data",
            Self::Bootloader => "Bootloader / Machine Code",
            Self::CompressedKernel => "Compressed Kernel / FS",
            Self::EncryptedOrRandom => "Encrypted / Random Payload",
            Self::Unknown => "Unknown / Empty",
        }
    }

    /// Short filesystem-safe slug for file names.
    pub fn slug(&self) -> &'static str {
        match self {
            Self::Padding => "padding",
            Self::TextOrData => "textdata",
            Self::Bootloader => "bootloader",
            Self::CompressedKernel => "compressed",
            Self::EncryptedOrRandom => "encrypted",
            Self::Unknown => "unknown",
        }
    }
}

/// Nature of an inflection point between adjacent firmware regions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InflectionType {
    /// Sharp entropy increase into compressed kernel or encrypted payload
    CompressionRise,
    /// Sharp entropy decrease leaving compressed payload into uncompressed data
    CompressionDrop,
    /// Transition entering zeroes or erased flash blocks
    PaddingEnter,
    /// Transition leaving padding into active code or data
    PaddingExit,
    /// General entropy divergence across boundaries
    GeneralShift,
}

/// Detected boundary and inflection transition point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SliceBoundary {
    /// Byte offset where the transition was detected
    pub offset: usize,
    /// Entropy before the boundary
    pub prev_entropy: f64,
    /// Entropy after the boundary
    pub new_entropy: f64,
    /// Absolute entropy delta
    pub delta: f64,
    /// Region classification before boundary
    pub from_kind: RegionKind,
    /// Region classification after boundary
    pub to_kind: RegionKind,
    /// Nature of inflection
    pub inflection: InflectionType,
}

/// Sliced partition slice spanning a contiguous byte range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlicedPartition {
    /// 1-based sequential partition index
    pub index: usize,
    /// Starting byte offset within firmware image
    pub start_offset: usize,
    /// Ending byte offset within firmware image (exclusive)
    pub end_offset: usize,
    /// Length of partition slice in bytes
    pub length: usize,
    /// Identified region classification
    pub kind: RegionKind,
    /// Mean Shannon entropy of partition slice
    pub mean_entropy: f64,
    /// Minimum Shannon entropy observed in slice windows
    pub min_entropy: f64,
    /// Maximum Shannon entropy observed in slice windows
    pub max_entropy: f64,
    /// Informational summary description
    pub description: String,
}

fn classify_inflection(
    from_kind: RegionKind,
    to_kind: RegionKind,
    prev_entropy: f64,
    new_entropy: f64,
) -> InflectionType {
    if to_kind == RegionKind::Padding && from_kind != RegionKind::Padding {
        InflectionType::PaddingEnter
    } else if from_kind == RegionKind::Padding && to_kind != RegionKind::Padding {
        InflectionType::PaddingExit
    } else if new_entropy > prev_entropy
        && (to_kind == RegionKind::CompressedKernel
            || to_kind == RegionKind::EncryptedOrRandom
            || new_entropy >= 6.8)
    {
        InflectionType::CompressionRise
    } else if prev_entropy > new_entropy
        && (from_kind == RegionKind::CompressedKernel
            || from_kind == RegionKind::EncryptedOrRandom
            || prev_entropy >= 6.0)
    {
        InflectionType::CompressionDrop
    } else {
        InflectionType::GeneralShift
    }
}

/// Detects inflection points and boundaries from an entropy profile.
pub fn detect_boundaries(profile: &EntropyProfile, threshold: f64) -> Vec<SliceBoundary> {
    if profile.windows.len() < 2 {
        return Vec::new();
    }

    let mut boundaries: Vec<SliceBoundary> = Vec::new();
    let threshold = threshold.max(0.20);
    let mut last_boundary_offset: Option<usize> = None;

    for i in 1..profile.windows.len() {
        let w_prev = &profile.windows[i - 1];
        let w_curr = &profile.windows[i];

        let delta = (w_curr.entropy - w_prev.entropy).abs();
        let from_kind = RegionKind::from_entropy(w_prev.entropy);
        let to_kind = RegionKind::from_entropy(w_curr.entropy);

        let is_sharp_delta = delta >= threshold;
        let is_kind_transition = from_kind != to_kind && delta >= (threshold * 0.40);

        if is_sharp_delta || is_kind_transition {
            // Debounce if too close to previous boundary
            if let Some(prev_off) = last_boundary_offset {
                if w_curr.offset.saturating_sub(prev_off) <= profile.step_size {
                    // Update previous boundary if cumulative delta from baseline is stronger
                    if let Some(last) = boundaries.last_mut() {
                        let cumulative_delta = (w_curr.entropy - last.prev_entropy).abs();
                        if cumulative_delta > last.delta {
                            last.offset = w_curr.offset;
                            last.new_entropy = w_curr.entropy;
                            last.delta = (cumulative_delta * 10000.0).round() / 10000.0;
                            last.to_kind = to_kind;
                            last.inflection = classify_inflection(
                                last.from_kind,
                                to_kind,
                                last.prev_entropy,
                                w_curr.entropy,
                            );
                        }
                    }
                    continue;
                }
            }

            let inflection =
                classify_inflection(from_kind, to_kind, w_prev.entropy, w_curr.entropy);

            boundaries.push(SliceBoundary {
                offset: w_curr.offset,
                prev_entropy: w_prev.entropy,
                new_entropy: w_curr.entropy,
                delta: (delta * 10000.0).round() / 10000.0,
                from_kind,
                to_kind,
                inflection,
            });

            last_boundary_offset = Some(w_curr.offset);
        }
    }

    boundaries
}

/// Slices a raw firmware image into contiguous partitions based on detected boundaries.
pub fn slice_into_partitions(
    data: &[u8],
    profile: &EntropyProfile,
    boundaries: &[SliceBoundary],
) -> Vec<SlicedPartition> {
    if data.is_empty() {
        return Vec::new();
    }

    let mut cut_points = Vec::new();
    cut_points.push(0);
    for b in boundaries {
        if b.offset > 0 && b.offset < data.len() {
            cut_points.push(b.offset);
        }
    }
    cut_points.push(data.len());
    cut_points.sort_unstable();
    cut_points.dedup();

    let mut partitions = Vec::new();

    for i in 0..cut_points.len().saturating_sub(1) {
        let start = cut_points[i];
        let end = cut_points[i + 1];
        if end <= start {
            continue;
        }

        let slice = &data[start..end];
        let slice_ent = shannon_entropy(slice);
        let kind = RegionKind::from_entropy(slice_ent);

        let mut min_ent = 8.0;
        let mut max_ent = 0.0;
        let mut count = 0;

        for w in &profile.windows {
            if w.offset >= start && w.offset < end {
                if w.entropy < min_ent {
                    min_ent = w.entropy;
                }
                if w.entropy > max_ent {
                    max_ent = w.entropy;
                }
                count += 1;
            }
        }

        if count == 0 {
            min_ent = slice_ent;
            max_ent = slice_ent;
        }

        let desc = match kind {
            RegionKind::Padding => {
                if slice.iter().all(|&b| b == 0xFF) {
                    "Erased NOR/NAND flash padding (all 0xFF)".to_string()
                } else if slice.iter().all(|&b| b == 0x00) {
                    "Zero-filled alignment padding (all 0x00)".to_string()
                } else {
                    "Low-entropy sparse padding / alignment block".to_string()
                }
            }
            RegionKind::TextOrData => {
                "Plaintext configuration tables, environment or ASCII data".to_string()
            }
            RegionKind::Bootloader => {
                "Bootloader / uncompressed executable machine code vectors".to_string()
            }
            RegionKind::CompressedKernel => {
                "Compressed Linux kernel, initramfs or SquashFS/CramFS stream".to_string()
            }
            RegionKind::EncryptedOrRandom => {
                "Encrypted payload, key blob or high-entropy ciphertext".to_string()
            }
            RegionKind::Unknown => "Unclassified partition slice".to_string(),
        };

        partitions.push(SlicedPartition {
            index: partitions.len() + 1,
            start_offset: start,
            end_offset: end,
            length: end - start,
            kind,
            mean_entropy: (slice_ent * 10000.0).round() / 10000.0,
            min_entropy: (min_ent * 10000.0).round() / 10000.0,
            max_entropy: (max_ent * 10000.0).round() / 10000.0,
            description: desc,
        });
    }

    partitions
}

/// Extracts sliced partitions to disk in the destination directory.
pub fn extract_sliced_partitions(
    data: &[u8],
    partitions: &[SlicedPartition],
    out_dir: &Path,
) -> Result<Vec<PathBuf>> {
    fs::create_dir_all(out_dir).map_err(|e| {
        CarverError::Io(std::io::Error::new(
            e.kind(),
            format!(
                "Failed to create output directory {}: {}",
                out_dir.display(),
                e
            ),
        ))
    })?;

    let mut written = Vec::new();

    for p in partitions {
        if p.end_offset > data.len() || p.start_offset >= p.end_offset {
            continue;
        }

        let file_name = format!(
            "partition_{:02}_{}_0x{:08X}.bin",
            p.index,
            p.kind.slug(),
            p.start_offset
        );
        let target_path = out_dir.join(&file_name);
        let slice = &data[p.start_offset..p.end_offset];

        fs::write(&target_path, slice).map_err(|e| {
            CarverError::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to write partition {}: {}", target_path.display(), e),
            ))
        })?;

        written.push(target_path);
    }

    Ok(written)
}
