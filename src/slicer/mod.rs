// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

pub mod boundary;
pub mod entropy;
pub mod synth;

pub use boundary::{
    detect_boundaries, extract_sliced_partitions, slice_into_partitions, InflectionType,
    RegionKind, SliceBoundary, SlicedPartition,
};
pub use entropy::{
    chi_squared_test, compute_entropy_profile, render_ascii_entropy_plot, shannon_entropy,
    EntropyProfile, EntropyWindow,
};
pub use synth::{
    build_bootloader_stage, build_compressed_stage, build_encrypted_stage, build_padding_stage,
    build_synthetic_sliced_firmware,
};

use serde::{Deserialize, Serialize};

/// Configuration options for sliding-window entropy profiling and inflection detection.
#[derive(Debug, Clone)]
pub struct SlicerConfig {
    /// Window size in bytes for sliding entropy calculation (default: 512)
    pub window_size: usize,
    /// Step stride in bytes between consecutive windows (default: 256)
    pub step_size: usize,
    /// Absolute entropy delta threshold for boundary detection (default: 0.80)
    pub threshold: f64,
}

impl Default for SlicerConfig {
    fn default() -> Self {
        Self {
            window_size: 512,
            step_size: 256,
            threshold: 0.80,
        }
    }
}

/// Comprehensive report of firmware entropy profile, detected boundaries, and sliced partitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlicerReport {
    /// Target file path or stream label
    pub target_file: String,
    /// Total binary size analyzed in bytes
    pub total_size: usize,
    /// Window size used for sliding calculations
    pub window_size: usize,
    /// Step stride used between consecutive windows
    pub step_size: usize,
    /// Global Shannon entropy across entire binary
    pub overall_entropy: f64,
    /// Inflection point boundaries detected between distinct regions
    pub boundaries: Vec<SliceBoundary>,
    /// Sliced contiguous partitions
    pub partitions: Vec<SlicedPartition>,
    /// Raw window samples (omitted in JSON serialization if empty)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub windows: Vec<EntropyWindow>,
}

/// Analyzes sliding-window Shannon entropy and slices the firmware blob into discrete partitions.
pub fn analyze_and_slice(data: &[u8], target_file: &str, config: &SlicerConfig) -> SlicerReport {
    let overall_entropy = (shannon_entropy(data) * 10000.0).round() / 10000.0;
    let profile = compute_entropy_profile(data, config.window_size, config.step_size);
    let boundaries = detect_boundaries(&profile, config.threshold);
    let partitions = slice_into_partitions(data, &profile, &boundaries);

    SlicerReport {
        target_file: target_file.to_string(),
        total_size: data.len(),
        window_size: config.window_size,
        step_size: config.step_size,
        overall_entropy,
        boundaries,
        partitions,
        windows: profile.windows,
    }
}

/// Formats the slicer report into a clean, human-readable terminal table summary.
pub fn format_slicer_report(report: &SlicerReport, plot: bool) -> String {
    use std::fmt::Write;
    let mut out = String::new();

    let _ = writeln!(out, "=== FirmCarver Entropy & Boundary Slicer ===");
    let _ = writeln!(out, "Target Image:     {}", report.target_file);
    let _ = writeln!(out, "Total Size:       {} bytes", report.total_size);
    let _ = writeln!(
        out,
        "Overall Entropy:  {:.4} bits/byte",
        report.overall_entropy
    );
    let _ = writeln!(
        out,
        "Sliding Window:   {} B (step: {} B)",
        report.window_size, report.step_size
    );
    let _ = writeln!(out, "Sliced Partitions:{}", report.partitions.len());
    let _ = writeln!(out, "Inflection Points:{}\n", report.boundaries.len());

    let _ = writeln!(out, "Discovered Firmware Partitions:");
    let _ = writeln!(
        out,
        "  #   Offset Range               Length    Mean Ent  Region Classification"
    );
    let _ = writeln!(
        out,
        "  ----------------------------------------------------------------------------------"
    );
    for p in &report.partitions {
        let range_str = format!("0x{:08X}..0x{:08X}", p.start_offset, p.end_offset);
        let _ = writeln!(
            out,
            "  [{:02}] {:<24} {:>8} B   {:.4}   {:<24}",
            p.index,
            range_str,
            p.length,
            p.mean_entropy,
            p.kind.name()
        );
        let _ = writeln!(out, "       Details: {}", p.description);
    }

    if !report.boundaries.is_empty() {
        let _ = writeln!(out, "\nDetected Inflection Point Boundaries:");
        let _ = writeln!(
            out,
            "  #   Offset      Delta    From Region              To Region                Type"
        );
        let _ = writeln!(
            out,
            "  ----------------------------------------------------------------------------------"
        );
        for (idx, b) in report.boundaries.iter().enumerate() {
            let type_str = match b.inflection {
                InflectionType::CompressionRise => "Compression Rise",
                InflectionType::CompressionDrop => "Compression Drop",
                InflectionType::PaddingEnter => "Padding Enter",
                InflectionType::PaddingExit => "Padding Exit",
                InflectionType::GeneralShift => "General Shift",
            };
            let _ = writeln!(
                out,
                "  [{:02}] 0x{:08X}  {:+6.4}  {:<24} {:<24} {}",
                idx + 1,
                b.offset,
                b.delta,
                b.from_kind.name(),
                b.to_kind.name(),
                type_str
            );
        }
    }

    if plot {
        let profile = EntropyProfile {
            total_size: report.total_size,
            window_size: report.window_size,
            step_size: report.step_size,
            mean_entropy: report.overall_entropy,
            min_entropy: 0.0,
            max_entropy: 8.0,
            windows: report.windows.clone(),
        };
        let _ = writeln!(out);
        out.push_str(&render_ascii_entropy_plot(&profile, 64, 8));
    }

    out
}
