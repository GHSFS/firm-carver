// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use firm_carver::slicer::{
    analyze_and_slice, build_bootloader_stage, build_compressed_stage, build_encrypted_stage,
    build_padding_stage, build_synthetic_sliced_firmware, chi_squared_test,
    compute_entropy_profile, detect_boundaries, extract_sliced_partitions, format_slicer_report,
    render_ascii_entropy_plot, shannon_entropy, EntropyProfile, InflectionType, RegionKind,
    SlicerConfig,
};
use std::fs;

#[test]
fn test_shannon_entropy_calculation() {
    // Empty data has 0 entropy
    assert_eq!(shannon_entropy(&[]), 0.0);

    // Uniform single-byte data has 0 entropy
    assert_eq!(shannon_entropy(&[0x00; 1000]), 0.0);
    assert_eq!(shannon_entropy(&[0xFF; 1000]), 0.0);
    assert_eq!(shannon_entropy(&[0x42; 512]), 0.0);

    // Perfect uniform distribution across all 256 bytes has exactly 8.0 bits/byte
    let mut all_bytes = Vec::with_capacity(256 * 4);
    for _ in 0..4 {
        for b in 0..=255u8 {
            all_bytes.push(b);
        }
    }
    let full_entropy = shannon_entropy(&all_bytes);
    assert!((full_entropy - 8.0).abs() < 0.0001);

    // Chi-square test on uniform distribution should be zero
    let chi = chi_squared_test(&all_bytes);
    assert!((chi - 0.0).abs() < 0.0001);

    // ASCII text typically has entropy ~3.5 to 5.0
    let ascii_text = b"The quick brown fox jumps over the lazy dog repeatedly in an embedded test.";
    let ascii_ent = shannon_entropy(ascii_text);
    assert!(ascii_ent > 3.0 && ascii_ent < 5.0);
}

#[test]
fn test_sliding_window_entropy_profile() {
    let mut data = Vec::new();
    data.extend_from_slice(&[0x00; 1024]); // 1K padding (ent 0.0)
    data.extend_from_slice(&build_encrypted_stage(1024)); // 1K encrypted (ent ~8.0)

    let profile = compute_entropy_profile(&data, 512, 256);
    assert_eq!(profile.total_size, 2048);
    assert_eq!(profile.window_size, 512);
    assert_eq!(profile.step_size, 256);
    assert!(!profile.windows.is_empty());

    // Min entropy should be 0.0 (padding windows)
    assert_eq!(profile.min_entropy, 0.0);
    // Max entropy should be close to 8.0 (encrypted windows)
    assert!(profile.max_entropy > 7.5);
    // Mean should be in between
    assert!(profile.mean_entropy > 2.0 && profile.mean_entropy < 6.0);
}

#[test]
fn test_synthetic_sliced_firmware_generation() {
    let fw = build_synthetic_sliced_firmware();
    assert_eq!(fw.len(), 19456);

    // Stage 1: Bootloader (0..4096)
    let boot_slice = &fw[0..4096];
    let boot_ent = shannon_entropy(boot_slice);
    assert!(
        (4.5..=7.1).contains(&boot_ent),
        "Bootloader entropy: {}",
        boot_ent
    );
    assert!(boot_slice.starts_with(b"U-Boot 2026.04-rc1"));

    // Stage 2: Compressed kernel (4096..12288)
    let kernel_slice = &fw[4096..12288];
    let kernel_ent = shannon_entropy(kernel_slice);
    assert!(
        (7.2..=7.92).contains(&kernel_ent),
        "Kernel entropy: {}",
        kernel_ent
    );

    // Stage 3: Plaintext config (12288..14336)
    let text_slice = &fw[12288..14336];
    let text_ent = shannon_entropy(text_slice);
    assert!(
        (1.2..4.8).contains(&text_ent),
        "Text config entropy: {}",
        text_ent
    );

    // Stage 4: Zero padding (14336..15360)
    let zero_slice = &fw[14336..15360];
    assert_eq!(shannon_entropy(zero_slice), 0.0);

    // Stage 5: Encrypted payload (15360..19456)
    let enc_slice = &fw[15360..19456];
    let enc_ent = shannon_entropy(enc_slice);
    assert!(enc_ent >= 7.92, "Encrypted entropy: {}", enc_ent);
}

#[test]
fn test_boundary_inflection_detection() {
    let fw = build_synthetic_sliced_firmware();
    let profile = compute_entropy_profile(&fw, 512, 256);
    let boundaries = detect_boundaries(&profile, 0.80);

    assert!(
        boundaries.len() >= 4,
        "Expected at least 4 stage boundaries, found {}",
        boundaries.len()
    );

    // Verify presence of characteristic inflection types
    let has_padding_enter = boundaries
        .iter()
        .any(|b| b.inflection == InflectionType::PaddingEnter);
    let has_compression_rise = boundaries
        .iter()
        .any(|b| b.inflection == InflectionType::CompressionRise);
    let has_compression_drop = boundaries
        .iter()
        .any(|b| b.inflection == InflectionType::CompressionDrop);
    let has_padding_exit = boundaries
        .iter()
        .any(|b| b.inflection == InflectionType::PaddingExit);

    assert!(has_padding_enter, "Expected PaddingEnter inflection");
    assert!(has_compression_rise, "Expected CompressionRise inflection");
    assert!(has_compression_drop, "Expected CompressionDrop inflection");
    assert!(has_padding_exit, "Expected PaddingExit inflection");
}

#[test]
fn test_slice_partitions_and_classification() {
    let fw = build_synthetic_sliced_firmware();
    let config = SlicerConfig {
        window_size: 512,
        step_size: 256,
        threshold: 0.80,
    };
    let report = analyze_and_slice(&fw, "synthetic_fw.bin", &config);

    assert_eq!(report.total_size, 19456);
    assert!(!report.partitions.is_empty());

    // Verify partitions are contiguous and cover entire binary
    let mut cursor = 0;
    for p in &report.partitions {
        assert_eq!(p.start_offset, cursor);
        assert_eq!(p.length, p.end_offset - p.start_offset);
        cursor = p.end_offset;
    }
    assert_eq!(cursor, fw.len());

    // Check that expected region classifications exist
    let kinds: Vec<RegionKind> = report.partitions.iter().map(|p| p.kind).collect();
    assert!(
        kinds.contains(&RegionKind::Bootloader),
        "Expected Bootloader partition"
    );
    assert!(
        kinds.contains(&RegionKind::Padding),
        "Expected Padding partition"
    );
    assert!(
        kinds.contains(&RegionKind::CompressedKernel)
            || kinds.contains(&RegionKind::EncryptedOrRandom),
        "Expected Compressed or Encrypted partition"
    );
}

#[test]
fn test_extract_sliced_partitions_to_disk() {
    let fw = build_synthetic_sliced_firmware();
    let config = SlicerConfig::default();
    let report = analyze_and_slice(&fw, "extract_test.bin", &config);

    let temp_dir =
        std::env::temp_dir().join(format!("firm_carver_slice_test_{}", std::process::id()));
    let extracted = extract_sliced_partitions(&fw, &report.partitions, &temp_dir).unwrap();

    assert_eq!(extracted.len(), report.partitions.len());
    for (path, p) in extracted.iter().zip(&report.partitions) {
        assert!(path.exists());
        let content = fs::read(path).unwrap();
        assert_eq!(content.len(), p.length);
        assert_eq!(&content[..], &fw[p.start_offset..p.end_offset]);
    }

    // Clean up test directory
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_slicer_report_formatting_and_ascii_plot() {
    let fw = build_synthetic_sliced_firmware();
    let config = SlicerConfig::default();
    let report = analyze_and_slice(&fw, "router_image.bin", &config);

    let text_without_plot = format_slicer_report(&report, false);
    assert!(text_without_plot.contains("=== FirmCarver Entropy & Boundary Slicer ==="));
    assert!(text_without_plot.contains("router_image.bin"));
    assert!(text_without_plot.contains("Discovered Firmware Partitions:"));

    let text_with_plot = format_slicer_report(&report, true);
    assert!(text_with_plot.contains("Entropy Curve (0.0 to 8.0 bits/byte):"));
    assert!(text_with_plot.contains("8.0 |"));
    assert!(text_with_plot.contains("0.0 |"));
}

#[test]
fn test_slicer_empty_and_edge_case_robustness() {
    let config = SlicerConfig::default();

    // 1. Empty buffer
    let empty_report = analyze_and_slice(&[], "empty.bin", &config);
    assert_eq!(empty_report.total_size, 0);
    assert_eq!(empty_report.overall_entropy, 0.0);
    assert!(empty_report.partitions.is_empty());
    assert!(empty_report.boundaries.is_empty());

    // 2. 1-byte buffer
    let single_byte = [0x55];
    let single_report = analyze_and_slice(&single_byte, "single.bin", &config);
    assert_eq!(single_report.total_size, 1);
    assert_eq!(single_report.partitions.len(), 1);
    assert_eq!(single_report.partitions[0].length, 1);

    // 3. Small uniform padding
    let pad = build_padding_stage(2048, 0x00);
    let pad_report = analyze_and_slice(&pad, "pad.bin", &config);
    assert_eq!(pad_report.partitions.len(), 1);
    assert_eq!(pad_report.partitions[0].kind, RegionKind::Padding);
    assert_eq!(pad_report.boundaries.len(), 0);

    // 4. Standalone stages
    let boot = build_bootloader_stage(512);
    assert_eq!(boot.len(), 512);

    let comp = build_compressed_stage(512);
    assert_eq!(comp.len(), 512);

    // 5. Empty ASCII plot
    let empty_prof = EntropyProfile {
        total_size: 0,
        window_size: 512,
        step_size: 256,
        mean_entropy: 0.0,
        min_entropy: 0.0,
        max_entropy: 0.0,
        windows: Vec::new(),
    };
    let empty_plot = render_ascii_entropy_plot(&empty_prof, 40, 6);
    assert!(empty_plot.contains("[No entropy data to plot]"));
}
