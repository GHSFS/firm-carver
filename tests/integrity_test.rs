// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use firm_carver::integrity::{
    build_synthetic_attested_firmware, compute_blake3, compute_sha256, compute_sha512,
    constant_time_eq_str, format_integrity_report, format_verification_report,
    tamper_firmware_byte, truncate_firmware, verify_attestation, AttestationManifest, DigestBundle,
    FindingStatus, HashAlgorithm,
};
use std::fs;

#[test]
fn test_sha256_sha512_blake3_known_vectors() {
    let empty = b"";
    // RFC test vectors for empty string
    assert_eq!(
        compute_sha256(empty),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        compute_sha512(empty),
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    );
    assert_eq!(
        compute_blake3(empty),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    );

    let sample = b"firm-carver";
    let bundle = DigestBundle::compute(sample);
    assert_eq!(bundle.sha256, compute_sha256(sample));
    assert_eq!(bundle.sha512, compute_sha512(sample));
    assert_eq!(bundle.blake3, compute_blake3(sample));
    assert!(bundle.matches(&bundle));
}

#[test]
fn test_constant_time_string_comparison() {
    assert!(constant_time_eq_str("abcdef123456", "abcdef123456"));
    assert!(!constant_time_eq_str("abcdef123456", "abcdef123457"));
    assert!(!constant_time_eq_str("short", "longer_string"));
    assert!(constant_time_eq_str("", ""));
}

#[test]
fn test_synthetic_attested_firmware_manifest_generation() {
    let (blob, manifest) = build_synthetic_attested_firmware();

    assert!(!blob.is_empty());
    assert_eq!(manifest.file_size, blob.len() as u64);
    assert_eq!(manifest.schema_version, "1.0.0");
    assert_eq!(manifest.target_file, "synthetic_firmware_v1.bin");

    // File digests should strictly match computed digests
    let expected_digests = DigestBundle::compute(&blob);
    assert_eq!(manifest.file_digests, expected_digests);

    // Partitions should be identified and within bounds
    assert!(!manifest.partitions.is_empty());
    for part in &manifest.partitions {
        assert!(part.size > 0);
        let end = part.offset + part.size;
        assert!(
            end <= blob.len() as u64,
            "Partition {} exceeds blob boundary: {} > {}",
            part.name,
            end,
            blob.len()
        );

        let slice = &blob[part.offset as usize..end as usize];
        let slice_digests = DigestBundle::compute(slice);
        assert_eq!(part.digests, slice_digests);
    }
}

#[test]
fn test_manifest_verification_clean_pass() {
    let (blob, manifest) = build_synthetic_attested_firmware();
    let report = verify_attestation(&blob, &manifest);

    assert!(report.overall_valid);
    assert!(report.file_digests_match);
    assert_eq!(report.failed_partitions, 0);
    assert_eq!(report.passed_partitions, manifest.partitions.len() + 1);

    for finding in &report.findings {
        assert_eq!(finding.status, FindingStatus::Valid);
        assert!(finding.mismatches.is_empty());
    }
}

#[test]
fn test_manifest_verification_tamper_detection() {
    let (blob, manifest) = build_synthetic_attested_firmware();

    // Tamper with byte 16 (inside U-Boot container header)
    let tampered = tamper_firmware_byte(&blob, 16);
    let report = verify_attestation(&tampered, &manifest);

    assert!(!report.overall_valid);
    assert!(!report.file_digests_match);
    assert!(report.failed_partitions >= 1);

    // Must have at least one HashMismatch finding
    let mismatch_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.status == FindingStatus::HashMismatch)
        .collect();
    assert!(!mismatch_findings.is_empty());

    // File level finding should show mismatch
    let file_finding = report
        .findings
        .iter()
        .find(|f| f.name == "entire_firmware_file")
        .expect("Missing entire_firmware_file finding");
    assert_eq!(file_finding.status, FindingStatus::HashMismatch);
    assert!(!file_finding.mismatches.is_empty());
}

#[test]
fn test_manifest_verification_truncation_and_bounds() {
    let (blob, manifest) = build_synthetic_attested_firmware();

    // Truncate firmware to half length
    let truncated_len = blob.len() / 2;
    let truncated = truncate_firmware(&blob, truncated_len);
    let report = verify_attestation(&truncated, &manifest);

    assert!(!report.overall_valid);
    assert!(!report.file_digests_match);

    let length_mismatch = report
        .findings
        .iter()
        .find(|f| f.status == FindingStatus::FileLengthMismatch);
    assert!(length_mismatch.is_some());

    let out_of_bounds = report
        .findings
        .iter()
        .find(|f| f.status == FindingStatus::OutOfBounds);
    assert!(out_of_bounds.is_some());
}

#[test]
fn test_manifest_json_roundtrip_and_file_io() {
    let (blob, manifest) = build_synthetic_attested_firmware();

    let json_text = manifest.to_json_pretty().expect("json serialize failed");
    assert!(json_text.contains("\"schema_version\": \"1.0.0\""));
    assert!(json_text.contains("\"target_file\": \"synthetic_firmware_v1.bin\""));

    let temp_dir = std::env::temp_dir().join(format!("fcarver_test_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).expect("create temp dir");
    let manifest_path = temp_dir.join("test_manifest.json");

    manifest
        .save_to_file(&manifest_path)
        .expect("save manifest");
    let loaded = AttestationManifest::from_file(&manifest_path).expect("load manifest");
    assert_eq!(manifest, loaded);

    let _ = fs::remove_dir_all(&temp_dir);
    assert_eq!(loaded.file_size, blob.len() as u64);
}

#[test]
fn test_report_formatting_outputs() {
    let (blob, manifest) = build_synthetic_attested_firmware();
    let report = verify_attestation(&blob, &manifest);

    let integrity_txt = format_integrity_report(&manifest, HashAlgorithm::All);
    assert!(integrity_txt.contains("=== FirmCarver Cryptographic Integrity Attestation ==="));
    assert!(integrity_txt.contains("Target File:     synthetic_firmware_v1.bin"));
    assert!(integrity_txt.contains("File SHA-256:"));
    assert!(integrity_txt.contains("File BLAKE3:"));

    let verify_txt = format_verification_report(&report);
    assert!(verify_txt.contains("=== FirmCarver Attestation Verification Report ==="));
    assert!(verify_txt.contains("[ PASS ] All digests and partitions strictly verified"));
    assert!(verify_txt.contains("File Digest Match:  YES"));
}
