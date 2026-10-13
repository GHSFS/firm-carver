// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

pub mod digest;
pub mod manifest;
pub mod synth;

pub use digest::{
    compute_blake3, compute_sha256, compute_sha512, constant_time_eq_str, DigestBundle,
    DigestMismatch, HashAlgorithm,
};
pub use manifest::{
    generate_attestation_manifest, verify_attestation, AttestationManifest, FindingStatus,
    PartitionAttestation, VerificationFinding, VerificationReport,
};
pub use synth::{build_synthetic_attested_firmware, tamper_firmware_byte, truncate_firmware};

/// Format an aligned, human-readable terminal report from an attestation manifest.
pub fn format_integrity_report(manifest: &AttestationManifest, algo: HashAlgorithm) -> String {
    let mut out = String::new();
    out.push_str("=== FirmCarver Cryptographic Integrity Attestation ===\n");
    out.push_str(&format!("Target File:     {}\n", manifest.target_file));
    out.push_str(&format!("File Size:       {} bytes\n", manifest.file_size));
    out.push_str(&format!("Schema Version:  {}\n", manifest.schema_version));
    out.push_str(&format!("Algorithm Focus: {}\n", algo));

    match algo {
        HashAlgorithm::Sha256 => {
            out.push_str(&format!(
                "File SHA-256:    {}\n",
                manifest.file_digests.sha256
            ));
        }
        HashAlgorithm::Sha512 => {
            out.push_str(&format!(
                "File SHA-512:    {}\n",
                manifest.file_digests.sha512
            ));
        }
        HashAlgorithm::Blake3 => {
            out.push_str(&format!(
                "File BLAKE3:     {}\n",
                manifest.file_digests.blake3
            ));
        }
        HashAlgorithm::All => {
            out.push_str(&format!(
                "File SHA-256:    {}\n",
                manifest.file_digests.sha256
            ));
            out.push_str(&format!(
                "File SHA-512:    {}\n",
                manifest.file_digests.sha512
            ));
            out.push_str(&format!(
                "File BLAKE3:     {}\n",
                manifest.file_digests.blake3
            ));
        }
    }

    out.push_str(&format!(
        "\nPartitions Attested: {} found\n\n",
        manifest.partitions.len()
    ));

    if manifest.partitions.is_empty() {
        out.push_str("No discrete container headers or carved stream partitions identified.\n");
        return out;
    }

    out.push_str(&format!(
        "{:<3} {:<24} {:<18} {:<10} {:<10} {:<64}\n",
        "#",
        "Partition Name",
        "Category",
        "Offset",
        "Size",
        "Cryptographic Digest (SHA-256 / BLAKE3)"
    ));
    out.push_str(&format!("{}\n", "-".repeat(135)));

    for (idx, p) in manifest.partitions.iter().enumerate() {
        let digest_display = match algo {
            HashAlgorithm::Sha256 => p.digests.sha256.clone(),
            HashAlgorithm::Sha512 => {
                if p.digests.sha512.len() > 60 {
                    format!("{}...", &p.digests.sha512[..60])
                } else {
                    p.digests.sha512.clone()
                }
            }
            HashAlgorithm::Blake3 => p.digests.blake3.clone(),
            HashAlgorithm::All => format!(
                "b3:{} / 256:{}...",
                &p.digests.blake3[..16],
                &p.digests.sha256[..16]
            ),
        };

        out.push_str(&format!(
            "{:<3} {:<24} {:<18} 0x{:<8X} {:<10} {:<64}\n",
            idx + 1,
            p.name,
            p.category,
            p.offset,
            format!("{} B", p.size),
            digest_display
        ));
    }

    out
}

/// Format an aligned terminal summary of an attestation verification outcome.
pub fn format_verification_report(report: &VerificationReport) -> String {
    let mut out = String::new();
    out.push_str("=== FirmCarver Attestation Verification Report ===\n");
    if report.overall_valid {
        out.push_str("Overall Status:     [ PASS ] All digests and partitions strictly verified\n");
    } else {
        out.push_str(
            "Overall Status:     [ FAIL ] Integrity violation or hash mismatch detected!\n",
        );
    }
    out.push_str(&format!(
        "File Digest Match:  {}\n",
        if report.file_digests_match {
            "YES"
        } else {
            "NO"
        }
    ));
    out.push_str(&format!(
        "Total Partitions:   {}\n",
        report.total_partitions
    ));
    out.push_str(&format!(
        "Passed Partitions:  {}\n",
        report.passed_partitions
    ));
    out.push_str(&format!(
        "Failed Partitions:  {}\n\n",
        report.failed_partitions
    ));

    out.push_str(&format!(
        "{:<3} {:<24} {:<10} {:<10} {:<14} {:<40}\n",
        "#", "Target", "Offset", "Size", "Status", "Message"
    ));
    out.push_str(&format!("{}\n", "-".repeat(105)));

    for (idx, f) in report.findings.iter().enumerate() {
        let status_str = match f.status {
            FindingStatus::Valid => "[PASS]",
            FindingStatus::HashMismatch => "[MISMATCH]",
            FindingStatus::OutOfBounds => "[OUT_OF_BOUNDS]",
            FindingStatus::FileLengthMismatch => "[LEN_MISMATCH]",
        };

        out.push_str(&format!(
            "{:<3} {:<24} 0x{:<8X} {:<10} {:<14} {:<40}\n",
            idx + 1,
            f.name,
            f.offset,
            format!("{} B", f.size),
            status_str,
            f.message
        ));

        for m in &f.mismatches {
            out.push_str(&format!(
                "    -> Algo: {:<6} Expected: {}... Actual: {}...\n",
                m.algo,
                &m.expected[..16.min(m.expected.len())],
                &m.actual[..16.min(m.actual.len())]
            ));
        }
    }

    out
}
