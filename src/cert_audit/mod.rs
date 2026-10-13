// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

pub mod asn1;
pub mod pem;
pub mod rules;
pub mod scanner;
pub mod synth;
pub mod types;

pub use asn1::{parse_rsa_private_key_modulus, parse_x509_certificate, DerElement};
pub use pem::{decode_base64, encode_base64, parse_pem_blocks, PemBlock};
pub use rules::CertRuleEngine;
pub use scanner::CertScanner;
pub use synth::CertSynth;
pub use types::{
    CertAuditConfig, CertAuditReport, CertDate, CertFinding, CertIssueKind, CertSeverity,
    DiscoveredPrivateKey, ParsedCertificate,
};

use crate::error::{CarverError, Result};
use std::path::Path;

/// High-level entry point to audit a certificate file, directory, or firmware binary.
pub fn audit_cert_path(target: &Path, config: &CertAuditConfig) -> Result<CertAuditReport> {
    if !target.exists() {
        return Err(CarverError::CertAudit(format!(
            "Target certificate path does not exist: {}",
            target.display()
        )));
    }

    if target.is_dir() {
        CertScanner::scan_directory(target, config)
    } else {
        CertScanner::scan_single_file(target, config)
    }
}

/// Audit an in-memory byte buffer for embedded certificates and private keys.
pub fn audit_cert_buffer(
    buffer: &[u8],
    name: &str,
    config: &CertAuditConfig,
) -> Result<CertAuditReport> {
    Ok(CertScanner::scan_buffer(buffer, name, config))
}

/// Format an aligned, human-readable terminal report from a certificate audit report.
pub fn format_cert_report(report: &CertAuditReport) -> String {
    let mut out = String::new();
    out.push_str("=== FirmCarver TLS Certificate & Root CA Auditor ===\n");
    out.push_str(&format!("Target Path:         {}\n", report.target_path));
    out.push_str(&format!(
        "Certificates Found:  {}\n",
        report.total_certs_scanned
    ));
    out.push_str(&format!(
        "Private Keys Found:  {}\n",
        report.total_keys_found
    ));
    out.push_str(&format!("Security Findings:   {}\n", report.total_findings));
    out.push_str(&format!(
        "Severity Breakdown:  Critical: {} | High: {} | Medium: {} | Low: {} | Info: {}\n\n",
        report.critical_count,
        report.high_count,
        report.medium_count,
        report.low_count,
        report.info_count
    ));

    if !report.certificates.is_empty() {
        out.push_str("Discovered Certificates:\n");
        out.push_str("----------------------------------------------------------------------\n");
        for (i, c) in report.certificates.iter().enumerate() {
            let key_info = if let Some(bits) = c.rsa_bits {
                format!("RSA {}-bit", bits)
            } else if let Some(ref curve) = c.ec_curve {
                format!("ECC {}", curve)
            } else {
                c.pubkey_algo_name.clone()
            };
            out.push_str(&format!("[{:02}] Subject: {}\n", i + 1, c.subject));
            out.push_str(&format!(
                "     Issuer:  {} (Self-Signed: {})\n",
                c.issuer, c.is_self_signed
            ));
            out.push_str(&format!(
                "     Valid:   {} to {}\n",
                c.not_before, c.not_after
            ));
            out.push_str(&format!(
                "     Crypto:  {} | {}\n",
                c.sig_algo_name, key_info
            ));
            out.push_str(&format!("     SHA-256: {}\n\n", c.fingerprint_sha256));
        }
    }

    if !report.private_keys.is_empty() {
        out.push_str("Discovered Cryptographic Private Keys:\n");
        out.push_str("----------------------------------------------------------------------\n");
        for (i, k) in report.private_keys.iter().enumerate() {
            let bits_str = k
                .modulus_bits
                .map(|b| format!("{} bits", b))
                .unwrap_or_else(|| "N/A".to_string());
            let off_str = k
                .offset
                .map(|o| format!("offset 0x{:08X}", o))
                .unwrap_or_else(|| "file".to_string());
            out.push_str(&format!(
                "[{:02}] Type: {} | Modulus: {} | Location: {}\n",
                i + 1,
                k.key_type,
                bits_str,
                off_str
            ));
            out.push_str(&format!("     Fingerprint: {}\n\n", k.fingerprint_sha256));
        }
    }

    if report.findings.is_empty() {
        out.push_str("No certificate security flaws or weak cryptographic keys identified.\n");
        return out;
    }

    out.push_str("Audit Findings & Vulnerability Details:\n");
    out.push_str("----------------------------------------------------------------------\n");
    for (idx, f) in report.findings.iter().enumerate() {
        let sev_label = match f.severity {
            CertSeverity::Critical => "[CRITICAL]",
            CertSeverity::High => "[HIGH]    ",
            CertSeverity::Medium => "[MEDIUM]  ",
            CertSeverity::Low => "[LOW]     ",
            CertSeverity::Info => "[INFO]    ",
        };

        out.push_str(&format!(
            "#{:02} {} {} - {}\n",
            idx + 1,
            sev_label,
            f.rule_id,
            f.title
        ));
        out.push_str(&format!("     Subject:     {}\n", f.cert_subject));
        if let Some(ref path) = f.file_path {
            out.push_str(&format!("     Target:      {}\n", path));
        }
        if let Some(off) = f.offset {
            out.push_str(&format!("     Offset:      0x{:08X}\n", off));
        }
        out.push_str(&format!("     Fingerprint: {}\n", f.fingerprint));
        out.push_str(&format!("     Description: {}\n", f.description));
        out.push_str(&format!("     Remedy:      {}\n\n", f.remediation));
    }

    out
}
