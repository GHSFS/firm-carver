// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::asn1::{parse_pem_blocks, parse_rsa_private_key_modulus, parse_x509_certificate};
use super::rules::CertRuleEngine;
use super::types::{CertAuditConfig, CertAuditReport, DiscoveredPrivateKey};
use crate::error::{CarverError, Result};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// Scanner engine for discovering, parsing, and auditing certificates and private keys.
pub struct CertScanner;

impl CertScanner {
    /// Recursively audit all files in a filesystem directory tree.
    pub fn scan_directory(dir: &Path, config: &CertAuditConfig) -> Result<CertAuditReport> {
        let mut report = CertAuditReport::new(dir.to_string_lossy().to_string());
        let mut files_to_scan = Vec::new();
        let mut visited = HashSet::new();

        collect_directory_files(dir, &mut files_to_scan, &mut visited, 0)?;

        for file_path in files_to_scan {
            if let Ok(mut data) = fs::read(&file_path) {
                let sub_report = Self::scan_buffer(&data, &file_path.to_string_lossy(), config);
                data.zeroize();
                merge_reports(&mut report, sub_report);
            }
        }

        // Post-scan cross-correlation: match all discovered private keys against all certificates
        correlate_private_keys(&mut report, config);
        Ok(report)
    }

    /// Audit an individual file (PEM bundle, DER binary, or raw firmware image).
    pub fn scan_single_file(file: &Path, config: &CertAuditConfig) -> Result<CertAuditReport> {
        let mut data = fs::read(file).map_err(|e| {
            CarverError::CertAudit(format!("Failed to read {}: {}", file.display(), e))
        })?;

        let mut report = Self::scan_buffer(&data, &file.to_string_lossy(), config);
        data.zeroize();
        correlate_private_keys(&mut report, config);
        Ok(report)
    }

    /// Audit an in-memory byte buffer by parsing PEM blocks, raw DER, or stream carving.
    pub fn scan_buffer(buffer: &[u8], name: &str, config: &CertAuditConfig) -> CertAuditReport {
        let mut report = CertAuditReport::new(name.to_string());
        let mut found_any_pem = false;

        // 1. Attempt PEM parsing if buffer contains ASCII PEM markers
        if let Ok(text) = std::str::from_utf8(buffer) {
            if text.contains("-----BEGIN ") {
                let blocks = parse_pem_blocks(text);
                if !blocks.is_empty() {
                    found_any_pem = true;
                    for block in blocks {
                        if block.label.contains("CERTIFICATE") {
                            if let Ok(cert) = parse_x509_certificate(&block.data) {
                                let findings = CertRuleEngine::evaluate_certificate(
                                    &cert,
                                    Some(name),
                                    None,
                                    config,
                                );
                                for f in findings {
                                    report.add_finding(f);
                                }
                                report.total_certs_scanned += 1;
                                report.certificates.push(cert);
                            }
                        } else if block.label.contains("PRIVATE KEY") {
                            let (mod_bytes, bits) = parse_rsa_private_key_modulus(&block.data)
                                .unwrap_or_else(|_| (Vec::new(), 0));
                            let fp = hex::encode(Sha256::digest(&block.data));
                            report.private_keys.push(DiscoveredPrivateKey {
                                key_type: block.label.clone(),
                                file_path: Some(name.to_string()),
                                offset: None,
                                modulus_bits: if bits > 0 { Some(bits) } else { None },
                                fingerprint_sha256: fp,
                                key_bytes: mod_bytes,
                            });
                            report.total_keys_found += 1;
                        }
                    }
                }
            }
        }

        // 2. Direct DER check if no PEM blocks were extracted
        if !found_any_pem {
            if let Ok(cert) = parse_x509_certificate(buffer) {
                let findings =
                    CertRuleEngine::evaluate_certificate(&cert, Some(name), None, config);
                for f in findings {
                    report.add_finding(f);
                }
                report.total_certs_scanned += 1;
                report.certificates.push(cert);
            } else if let Ok((mod_bytes, bits)) = parse_rsa_private_key_modulus(buffer) {
                let fp = hex::encode(Sha256::digest(buffer));
                report.private_keys.push(DiscoveredPrivateKey {
                    key_type: "Raw DER Private Key".to_string(),
                    file_path: Some(name.to_string()),
                    offset: None,
                    modulus_bits: if bits > 0 { Some(bits) } else { None },
                    fingerprint_sha256: fp,
                    key_bytes: mod_bytes,
                });
                report.total_keys_found += 1;
            } else {
                // 3. Raw buffer stream carving for embedded certificates and keys
                carve_embedded_certificates(buffer, name, config, &mut report);
            }
        }

        correlate_private_keys(&mut report, config);
        report
    }
}

/// Recursively scan raw byte slices for embedded DER and PEM certificates/keys.
fn carve_embedded_certificates(
    buffer: &[u8],
    name: &str,
    config: &CertAuditConfig,
    report: &mut CertAuditReport,
) {
    let len = buffer.len();
    if len < 64 {
        return;
    }

    let mut i = 0;
    while i + 4 < len {
        // DER Certificate pattern: 0x30, 0x82, length_high, length_low, 0x30, 0x82...
        if buffer[i] == 0x30 && buffer[i + 1] == 0x82 {
            let total_len = ((buffer[i + 2] as usize) << 8) | (buffer[i + 3] as usize);
            if let Some(full_elem_len) = total_len.checked_add(4) {
                if (64..=16384).contains(&full_elem_len) {
                    if let Some(end_offset) = i.checked_add(full_elem_len) {
                        if end_offset <= len {
                            let slice = &buffer[i..end_offset];
                            if let Ok(cert) = parse_x509_certificate(slice) {
                                let findings = CertRuleEngine::evaluate_certificate(
                                    &cert,
                                    Some(name),
                                    Some(i),
                                    config,
                                );
                                for f in findings {
                                    report.add_finding(f);
                                }
                                report.total_certs_scanned += 1;
                                report.certificates.push(cert);
                                i += full_elem_len;
                                continue;
                            }

                            // Check for embedded RSA private key
                            if let Ok((mut mod_bytes, bits)) = parse_rsa_private_key_modulus(slice)
                            {
                                let fp = hex::encode(Sha256::digest(slice));
                                report.private_keys.push(DiscoveredPrivateKey {
                                    key_type: "Carved DER RSA Private Key".to_string(),
                                    file_path: Some(name.to_string()),
                                    offset: Some(i),
                                    modulus_bits: if bits > 0 { Some(bits) } else { None },
                                    fingerprint_sha256: fp,
                                    key_bytes: mod_bytes.clone(),
                                });
                                mod_bytes.zeroize();
                                report.total_keys_found += 1;
                                i += full_elem_len;
                                continue;
                            }
                        }
                    }
                }
            }
        }
        i += 1;
    }

    // Also scan for embedded PEM blocks in raw firmware dump
    let begin_needle = b"-----BEGIN ";
    let mut p = 0;
    while p + begin_needle.len() < len {
        if &buffer[p..p + begin_needle.len()] == begin_needle {
            if let Some(end_rel) = buffer[p..].windows(9).position(|w| w == b"-----END ") {
                let tail = &buffer[p + end_rel..];
                if tail.len() > 9 {
                    if let Some(dash_rel) = tail[9..].windows(5).position(|w| w == b"-----") {
                        if let Some(pem_len) = end_rel
                            .checked_add(9)
                            .and_then(|v| v.checked_add(dash_rel))
                            .and_then(|v| v.checked_add(5))
                        {
                            if let Some(end_p) = p.checked_add(pem_len) {
                                if end_p <= len {
                                    let block_bytes = &buffer[p..end_p];
                                    if let Ok(pem_str) = std::str::from_utf8(block_bytes) {
                                        let blocks = parse_pem_blocks(pem_str);
                                        for block in blocks {
                                            if block.label.contains("CERTIFICATE") {
                                                if let Ok(cert) =
                                                    parse_x509_certificate(&block.data)
                                                {
                                                    let findings =
                                                        CertRuleEngine::evaluate_certificate(
                                                            &cert,
                                                            Some(name),
                                                            Some(p),
                                                            config,
                                                        );
                                                    for f in findings {
                                                        report.add_finding(f);
                                                    }
                                                    report.total_certs_scanned += 1;
                                                    report.certificates.push(cert);
                                                }
                                            } else if block.label.contains("PRIVATE KEY") {
                                                let (mod_bytes, bits) =
                                                    parse_rsa_private_key_modulus(&block.data)
                                                        .unwrap_or_else(|_| (Vec::new(), 0));
                                                let fp = hex::encode(Sha256::digest(&block.data));
                                                report.private_keys.push(DiscoveredPrivateKey {
                                                    key_type: block.label.clone(),
                                                    file_path: Some(name.to_string()),
                                                    offset: Some(p),
                                                    modulus_bits: if bits > 0 {
                                                        Some(bits)
                                                    } else {
                                                        None
                                                    },
                                                    fingerprint_sha256: fp,
                                                    key_bytes: mod_bytes,
                                                });
                                                report.total_keys_found += 1;
                                            }
                                        }
                                    }
                                    p += pem_len;
                                    continue;
                                }
                            }
                        }
                    }
                }
            }
        }
        p += 1;
    }
}

fn collect_directory_files(
    dir: &Path,
    collected: &mut Vec<PathBuf>,
    visited: &mut HashSet<PathBuf>,
    depth: usize,
) -> Result<()> {
    if depth > 16 {
        return Ok(());
    }

    let canonical = fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    if !visited.insert(canonical) {
        return Ok(()); // Symlink loop defense
    }

    let entries = fs::read_dir(dir).map_err(|e| {
        CarverError::CertAudit(format!("Failed reading dir {}: {}", dir.display(), e))
    })?;

    for entry_res in entries {
        let entry = entry_res.map_err(|e| CarverError::CertAudit(e.to_string()))?;
        let path = entry.path();
        if path.is_dir() {
            collect_directory_files(&path, collected, visited, depth + 1)?;
        } else if path.is_file() {
            collected.push(path);
        }
    }
    Ok(())
}

fn merge_reports(target: &mut CertAuditReport, source: CertAuditReport) {
    target.total_certs_scanned += source.total_certs_scanned;
    target.total_keys_found += source.total_keys_found;
    target.certificates.extend(source.certificates);
    target.private_keys.extend(source.private_keys);
    for finding in source.findings {
        target.add_finding(finding);
    }
}

fn correlate_private_keys(report: &mut CertAuditReport, config: &CertAuditConfig) {
    let mut new_findings = Vec::new();
    for key in &report.private_keys {
        if let Some(finding) =
            CertRuleEngine::evaluate_private_key_match(key, &report.certificates, config)
        {
            new_findings.push(finding);
        }
    }
    for f in new_findings {
        report.add_finding(f);
    }
}
