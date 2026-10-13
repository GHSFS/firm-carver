// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::types::{
    CertAuditConfig, CertFinding, CertIssueKind, CertSeverity, DiscoveredPrivateKey,
    ParsedCertificate,
};

/// Security rule engine evaluating X.509 certificates and private keys.
pub struct CertRuleEngine;

impl CertRuleEngine {
    /// Evaluate a single certificate against all certificate rules.
    pub fn evaluate_certificate(
        cert: &ParsedCertificate,
        file_path: Option<&str>,
        offset: Option<usize>,
        config: &CertAuditConfig,
    ) -> Vec<CertFinding> {
        let mut findings = Vec::new();
        let ref_time = config.reference_timestamp;

        // CERT-EXP-001: Expired certificate
        if ref_time > cert.not_after.unix_timestamp {
            let elapsed_sec = ref_time - cert.not_after.unix_timestamp;
            let days_expired = elapsed_sec / 86400;
            let severity = if days_expired > 365 {
                CertSeverity::Critical
            } else {
                CertSeverity::High
            };

            if severity >= config.min_severity {
                findings.push(CertFinding {
                    rule_id: "CERT-EXP-001".to_string(),
                    severity,
                    issue_kind: CertIssueKind::Expired,
                    title: format!("Certificate Expired (expired {} days ago)", days_expired),
                    description: format!(
                        "Certificate for '{}' expired on {} (reference audit date: {}).",
                        cert.subject, cert.not_after, cert_format_timestamp(ref_time)
                    ),
                    cert_subject: cert.subject.clone(),
                    file_path: file_path.map(str::to_string),
                    offset,
                    fingerprint: cert.fingerprint_sha256.clone(),
                    remediation: "Regenerate and replace the TLS certificate with a freshly issued valid certificate."
                        .to_string(),
                });
            }
        } else if cert.not_after.unix_timestamp - ref_time < 30 * 86400 {
            // CERT-EXP-002: Expiring soon (<30 days)
            let remaining_days = (cert.not_after.unix_timestamp - ref_time) / 86400;
            if CertSeverity::Medium >= config.min_severity {
                findings.push(CertFinding {
                    rule_id: "CERT-EXP-002".to_string(),
                    severity: CertSeverity::Medium,
                    issue_kind: CertIssueKind::ExpiringSoon,
                    title: format!(
                        "Certificate Expiring Soon ({} days remaining)",
                        remaining_days
                    ),
                    description: format!(
                        "Certificate for '{}' expires soon on {} ({} days from reference date).",
                        cert.subject, cert.not_after, remaining_days
                    ),
                    cert_subject: cert.subject.clone(),
                    file_path: file_path.map(str::to_string),
                    offset,
                    fingerprint: cert.fingerprint_sha256.clone(),
                    remediation: "Schedule automatic certificate renewal before expiration."
                        .to_string(),
                });
            }
        }

        // CERT-SIG-001: Broken signature algorithm (MD2, MD5)
        if cert.sig_algo_oid == "1.2.840.113549.1.1.2"
            || cert.sig_algo_oid == "1.2.840.113549.1.1.4"
        {
            if CertSeverity::Critical >= config.min_severity {
                findings.push(CertFinding {
                    rule_id: "CERT-SIG-001".to_string(),
                    severity: CertSeverity::Critical,
                    issue_kind: CertIssueKind::WeakSignatureBroken,
                    title: format!("Broken Cryptographic Signature Algorithm ({})", cert.sig_algo_name),
                    description: format!(
                        "Certificate for '{}' was signed using collision-vulnerable algorithm {} (OID: {}).",
                        cert.subject, cert.sig_algo_name, cert.sig_algo_oid
                    ),
                    cert_subject: cert.subject.clone(),
                    file_path: file_path.map(str::to_string),
                    offset,
                    fingerprint: cert.fingerprint_sha256.clone(),
                    remediation: "Re-issue certificate using modern SHA-256 or SHA-384 signature algorithm."
                        .to_string(),
                });
            }
        } else if cert.sig_algo_oid == "1.2.840.113549.1.1.5"
            || cert.sig_algo_oid == "1.2.840.10045.4.1"
        {
            // CERT-SIG-002: Deprecated signature algorithm (SHA-1)
            if CertSeverity::High >= config.min_severity {
                findings.push(CertFinding {
                    rule_id: "CERT-SIG-002".to_string(),
                    severity: CertSeverity::High,
                    issue_kind: CertIssueKind::DeprecatedSignatureSha1,
                    title: format!("Deprecated SHA-1 Signature Algorithm ({})", cert.sig_algo_name),
                    description: format!(
                        "Certificate for '{}' uses deprecated SHA-1 digest (OID: {}), vulnerable to chosen-prefix collisions.",
                        cert.subject, cert.sig_algo_oid
                    ),
                    cert_subject: cert.subject.clone(),
                    file_path: file_path.map(str::to_string),
                    offset,
                    fingerprint: cert.fingerprint_sha256.clone(),
                    remediation: "Upgrade certificate authority to sign with SHA-256 or ECDSA P-256.".to_string(),
                });
            }
        }

        // CERT-KEY-001: Weak RSA key size (<1024 bits)
        if let Some(bits) = cert.rsa_bits {
            if bits < 1024 {
                if CertSeverity::Critical >= config.min_severity {
                    findings.push(CertFinding {
                        rule_id: "CERT-KEY-001".to_string(),
                        severity: CertSeverity::Critical,
                        issue_kind: CertIssueKind::WeakRsaKeyCritical,
                        title: format!("Insecure RSA Key Length ({} bits)", bits),
                        description: format!(
                            "Certificate for '{}' contains a {}-bit RSA key, which can be factored in hours with commodity hardware.",
                            cert.subject, bits
                        ),
                        cert_subject: cert.subject.clone(),
                        file_path: file_path.map(str::to_string),
                        offset,
                        fingerprint: cert.fingerprint_sha256.clone(),
                        remediation: "Generate a minimum 2048-bit (preferably 3072-bit or ECC P-256) public key."
                            .to_string(),
                    });
                }
            } else if bits == 1024 {
                // CERT-KEY-002: Deprecated RSA key size (1024 bits)
                if CertSeverity::High >= config.min_severity {
                    findings.push(CertFinding {
                        rule_id: "CERT-KEY-002".to_string(),
                        severity: CertSeverity::High,
                        issue_kind: CertIssueKind::DeprecatedRsaKey1024,
                        title: "Deprecated 1024-bit RSA Key Length".to_string(),
                        description: format!(
                            "Certificate for '{}' utilizes a legacy 1024-bit RSA key disallowed by modern NIST/CAB guidelines.",
                            cert.subject
                        ),
                        cert_subject: cert.subject.clone(),
                        file_path: file_path.map(str::to_string),
                        offset,
                        fingerprint: cert.fingerprint_sha256.clone(),
                        remediation: "Replace with at least a 2048-bit RSA key or ECDSA secp256r1 key."
                            .to_string(),
                    });
                }
            }
        }

        // CERT-SELF-001: Self-signed certificate deployed in firmware
        if cert.is_self_signed && CertSeverity::High >= config.min_severity {
            findings.push(CertFinding {
                rule_id: "CERT-SELF-001".to_string(),
                severity: CertSeverity::High,
                issue_kind: CertIssueKind::SelfSigned,
                title: "Self-Signed Certificate in Firmware Image".to_string(),
                description: format!(
                    "Certificate for '{}' is self-signed (Issuer equals Subject), lacking trust chain verification.",
                    cert.subject
                ),
                cert_subject: cert.subject.clone(),
                file_path: file_path.map(str::to_string),
                offset,
                fingerprint: cert.fingerprint_sha256.clone(),
                remediation: "Deploy certificates signed by an internal PKI or trusted Root CA."
                    .to_string(),
            });
        }

        // CERT-VAL-001: Anomalous validity period (>25 years or starting in distant future)
        let lifespan_sec = cert
            .not_after
            .unix_timestamp
            .saturating_sub(cert.not_before.unix_timestamp);
        let max_reasonable_sec = 25 * 365 * 86400; // ~25 years
        let post_dated = cert.not_before.unix_timestamp > ref_time + 30 * 86400;

        if (lifespan_sec > max_reasonable_sec || post_dated)
            && CertSeverity::Medium >= config.min_severity
        {
            let reason = if post_dated {
                format!("starts in future on {}", cert.not_before)
            } else {
                format!("lifespan is {} years", lifespan_sec / (365 * 86400))
            };
            findings.push(CertFinding {
                rule_id: "CERT-VAL-001".to_string(),
                severity: CertSeverity::Medium,
                issue_kind: CertIssueKind::AnomalousValidity,
                title: "Anomalous Certificate Validity Period".to_string(),
                description: format!(
                    "Certificate for '{}' has irregular validity bounds ({}): {} to {}.",
                    cert.subject, reason, cert.not_before, cert.not_after
                ),
                cert_subject: cert.subject.clone(),
                file_path: file_path.map(str::to_string),
                offset,
                fingerprint: cert.fingerprint_sha256.clone(),
                remediation:
                    "Issue certificate with standard validity period (typically <= 398 days)."
                        .to_string(),
            });
        }

        findings
    }

    /// Evaluate discovered private keys and check for matches against certificates.
    pub fn evaluate_private_key_match(
        key: &DiscoveredPrivateKey,
        certs: &[ParsedCertificate],
        config: &CertAuditConfig,
    ) -> Option<CertFinding> {
        if CertSeverity::Critical < config.min_severity {
            return None;
        }

        // Check if key matches any known certificate public key using constant-time comparison
        let mut matched_subject = None;
        for c in certs {
            if !c.public_key_bytes.is_empty() && !key.key_bytes.is_empty() {
                // If RSA, match modulus bytes in constant time to avoid timing side channels
                if constant_time_eq_bytes(&c.public_key_bytes, &key.key_bytes) {
                    matched_subject = Some(c.subject.clone());
                    break;
                }
            }
        }

        let desc = match matched_subject {
            Some(ref subj) => format!(
                "Hardcoded {} private key matches public key of certificate '{}'. Firmware leak permits full TLS decryption and MITM attacks.",
                key.key_type, subj
            ),
            None => format!(
                "Hardcoded {} private key discovered in firmware filesystem or stream dump. Unprotected private key allows unauthorized authentication.",
                key.key_type
            ),
        };

        Some(CertFinding {
            rule_id: "CERT-PRIV-001".to_string(),
            severity: CertSeverity::Critical,
            issue_kind: CertIssueKind::HardcodedPrivateKey,
            title: "Hardcoded TLS/Cryptographic Private Key Found".to_string(),
            description: desc,
            cert_subject: matched_subject.unwrap_or_else(|| "Unknown / Standalone Key".to_string()),
            file_path: key.file_path.clone(),
            offset: key.offset,
            fingerprint: key.fingerprint_sha256.clone(),
            remediation: "Remove embedded private keys from production firmware builds. Store device keys in hardware secure elements (TPM/HSM/SE) with per-device provisioning.".to_string(),
        })
    }
}

fn cert_format_timestamp(ts: i64) -> String {
    let days = ts / 86400;
    // Approximated readable UTC date for log display
    let mut year = 1970 + (days / 365) as i32;
    if year > 2050 {
        year = 2026;
    }
    format!("{} (epoch {})", year, ts)
}

/// Constant-time byte slice comparison to eliminate timing side channels.
fn constant_time_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
