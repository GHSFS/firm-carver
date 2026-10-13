// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Severity classification for discovered TLS certificate and cryptographic issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CertSeverity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl fmt::Display for CertSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl FromStr for CertSeverity {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "critical" => Ok(Self::Critical),
            "high" => Ok(Self::High),
            "medium" | "med" => Ok(Self::Medium),
            "low" => Ok(Self::Low),
            "info" => Ok(Self::Info),
            other => Err(format!(
                "Invalid severity '{}'. Expected critical, high, medium, low, or info.",
                other
            )),
        }
    }
}

/// Category taxonomy for discovered certificate security flaws.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertIssueKind {
    /// Certificate expired past reference date
    Expired,
    /// Certificate expiring soon (< 30 days)
    ExpiringSoon,
    /// Broken signature hash algorithm (MD2, MD5)
    WeakSignatureBroken,
    /// Deprecated signature hash algorithm (SHA-1)
    DeprecatedSignatureSha1,
    /// Vulnerable RSA key size (< 1024 bits, e.g. 512-bit)
    WeakRsaKeyCritical,
    /// Deprecated RSA key size (1024 bits)
    DeprecatedRsaKey1024,
    /// Self-signed certificate deployed in production firmware
    SelfSigned,
    /// Embedded plaintext private key found
    HardcodedPrivateKey,
    /// Anomalous validity lifespan (> 25 years or post-dated start)
    AnomalousValidity,
}

impl fmt::Display for CertIssueKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expired => write!(f, "Expired Certificate"),
            Self::ExpiringSoon => write!(f, "Expiring Soon (<30d)"),
            Self::WeakSignatureBroken => write!(f, "Broken Signature Algo (MD2/MD5)"),
            Self::DeprecatedSignatureSha1 => write!(f, "Deprecated Signature Algo (SHA-1)"),
            Self::WeakRsaKeyCritical => write!(f, "Weak RSA Key (<1024 bits)"),
            Self::DeprecatedRsaKey1024 => write!(f, "Deprecated RSA Key (1024 bits)"),
            Self::SelfSigned => write!(f, "Self-Signed Certificate"),
            Self::HardcodedPrivateKey => write!(f, "Hardcoded Private Key"),
            Self::AnomalousValidity => write!(f, "Anomalous Validity Period"),
        }
    }
}

/// UTC date representation for ASN.1 validity intervals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertDate {
    pub year: i32,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub unix_timestamp: i64,
}

impl fmt::Display for CertDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}

/// Parsed X.509 certificate metadata extracted from DER or PEM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedCertificate {
    pub subject: String,
    pub issuer: String,
    pub serial_hex: String,
    pub not_before: CertDate,
    pub not_after: CertDate,
    pub sig_algo_oid: String,
    pub sig_algo_name: String,
    pub pubkey_algo_oid: String,
    pub pubkey_algo_name: String,
    pub rsa_bits: Option<usize>,
    pub ec_curve: Option<String>,
    pub is_self_signed: bool,
    pub fingerprint_sha256: String,
    #[serde(skip)]
    pub public_key_bytes: Vec<u8>,
    #[serde(skip)]
    pub raw_der: Vec<u8>,
}

use zeroize::Zeroize;

/// Discovered private key block in firmware.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredPrivateKey {
    pub key_type: String,
    pub file_path: Option<String>,
    pub offset: Option<usize>,
    pub modulus_bits: Option<usize>,
    pub fingerprint_sha256: String,
    #[serde(skip)]
    pub key_bytes: Vec<u8>,
}

impl Drop for DiscoveredPrivateKey {
    fn drop(&mut self) {
        self.key_bytes.zeroize();
    }
}

impl Zeroize for DiscoveredPrivateKey {
    fn zeroize(&mut self) {
        self.key_bytes.zeroize();
    }
}

/// Single security finding identified during certificate audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertFinding {
    pub rule_id: String,
    pub severity: CertSeverity,
    pub issue_kind: CertIssueKind,
    pub title: String,
    pub description: String,
    pub cert_subject: String,
    pub file_path: Option<String>,
    pub offset: Option<usize>,
    pub fingerprint: String,
    pub remediation: String,
}

/// Configuration options for certificate auditing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertAuditConfig {
    pub min_severity: CertSeverity,
    pub reference_timestamp: i64,
}

impl Default for CertAuditConfig {
    fn default() -> Self {
        Self {
            min_severity: CertSeverity::Low,
            // Default reference date: 2026-10-13 00:00:00 UTC (1791849600)
            reference_timestamp: 1_791_849_600,
        }
    }
}

/// Complete audit report for discovered certificates and cryptographic keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertAuditReport {
    pub target_path: String,
    pub total_certs_scanned: usize,
    pub total_keys_found: usize,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub certificates: Vec<ParsedCertificate>,
    pub private_keys: Vec<DiscoveredPrivateKey>,
    pub findings: Vec<CertFinding>,
}

impl CertAuditReport {
    pub fn new(target_path: String) -> Self {
        Self {
            target_path,
            total_certs_scanned: 0,
            total_keys_found: 0,
            total_findings: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            info_count: 0,
            certificates: Vec::new(),
            private_keys: Vec::new(),
            findings: Vec::new(),
        }
    }

    pub fn add_finding(&mut self, finding: CertFinding) {
        match finding.severity {
            CertSeverity::Critical => self.critical_count += 1,
            CertSeverity::High => self.high_count += 1,
            CertSeverity::Medium => self.medium_count += 1,
            CertSeverity::Low => self.low_count += 1,
            CertSeverity::Info => self.info_count += 1,
        }
        self.total_findings += 1;
        self.findings.push(finding);
    }
}
