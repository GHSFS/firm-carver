// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum VulnSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VulnCategory {
    PrivateKey,
    HardcodedCredential,
    BackdoorCommand,
    SecurityBypass,
    InsecureConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnFinding {
    pub id: String,
    pub title: String,
    pub severity: VulnSeverity,
    pub category: VulnCategory,
    pub offset: usize,
    pub evidence: String,
    pub description: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnAuditReport {
    pub target_file: String,
    pub target_size: usize,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub findings: Vec<VulnFinding>,
}

struct PatternRule {
    pattern: &'static [u8],
    id: &'static str,
    title: &'static str,
    severity: VulnSeverity,
    category: VulnCategory,
    desc: &'static str,
    remedy: &'static str,
}

const STATIC_RULES: &[PatternRule] = &[
    PatternRule {
        pattern: b"-----BEGIN RSA PRIVATE KEY-----",
        id: "FCARV-SEC-001",
        title: "Embedded Unencrypted RSA Private Key",
        severity: VulnSeverity::Critical,
        category: VulnCategory::PrivateKey,
        desc: "Found an unencrypted RSA private key hardcoded into the firmware blob.",
        remedy: "Strip hardcoded private keys from firmware builds; use hardware secure elements or generate keys on initial boot.",
    },
    PatternRule {
        pattern: b"-----BEGIN EC PRIVATE KEY-----",
        id: "FCARV-SEC-002",
        title: "Embedded Unencrypted EC Private Key",
        severity: VulnSeverity::Critical,
        category: VulnCategory::PrivateKey,
        desc: "Found an unencrypted Elliptic Curve private key in firmware storage.",
        remedy: "Do not bake cryptographic signing or identity keys into public firmware images.",
    },
    PatternRule {
        pattern: b"-----BEGIN OPENSSH PRIVATE KEY-----",
        id: "FCARV-SEC-003",
        title: "Embedded OpenSSH Host Private Key",
        severity: VulnSeverity::Critical,
        category: VulnCategory::PrivateKey,
        desc: "Found OpenSSH static host private key baked into filesystem image.",
        remedy: "Generate device-unique SSH host keys during factory onboarding or first-time setup wizard.",
    },
    PatternRule {
        pattern: b"-----BEGIN PRIVATE KEY-----",
        id: "FCARV-SEC-004",
        title: "Embedded PKCS#8 Private Key",
        severity: VulnSeverity::Critical,
        category: VulnCategory::PrivateKey,
        desc: "Found an unencrypted PKCS#8 generic private key in firmware image.",
        remedy: "Store secrets in an encrypted keystore or hardware security module (HSM).",
    },
    PatternRule {
        pattern: b"telnetd -l /bin/sh",
        id: "FCARV-SEC-010",
        title: "Unauthenticated Root Telnet Shell Backdoor",
        severity: VulnSeverity::Critical,
        category: VulnCategory::BackdoorCommand,
        desc: "Firmware launches telnet daemon binding directly to root shell without password authentication.",
        remedy: "Disable insecure telnetd invocations with unauthenticated shell flags (-l /bin/sh).",
    },
    PatternRule {
        pattern: b"telnetd -l /bin/ash",
        id: "FCARV-SEC-011",
        title: "Unauthenticated Ash Telnet Shell Backdoor",
        severity: VulnSeverity::Critical,
        category: VulnCategory::BackdoorCommand,
        desc: "Detected telnet daemon bound to BusyBox ash shell bypass.",
        remedy: "Ensure login authentication PAM/shadow integration is strictly enforced.",
    },
    PatternRule {
        pattern: b"iptables -F",
        id: "FCARV-SEC-020",
        title: "Firewall Filter Flush Command",
        severity: VulnSeverity::High,
        category: VulnCategory::SecurityBypass,
        desc: "Startup or diagnostic script flushes all network firewall filter rules.",
        remedy: "Avoid indiscriminate iptables -F in production firmware scripts.",
    },
    PatternRule {
        pattern: b"root:$1$",
        id: "FCARV-SEC-030",
        title: "Static MD5 Root Password Hash in Shadow",
        severity: VulnSeverity::Critical,
        category: VulnCategory::HardcodedCredential,
        desc: "Found static MD5 crypt root password hash in embedded /etc/shadow file.",
        remedy: "Enforce dynamic per-device randomized initial root credentials or prompt at setup.",
    },
    PatternRule {
        pattern: b"root:$6$",
        id: "FCARV-SEC-031",
        title: "Static SHA-512 Root Password Hash in Shadow",
        severity: VulnSeverity::Critical,
        category: VulnCategory::HardcodedCredential,
        desc: "Found static SHA-512 crypt root password hash in embedded /etc/shadow file.",
        remedy: "Avoid pre-baked root credentials shared across all manufactured devices.",
    },
    PatternRule {
        pattern: b"root::0:0:",
        id: "FCARV-SEC-032",
        title: "Empty Root Password Account",
        severity: VulnSeverity::Critical,
        category: VulnCategory::HardcodedCredential,
        desc: "Found passwordless root account entry in /etc/passwd.",
        remedy: "Lock passwordless root accounts using 'root:*:0:0:' or strict SSH key auth.",
    },
    PatternRule {
        pattern: b"admin:admin",
        id: "FCARV-SEC-040",
        title: "Default 'admin:admin' Credential Pair",
        severity: VulnSeverity::High,
        category: VulnCategory::HardcodedCredential,
        desc: "Hardcoded default admin:admin credentials detected in configuration or script.",
        remedy: "Mandate unique setup password printed on device label or initial onboarding.",
    },
    PatternRule {
        pattern: b"root:root",
        id: "FCARV-SEC-041",
        title: "Default 'root:root' Credential Pair",
        severity: VulnSeverity::High,
        category: VulnCategory::HardcodedCredential,
        desc: "Hardcoded default root:root credentials detected.",
        remedy: "Eliminate static default passwords across all production images.",
    },
    PatternRule {
        pattern: b"root:toor",
        id: "FCARV-SEC-042",
        title: "Default 'root:toor' Credential Pair",
        severity: VulnSeverity::High,
        category: VulnCategory::HardcodedCredential,
        desc: "Common test credential pair root:toor discovered in firmware blob.",
        remedy: "Remove debugging and QA default accounts before firmware release.",
    },
];

fn extract_evidence(data: &[u8], offset: usize, pat_len: usize) -> String {
    let start = offset.saturating_sub(16);
    let end = (offset + pat_len + 32).min(data.len());
    let slice = &data[start..end];
    let sanitized: String = slice
        .iter()
        .map(|&b| {
            if (0x20..=0x7E).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect();
    sanitized
}

pub fn scan_vulnerabilities(data: &[u8], target_file: &str) -> VulnAuditReport {
    let mut findings = Vec::new();

    // 1. Static Rule Scanning
    for rule in STATIC_RULES {
        let mut pos = 0;
        while let Some(idx) = find_subslice(&data[pos..], rule.pattern) {
            let offset = pos + idx;
            findings.push(VulnFinding {
                id: rule.id.to_string(),
                title: rule.title.to_string(),
                severity: rule.severity,
                category: rule.category.clone(),
                offset,
                evidence: extract_evidence(data, offset, rule.pattern.len()),
                description: rule.desc.to_string(),
                remediation: rule.remedy.to_string(),
            });
            pos = offset + rule.pattern.len();
            if pos >= data.len() {
                break;
            }
        }
    }

    // 2. Netcat backdoor scanning (e.g. nc -l -p ... -e /bin/sh or nc -e /bin/sh)
    let nc_patterns: &[(&[u8], &str)] = &[
        (b"-e /bin/sh", "Netcat Shell Execution Flag (-e /bin/sh)"),
        (
            b"-e /bin/ash",
            "Netcat Ash Shell Execution Flag (-e /bin/ash)",
        ),
    ];

    for (pat, desc) in nc_patterns {
        let mut pos = 0;
        while let Some(idx) = find_subslice(&data[pos..], pat) {
            let offset = pos + idx;
            findings.push(VulnFinding {
                id: "FCARV-SEC-050".to_string(),
                title: "Dangerous Netcat Shell Redirection".to_string(),
                severity: VulnSeverity::Critical,
                category: VulnCategory::BackdoorCommand,
                offset,
                evidence: extract_evidence(data, offset, pat.len()),
                description: desc.to_string(),
                remediation:
                    "Compile busybox without FEATURE_NETCAT_SHELL_EXEC or remove backdoor scripts."
                        .to_string(),
            });
            pos = offset + pat.len();
            if pos >= data.len() {
                break;
            }
        }
    }

    let mut critical_count = 0;
    let mut high_count = 0;
    let mut medium_count = 0;
    let mut low_count = 0;

    for f in &findings {
        match f.severity {
            VulnSeverity::Critical => critical_count += 1,
            VulnSeverity::High => high_count += 1,
            VulnSeverity::Medium => medium_count += 1,
            VulnSeverity::Low => low_count += 1,
        }
    }

    VulnAuditReport {
        target_file: target_file.to_string(),
        target_size: data.len(),
        total_findings: findings.len(),
        critical_count,
        high_count,
        medium_count,
        low_count,
        findings,
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}
