// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

pub mod classifier;
pub mod extractor;
pub mod rules;
pub mod scanner;
pub mod synth;
pub mod types;

use crate::error::Result;
use std::path::Path;

pub use classifier::{
    classify_domain_category, classify_ip_str, classify_ipv4_scope, classify_ipv6_scope,
};
pub use extractor::{extract_endpoints_from_binary, extract_endpoints_from_text, ExtractedToken};
pub use rules::DomainRuleEngine;
pub use scanner::DomainScanner;
pub use synth::DomainSynth;
pub use types::{
    DomainAuditConfig, DomainAuditReport, DomainAuditSummary, DomainCategory, DomainIssueCode,
    DomainSecurityIssue, DomainSeverity, EndpointFinding, EndpointKind, IpScope, UrlScheme,
};

/// High-level function to audit a filesystem path (file or directory).
pub fn audit_domain_path(path: &Path, config: &DomainAuditConfig) -> Result<DomainAuditReport> {
    if path.is_dir() {
        DomainScanner::audit_directory(path, config)
    } else {
        DomainScanner::audit_single_file(path, config)
    }
}

/// High-level function to audit an in-memory binary firmware slice.
pub fn audit_domain_buffer(
    name: &str,
    bytes: &[u8],
    base_offset: usize,
    config: &DomainAuditConfig,
) -> DomainAuditReport {
    DomainScanner::audit_raw_buffer(name, bytes, base_offset, config)
}

/// Format the domain audit report as a clean human-readable CLI report.
pub fn format_domain_report(report: &DomainAuditReport) -> String {
    let mut out = String::new();

    out.push_str(
        "================================================================================\n",
    );
    out.push_str(
        "                FIRM-CARVER NETWORK ENDPOINT & DOMAIN AUDIT REPORT             \n",
    );
    out.push_str(
        "================================================================================\n",
    );
    out.push_str(&format!("Target:             {}\n", report.target));
    out.push_str(&format!(
        "Scan Duration:      {} ms\n",
        report.scan_duration_ms
    ));
    out.push_str(&format!(
        "Scanned Payload:    {} bytes ({:.2} KB)\n",
        report.summary.total_scanned_bytes,
        report.summary.total_scanned_bytes as f64 / 1024.0
    ));
    out.push_str(&format!(
        "Total Endpoints:    {}\n",
        report.summary.total_endpoints_found
    ));
    out.push_str(&format!(
        "Distribution:       {} URLs | {} IPv4 | {} IPv6 | {} Domains\n",
        report.summary.url_count,
        report.summary.ipv4_count,
        report.summary.ipv6_count,
        report.summary.domain_count
    ));
    out.push_str(&format!(
        "Risk Assessment:    {} CRITICAL | {} HIGH | {} MEDIUM | {} LOW | {} INFO\n",
        report.summary.critical_count,
        report.summary.high_count,
        report.summary.medium_count,
        report.summary.low_count,
        report.summary.info_count
    ));
    out.push_str(
        "--------------------------------------------------------------------------------\n",
    );
    out.push_str(&format!(
        "{:<8} {:<10} {:<34} {:<15} {:<10}\n",
        "KIND", "SCHEME/IP", "ENDPOINT / HOST", "CATEGORY", "ISSUES"
    ));
    out.push_str(
        "--------------------------------------------------------------------------------\n",
    );

    if report.findings.is_empty() {
        out.push_str("No network endpoints matching filter criteria were discovered.\n");
    } else {
        for f in &report.findings {
            let scheme_or_ip = if let Some(s) = &f.scheme {
                s.to_string()
            } else if let Some(ip) = f.ip_scope {
                ip.to_string()
            } else {
                "-".to_string()
            };

            let cat = f
                .domain_category
                .map(|c| c.to_string())
                .unwrap_or_else(|| "-".to_string());

            let issues_str = if f.issues.is_empty() {
                "CLEAN".to_string()
            } else {
                f.issues
                    .iter()
                    .map(|i| format!("{}:{}", i.code, i.severity))
                    .collect::<Vec<_>>()
                    .join(", ")
            };

            let truncated_endpoint = if f.normalized.len() > 32 {
                format!("{}...", &f.normalized[..29])
            } else {
                f.normalized.clone()
            };

            out.push_str(&format!(
                "{:<8} {:<10} {:<34} {:<15} {:<10}\n",
                f.kind, scheme_or_ip, truncated_endpoint, cat, issues_str
            ));

            for issue in &f.issues {
                out.push_str(&format!(
                    "         -> [{}] {}: {}\n",
                    issue.severity, issue.code, issue.title
                ));
            }
        }
    }

    out.push_str(
        "================================================================================\n",
    );
    out
}
