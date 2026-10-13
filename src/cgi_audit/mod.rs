// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

pub mod rules;
pub mod scanner;
pub mod synth;
pub mod types;

pub use rules::CgiRuleEngine;
pub use scanner::CgiScanner;
pub use synth::CgiSynth;
pub use types::{CgiAuditConfig, CgiAuditReport, CgiFinding, CgiSeverity, CgiVulnCategory};

use crate::error::{CarverError, Result};
use std::path::Path;

/// High-level entry point to audit either an extracted `/www` directory or a standalone CGI script file.
pub fn audit_web_path(target: &Path, config: &CgiAuditConfig) -> Result<CgiAuditReport> {
    if !target.exists() {
        return Err(CarverError::CgiAudit(format!(
            "Target path does not exist: {}",
            target.display()
        )));
    }

    if target.is_dir() {
        CgiScanner::audit_directory(target, config)
    } else {
        CgiScanner::audit_single_file(target, config)
    }
}

/// Format an aligned, human-readable terminal report from a CGI audit report.
pub fn format_cgi_report(report: &CgiAuditReport) -> String {
    let mut out = String::new();
    out.push_str("=== FirmCarver Embedded Web Management & CGI Static Auditor ===\n");
    out.push_str(&format!("Target Path:         {}\n", report.target_path));
    out.push_str(&format!(
        "Files Scanned:       {}\n",
        report.total_files_scanned
    ));
    out.push_str(&format!(
        "Lines Inspected:     {}\n",
        report.total_lines_scanned
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

    if report.findings.is_empty() {
        out.push_str("No security vulnerabilities or suspicious CGI script patterns identified.\n");
        return out;
    }

    out.push_str(&format!(
        "{:<3} {:<10} {:<12} {:<22} {:<24} {:<4}\n",
        "#", "Severity", "Rule ID", "Weakness Category", "File Path", "Line"
    ));
    out.push_str(&format!("{}\n", "-".repeat(95)));

    for (idx, f) in report.findings.iter().enumerate() {
        let line_str = f
            .line_number
            .map(|l| l.to_string())
            .unwrap_or_else(|| "-".to_string());

        let file_truncated = if f.file_path.len() > 23 {
            format!("...{}", &f.file_path[f.file_path.len() - 20..])
        } else {
            f.file_path.clone()
        };

        out.push_str(&format!(
            "{:<3} [{:<8}] {:<12} {:<22} {:<24} {:<4}\n",
            idx + 1,
            f.severity.to_string(),
            f.rule_id,
            match f.category {
                CgiVulnCategory::CommandInjection => "Cmd Injection (CWE-78)",
                CgiVulnCategory::AuthBypass => "Auth Bypass (CWE-306)",
                CgiVulnCategory::HardcodedCredentials => "Credentials (CWE-798)",
                CgiVulnCategory::PathTraversal => "Path Trav (CWE-22)",
                CgiVulnCategory::InformationDisclosure => "Info Disclose (CWE-200)",
                CgiVulnCategory::InsecureConfiguration => "Insecure Cfg (CWE-16)",
            },
            file_truncated,
            line_str
        ));
        out.push_str(&format!("     Evidence:   \"{}\"\n", f.evidence));
        out.push_str(&format!("     Remediation: {}\n", f.remediation));
        out.push('\n');
    }

    out
}
