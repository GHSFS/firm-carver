// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Severity classification for discovered CGI and web interface vulnerabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CgiSeverity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl fmt::Display for CgiSeverity {
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

impl FromStr for CgiSeverity {
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

/// Vulnerability category taxonomy based on common CWE weaknesses in embedded web management.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CgiVulnCategory {
    /// CWE-78: OS Command Injection via unescaped shell inputs or system sinks
    CommandInjection,
    /// CWE-306: Missing Authentication for Critical Function / Admin Bypass
    AuthBypass,
    /// CWE-798: Use of Hard-coded Administrative Credentials or Secret Keys
    HardcodedCredentials,
    /// CWE-22: Improper Limitation of a Pathname to a Restricted Directory
    PathTraversal,
    /// CWE-200: Exposure of Sensitive System Information (shadow, nvram, dmesg)
    InformationDisclosure,
    /// CWE-16: Insecure Configuration, Debug Flags or Diagnostic Interfaces
    InsecureConfiguration,
}

impl fmt::Display for CgiVulnCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommandInjection => write!(f, "Command Injection (CWE-78)"),
            Self::AuthBypass => write!(f, "Authentication Bypass (CWE-306)"),
            Self::HardcodedCredentials => write!(f, "Hardcoded Credentials (CWE-798)"),
            Self::PathTraversal => write!(f, "Path Traversal (CWE-22)"),
            Self::InformationDisclosure => write!(f, "Information Disclosure (CWE-200)"),
            Self::InsecureConfiguration => write!(f, "Insecure Configuration (CWE-16)"),
        }
    }
}

/// A single security finding discovered within an embedded CGI script or web interface file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgiFinding {
    /// Unique finding identifier
    pub id: String,
    /// Detection rule identifier (e.g., CGI-CMD-001)
    pub rule_id: String,
    /// Human-readable title
    pub title: String,
    /// Finding severity level
    pub severity: CgiSeverity,
    /// CWE categorization
    pub category: CgiVulnCategory,
    /// Official CWE identifier (e.g. CWE-78)
    pub cwe: String,
    /// Relative or absolute path of the affected script file
    pub file_path: String,
    /// 1-based line number if identifiable within the file
    pub line_number: Option<usize>,
    /// Code snippet or matched token providing proof of vulnerability
    pub evidence: String,
    /// Detailed vulnerability impact explanation
    pub description: String,
    /// Concrete engineering remediation instructions
    pub remediation: String,
}

/// Configuration settings controlling the CGI static auditing engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CgiAuditConfig {
    /// Minimum severity threshold to include in reports
    pub min_severity: CgiSeverity,
    /// Maximum file size in bytes to inspect (default: 5 MiB)
    pub max_file_size: usize,
    /// Whether to recursively inspect subdirectories
    pub scan_subdirectories: bool,
    /// Whitelist of file extensions to audit
    pub target_extensions: Vec<String>,
}

impl Default for CgiAuditConfig {
    fn default() -> Self {
        Self {
            min_severity: CgiSeverity::Low,
            max_file_size: 5 * 1024 * 1024,
            scan_subdirectories: true,
            target_extensions: vec![
                "cgi".to_string(),
                "sh".to_string(),
                "asp".to_string(),
                "aspx".to_string(),
                "lua".to_string(),
                "php".to_string(),
                "js".to_string(),
                "htm".to_string(),
                "html".to_string(),
                "inc".to_string(),
                "pl".to_string(),
                "py".to_string(),
                "conf".to_string(),
            ],
        }
    }
}

/// Comprehensive static audit report aggregating all findings across web files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgiAuditReport {
    /// Analyzed target directory or file path
    pub target_path: String,
    /// Total number of script / web files scanned
    pub total_files_scanned: usize,
    /// Total lines of code inspected across all files
    pub total_lines_scanned: usize,
    /// Total number of security findings matching severity threshold
    pub total_findings: usize,
    /// Count of critical severity findings
    pub critical_count: usize,
    /// Count of high severity findings
    pub high_count: usize,
    /// Count of medium severity findings
    pub medium_count: usize,
    /// Count of low severity findings
    pub low_count: usize,
    /// Count of informational findings
    pub info_count: usize,
    /// List of discovered findings sorted by severity descending
    pub findings: Vec<CgiFinding>,
    /// List of file paths included in the audit
    pub scanned_files: Vec<String>,
}
