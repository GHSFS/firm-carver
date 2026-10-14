// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::classifier::{classify_domain_category, classify_ip_str};
use super::extractor::{
    extract_endpoints_from_binary, extract_endpoints_from_text, ExtractedToken,
};
use super::rules::DomainRuleEngine;
use super::types::{
    DomainAuditConfig, DomainAuditReport, DomainAuditSummary, DomainSeverity, EndpointFinding,
    EndpointKind, IpScope,
};
use crate::error::{CarverError, Result};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::time::Instant;

/// Maximum single-file buffer read size (128 MiB) to prevent memory exhaustion
const MAX_READ_BYTES: u64 = 128 * 1024 * 1024;

/// Scanner engine for static domain, IP, and endpoint auditing.
pub struct DomainScanner;

impl DomainScanner {
    /// Recursively audit a directory tree for network endpoints and insecure communications.
    pub fn audit_directory(path: &Path, config: &DomainAuditConfig) -> Result<DomainAuditReport> {
        let start = Instant::now();
        if !path.exists() {
            return Err(CarverError::DomainAudit(format!(
                "Target path '{}' does not exist",
                path.display()
            )));
        }

        let mut findings = Vec::new();
        let mut total_bytes = 0;
        let mut visited_paths = HashSet::new();

        let mut stack = vec![path.to_path_buf()];

        while let Some(current) = stack.pop() {
            let canonical = match fs::canonicalize(&current) {
                Ok(c) => c,
                Err(_) => current.clone(),
            };

            if !visited_paths.insert(canonical) {
                continue; // Symlink loop guard
            }

            let metadata = match fs::symlink_metadata(&current) {
                Ok(m) => m,
                Err(_) => continue,
            };

            if metadata.is_dir() {
                let entries = match fs::read_dir(&current) {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                for entry in entries.flatten() {
                    stack.push(entry.path());
                }
            } else if metadata.is_file() {
                let file_len = metadata.len();
                if file_len > MAX_READ_BYTES {
                    continue;
                }
                total_bytes += file_len as usize;

                let file_findings = Self::scan_file_internal(&current, config)?;
                findings.extend(file_findings);
            }
        }

        let summary = build_summary(total_bytes, &findings);
        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(DomainAuditReport {
            target: path.to_string_lossy().to_string(),
            scan_duration_ms: duration_ms,
            summary,
            findings,
        })
    }

    /// Audit a single file (script, config, binary, or flash dump).
    pub fn audit_single_file(path: &Path, config: &DomainAuditConfig) -> Result<DomainAuditReport> {
        let start = Instant::now();
        if !path.exists() {
            return Err(CarverError::DomainAudit(format!(
                "File '{}' does not exist",
                path.display()
            )));
        }

        let metadata = fs::metadata(path)?;
        let total_bytes = metadata.len() as usize;
        let findings = Self::scan_file_internal(path, config)?;
        let summary = build_summary(total_bytes, &findings);
        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(DomainAuditReport {
            target: path.to_string_lossy().to_string(),
            scan_duration_ms: duration_ms,
            summary,
            findings,
        })
    }

    /// Audit an in-memory byte buffer (e.g. carved partition or flash dump).
    pub fn audit_raw_buffer(
        name: &str,
        bytes: &[u8],
        base_offset: usize,
        config: &DomainAuditConfig,
    ) -> DomainAuditReport {
        let start = Instant::now();
        let tokens = extract_endpoints_from_binary(bytes, config.min_string_length, base_offset);
        let findings = process_tokens(tokens, Some(name.to_string()), config);
        let summary = build_summary(bytes.len(), &findings);
        let duration_ms = start.elapsed().as_millis() as u64;

        DomainAuditReport {
            target: name.to_string(),
            scan_duration_ms: duration_ms,
            summary,
            findings,
        }
    }

    fn scan_file_internal(path: &Path, config: &DomainAuditConfig) -> Result<Vec<EndpointFinding>> {
        let path_str = path.to_string_lossy().to_string();
        let is_text = is_probable_text_file(path);

        if is_text {
            // Read line by line with line numbers
            let file = File::open(path)?;
            let reader = BufReader::new(file);
            let mut all_tokens = Vec::new();

            for (idx, line_res) in reader.lines().enumerate() {
                if let Ok(line) = line_res {
                    let tokens = extract_endpoints_from_text(&line, None, Some(idx + 1));
                    all_tokens.extend(tokens);
                }
            }

            Ok(process_tokens(all_tokens, Some(path_str), config))
        } else {
            // Read binary buffer
            let mut file = File::open(path)?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;

            let tokens = extract_endpoints_from_binary(&buffer, config.min_string_length, 0);
            Ok(process_tokens(tokens, Some(path_str), config))
        }
    }
}

fn process_tokens(
    tokens: Vec<ExtractedToken>,
    file_path: Option<String>,
    config: &DomainAuditConfig,
) -> Vec<EndpointFinding> {
    let mut findings = Vec::new();
    let mut seen_normalized = HashSet::new();

    for token in tokens {
        if let Some(kf) = config.kind_filter {
            if token.kind != kf {
                continue;
            }
        }

        let ip_scope = if token.kind == EndpointKind::Ipv4 || token.kind == EndpointKind::Ipv6 {
            classify_ip_str(&token.host)
        } else {
            None
        };

        if !config.include_private_ips
            && matches!(
                ip_scope,
                Some(IpScope::PrivateRfc1918) | Some(IpScope::Loopback) | Some(IpScope::LinkLocal)
            )
        {
            continue;
        }

        let domain_category =
            if token.kind == EndpointKind::Domain || token.kind == EndpointKind::Url {
                Some(classify_domain_category(&token.host))
            } else {
                None
            };

        let issues = DomainRuleEngine::audit_token(&token, ip_scope, domain_category);

        // Filter by minimum severity if issues are present
        let highest_severity = issues
            .iter()
            .map(|i| i.severity)
            .max()
            .unwrap_or(DomainSeverity::Info);
        if !issues.is_empty() && highest_severity < config.min_severity {
            continue;
        }

        // Deduplicate repeated endpoints in the same file/context
        let dedupe_key = format!(
            "{}:{}:{:?}",
            token.host,
            token.port.unwrap_or(0),
            token.scheme
        );
        if !seen_normalized.insert(dedupe_key) {
            continue;
        }

        let normalized = if let Some(scheme) = &token.scheme {
            if let Some(port) = token.port {
                format!(
                    "{}://{}:{}{}",
                    scheme,
                    token.host,
                    port,
                    token.path.as_deref().unwrap_or("")
                )
            } else {
                format!(
                    "{}://{}{}",
                    scheme,
                    token.host,
                    token.path.as_deref().unwrap_or("")
                )
            }
        } else if let Some(port) = token.port {
            format!("{}:{}", token.host, port)
        } else {
            token.host.clone()
        };

        findings.push(EndpointFinding {
            raw: token.raw,
            normalized,
            kind: token.kind,
            scheme: token.scheme,
            ip_scope,
            domain_category,
            port: token.port,
            file_path: file_path.clone(),
            offset: token.offset,
            line_number: token.line_number,
            issues,
        });
    }

    findings
}

fn build_summary(total_bytes: usize, findings: &[EndpointFinding]) -> DomainAuditSummary {
    let mut summary = DomainAuditSummary {
        total_scanned_bytes: total_bytes,
        total_endpoints_found: findings.len(),
        ..Default::default()
    };

    for f in findings {
        match f.kind {
            EndpointKind::Url => summary.url_count += 1,
            EndpointKind::Ipv4 => summary.ipv4_count += 1,
            EndpointKind::Ipv6 => summary.ipv6_count += 1,
            EndpointKind::Domain => summary.domain_count += 1,
        }

        for issue in &f.issues {
            match issue.severity {
                DomainSeverity::Critical => summary.critical_count += 1,
                DomainSeverity::High => summary.high_count += 1,
                DomainSeverity::Medium => summary.medium_count += 1,
                DomainSeverity::Low => summary.low_count += 1,
                DomainSeverity::Info => summary.info_count += 1,
            }
        }
    }

    summary
}

fn is_probable_text_file(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let text_exts = [
        "txt", "sh", "bash", "cgi", "pl", "py", "lua", "conf", "cfg", "ini", "json", "xml", "html",
        "htm", "js", "css", "env", "default", "rc", "service", "dts", "dtsi", "log", "md", "yml",
        "yaml", "toml",
    ];

    if text_exts.contains(&ext.as_str()) {
        return true;
    }

    // Check first 512 bytes for null byte
    if let Ok(mut file) = File::open(path) {
        let mut sample = [0u8; 512];
        if let Ok(n) = file.read(&mut sample) {
            return !sample[..n].contains(&0);
        }
    }

    false
}
