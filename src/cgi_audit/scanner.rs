// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::rules::CgiRuleEngine;
use super::types::{CgiAuditConfig, CgiAuditReport, CgiFinding, CgiSeverity};
use crate::error::{CarverError, Result};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Scanner engine for executing static security audits across filesystem trees and in-memory assets.
pub struct CgiScanner;

impl CgiScanner {
    /// Recursively audit a directory tree on disk (e.g., carved `/www` or `/cgi-bin` root).
    pub fn audit_directory(dir: &Path, config: &CgiAuditConfig) -> Result<CgiAuditReport> {
        if !dir.exists() {
            return Err(CarverError::CgiAudit(format!(
                "Directory does not exist: {}",
                dir.display()
            )));
        }

        let mut collected_files = Vec::new();
        let mut visited_paths = HashSet::new();

        Self::collect_files_recursive(dir, config, &mut collected_files, &mut visited_paths)?;

        let mut total_lines = 0;
        let mut all_findings = Vec::new();
        let mut scanned_files = Vec::new();

        for file_path in &collected_files {
            let metadata = match fs::metadata(file_path) {
                Ok(m) => m,
                Err(_) => continue,
            };

            if metadata.len() as usize > config.max_file_size {
                continue;
            }

            let raw_bytes = match fs::read(file_path) {
                Ok(b) => b,
                Err(_) => continue,
            };

            let content = String::from_utf8_lossy(&raw_bytes);
            let line_count = content.lines().count();
            total_lines += line_count;

            let relative_display = file_path
                .strip_prefix(dir)
                .unwrap_or(file_path)
                .to_string_lossy()
                .replace('\\', "/");

            scanned_files.push(relative_display.clone());

            let mut findings = CgiRuleEngine::evaluate_lines(&relative_display, &content);
            findings.extend(CgiRuleEngine::evaluate_file_context(
                &relative_display,
                &content,
            ));

            for f in findings {
                if f.severity >= config.min_severity {
                    all_findings.push(f);
                }
            }
        }

        Self::build_report(
            &dir.to_string_lossy(),
            scanned_files,
            total_lines,
            all_findings,
        )
    }

    /// Audit a single file on disk.
    pub fn audit_single_file(file: &Path, config: &CgiAuditConfig) -> Result<CgiAuditReport> {
        if !file.exists() {
            return Err(CarverError::CgiAudit(format!(
                "Target file does not exist: {}",
                file.display()
            )));
        }

        let raw_bytes = fs::read(file).map_err(CarverError::Io)?;
        let content = String::from_utf8_lossy(&raw_bytes);
        let line_count = content.lines().count();
        let file_display = file.to_string_lossy().replace('\\', "/");

        let mut findings = CgiRuleEngine::evaluate_lines(&file_display, &content);
        findings.extend(CgiRuleEngine::evaluate_file_context(
            &file_display,
            &content,
        ));

        let filtered_findings: Vec<CgiFinding> = findings
            .into_iter()
            .filter(|f| f.severity >= config.min_severity)
            .collect();

        Self::build_report(
            &file_display,
            vec![file_display.clone()],
            line_count,
            filtered_findings,
        )
    }

    /// Audit an in-memory virtual directory tree without touching disk.
    pub fn audit_virtual_tree(
        files: &[(String, String)],
        target_name: &str,
        config: &CgiAuditConfig,
    ) -> CgiAuditReport {
        let mut total_lines = 0;
        let mut all_findings = Vec::new();
        let mut scanned_files = Vec::new();

        for (path, content) in files {
            if !Self::matches_extension(path, &config.target_extensions) {
                continue;
            }

            scanned_files.push(path.clone());
            total_lines += content.lines().count();

            let mut findings = CgiRuleEngine::evaluate_lines(path, content);
            findings.extend(CgiRuleEngine::evaluate_file_context(path, content));

            for f in findings {
                if f.severity >= config.min_severity {
                    all_findings.push(f);
                }
            }
        }

        Self::build_report_direct(target_name, scanned_files, total_lines, all_findings)
    }

    /// Audit raw buffer directly as an isolated script or embedded string chunk.
    pub fn audit_raw_buffer(name: &str, buffer: &[u8], config: &CgiAuditConfig) -> CgiAuditReport {
        let content = String::from_utf8_lossy(buffer);
        let line_count = content.lines().count();

        let mut findings = CgiRuleEngine::evaluate_lines(name, &content);
        findings.extend(CgiRuleEngine::evaluate_file_context(name, &content));

        let filtered_findings: Vec<CgiFinding> = findings
            .into_iter()
            .filter(|f| f.severity >= config.min_severity)
            .collect();

        Self::build_report_direct(name, vec![name.to_string()], line_count, filtered_findings)
    }

    fn collect_files_recursive(
        dir: &Path,
        config: &CgiAuditConfig,
        out_files: &mut Vec<PathBuf>,
        visited: &mut HashSet<PathBuf>,
    ) -> Result<()> {
        let canonical = fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
        if !visited.insert(canonical) {
            return Ok(()); // Avoid directory symlink cycle
        }

        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(err) => return Err(CarverError::Io(err)),
        };

        for entry_res in entries {
            let entry = match entry_res {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = entry.path();

            if path.is_dir() {
                if config.scan_subdirectories {
                    Self::collect_files_recursive(&path, config, out_files, visited)?;
                }
            } else if path.is_file() {
                let path_str = path.to_string_lossy();
                if Self::matches_extension(&path_str, &config.target_extensions) {
                    out_files.push(path);
                }
            }
        }

        Ok(())
    }

    fn matches_extension(path: &str, extensions: &[String]) -> bool {
        let path_lower = path.to_ascii_lowercase();
        // Also accept files inside cgi-bin even without standard extension
        if path_lower.contains("cgi-bin/") || path_lower.contains("cgi-bin\\") {
            return true;
        }

        if let Some(ext) = Path::new(path).extension().and_then(|e| e.to_str()) {
            let ext_lower = ext.to_ascii_lowercase();
            return extensions.iter().any(|target| target == &ext_lower);
        }

        false
    }

    fn build_report(
        target_path: &str,
        scanned_files: Vec<String>,
        total_lines: usize,
        mut findings: Vec<CgiFinding>,
    ) -> Result<CgiAuditReport> {
        findings.sort_by_key(|a| std::cmp::Reverse(a.severity));

        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;
        let mut info = 0;

        for f in &findings {
            match f.severity {
                CgiSeverity::Critical => critical += 1,
                CgiSeverity::High => high += 1,
                CgiSeverity::Medium => medium += 1,
                CgiSeverity::Low => low += 1,
                CgiSeverity::Info => info += 1,
            }
        }

        Ok(CgiAuditReport {
            target_path: target_path.to_string(),
            total_files_scanned: scanned_files.len(),
            total_lines_scanned: total_lines,
            total_findings: findings.len(),
            critical_count: critical,
            high_count: high,
            medium_count: medium,
            low_count: low,
            info_count: info,
            findings,
            scanned_files,
        })
    }

    fn build_report_direct(
        target_path: &str,
        scanned_files: Vec<String>,
        total_lines: usize,
        mut findings: Vec<CgiFinding>,
    ) -> CgiAuditReport {
        findings.sort_by_key(|a| std::cmp::Reverse(a.severity));

        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;
        let mut info = 0;

        for f in &findings {
            match f.severity {
                CgiSeverity::Critical => critical += 1,
                CgiSeverity::High => high += 1,
                CgiSeverity::Medium => medium += 1,
                CgiSeverity::Low => low += 1,
                CgiSeverity::Info => info += 1,
            }
        }

        CgiAuditReport {
            target_path: target_path.to_string(),
            total_files_scanned: scanned_files.len(),
            total_lines_scanned: total_lines,
            total_findings: findings.len(),
            critical_count: critical,
            high_count: high,
            medium_count: medium,
            low_count: low,
            info_count: info,
            findings,
            scanned_files,
        }
    }
}
