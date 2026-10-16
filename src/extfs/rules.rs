// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::types::*;
use std::collections::HashSet;

pub struct ExtRuleEngine;

impl ExtRuleEngine {
    pub fn audit(sb: &ExtSuperblock, entries: &[ExtEntry]) -> ExtAuditReport {
        let mut findings = Vec::new();
        let path_set: HashSet<&str> = entries.iter().map(|e| e.path.as_str()).collect();

        // 1. Superblock Integrity Check (EXTFS-INTEG-001)
        if sb.free_blocks_count > sb.blocks_count {
            findings.push(ExtAuditFinding {
                code: "EXTFS-INTEG-001".to_string(),
                severity: ExtSeverity::Medium,
                path: "/".to_string(),
                inode: EXT_SUPER_MAGIC as u32,
                message: format!(
                    "Superblock reports free blocks ({}) exceeding total blocks ({})",
                    sb.free_blocks_count, sb.blocks_count
                ),
                detail: Some(
                    "Filesystem metadata inconsistency detected in superblock header.".to_string(),
                ),
            });
        }

        for entry in entries {
            // 2. Path Traversal Symlink (EXTFS-TRAV-001)
            if entry.file_type == ExtFileType::Symlink {
                if let Some(target) = &entry.symlink_target {
                    if target.contains("../")
                        || target.contains("..\\")
                        || target.starts_with("../")
                    {
                        findings.push(ExtAuditFinding {
                            code: "EXTFS-TRAV-001".to_string(),
                            severity: ExtSeverity::Critical,
                            path: entry.path.clone(),
                            inode: entry.ino,
                            message: format!(
                                "Path traversal symlink detected pointing to '{}'",
                                target
                            ),
                            detail: Some(
                                "Symlink attempts to escape filesystem hierarchy via relative traversal components."
                                    .to_string(),
                            ),
                        });
                    }

                    // 3. Sensitive Host / Hardware Target Symlink (EXTFS-SYMLNK-002)
                    if target.starts_with("/dev/")
                        || target.starts_with("/proc/")
                        || target.starts_with("/sys/")
                    {
                        findings.push(ExtAuditFinding {
                            code: "EXTFS-SYMLNK-002".to_string(),
                            severity: ExtSeverity::High,
                            path: entry.path.clone(),
                            inode: entry.ino,
                            message: format!(
                                "Symlink points to sensitive hardware or virtual device path '{}'",
                                target
                            ),
                            detail: Some(
                                "Targeting raw device nodes or procfs can allow container escapes or unauthorized peripheral access."
                                    .to_string(),
                            ),
                        });
                    }

                    // 4. Dangling Symlink (EXTFS-SYMLNK-001)
                    let is_internal_abs = target.starts_with('/');
                    if is_internal_abs && !path_set.contains(target.as_str()) {
                        findings.push(ExtAuditFinding {
                            code: "EXTFS-SYMLNK-001".to_string(),
                            severity: ExtSeverity::Low,
                            path: entry.path.clone(),
                            inode: entry.ino,
                            message: format!(
                                "Dangling symlink points to non-existent target '{}'",
                                target
                            ),
                            detail: Some(
                                "Dead link detected inside root filesystem image.".to_string(),
                            ),
                        });
                    }
                }
            }

            // 5. SUID / SGID Binaries (EXTFS-PERM-001)
            if entry.file_type == ExtFileType::RegularFile {
                let is_suid = entry.mode & 0o4000 != 0;
                let is_sgid = entry.mode & 0o2000 != 0;
                if is_suid || is_sgid {
                    let flag_str = match (is_suid, is_sgid) {
                        (true, true) => "SUID+SGID",
                        (true, false) => "SUID",
                        (false, true) => "SGID",
                        _ => "",
                    };
                    findings.push(ExtAuditFinding {
                        code: "EXTFS-PERM-001".to_string(),
                        severity: ExtSeverity::High,
                        path: entry.path.clone(),
                        inode: entry.ino,
                        message: format!(
                            "Elevated privileges binary discovered: {} (mode: 0o{:o}, UID: {})",
                            flag_str, entry.mode, entry.uid
                        ),
                        detail: Some(
                            "SUID/SGID executables can be leveraged for privilege escalation if vulnerable to buffer overflow or environment poisoning."
                                .to_string(),
                        ),
                    });
                }

                // 6. Hardcoded Shadow / Password File (EXTFS-SHADOW-001)
                if entry.path == "/etc/shadow" || entry.path == "/etc/master.passwd" {
                    findings.push(ExtAuditFinding {
                        code: "EXTFS-SHADOW-001".to_string(),
                        severity: ExtSeverity::Critical,
                        path: entry.path.clone(),
                        inode: entry.ino,
                        message: "Embedded shadow credentials database discovered in filesystem image"
                            .to_string(),
                        detail: Some(
                            "Contains encrypted password hashes which can be subject to offline brute-force cracking."
                                .to_string(),
                        ),
                    });
                }
            }

            // 7. Non-standard Device Nodes (EXTFS-DEV-001)
            if (entry.file_type == ExtFileType::BlockDevice
                || entry.file_type == ExtFileType::CharDevice)
                && !entry.path.starts_with("/dev/")
            {
                findings.push(ExtAuditFinding {
                    code: "EXTFS-DEV-001".to_string(),
                    severity: ExtSeverity::Medium,
                    path: entry.path.clone(),
                    inode: entry.ino,
                    message: format!(
                        "Device node located in non-standard location '{}' outside /dev/",
                        entry.path
                    ),
                    detail: Some(
                        "Anomalous character/block device node placement in user directories."
                            .to_string(),
                    ),
                });
            }
        }

        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;

        for f in &findings {
            match f.severity {
                ExtSeverity::Critical => critical_count += 1,
                ExtSeverity::High => high_count += 1,
                ExtSeverity::Medium => medium_count += 1,
                ExtSeverity::Low | ExtSeverity::Info => low_count += 1,
            }
        }

        ExtAuditReport {
            timestamp: sb.wtime as u64,
            filesystem_version: sb.version.as_str().to_string(),
            total_findings: findings.len(),
            critical_count,
            high_count,
            medium_count,
            low_count,
            findings,
        }
    }
}
