// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::types::{
    CramFsAuditFinding, CramFsAuditReport, CramFsEntry, CramFsFileType, CramFsSeverity,
    CramFsSuperblock, S_ISGID, S_ISUID,
};

pub struct CramFsRuleEngine;

impl CramFsRuleEngine {
    pub fn audit(superblock: &CramFsSuperblock, entries: &[CramFsEntry]) -> CramFsAuditReport {
        let mut findings = Vec::new();

        // 1. Audit superblock integrity
        if superblock.size == 0 {
            findings.push(CramFsAuditFinding {
                rule_id: "CRAMFS-INTEG-001".to_string(),
                severity: CramFsSeverity::High,
                title: "Zero Superblock Filesystem Size".to_string(),
                description: "CramFS superblock declares 0 total size in bytes.".to_string(),
                path: "/".to_string(),
                target: None,
            });
        }

        for entry in entries {
            // 2. Audit path traversal in filename / dirent
            if entry.is_path_traversal || entry.name.contains("..") || entry.name.contains('/') {
                findings.push(CramFsAuditFinding {
                    rule_id: "CRAMFS-TRAV-001".to_string(),
                    severity: CramFsSeverity::Critical,
                    title: "Path Traversal in Directory Entry".to_string(),
                    description: format!(
                        "Entry '{}' contains relative traversal components ('..') or illegal separators.",
                        entry.name
                    ),
                    path: entry.path.clone(),
                    target: None,
                });
            }

            // 3. Audit symlink vulnerabilities
            if entry.file_type == CramFsFileType::Symlink {
                if let Some(target) = &entry.symlink_target {
                    if entry.is_path_traversal || is_traversal_path(target) {
                        findings.push(CramFsAuditFinding {
                            rule_id: "CRAMFS-SYMLNK-001".to_string(),
                            severity: CramFsSeverity::High,
                            title: "Malicious Symlink Target Path Traversal".to_string(),
                            description: format!(
                                "Symbolic link at '{}' targets escaping path '{}'.",
                                entry.path, target
                            ),
                            path: entry.path.clone(),
                            target: Some(target.clone()),
                        });
                    }

                    if entry.is_dangling_symlink {
                        findings.push(CramFsAuditFinding {
                            rule_id: "CRAMFS-SYMLNK-002".to_string(),
                            severity: CramFsSeverity::Medium,
                            title: "Dangling or Broken Symbolic Link".to_string(),
                            description: format!(
                                "Symbolic link at '{}' points to nonexistent destination '{}'.",
                                entry.path, target
                            ),
                            path: entry.path.clone(),
                            target: Some(target.clone()),
                        });
                    }
                }
            }

            // 4. Audit SUID / SGID permissions
            if entry.mode & S_ISUID != 0 || entry.mode & S_ISGID != 0 {
                let kind = if entry.mode & S_ISUID != 0 {
                    "SUID"
                } else {
                    "SGID"
                };
                findings.push(CramFsAuditFinding {
                    rule_id: "CRAMFS-PERM-001".to_string(),
                    severity: CramFsSeverity::High,
                    title: format!("Privileged {} Executable Binary", kind),
                    description: format!(
                        "Binary '{}' has {} bit set (mode: 0o{:04o}, uid: {}, gid: {}).",
                        entry.path, kind, entry.mode, entry.uid, entry.gid
                    ),
                    path: entry.path.clone(),
                    target: None,
                });
            }

            // 5. Audit device nodes in unusual directories
            if (entry.file_type == CramFsFileType::BlockDevice
                || entry.file_type == CramFsFileType::CharDevice)
                && !entry.path.starts_with("/dev/")
            {
                findings.push(CramFsAuditFinding {
                    rule_id: "CRAMFS-DEV-001".to_string(),
                    severity: CramFsSeverity::Medium,
                    title: "Device Node Outside Standard /dev Directory".to_string(),
                    description: format!(
                        "Device node located at non-standard path '{}'.",
                        entry.path
                    ),
                    path: entry.path.clone(),
                    target: None,
                });
            }
        }

        // Sort findings by severity descending (Critical first)
        findings.sort_by_key(|a| std::cmp::Reverse(a.severity));

        let mut report = CramFsAuditReport {
            total_findings: findings.len(),
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            findings,
        };

        for f in &report.findings {
            match f.severity {
                CramFsSeverity::Critical => report.critical += 1,
                CramFsSeverity::High => report.high += 1,
                CramFsSeverity::Medium => report.medium += 1,
                CramFsSeverity::Low => report.low += 1,
                CramFsSeverity::Info => {}
            }
        }

        report
    }
}

fn is_traversal_path(target: &str) -> bool {
    target.contains("../")
        || target.starts_with('/')
            && (target.starts_with("/etc/")
                || target.starts_with("/root/")
                || target.starts_with("/sys/")
                || target.starts_with("/proc/")
                || target.starts_with("/dev/"))
}
