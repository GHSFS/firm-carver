// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use firm_carver::cgi_audit::{
    audit_web_path, format_cgi_report, CgiAuditConfig, CgiFinding, CgiScanner, CgiSeverity,
    CgiSynth, CgiVulnCategory,
};
use std::env;
use std::fs;

#[test]
fn test_cgi_audit_command_injection_detection() {
    let script = r#"#!/bin/sh
echo "Content-type: text/html"
echo ""
TARGET=$(echo "$QUERY_STRING" | cut -d'=' -f2)
ping -c 2 $TARGET
"#;

    let config = CgiAuditConfig::default();
    let report = CgiScanner::audit_raw_buffer("cgi-bin/ping.cgi", script.as_bytes(), &config);

    assert!(report.total_findings >= 1);
    let cmd_finding = report
        .findings
        .iter()
        .find(|f| f.rule_id == "CGI-CMD-001")
        .expect("Expected CGI-CMD-001 finding for unescaped QUERY_STRING");

    assert_eq!(cmd_finding.severity, CgiSeverity::Critical);
    assert_eq!(cmd_finding.category, CgiVulnCategory::CommandInjection);
    assert_eq!(cmd_finding.cwe, "CWE-78");
    assert!(cmd_finding.evidence.contains("QUERY_STRING"));
}

#[test]
fn test_cgi_audit_unauthenticated_admin_endpoints() {
    let script = r#"#!/bin/sh
echo "Content-type: text/plain"
echo "Rebooting system..."
reboot
"#;

    let config = CgiAuditConfig::default();
    let report = CgiScanner::audit_raw_buffer("apply_reboot.cgi", script.as_bytes(), &config);

    let auth_finding = report
        .findings
        .iter()
        .find(|f| f.rule_id == "CGI-AUTH-001")
        .expect("Expected CGI-AUTH-001 finding for unauthenticated reboot script");

    assert_eq!(auth_finding.severity, CgiSeverity::High);
    assert_eq!(auth_finding.category, CgiVulnCategory::AuthBypass);
    assert_eq!(auth_finding.cwe, "CWE-306");
}

#[test]
fn test_cgi_audit_backdoor_cookie_detection() {
    let script = r#"#!/bin/sh
if [ "$HTTP_COOKIE" = "dlink_uid=0" ]; then
    reboot
fi
"#;

    let config = CgiAuditConfig::default();
    let report = CgiScanner::audit_raw_buffer("reboot.cgi", script.as_bytes(), &config);

    let backdoor_finding = report
        .findings
        .iter()
        .find(|f| f.rule_id == "CGI-AUTH-002")
        .expect("Expected CGI-AUTH-002 backdoor cookie finding");

    assert_eq!(backdoor_finding.severity, CgiSeverity::Critical);
    assert!(backdoor_finding.evidence.contains("dlink_uid=0"));
}

#[test]
fn test_cgi_audit_hardcoded_credentials() {
    let script = r#"#!/bin/sh
if [ "$USER" = "admin" ] && [ "$PASS" == "admin" ]; then
    echo "ACCESS_GRANTED"
fi
"#;

    let config = CgiAuditConfig::default();
    let report = CgiScanner::audit_raw_buffer("login.cgi", script.as_bytes(), &config);

    let cred_finding = report
        .findings
        .iter()
        .find(|f| f.rule_id == "CGI-CRED-001")
        .expect("Expected CGI-CRED-001 finding for hardcoded password");

    assert_eq!(cred_finding.severity, CgiSeverity::High);
    assert_eq!(cred_finding.category, CgiVulnCategory::HardcodedCredentials);
    assert_eq!(cred_finding.cwe, "CWE-798");
}

#[test]
fn test_cgi_audit_path_traversal_detection() {
    let script = r#"#!/bin/sh
FILE="$QUERY_STRING"
cat /www/data/$FILE
"#;

    let config = CgiAuditConfig::default();
    let report = CgiScanner::audit_raw_buffer("view.cgi", script.as_bytes(), &config);

    let trav_finding = report
        .findings
        .iter()
        .find(|f| f.rule_id == "CGI-TRAV-001")
        .expect("Expected CGI-TRAV-001 path traversal finding");

    assert_eq!(trav_finding.severity, CgiSeverity::High);
    assert_eq!(trav_finding.category, CgiVulnCategory::PathTraversal);
    assert_eq!(trav_finding.cwe, "CWE-22");
}

#[test]
fn test_cgi_audit_sensitive_information_disclosure() {
    let script = r#"#!/bin/sh
echo "Dumping diagnostic status..."
cat /proc/kmsg
cat /tmp/nvram
"#;

    let config = CgiAuditConfig::default();
    let report = CgiScanner::audit_raw_buffer("diag.cgi", script.as_bytes(), &config);

    let info_findings: Vec<&CgiFinding> = report
        .findings
        .iter()
        .filter(|f| f.rule_id == "CGI-INFO-001")
        .collect();

    assert!(
        !info_findings.is_empty(),
        "Expected at least one sensitive info disclosure finding"
    );
    assert_eq!(
        info_findings[0].category,
        CgiVulnCategory::InformationDisclosure
    );
    assert_eq!(info_findings[0].cwe, "CWE-200");
}

#[test]
fn test_cgi_audit_safe_script_false_positive_suppression() {
    let safe_script = r#"#!/bin/sh
# Strict authentication check
check_auth || exit 1

echo "Content-type: text/plain"
echo ""
echo "Secure Administration Settings"
"#;

    let config = CgiAuditConfig::default();
    let report = CgiScanner::audit_raw_buffer("admin_safe.cgi", safe_script.as_bytes(), &config);

    let unauth_admin = report.findings.iter().any(|f| f.rule_id == "CGI-AUTH-001");
    assert!(
        !unauth_admin,
        "Safe authenticated script should not trigger unauthenticated route finding"
    );
}

#[test]
fn test_cgi_audit_virtual_tree_and_severity_filtering() {
    let tree = CgiSynth::build_synthetic_web_tree();
    assert!(!tree.is_empty());

    let config_all = CgiAuditConfig {
        min_severity: CgiSeverity::Low,
        ..Default::default()
    };
    let report_all = CgiScanner::audit_virtual_tree(&tree, "/synthetic/www", &config_all);

    assert!(report_all.total_files_scanned >= 7);
    assert!(report_all.total_findings >= 5);
    assert!(report_all.critical_count >= 1);
    assert!(report_all.high_count >= 1);

    // Filter by Critical only
    let config_crit = CgiAuditConfig {
        min_severity: CgiSeverity::Critical,
        ..Default::default()
    };
    let report_crit = CgiScanner::audit_virtual_tree(&tree, "/synthetic/www", &config_crit);

    assert_eq!(report_crit.total_findings, report_crit.critical_count);
    assert!(report_crit
        .findings
        .iter()
        .all(|f| f.severity == CgiSeverity::Critical));
}

#[test]
fn test_cgi_audit_disk_directory_and_report_formatting() {
    let temp_dir = env::temp_dir().join(format!("fcarver_cgi_test_{}", std::process::id()));
    let created = CgiSynth::write_synthetic_web_tree_to_disk(&temp_dir)
        .expect("Synthetic web tree generation to disk failed");

    assert!(!created.is_empty());

    let config = CgiAuditConfig::default();
    let report = audit_web_path(&temp_dir, &config).expect("Directory audit failed");

    assert!(report.total_files_scanned >= 7);
    assert!(report.total_findings >= 5);

    // Terminal formatting verification
    let formatted = format_cgi_report(&report);
    assert!(formatted.contains("Embedded Web Management & CGI Static Auditor"));
    assert!(formatted.contains("Severity Breakdown"));
    assert!(formatted.contains("CGI-CMD-001"));

    // JSON serialization verification
    let json_output = serde_json::to_string_pretty(&report).expect("JSON serialization failed");
    let parsed: serde_json::Value = serde_json::from_str(&json_output).expect("JSON parse failed");
    assert_eq!(
        parsed["total_findings"].as_u64().unwrap(),
        report.total_findings as u64
    );

    // Cleanup disk test files
    let _ = fs::remove_dir_all(&temp_dir);
}
