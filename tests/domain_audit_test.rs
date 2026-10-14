// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use firm_carver::domain_audit::{
    audit_domain_buffer, audit_domain_path, classify_domain_category, classify_ipv4_scope,
    classify_ipv6_scope, extract_endpoints_from_text, format_domain_report, DomainAuditConfig,
    DomainCategory, DomainIssueCode, DomainSeverity, DomainSynth, EndpointKind, IpScope, UrlScheme,
};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[test]
fn test_ipv4_extraction_and_scope_classification() {
    let cases = [
        ("8.8.8.8", IpScope::Public),
        ("192.168.1.1", IpScope::PrivateRfc1918),
        ("10.0.0.1", IpScope::PrivateRfc1918),
        ("172.16.0.1", IpScope::PrivateRfc1918),
        ("172.31.255.254", IpScope::PrivateRfc1918),
        ("127.0.0.1", IpScope::Loopback),
        ("169.254.10.20", IpScope::LinkLocal),
        ("100.64.0.1", IpScope::CarrierGradeNat),
        ("192.0.2.1", IpScope::Documentation),
        ("203.0.113.5", IpScope::Documentation),
        ("224.0.0.1", IpScope::Multicast),
        ("255.255.255.255", IpScope::Broadcast),
        ("0.0.0.0", IpScope::Unspecified),
    ];

    for (ip_str, expected_scope) in cases {
        let ip = Ipv4Addr::from_str(ip_str).unwrap();
        assert_eq!(
            classify_ipv4_scope(ip),
            expected_scope,
            "Failed for {}",
            ip_str
        );

        let tokens = extract_endpoints_from_text(&format!("IP={}", ip_str), None, None);
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].kind, EndpointKind::Ipv4);
        assert_eq!(tokens[0].host, ip_str);
    }
}

#[test]
fn test_ipv6_extraction_and_scope_classification() {
    let cases = [
        ("::1", IpScope::Loopback),
        ("fe80::1", IpScope::LinkLocal),
        ("fc00::1", IpScope::PrivateRfc1918),
        ("ff02::1", IpScope::Multicast),
        ("2001:db8::1", IpScope::Documentation),
        ("2606:4700:4700::1111", IpScope::Public),
    ];

    for (ip_str, expected_scope) in cases {
        let ip = Ipv6Addr::from_str(ip_str).unwrap();
        assert_eq!(
            classify_ipv6_scope(ip),
            expected_scope,
            "Failed for {}",
            ip_str
        );

        let tokens = extract_endpoints_from_text(&format!("IPV6=[{}]", ip_str), None, None);
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].kind, EndpointKind::Ipv6);
    }
}

#[test]
fn test_url_extraction_with_schemes_and_ports() {
    let text = "URL1=http://192.168.1.1:8080/api/status URL2=https://cloud.vendor.com/v1 URL3=mqtt://broker.hivemq.com:1883";
    let tokens = extract_endpoints_from_text(text, None, Some(1));

    assert_eq!(tokens.len(), 3);
    assert_eq!(tokens[0].scheme, Some(UrlScheme::Http));
    assert_eq!(tokens[0].host, "192.168.1.1");
    assert_eq!(tokens[0].port, Some(8080));
    assert_eq!(tokens[0].path.as_deref(), Some("/api/status"));

    assert_eq!(tokens[1].scheme, Some(UrlScheme::Https));
    assert_eq!(tokens[1].host, "cloud.vendor.com");
    assert_eq!(tokens[1].port, None);

    assert_eq!(tokens[2].scheme, Some(UrlScheme::Mqtt));
    assert_eq!(tokens[2].host, "broker.hivemq.com");
    assert_eq!(tokens[2].port, Some(1883));
}

#[test]
fn test_cleartext_ota_rule_net_clear_001() {
    let buffer = b"UPDATE_URL=http://updates.router.com/fw/download.cgi?v=1.0\x00";
    let config = DomainAuditConfig::default();
    let report = audit_domain_buffer("test_ota", buffer, 0, &config);

    assert_eq!(report.summary.critical_count, 1);
    let finding = &report.findings[0];
    assert!(finding
        .issues
        .iter()
        .any(|i| i.code == DomainIssueCode::NetClearOta && i.severity == DomainSeverity::Critical));
}

#[test]
fn test_cleartext_api_rule_net_clear_002() {
    let buffer = b"API_ENDPOINT=http://api.external-service.com/heartbeat\x00";
    let config = DomainAuditConfig::default();
    let report = audit_domain_buffer("test_api", buffer, 0, &config);

    assert!(report
        .findings
        .iter()
        .any(|f| f.issues.iter().any(
            |i| i.code == DomainIssueCode::NetClearApi && i.severity == DomainSeverity::Medium
        )));
}

#[test]
fn test_hardcoded_public_ip_rule_net_hardip_001() {
    let buffer = b"EXTERNAL_C2=198.51.100.42:9000\x00";
    let config = DomainAuditConfig::default();
    let report = audit_domain_buffer("test_ip", buffer, 0, &config);

    assert!(!report.findings.is_empty());
}

#[test]
fn test_dynamic_dns_domain_rule_net_ddns_001() {
    let buffer = b"BACKDOOR_ADDR=test-mgmt.no-ip.com\x00";
    let config = DomainAuditConfig::default();
    let report = audit_domain_buffer("test_ddns", buffer, 0, &config);

    assert!(report.findings.iter().any(|f| f
        .issues
        .iter()
        .any(|i| i.code == DomainIssueCode::NetDdns && i.severity == DomainSeverity::High)));
}

#[test]
fn test_insecure_protocols_rule_net_insec_001() {
    let buffer =
        b"DEBUG_TELNET=telnet://192.168.1.1:23\x00FTP_LOG=ftp://logs.vendor.com/upload\x00";
    let config = DomainAuditConfig::default();
    let report = audit_domain_buffer("test_insec", buffer, 0, &config);

    let insec_count = report
        .findings
        .iter()
        .flat_map(|f| &f.issues)
        .filter(|i| i.code == DomainIssueCode::NetInsecureProtocol)
        .count();
    assert_eq!(insec_count, 2);
}

#[test]
fn test_embedded_uri_credentials_rule_net_auth_001() {
    let buffer = b"PROXY=http://admin:SecretPass2026@proxy.corp.net:3128\x00";
    let config = DomainAuditConfig::default();
    let report = audit_domain_buffer("test_auth", buffer, 0, &config);

    assert!(report.findings.iter().any(|f| f
        .issues
        .iter()
        .any(|i| i.code == DomainIssueCode::NetEmbeddedCreds
            && i.severity == DomainSeverity::Critical)));
}

#[test]
fn test_telemetry_domain_profiling_and_classification() {
    let domains = [
        (
            "analytics.crashlytics.com",
            DomainCategory::TelemetryAnalytics,
        ),
        ("telemetry.sentry.io", DomainCategory::TelemetryAnalytics),
        ("updates.netgear.com", DomainCategory::FirmwareUpdateOta),
        ("router.asuscomm.com", DomainCategory::DynamicDns),
        ("s3.amazonaws.com", DomainCategory::CloudInfrastructure),
        ("pool.ntp.org", DomainCategory::NtpTimeServer),
        ("gateway.local", DomainCategory::LocalNetwork),
        ("example.com", DomainCategory::GeneralPublic),
    ];

    for (domain, expected_cat) in domains {
        assert_eq!(
            classify_domain_category(domain),
            expected_cat,
            "Mismatch for domain {}",
            domain
        );
    }
}

#[test]
fn test_raw_buffer_stream_carving_with_synthetic_vulnerable() {
    let vulnerable_blob = DomainSynth::build_synthetic_vulnerable_buffer();
    let config = DomainAuditConfig {
        min_severity: DomainSeverity::Info,
        ..Default::default()
    };
    let report = audit_domain_buffer("synthetic_vuln.bin", &vulnerable_blob, 0, &config);

    assert!(report.summary.total_endpoints_found >= 6);
    assert!(report.summary.critical_count >= 2); // NetClearOta + NetEmbeddedCreds
    assert!(report.summary.high_count >= 2); // NetDdns + NetInsecureProtocol

    let rendered = format_domain_report(&report);
    assert!(rendered.contains("FIRM-CARVER NETWORK ENDPOINT & DOMAIN AUDIT REPORT"));
    assert!(rendered.contains("CRITICAL"));
}

#[test]
fn test_hardened_firmware_clean_audit() {
    let hardened_blob = DomainSynth::build_synthetic_hardened_buffer();
    let config = DomainAuditConfig {
        min_severity: DomainSeverity::High,
        ..Default::default()
    };
    let report = audit_domain_buffer("synthetic_hardened.bin", &hardened_blob, 0, &config);

    // Hardened firmware has 0 High or Critical vulnerabilities
    assert_eq!(report.summary.critical_count, 0);
    assert_eq!(report.summary.high_count, 0);
}

#[test]
fn test_directory_scan_and_tree_audit() {
    let temp_dir =
        std::env::temp_dir().join(format!("firm_carver_domain_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();

    let root = DomainSynth::write_synthetic_tree(&temp_dir).unwrap();
    let config = DomainAuditConfig::default();
    let report = audit_domain_path(&root, &config).unwrap();

    assert!(report.summary.total_endpoints_found >= 4);
    assert!(report.summary.critical_count >= 1); // OTA update.sh
    assert!(report.summary.high_count >= 1); // DDNS in network.conf

    let _ = std::fs::remove_dir_all(&temp_dir);
}
