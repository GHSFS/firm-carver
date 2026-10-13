// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use firm_carver::cert_audit::asn1::{parse_pem_blocks, parse_x509_certificate};
use firm_carver::cert_audit::{
    audit_cert_buffer, audit_cert_path, format_cert_report, CertAuditConfig, CertIssueKind,
    CertSeverity, CertSynth,
};
use std::fs;

#[test]
fn test_cert_audit_valid_pem_and_der_parsing() {
    let valid_der = CertSynth::build_valid_cert();
    let cert = parse_x509_certificate(&valid_der).expect("Must parse valid DER certificate");

    assert!(cert.subject.contains("Router Admin"));
    assert!(cert.issuer.contains("Enterprise Root CA"));
    assert_eq!(cert.rsa_bits, Some(2048));
    assert_eq!(cert.sig_algo_name, "sha256WithRSAEncryption");
    assert!(!cert.is_self_signed);
    assert_eq!(cert.fingerprint_sha256.len(), 64);

    let pem_str = CertSynth::to_pem("CERTIFICATE", &valid_der);
    let blocks = parse_pem_blocks(&pem_str);
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].label, "CERTIFICATE");
    assert_eq!(blocks[0].data, valid_der);
}

#[test]
fn test_cert_audit_expired_and_expiring_soon_detection() {
    let expired_der = CertSynth::build_expired_cert();
    let expiring_der = CertSynth::build_expiring_soon_cert();
    let config = CertAuditConfig::default();

    let rep1 = audit_cert_buffer(&expired_der, "expired.der", &config).unwrap();
    assert_eq!(rep1.total_certs_scanned, 1);
    let f1 = rep1
        .findings
        .iter()
        .find(|f| f.issue_kind == CertIssueKind::Expired);
    assert!(f1.is_some(), "Must report expired certificate");
    assert_eq!(f1.unwrap().rule_id, "CERT-EXP-001");

    let rep2 = audit_cert_buffer(&expiring_der, "expiring.der", &config).unwrap();
    let f2 = rep2
        .findings
        .iter()
        .find(|f| f.issue_kind == CertIssueKind::ExpiringSoon);
    assert!(f2.is_some(), "Must report expiring soon certificate");
    assert_eq!(f2.unwrap().rule_id, "CERT-EXP-002");
    assert_eq!(f2.unwrap().severity, CertSeverity::Medium);
}

#[test]
fn test_cert_audit_weak_signature_algorithms() {
    let md5_der = CertSynth::build_weak_md5_cert();
    let sha1_der = CertSynth::build_weak_sha1_cert();
    let config = CertAuditConfig::default();

    let rep_md5 = audit_cert_buffer(&md5_der, "md5.der", &config).unwrap();
    let f_md5 = rep_md5
        .findings
        .iter()
        .find(|f| f.issue_kind == CertIssueKind::WeakSignatureBroken);
    assert!(f_md5.is_some(), "Must detect broken MD5 signature");
    assert_eq!(f_md5.unwrap().rule_id, "CERT-SIG-001");
    assert_eq!(f_md5.unwrap().severity, CertSeverity::Critical);

    let rep_sha1 = audit_cert_buffer(&sha1_der, "sha1.der", &config).unwrap();
    let f_sha1 = rep_sha1
        .findings
        .iter()
        .find(|f| f.issue_kind == CertIssueKind::DeprecatedSignatureSha1);
    assert!(f_sha1.is_some(), "Must detect deprecated SHA-1 signature");
    assert_eq!(f_sha1.unwrap().rule_id, "CERT-SIG-002");
    assert_eq!(f_sha1.unwrap().severity, CertSeverity::High);
}

#[test]
fn test_cert_audit_weak_and_deprecated_rsa_keys() {
    let (rsa512_der, _) = CertSynth::build_weak_rsa512_cert_and_key();
    let rsa1024_der = CertSynth::build_deprecated_rsa1024_cert();
    let config = CertAuditConfig::default();

    let rep_512 = audit_cert_buffer(&rsa512_der, "key512.der", &config).unwrap();
    let f_512 = rep_512
        .findings
        .iter()
        .find(|f| f.issue_kind == CertIssueKind::WeakRsaKeyCritical);
    assert!(f_512.is_some(), "Must detect 512-bit RSA key");
    assert_eq!(f_512.unwrap().rule_id, "CERT-KEY-001");
    assert_eq!(f_512.unwrap().severity, CertSeverity::Critical);

    let rep_1024 = audit_cert_buffer(&rsa1024_der, "key1024.der", &config).unwrap();
    let f_1024 = rep_1024
        .findings
        .iter()
        .find(|f| f.issue_kind == CertIssueKind::DeprecatedRsaKey1024);
    assert!(f_1024.is_some(), "Must detect 1024-bit RSA key");
    assert_eq!(f_1024.unwrap().rule_id, "CERT-KEY-002");
    assert_eq!(f_1024.unwrap().severity, CertSeverity::High);
}

#[test]
fn test_cert_audit_self_signed_and_anomalous_validity() {
    let self_signed = CertSynth::build_self_signed_cert();
    let anomalous = CertSynth::build_anomalous_validity_cert();
    let config = CertAuditConfig::default();

    let rep_self = audit_cert_buffer(&self_signed, "self.der", &config).unwrap();
    let f_self = rep_self
        .findings
        .iter()
        .find(|f| f.issue_kind == CertIssueKind::SelfSigned);
    assert!(f_self.is_some(), "Must detect self-signed certificate");
    assert_eq!(f_self.unwrap().rule_id, "CERT-SELF-001");

    let rep_anom = audit_cert_buffer(&anomalous, "anom.der", &config).unwrap();
    let f_anom = rep_anom
        .findings
        .iter()
        .find(|f| f.issue_kind == CertIssueKind::AnomalousValidity);
    assert!(f_anom.is_some(), "Must detect anomalous validity");
    assert_eq!(f_anom.unwrap().rule_id, "CERT-VAL-001");
}

#[test]
fn test_cert_audit_private_key_pairing_and_leak() {
    let (cert_der, key_der) = CertSynth::build_weak_rsa512_cert_and_key();
    let mut bundle = Vec::new();
    bundle.extend_from_slice(CertSynth::to_pem("CERTIFICATE", &cert_der).as_bytes());
    bundle.extend_from_slice(b"\n");
    bundle.extend_from_slice(CertSynth::to_pem("RSA PRIVATE KEY", &key_der).as_bytes());

    let config = CertAuditConfig::default();
    let report = audit_cert_buffer(&bundle, "bundle.pem", &config).unwrap();

    assert_eq!(report.total_certs_scanned, 1);
    assert_eq!(report.total_keys_found, 1);
    let f_priv = report
        .findings
        .iter()
        .find(|f| f.issue_kind == CertIssueKind::HardcodedPrivateKey);
    assert!(f_priv.is_some(), "Must detect hardcoded private key");
    assert_eq!(f_priv.unwrap().rule_id, "CERT-PRIV-001");
    assert_eq!(f_priv.unwrap().severity, CertSeverity::Critical);
    assert!(f_priv.unwrap().description.contains("matches public key"));
}

#[test]
fn test_cert_audit_raw_buffer_stream_carving() {
    let firmware_blob = CertSynth::build_synthetic_firmware_cert_blob();
    let config = CertAuditConfig::default();
    let report = audit_cert_buffer(&firmware_blob, "firmware.bin", &config).unwrap();

    assert!(
        report.total_certs_scanned >= 3,
        "Carver must discover at least 3 embedded certificates"
    );
    assert!(
        report.total_keys_found >= 1,
        "Carver must discover embedded private key"
    );
    assert!(
        report.findings.iter().any(|f| f.offset.is_some()),
        "Carved findings must record exact byte offsets"
    );
}

#[test]
fn test_cert_audit_directory_scan_and_report_formatting() {
    let temp_dir = std::env::temp_dir().join("firm_carver_test_cert_store");
    let _ = fs::remove_dir_all(&temp_dir);
    let created =
        CertSynth::write_synthetic_cert_store(&temp_dir).expect("Must write synthetic cert store");
    assert!(created.len() >= 5);

    let config = CertAuditConfig::default();
    let report = audit_cert_path(&temp_dir, &config).expect("Must audit certificate directory");

    assert!(report.total_certs_scanned >= 4);
    assert!(report.total_keys_found >= 1);
    assert!(report.critical_count >= 1);

    let formatted = format_cert_report(&report);
    assert!(formatted.contains("=== FirmCarver TLS Certificate & Root CA Auditor ==="));
    assert!(formatted.contains("Severity Breakdown:"));
    assert!(formatted.contains("[CRITICAL]"));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cert_audit_corrupted_and_truncated_resilience() {
    let empty_bytes = [];
    let noise = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22];
    let truncated_der = [0x30, 0x82, 0x01, 0x00, 0x30, 0x82];
    let config = CertAuditConfig::default();

    let r1 = audit_cert_buffer(&empty_bytes, "empty.bin", &config).unwrap();
    assert_eq!(r1.total_certs_scanned, 0);

    let r2 = audit_cert_buffer(&noise, "noise.bin", &config).unwrap();
    assert_eq!(r2.total_certs_scanned, 0);

    let r3 = audit_cert_buffer(&truncated_der, "truncated.der", &config).unwrap();
    assert_eq!(r3.total_certs_scanned, 0);
}

#[test]
fn test_cert_audit_zeroize_memory_wiping() {
    use firm_carver::cert_audit::DiscoveredPrivateKey;
    use zeroize::Zeroize;

    let mut key = DiscoveredPrivateKey {
        key_type: "RSA PRIVATE KEY".to_string(),
        file_path: Some("/tmp/key.pem".to_string()),
        offset: Some(0),
        modulus_bits: Some(2048),
        fingerprint_sha256: "testfp".to_string(),
        key_bytes: vec![0x42; 256],
    };

    assert_eq!(key.key_bytes[0], 0x42);
    key.zeroize();
    assert!(key.key_bytes.iter().all(|&b| b == 0));
}

#[test]
fn test_cert_audit_asn1_overflow_and_bounds_guards() {
    use firm_carver::cert_audit::DerElement;

    // 1. Multi-byte length overflow attempt: tag 0x30, length octets 0x84, 0xFF, 0xFF, 0xFF, 0xFF
    let overflow_len = [0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x02];
    let res = DerElement::parse(&overflow_len);
    assert!(res.is_err(), "Must reject huge length exceeding buffer");

    // 2. Malformed / non-ASCII time
    let non_ascii_time_elem = DerElement {
        tag: 0x17, // UTCTime
        constructed: false,
        value: &[
            0xFF, 0xFE, 0xFD, 0xFC, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ],
        full_len: 15,
    };
    assert!(non_ascii_time_elem.as_time().is_err());

    // 3. Overflowing OID arc: tag 0x06, arcs with continuous high bits
    let huge_oid = DerElement {
        tag: 0x06,
        constructed: false,
        value: &[
            0x2A, 0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01,
        ],
        full_len: 14,
    };
    assert!(huge_oid.as_oid_string().is_err());
}
