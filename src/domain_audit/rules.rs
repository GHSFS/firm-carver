// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::extractor::ExtractedToken;
use super::types::{
    DomainCategory, DomainIssueCode, DomainSecurityIssue, DomainSeverity, EndpointKind, IpScope,
    UrlScheme,
};

/// Security rule engine evaluating network endpoints for vulnerabilities.
pub struct DomainRuleEngine;

impl DomainRuleEngine {
    /// Evaluate all security auditing rules on an extracted token.
    pub fn audit_token(
        token: &ExtractedToken,
        ip_scope: Option<IpScope>,
        category: Option<DomainCategory>,
    ) -> Vec<DomainSecurityIssue> {
        let mut issues = Vec::new();

        // Rule 1: NET-AUTH-001 (Critical) - Embedded credentials in URI
        if let Some(creds) = &token.credentials {
            if !creds.is_empty() {
                issues.push(DomainSecurityIssue {
                    code: DomainIssueCode::NetEmbeddedCreds,
                    severity: DomainSeverity::Critical,
                    title: "Hardcoded Credentials in Network URI Authority".to_string(),
                    description: format!(
                        "Network URI '{}' contains embedded authentication credentials in its authority block.",
                        sanitize_uri_for_log(&token.raw)
                    ),
                    recommendation: "Remove hardcoded credentials from URIs; use secure keystores or dynamic tokens."
                        .to_string(),
                });
            }
        }

        // Rule 2: NET-CLEAR-001 (Critical / High) - Insecure cleartext HTTP firmware update or OTA URL
        if token.scheme == Some(UrlScheme::Http) {
            let is_ota = category == Some(DomainCategory::FirmwareUpdateOta)
                || is_firmware_update_indicator(&token.host, token.path.as_deref());

            if is_ota {
                issues.push(DomainSecurityIssue {
                    code: DomainIssueCode::NetClearOta,
                    severity: DomainSeverity::Critical,
                    title: "Insecure Cleartext HTTP Firmware Update / OTA URL".to_string(),
                    description: format!(
                        "Firmware update endpoint '{}' communicates over unencrypted cleartext HTTP, enabling Man-in-the-Middle (MitM) firmware tampering.",
                        token.raw
                    ),
                    recommendation: "Enforce HTTPS (TLS 1.2+) with certificate pinning and cryptographically verify firmware signatures before flashing."
                        .to_string(),
                });
            } else if is_external_host(token.host.as_str(), ip_scope, category) {
                // Rule 3: NET-CLEAR-002 (Medium) - Insecure cleartext HTTP remote API/telemetry
                issues.push(DomainSecurityIssue {
                    code: DomainIssueCode::NetClearApi,
                    severity: DomainSeverity::Medium,
                    title: "Cleartext HTTP Remote Endpoint Communication".to_string(),
                    description: format!(
                        "External endpoint '{}' communicates over unencrypted HTTP, exposing data and tokens to passive network inspection.",
                        token.raw
                    ),
                    recommendation: "Migrate all external network communication to TLS-encrypted HTTPS or secure sockets."
                        .to_string(),
                });
            }
        }

        // Rule 4: NET-INSEC-001 (High) - Deprecated insecure legacy protocols
        if let Some(scheme) = &token.scheme {
            match scheme {
                UrlScheme::Telnet | UrlScheme::Ftp | UrlScheme::Tftp => {
                    issues.push(DomainSecurityIssue {
                        code: DomainIssueCode::NetInsecureProtocol,
                        severity: DomainSeverity::High,
                        title: format!("Insecure Legacy Protocol URI ({})", scheme),
                        description: format!(
                            "Embedded URI '{}' uses plaintext protocol '{}' without transport security or integrity verification.",
                            token.raw, scheme
                        ),
                        recommendation: "Replace insecure legacy protocols with SSH, SFTP, or TLS-authenticated transport channels."
                            .to_string(),
                    });
                }
                _ => {}
            }
        }

        // Rule 5: NET-HARDIP-001 (Medium / Low) - Hardcoded public routable IP
        if (token.kind == EndpointKind::Ipv4 || token.kind == EndpointKind::Ipv6)
            && (ip_scope == Some(IpScope::Public) || ip_scope == Some(IpScope::Documentation))
        {
            let is_known_public_dns = is_well_known_public_dns(&token.host);
            let severity = if is_known_public_dns {
                DomainSeverity::Low
            } else {
                DomainSeverity::Medium
            };

            issues.push(DomainSecurityIssue {
                code: DomainIssueCode::NetHardcodedIp,
                severity,
                title: "Hardcoded Public Routable IP Address in Firmware".to_string(),
                description: format!(
                    "Static public IP '{}' is hardcoded into firmware, bypassing DNS failover and risking hijacking upon IP reallocation.",
                    token.host
                ),
                recommendation: "Use domain names with DNS resolution or configurable server pools instead of static public IPs."
                    .to_string(),
            });
        }

        // Rule 6: NET-DDNS-001 (High) - Hardcoded Dynamic DNS provider
        if category == Some(DomainCategory::DynamicDns) {
            issues.push(DomainSecurityIssue {
                code: DomainIssueCode::NetDdns,
                severity: DomainSeverity::High,
                title: "Hardcoded Dynamic DNS (DDNS) Service Endpoint".to_string(),
                description: format!(
                    "Dynamic DNS domain '{}' in firmware may expose hardcoded test environments or remote diagnostic backdoors.",
                    token.host
                ),
                recommendation: "Remove hardcoded dynamic DNS domains from production firmware builds."
                    .to_string(),
            });
        }

        // Rule 7: NET-TELEM-001 (Info) - Telemetry / Analytics tracking
        if category == Some(DomainCategory::TelemetryAnalytics) {
            issues.push(DomainSecurityIssue {
                code: DomainIssueCode::NetTelemetry,
                severity: DomainSeverity::Info,
                title: "External Telemetry and Analytics Reporting Service".to_string(),
                description: format!(
                    "Device transmits runtime telemetry or diagnostics to external analytics service '{}'.",
                    token.host
                ),
                recommendation: "Ensure device provides user opt-out consent and abides by data minimization standards."
                    .to_string(),
            });
        }

        issues
    }
}

fn is_firmware_update_indicator(host: &str, path: Option<&str>) -> bool {
    let lower_host = host.to_ascii_lowercase();
    if lower_host.contains("update")
        || lower_host.contains("upgrade")
        || lower_host.contains("firmware")
        || lower_host.contains("ota")
    {
        return true;
    }

    if let Some(p) = path {
        let lower_p = p.to_ascii_lowercase();
        if lower_p.contains("update")
            || lower_p.contains("upgrade")
            || lower_p.contains("firmware")
            || lower_p.contains("check_fw")
            || lower_p.contains("get_fw")
            || lower_p.ends_with(".bin")
            || lower_p.ends_with(".trx")
            || lower_p.ends_with(".img")
        {
            return true;
        }
    }

    false
}

fn is_external_host(
    host: &str,
    ip_scope: Option<IpScope>,
    category: Option<DomainCategory>,
) -> bool {
    if let Some(scope) = ip_scope {
        return matches!(scope, IpScope::Public | IpScope::CarrierGradeNat);
    }

    if let Some(cat) = category {
        return matches!(
            cat,
            DomainCategory::TelemetryAnalytics
                | DomainCategory::FirmwareUpdateOta
                | DomainCategory::DynamicDns
                | DomainCategory::CloudInfrastructure
                | DomainCategory::GeneralPublic
        );
    }

    let lower = host.to_ascii_lowercase();
    !(lower == "localhost"
        || lower.ends_with(".local")
        || lower.ends_with(".lan")
        || lower.ends_with(".home")
        || lower.ends_with(".internal"))
}

fn is_well_known_public_dns(ip: &str) -> bool {
    matches!(
        ip,
        "8.8.8.8"
            | "8.8.4.4"
            | "1.1.1.1"
            | "1.0.0.1"
            | "9.9.9.9"
            | "149.112.112.112"
            | "208.67.222.222"
            | "208.67.220.220"
    )
}

fn sanitize_uri_for_log(raw: &str) -> String {
    if let Some(at_idx) = raw.find('@') {
        if let Some(scheme_idx) = raw.find("://") {
            let start = scheme_idx + 3;
            if start < at_idx {
                return format!("{}***:***{}", &raw[..start], &raw[at_idx..]);
            }
        }
    }
    raw.to_string()
}
