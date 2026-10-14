// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

/// Classified kind of network endpoint identified in firmware.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EndpointKind {
    /// Full Uniform Resource Identifier (e.g. http://..., ftp://...)
    Url,
    /// IPv4 Address (e.g. 192.168.1.1, 8.8.8.8)
    Ipv4,
    /// IPv6 Address (e.g. 2001:db8::1, fe80::1)
    Ipv6,
    /// Fully qualified domain name or hostname (e.g. update.vendor.com)
    Domain,
}

impl fmt::Display for EndpointKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Url => write!(f, "url"),
            Self::Ipv4 => write!(f, "ipv4"),
            Self::Ipv6 => write!(f, "ipv6"),
            Self::Domain => write!(f, "domain"),
        }
    }
}

/// Recognized URI communication scheme.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UrlScheme {
    Http,
    Https,
    Ftp,
    Tftp,
    Telnet,
    Ws,
    Wss,
    Mqtt,
    Mqtts,
    Other(String),
}

impl fmt::Display for UrlScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http => write!(f, "http"),
            Self::Https => write!(f, "https"),
            Self::Ftp => write!(f, "ftp"),
            Self::Tftp => write!(f, "tftp"),
            Self::Telnet => write!(f, "telnet"),
            Self::Ws => write!(f, "ws"),
            Self::Wss => write!(f, "wss"),
            Self::Mqtt => write!(f, "mqtt"),
            Self::Mqtts => write!(f, "mqtts"),
            Self::Other(s) => write!(f, "{}", s),
        }
    }
}

/// Address scope classification for IP addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpScope {
    /// Public globally routable address (Internet facing)
    Public,
    /// Private network (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, or RFC 4193 ULA fc00::/7)
    PrivateRfc1918,
    /// Host loopback address (127.0.0.0/8, ::1)
    Loopback,
    /// Link-local autoconfiguration (169.254.0.0/16, fe80::/10)
    LinkLocal,
    /// Carrier-Grade NAT (RFC 6598: 100.64.0.0/10)
    CarrierGradeNat,
    /// Multicast group (224.0.0.0/4, ff00::/8)
    Multicast,
    /// Subnet or global broadcast (255.255.255.255)
    Broadcast,
    /// Documentation & test net (RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, RFC 3849: 2001:db8::/32)
    Documentation,
    /// Unspecified all-zero address (0.0.0.0, ::)
    Unspecified,
}

impl fmt::Display for IpScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public => write!(f, "public"),
            Self::PrivateRfc1918 => write!(f, "private-rfc1918"),
            Self::Loopback => write!(f, "loopback"),
            Self::LinkLocal => write!(f, "link-local"),
            Self::CarrierGradeNat => write!(f, "cgnat"),
            Self::Multicast => write!(f, "multicast"),
            Self::Broadcast => write!(f, "broadcast"),
            Self::Documentation => write!(f, "documentation"),
            Self::Unspecified => write!(f, "unspecified"),
        }
    }
}

/// Functional and security categorization for domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainCategory {
    /// Cloud telemetry, crash reporting, tracking, or analytics backend
    TelemetryAnalytics,
    /// Vendor firmware update or OTA distribution server
    FirmwareUpdateOta,
    /// Dynamic DNS (DDNS) provider domain often used for remote access
    DynamicDns,
    /// Public cloud infrastructure or CDN (AWS, Azure, Cloudflare)
    CloudInfrastructure,
    /// Network Time Protocol (NTP) synchronization server
    NtpTimeServer,
    /// Local network or mDNS domain (.local, .lan, .internal, localhost)
    LocalNetwork,
    /// Standard public domain
    GeneralPublic,
}

impl fmt::Display for DomainCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TelemetryAnalytics => write!(f, "telemetry-analytics"),
            Self::FirmwareUpdateOta => write!(f, "firmware-update-ota"),
            Self::DynamicDns => write!(f, "dynamic-dns"),
            Self::CloudInfrastructure => write!(f, "cloud-infrastructure"),
            Self::NtpTimeServer => write!(f, "ntp-time"),
            Self::LocalNetwork => write!(f, "local-network"),
            Self::GeneralPublic => write!(f, "general-public"),
        }
    }
}

/// Security issue severity ranking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DomainSeverity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl fmt::Display for DomainSeverity {
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

impl std::str::FromStr for DomainSeverity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "critical" => Ok(Self::Critical),
            "high" => Ok(Self::High),
            "medium" => Ok(Self::Medium),
            "low" => Ok(Self::Low),
            "info" => Ok(Self::Info),
            other => Err(format!(
                "Unknown severity '{}', expected critical|high|medium|low|info",
                other
            )),
        }
    }
}

/// Security issue code identifiers for domain and endpoint auditing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainIssueCode {
    /// Insecure cleartext HTTP firmware update or OTA URL
    NetClearOta,
    /// Insecure cleartext HTTP remote API or external communication
    NetClearApi,
    /// Hardcoded public routable IP address in firmware
    NetHardcodedIp,
    /// Hardcoded Dynamic DNS domain in firmware
    NetDdns,
    /// Deprecated insecure protocol URI (telnet, ftp, tftp)
    NetInsecureProtocol,
    /// Embedded user credentials in URI authority
    NetEmbeddedCreds,
    /// External telemetry and behavioral tracking endpoint
    NetTelemetry,
}

impl fmt::Display for DomainIssueCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NetClearOta => write!(f, "NET-CLEAR-001"),
            Self::NetClearApi => write!(f, "NET-CLEAR-002"),
            Self::NetHardcodedIp => write!(f, "NET-HARDIP-001"),
            Self::NetDdns => write!(f, "NET-DDNS-001"),
            Self::NetInsecureProtocol => write!(f, "NET-INSEC-001"),
            Self::NetEmbeddedCreds => write!(f, "NET-AUTH-001"),
            Self::NetTelemetry => write!(f, "NET-TELEM-001"),
        }
    }
}

/// Detailed security finding associated with an endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainSecurityIssue {
    pub code: DomainIssueCode,
    pub severity: DomainSeverity,
    pub title: String,
    pub description: String,
    pub recommendation: String,
}

/// An extracted and classified network endpoint record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointFinding {
    /// Raw unparsed string extracted from binary or text
    pub raw: String,
    /// Normalized clean representation (host, IP, or sanitized URL)
    pub normalized: String,
    /// Categorized endpoint kind
    pub kind: EndpointKind,
    /// URI scheme if endpoint is a URL
    pub scheme: Option<UrlScheme>,
    /// Address scope if endpoint is an IP address
    pub ip_scope: Option<IpScope>,
    /// Domain category if endpoint is a hostname/domain or URL
    pub domain_category: Option<DomainCategory>,
    /// Explicit port number if specified
    pub port: Option<u16>,
    /// Relative or absolute file path where endpoint was discovered
    pub file_path: Option<String>,
    /// Byte offset within binary or container image
    pub offset: Option<usize>,
    /// Line number if discovered in text file
    pub line_number: Option<usize>,
    /// Associated security audit issues
    pub issues: Vec<DomainSecurityIssue>,
}

impl Zeroize for EndpointFinding {
    fn zeroize(&mut self) {
        self.raw.zeroize();
        self.normalized.zeroize();
        if let Some(fp) = &mut self.file_path {
            fp.zeroize();
        }
        self.offset = None;
        self.line_number = None;
        self.port = None;
    }
}

impl Drop for EndpointFinding {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Summary metrics of the domain audit sweep.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DomainAuditSummary {
    pub total_scanned_bytes: usize,
    pub total_endpoints_found: usize,
    pub url_count: usize,
    pub ipv4_count: usize,
    pub ipv6_count: usize,
    pub domain_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
}

/// Complete report containing findings and audit metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainAuditReport {
    pub target: String,
    pub scan_duration_ms: u64,
    pub summary: DomainAuditSummary,
    pub findings: Vec<EndpointFinding>,
}

/// Configuration options for domain auditing.
#[derive(Debug, Clone)]
pub struct DomainAuditConfig {
    pub min_severity: DomainSeverity,
    pub min_string_length: usize,
    pub include_private_ips: bool,
    pub kind_filter: Option<EndpointKind>,
}

impl Default for DomainAuditConfig {
    fn default() -> Self {
        Self {
            min_severity: DomainSeverity::Low,
            min_string_length: 4,
            include_private_ips: true,
            kind_filter: None,
        }
    }
}
