// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::types::{DomainCategory, IpScope};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Classify the network address scope for an IPv4 address.
pub fn classify_ipv4_scope(ip: Ipv4Addr) -> IpScope {
    let octets = ip.octets();

    // 0.0.0.0/8
    if octets[0] == 0 {
        return IpScope::Unspecified;
    }

    // 127.0.0.0/8
    if octets[0] == 127 {
        return IpScope::Loopback;
    }

    // 10.0.0.0/8
    if octets[0] == 10 {
        return IpScope::PrivateRfc1918;
    }

    // 172.16.0.0/12
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return IpScope::PrivateRfc1918;
    }

    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return IpScope::PrivateRfc1918;
    }

    // 169.254.0.0/16
    if octets[0] == 169 && octets[1] == 254 {
        return IpScope::LinkLocal;
    }

    // 100.64.0.0/10 (Carrier-Grade NAT RFC 6598)
    if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        return IpScope::CarrierGradeNat;
    }

    // Documentation subnets RFC 5737
    // 192.0.2.0/24 (TEST-NET-1)
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
        return IpScope::Documentation;
    }
    // 198.51.100.0/24 (TEST-NET-2)
    if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
        return IpScope::Documentation;
    }
    // 203.0.113.0/24 (TEST-NET-3)
    if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
        return IpScope::Documentation;
    }

    // 224.0.0.0/4 (Multicast)
    if (224..=239).contains(&octets[0]) {
        return IpScope::Multicast;
    }

    // 255.255.255.255 (Broadcast)
    if octets == [255, 255, 255, 255] {
        return IpScope::Broadcast;
    }

    IpScope::Public
}

/// Classify the network address scope for an IPv6 address.
pub fn classify_ipv6_scope(ip: Ipv6Addr) -> IpScope {
    let octets = ip.octets();

    // :: (Unspecified)
    if ip.is_unspecified() {
        return IpScope::Unspecified;
    }

    // ::1 (Loopback)
    if ip.is_loopback() {
        return IpScope::Loopback;
    }

    // fe80::/10 (Link-Local)
    if octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80 {
        return IpScope::LinkLocal;
    }

    // fc00::/7 (Unique Local ULA / RFC 4193)
    if (octets[0] & 0xfe) == 0xfc {
        return IpScope::PrivateRfc1918;
    }

    // ff00::/8 (Multicast)
    if octets[0] == 0xff {
        return IpScope::Multicast;
    }

    // 2001:db8::/32 (Documentation RFC 3849)
    if octets[0] == 0x20 && octets[1] == 0x01 && octets[2] == 0x0d && octets[3] == 0xb8 {
        return IpScope::Documentation;
    }

    IpScope::Public
}

/// Helper to classify IP string as IPv4 or IPv6 scope.
pub fn classify_ip_str(ip_str: &str) -> Option<IpScope> {
    if let Ok(ipv4) = Ipv4Addr::from_str(ip_str) {
        Some(classify_ipv4_scope(ipv4))
    } else if let Ok(ipv6) = Ipv6Addr::from_str(ip_str) {
        Some(classify_ipv6_scope(ipv6))
    } else {
        None
    }
}

/// Categorize a domain or hostname into functional and security classifications.
pub fn classify_domain_category(host: &str) -> DomainCategory {
    let lower = host.to_ascii_lowercase();

    // 1. Local Network / mDNS
    let local_suffixes = [
        ".local",
        ".lan",
        ".home",
        ".internal",
        ".corp",
        ".router",
        ".box",
        ".priv",
        ".home.arpa",
        ".test",
        ".example",
        ".invalid",
        "localhost",
    ];
    for suffix in local_suffixes {
        if lower.ends_with(suffix) || lower == suffix {
            return DomainCategory::LocalNetwork;
        }
    }

    // 2. Dynamic DNS (DDNS) providers
    let ddns_suffixes = [
        "dyndns.org",
        "no-ip.com",
        "ddns.net",
        "duckdns.org",
        "freedns.afraid.org",
        "changeip.com",
        "zapto.org",
        "myftp.org",
        "dlinkddns.com",
        "asuscomm.com",
        "tplinkdns.com",
        "dynu.com",
        "spdyn.de",
        "dnsomatic.com",
        "hopto.org",
        "myddns.me",
        "synology.me",
        "3322.org",
        "oray.com",
        "f3322.net",
    ];
    for suffix in ddns_suffixes {
        if lower.ends_with(suffix) || lower == suffix {
            return DomainCategory::DynamicDns;
        }
    }

    // 3. NTP Time Servers
    let ntp_indicators = [
        "pool.ntp.org",
        "time.nist.gov",
        "time.windows.com",
        "time.google.com",
        "time.apple.com",
        "time.cloudflare.com",
    ];
    for indicator in ntp_indicators {
        if lower.contains(indicator) {
            return DomainCategory::NtpTimeServer;
        }
    }
    if lower.starts_with("ntp.") || lower.contains(".ntp.") || lower.starts_with("time.") {
        return DomainCategory::NtpTimeServer;
    }

    // 4. Firmware Update / OTA
    let ota_indicators = [
        "update.",
        "updates.",
        "firmware.",
        "download.",
        "downloads.",
        "upgrade.",
        "ota.",
        "fwupdate.",
        "fw.",
    ];
    for prefix in ota_indicators {
        if lower.starts_with(prefix) || lower.contains(&format!(".{}", prefix)) {
            return DomainCategory::FirmwareUpdateOta;
        }
    }

    // 5. Telemetry / Analytics / Tracking
    let telemetry_keywords = [
        "telemetry",
        "analytics",
        "tracking",
        "metrics",
        "stats",
        "crashlytics",
        "sentry",
        "datadog",
        "segment.io",
        "mixpanel",
        "firebase",
        "umeng",
        "branch.io",
        "adjust.com",
        "appsflyer.com",
        "log.",
        "report.",
        "diag.",
    ];
    for keyword in telemetry_keywords {
        if lower.contains(keyword) {
            return DomainCategory::TelemetryAnalytics;
        }
    }

    // 6. Cloud Infrastructure & CDN
    let cloud_suffixes = [
        "amazonaws.com",
        "azure.com",
        "cloudfront.net",
        "cloudflare.com",
        "aliyuncs.com",
        "googleusercontent.com",
        "digitaloceanspaces.com",
        "akamaihd.net",
        "fastly.net",
        "blob.core.windows.net",
        "trafficmanager.net",
    ];
    for suffix in cloud_suffixes {
        if lower.ends_with(suffix) || lower == suffix {
            return DomainCategory::CloudInfrastructure;
        }
    }

    DomainCategory::GeneralPublic
}
