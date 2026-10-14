// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::types::{
    NvramCategory, NvramEntry, NvramSecurityIssue, NvramSeverity, NvramSourceKind, NvramSummary,
};

/// Automated security auditing rule engine for embedded NVRAM parameters.
#[derive(Debug, Default, Clone)]
pub struct NvramRuleEngine;

impl NvramRuleEngine {
    pub fn new() -> Self {
        Self
    }

    /// Evaluates all security audit rules against extracted NVRAM key-value entries.
    pub fn evaluate(
        &self,
        entries: &[NvramEntry],
        source_kind: NvramSourceKind,
    ) -> (Vec<NvramSecurityIssue>, NvramSummary) {
        let mut issues = Vec::new();

        for entry in entries {
            self.check_wifi_passwords(entry, &mut issues);
            self.check_insecure_wireless_modes(entry, &mut issues);
            self.check_wps_pins(entry, &mut issues);
            self.check_default_credentials(entry, &mut issues);
            self.check_backdoor_diagnostic_flags(entry, &mut issues);
            self.check_insecure_services_and_wan(entry, &mut issues);
        }

        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;
        let mut info_count = 0;

        for issue in &issues {
            match issue.severity {
                NvramSeverity::Critical => critical_count += 1,
                NvramSeverity::High => high_count += 1,
                NvramSeverity::Medium => medium_count += 1,
                NvramSeverity::Low => low_count += 1,
                NvramSeverity::Info => info_count += 1,
            }
        }

        let summary = NvramSummary {
            total_entries: entries.len(),
            source_kind,
            critical_count,
            high_count,
            medium_count,
            low_count,
            info_count,
        };

        (issues, summary)
    }

    fn check_wifi_passwords(&self, entry: &NvramEntry, issues: &mut Vec<NvramSecurityIssue>) {
        let key_lower = entry.key.to_ascii_lowercase();
        let is_wifi_key = key_lower.contains("wpa_psk")
            || key_lower.contains("wpapsk")
            || key_lower.contains("wifi_password")
            || key_lower.contains("wlan_key")
            || key_lower.contains("psk_key")
            || key_lower.starts_with("key1str")
            || key_lower.starts_with("key2str")
            || key_lower == "passphrase";

        if !is_wifi_key || entry.value.is_empty() {
            return;
        }

        let weak_passwords = [
            "12345678",
            "password",
            "admin",
            "00000000",
            "admin123",
            "11111111",
            "1234567890",
            "root",
            "guest",
            "default",
            "qwertyuiop",
        ];

        let val_lower = entry.value.to_ascii_lowercase();
        if weak_passwords.contains(&val_lower.as_str()) {
            issues.push(NvramSecurityIssue {
                rule_id: "NVRAM-WIFI-001".to_string(),
                severity: NvramSeverity::Critical,
                category: NvramCategory::WeakWireless,
                title: "Weak or Factory Default Wi-Fi Pre-Shared Key (PSK)".to_string(),
                description: format!(
                    "Wireless parameter '{}' is configured with trivial or well-known password '{}'.",
                    entry.key, entry.value
                ),
                key: entry.key.clone(),
                value: entry.value.clone(),
                recommendation: "Enforce high-entropy random WPA2/WPA3 pre-shared keys generated per-device during manufacturing.".to_string(),
            });
        }
    }

    fn check_insecure_wireless_modes(
        &self,
        entry: &NvramEntry,
        issues: &mut Vec<NvramSecurityIssue>,
    ) {
        let key_lower = entry.key.to_ascii_lowercase();
        let val_upper = entry.value.to_ascii_uppercase();

        if key_lower == "authmode"
            || key_lower == "encryptype"
            || key_lower.contains("wep")
            || key_lower.contains("akm")
            || key_lower == "security_mode"
        {
            if val_upper == "OPEN" || val_upper == "NONE" || val_upper == "DISABLED" {
                issues.push(NvramSecurityIssue {
                    rule_id: "NVRAM-WIFI-002".to_string(),
                    severity: NvramSeverity::Medium,
                    category: NvramCategory::WeakWireless,
                    title: "Insecure Open Unencrypted Wireless Network".to_string(),
                    description: format!(
                        "Wireless configuration parameter '{}' is set to '{}', exposing unauthenticated network traffic.",
                        entry.key, entry.value
                    ),
                    key: entry.key.clone(),
                    value: entry.value.clone(),
                    recommendation: "Enable WPA2-PSK (AES/CCMP) or WPA3-SAE by default.".to_string(),
                });
            } else if val_upper.contains("WEP") || val_upper == "SHARED" {
                issues.push(NvramSecurityIssue {
                    rule_id: "NVRAM-WIFI-002".to_string(),
                    severity: NvramSeverity::Medium,
                    category: NvramCategory::WeakWireless,
                    title: "Deprecated WEP Encryption Algorithm".to_string(),
                    description: format!(
                        "Wireless parameter '{}' uses cryptographically broken WEP encryption ('{}').",
                        entry.key, entry.value
                    ),
                    key: entry.key.clone(),
                    value: entry.value.clone(),
                    recommendation: "Deprecate WEP support and migrate to robust WPA2/WPA3 encryption.".to_string(),
                });
            }
        }
    }

    fn check_wps_pins(&self, entry: &NvramEntry, issues: &mut Vec<NvramSecurityIssue>) {
        let key_lower = entry.key.to_ascii_lowercase();
        let is_wps_key = key_lower.contains("wps_pin")
            || key_lower.contains("wps_device_pin")
            || key_lower.contains("wscvendorpincode")
            || key_lower.contains("wps_ap_pin");

        if !is_wps_key || entry.value.is_empty() {
            return;
        }

        let is_known_default =
            entry.value == "12345670" || entry.value == "00000000" || entry.value == "12345678";
        let is_valid_pin_checksum = verify_wps_pin_checksum(&entry.value);

        if is_known_default || is_valid_pin_checksum {
            issues.push(NvramSecurityIssue {
                rule_id: "NVRAM-WPS-001".to_string(),
                severity: NvramSeverity::High,
                category: NvramCategory::WeakWireless,
                title: "Static or Default Wi-Fi Protected Setup (WPS) PIN".to_string(),
                description: format!(
                    "Static WPS PIN parameter '{}' is set to '{}' (valid checksum: {}).",
                    entry.key, entry.value, is_valid_pin_checksum
                ),
                key: entry.key.clone(),
                value: entry.value.clone(),
                recommendation: "Disable WPS PIN authentication by default or enable robust rate-limiting lockouts (Pixie Dust / Reaver defense).".to_string(),
            });
        }
    }

    fn check_default_credentials(&self, entry: &NvramEntry, issues: &mut Vec<NvramSecurityIssue>) {
        let key_lower = entry.key.to_ascii_lowercase();
        let is_cred_key = key_lower == "http_passwd"
            || key_lower == "http_password"
            || key_lower == "admin_password"
            || key_lower == "user_password"
            || key_lower == "login_password"
            || key_lower == "web_passwd"
            || key_lower == "sys_passwd";

        if is_cred_key {
            let weak_passwords = [
                "admin", "admin123", "1234", "123456", "password", "root", "default", "guest", "",
            ];
            let val_lower = entry.value.to_ascii_lowercase();
            if weak_passwords.contains(&val_lower.as_str()) {
                issues.push(NvramSecurityIssue {
                    rule_id: "NVRAM-CRED-001".to_string(),
                    severity: NvramSeverity::Critical,
                    category: NvramCategory::DefaultCredentials,
                    title: "Factory Default Web Administrative Password".to_string(),
                    description: format!(
                        "Administrative credential parameter '{}' is set to insecure default '{}'.",
                        entry.key, entry.value
                    ),
                    key: entry.key.clone(),
                    value: entry.value.clone(),
                    recommendation: "Require user-mandated password change on initial boot or generate unique per-device passwords.".to_string(),
                });
            }
        }
    }

    fn check_backdoor_diagnostic_flags(
        &self,
        entry: &NvramEntry,
        issues: &mut Vec<NvramSecurityIssue>,
    ) {
        let key_lower = entry.key.to_ascii_lowercase();
        let val_lower = entry.value.to_ascii_lowercase();
        let is_enabled = val_lower == "1"
            || val_lower == "on"
            || val_lower == "true"
            || val_lower == "yes"
            || val_lower == "enable"
            || val_lower == "enabled";

        if !is_enabled {
            return;
        }

        if key_lower == "telnetd_enable"
            || key_lower == "enable_telnet"
            || key_lower == "factory_mode"
            || key_lower == "remote_d"
            || key_lower == "backdoor_enable"
        {
            issues.push(NvramSecurityIssue {
                rule_id: "NVRAM-FLAG-001".to_string(),
                severity: NvramSeverity::Critical,
                category: NvramCategory::BackdoorDiagnostic,
                title: "Diagnostic Backdoor or Unauthenticated Shell Service Enabled".to_string(),
                description: format!(
                    "Production NVRAM table enables diagnostic backdoor flag '{}={}'.",
                    entry.key, entry.value
                ),
                key: entry.key.clone(),
                value: entry.value.clone(),
                recommendation: "Disable debug daemons and remote shell listeners in production firmware releases.".to_string(),
            });
        } else if key_lower == "console_enable"
            || key_lower == "debug_enable"
            || key_lower == "boot_wait"
            || key_lower == "uart_enable"
        {
            issues.push(NvramSecurityIssue {
                rule_id: "NVRAM-FLAG-001".to_string(),
                severity: NvramSeverity::High,
                category: NvramCategory::BackdoorDiagnostic,
                title: "Console Debug or Bootloader Interruption Flag Enabled".to_string(),
                description: format!(
                    "Hardware debug or CFE bootloader wait flag '{}' is active ('{}').",
                    entry.key, entry.value
                ),
                key: entry.key.clone(),
                value: entry.value.clone(),
                recommendation: "Lock down bootloader wait parameters and disable diagnostic serial consoles for production devices.".to_string(),
            });
        }
    }

    fn check_insecure_services_and_wan(
        &self,
        entry: &NvramEntry,
        issues: &mut Vec<NvramSecurityIssue>,
    ) {
        let key_lower = entry.key.to_ascii_lowercase();
        let val_lower = entry.value.to_ascii_lowercase();

        // Remote WAN management enabled
        if (key_lower == "remote_management"
            || key_lower == "http_remote_enable"
            || key_lower == "remote_access")
            && (val_lower == "1" || val_lower == "on" || val_lower == "enable")
        {
            issues.push(NvramSecurityIssue {
                rule_id: "NVRAM-SVC-001".to_string(),
                severity: NvramSeverity::High,
                category: NvramCategory::InsecureProtocol,
                title: "Remote WAN Web Management Enabled by Default".to_string(),
                description: format!(
                    "Parameter '{}={}' exposes router web administration to the public WAN interface.",
                    entry.key, entry.value
                ),
                key: entry.key.clone(),
                value: entry.value.clone(),
                recommendation: "Restrict administrative management interfaces strictly to local LAN/VLAN subnets.".to_string(),
            });
        }

        // Unencrypted TR-069 CWMP ACS connection
        if (key_lower == "cwmp_acs_url" || key_lower == "tr069_acs_url" || key_lower == "acs_url")
            && val_lower.starts_with("http://")
        {
            issues.push(NvramSecurityIssue {
                rule_id: "NVRAM-SVC-001".to_string(),
                severity: NvramSeverity::High,
                category: NvramCategory::InsecureProtocol,
                title: "Unencrypted TR-069 CWMP Auto-Configuration Server URL".to_string(),
                description: format!(
                    "TR-069 management server URL '{}={}' uses cleartext HTTP instead of mutual TLS HTTPS.",
                    entry.key, entry.value
                ),
                key: entry.key.clone(),
                value: entry.value.clone(),
                recommendation: "Enforce HTTPS with certificate pinning for TR-069 ACS communication.".to_string(),
            });
        }

        // Cleartext WAN credentials in NVRAM
        if (key_lower == "wan_pppoe_passwd"
            || key_lower == "wan_pppoe_password"
            || key_lower == "ddns_passwd")
            && !entry.value.is_empty()
        {
            issues.push(NvramSecurityIssue {
                rule_id: "NVRAM-SVC-001".to_string(),
                severity: NvramSeverity::High,
                category: NvramCategory::HardcodedSecret,
                title: "Cleartext WAN / ISP Account Credentials Stored in NVRAM".to_string(),
                description: format!(
                    "External service credential '{}' is stored in plaintext in the flash NVRAM partition.",
                    entry.key
                ),
                key: entry.key.clone(),
                value: entry.value.clone(),
                recommendation: "Encrypt stored ISP and dynamic DNS credentials using secure keystores or hardware crypto engines.".to_string(),
            });
        }
    }
}

/// Verifies whether an 8-digit WPS PIN satisfies the Wi-Fi Alliance checksum algorithm.
pub fn verify_wps_pin_checksum(pin_str: &str) -> bool {
    if pin_str.len() != 8 || !pin_str.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let digits: Vec<u32> = pin_str.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() != 8 {
        return false;
    }
    let accum =
        3 * (digits[0] + digits[2] + digits[4] + digits[6]) + (digits[1] + digits[3] + digits[5]);
    let check = (10 - (accum % 10)) % 10;
    check == digits[7]
}
