// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::error::Result;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Deterministic test fixture generator for network endpoint and domain auditing.
pub struct DomainSynth;

impl DomainSynth {
    /// Build a synthetic binary firmware buffer containing known vulnerable endpoints.
    pub fn build_synthetic_vulnerable_buffer() -> Vec<u8> {
        let mut buffer = Vec::new();

        // Padding prefix
        buffer
            .extend_from_slice(b"\x7F\x45\x4C\x46\x01\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        buffer.extend_from_slice(b"BOOT_SIGNATURE_MIPS_BE_LINUX_2026\x00\x00\x00");

        // Vulnerable Cleartext OTA URL (NET-CLEAR-001)
        buffer.extend_from_slice(
            b"CHECK_URL=http://update.router-vendor.com/v2/check_fw.cgi?model=R6400\x00",
        );

        // Cleartext Remote API (NET-CLEAR-002)
        buffer.extend_from_slice(b"CLOUD_API=http://api.iotcloud.io/v1/heartbeat\x00");

        // Hardcoded Public Routable IP (NET-HARDIP-001)
        buffer.extend_from_slice(b"REMOTE_LOG_SERVER=203.0.113.88:514\x00");

        // Hardcoded Dynamic DNS domain (NET-DDNS-001)
        buffer.extend_from_slice(b"FALLBACK_HOST=remote-mgmt.dyndns.org\x00");

        // Insecure Protocol URIs (NET-INSEC-001)
        buffer.extend_from_slice(b"DIAG_SHELL=telnet://192.168.1.1:23\x00");
        buffer
            .extend_from_slice(b"FTP_BACKUP=ftp://backup.firmware-store.net/pub/config.tar.gz\x00");

        // Hardcoded URI Credentials (NET-AUTH-001)
        buffer.extend_from_slice(
            b"ADMIN_UPGRADE=http://admin:SuperSecretPass123@update.vendor.com/flash\x00",
        );

        // External Telemetry (NET-TELEM-001)
        buffer.extend_from_slice(
            b"TELEMETRY_ENDPOINT=https://analytics.crashlytics.com/v1/event\x00",
        );

        // Public DNS (Known provider)
        buffer.extend_from_slice(b"PRIMARY_DNS=8.8.8.8\x00");

        // IPv6 address
        buffer.extend_from_slice(b"IPV6_UPSTREAM=2001:db8::1\x00");

        // Binary noise / benign false-positive candidates
        buffer.extend_from_slice(
            b"libc.so.0\x00libcrypto.so.1.0.0\x00kernel.tar.gz\x00index.html\x00",
        );
        buffer.extend_from_slice(b"\x00\x00\xFF\xFE\x00\x00PADDING_BYTES_AT_END\x00");

        buffer
    }

    /// Build a synthetic hardened firmware buffer with only secure endpoints.
    pub fn build_synthetic_hardened_buffer() -> Vec<u8> {
        let mut buffer = Vec::new();

        buffer
            .extend_from_slice(b"\x7F\x45\x4C\x46\x01\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        buffer.extend_from_slice(b"HARDENED_FIRMWARE_BUILD_2026_LE\x00");

        // Encrypted HTTPS OTA URL
        buffer
            .extend_from_slice(b"OTA_URL=https://updates.hardened-vendor.com/v1/manifest.json\x00");

        // Encrypted HTTPS Cloud API
        buffer.extend_from_slice(b"API_GATEWAY=https://api.hardened-vendor.com/devices/sync\x00");

        // Private LAN IP
        buffer.extend_from_slice(b"LAN_GATEWAY=192.168.1.1\x00");
        buffer.extend_from_slice(b"DEFAULT_SUBNET=10.0.0.1\x00");

        // Local mDNS domain
        buffer.extend_from_slice(b"LOCAL_HOSTNAME=router.local\x00");
        buffer.extend_from_slice(b"INTERNAL_ZONE=gateway.home\x00");

        // Standard NTP Time Sync
        buffer.extend_from_slice(b"NTP_SERVER=pool.ntp.org\x00");

        // Clean binary metadata
        buffer.extend_from_slice(b"libpthread.so.0\x00busybox\x00version 1.36.1\x00");

        buffer
    }

    /// Write a realistic synthetic directory hierarchy containing scripts and configs.
    pub fn write_synthetic_tree(base_dir: &Path) -> Result<PathBuf> {
        let root = base_dir.join("synthetic_root");
        let etc = root.join("etc");
        let www = root.join("www");
        fs::create_dir_all(&etc)?;
        fs::create_dir_all(&www)?;

        // /etc/network.conf
        let mut net_conf = File::create(etc.join("network.conf"))?;
        writeln!(net_conf, "# Network configuration")?;
        writeln!(net_conf, "LAN_IP=192.168.1.1")?;
        writeln!(net_conf, "WAN_DNS=8.8.8.8")?;
        writeln!(net_conf, "NTP_HOST=time.nist.gov")?;
        writeln!(net_conf, "DDNS_DOMAIN=myhome.dyndns.org")?;

        // /etc/update.sh
        let mut update_sh = File::create(etc.join("update.sh"))?;
        writeln!(update_sh, "#!/bin/sh")?;
        writeln!(update_sh, "# Insecure OTA check")?;
        writeln!(
            update_sh,
            "curl -s http://download.router-firmware.com/fw/latest.bin -o /tmp/fw.bin"
        )?;

        // /www/telemetry.js
        let mut telem_js = File::create(www.join("telemetry.js"))?;
        writeln!(telem_js, "// Client side telemetry")?;
        writeln!(
            telem_js,
            "const ENDPOINT = 'https://telemetry.iotstats.io/collect';"
        )?;
        writeln!(
            telem_js,
            "const BACKUP_FTP = 'ftp://ftp.firmware-vendor.com/logs';"
        )?;

        Ok(root)
    }
}
