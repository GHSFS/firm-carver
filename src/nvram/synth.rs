// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::broadcom::{compute_bcm_crc8, BCM_NVRAM_HEADER_LEN};
use super::mediatek::{MTK_CHIP_MT7620, MTK_CHIP_MT7628, MTK_CHIP_RT2880};
use super::types::{Endianness, NvramSourceKind};

/// Builds a deterministic synthetic Broadcom FLSH partition buffer.
pub fn build_synthetic_broadcom_flsh(entries: &[(&str, &str)], endianness: Endianness) -> Vec<u8> {
    let mut payload = Vec::new();
    for (k, v) in entries {
        payload.extend_from_slice(format!("{}={}\0", k, v).as_bytes());
    }
    // Trailing double null terminator
    payload.push(0x00);

    let total_len = BCM_NVRAM_HEADER_LEN + payload.len();
    let crc8 = compute_bcm_crc8(&payload);
    let version: u8 = 1;
    let flags: u16 = 0x0000;
    let crc_ver_flg = (crc8 as u32) | ((version as u32) << 8) | ((flags as u32) << 16);

    let mut buf = Vec::with_capacity(total_len);
    match endianness {
        Endianness::Little => {
            buf.extend_from_slice(b"FLSH"); // 0x46, 0x4C, 0x53, 0x48
            buf.extend_from_slice(&(total_len as u32).to_le_bytes());
            buf.extend_from_slice(&crc_ver_flg.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes()); // config_refresh
            buf.extend_from_slice(&0u32.to_le_bytes()); // config_ncdl
        }
        Endianness::Big => {
            buf.extend_from_slice(b"HSLF"); // 0x48, 0x53, 0x4C, 0x46
            buf.extend_from_slice(&(total_len as u32).to_be_bytes());
            buf.extend_from_slice(&crc_ver_flg.to_be_bytes());
            buf.extend_from_slice(&0u32.to_be_bytes());
            buf.extend_from_slice(&0u32.to_be_bytes());
        }
    }

    buf.extend_from_slice(&payload);
    buf
}

/// Builds a deterministic packed null-delimited strings table without FLSH header.
pub fn build_synthetic_packed_strings(entries: &[(&str, &str)]) -> Vec<u8> {
    let mut buf = Vec::new();
    for (k, v) in entries {
        buf.extend_from_slice(format!("{}={}\0", k, v).as_bytes());
    }
    buf.push(0x00);
    buf
}

/// Builds a synthetic MediaTek .dat line-delimited wireless configuration file.
pub fn build_synthetic_mediatek_dat(entries: &[(&str, &str)]) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("# MediaTek / Ralink Wi-Fi Configuration File\n");
    out.push_str("Default\n");
    for (k, v) in entries {
        out.push_str(&format!("{}={}\n", k, v));
    }
    out.into_bytes()
}

/// Builds a synthetic 512-byte MediaTek / Ralink factory EEPROM binary.
pub fn build_synthetic_mediatek_eeprom(
    chip_id: u16,
    mac_lan: [u8; 6],
    mac_wan: Option<[u8; 6]>,
    endianness: Endianness,
) -> Vec<u8> {
    let mut buf = vec![0xFFu8; 512];

    // Chip ID at offset 0x00..0x02
    match endianness {
        Endianness::Little => {
            buf[0..2].copy_from_slice(&chip_id.to_le_bytes());
        }
        Endianness::Big => {
            buf[0..2].copy_from_slice(&chip_id.to_be_bytes());
        }
    }

    // LAN MAC at offset 0x04..0x0A
    buf[4..10].copy_from_slice(&mac_lan);

    // WAN MAC at offset 0x28..0x2E
    if let Some(wan) = mac_wan {
        buf[0x28..0x2E].copy_from_slice(&wan);
    }

    // NIC configs at 0x34 and 0x36
    buf[0x34..0x36].copy_from_slice(&0x0011u16.to_le_bytes());
    buf[0x36..0x38].copy_from_slice(&0x0022u16.to_le_bytes());

    // Country region at 0x38
    buf[0x38] = 5;

    // Freq offset & TX power at 0x52, 0x53
    buf[0x52] = 0x1A;
    buf[0x53] = 0x2C;

    buf
}

/// Builds a synthetic vulnerable NVRAM table triggering all 6 security rules.
pub fn build_synthetic_vulnerable_nvram() -> (Vec<u8>, NvramSourceKind) {
    let entries = [
        ("wl0_ssid", "HomeRouter_2.4G"),
        ("wl0_wpa_psk", "12345678"),
        ("AuthMode", "OPEN"),
        ("wps_device_pin", "12345670"),
        ("http_username", "admin"),
        ("http_passwd", "admin123"),
        ("telnetd_enable", "1"),
        ("boot_wait", "on"),
        ("remote_management", "1"),
        ("cwmp_acs_url", "http://acs.telecom.local/tr069"),
        ("wan_pppoe_passwd", "super_secret_isp_pw"),
    ];

    let blob = build_synthetic_broadcom_flsh(&entries, Endianness::Little);
    (blob, NvramSourceKind::BroadcomFlsh)
}

/// Builds a synthetic hardened NVRAM table passing security checks.
pub fn build_synthetic_hardened_nvram() -> Vec<u8> {
    let entries = [
        ("wl0_ssid", "SecureCorporateMesh"),
        ("wl0_wpa_psk", "k9#Vp!82MxQ$dZ92b"),
        ("AuthMode", "WPA2PSK"),
        ("EncrypType", "AES"),
        ("http_username", "secadmin"),
        ("http_passwd", "Tr9#qP!mK$7729Aa!"),
        ("telnetd_enable", "0"),
        ("boot_wait", "off"),
        ("remote_management", "0"),
        ("cwmp_acs_url", "https://acs.telecom.local/tr069"),
    ];

    build_synthetic_broadcom_flsh(&entries, Endianness::Little)
}

/// Builds a synthetic MediaTek MT7628 factory partition blob.
pub fn build_synthetic_mtk7628_factory() -> Vec<u8> {
    build_synthetic_mediatek_eeprom(
        MTK_CHIP_MT7628,
        [0x00, 0x0C, 0x43, 0x28, 0x76, 0x01],
        Some([0x00, 0x0C, 0x43, 0x28, 0x76, 0x02]),
        Endianness::Little,
    )
}

/// Builds a synthetic MediaTek RT2880 factory partition blob.
pub fn build_synthetic_rt2880_factory() -> Vec<u8> {
    build_synthetic_mediatek_eeprom(
        MTK_CHIP_RT2880,
        [0x00, 0x0C, 0x43, 0x28, 0x80, 0x01],
        None,
        Endianness::Little,
    )
}

/// Builds a synthetic MediaTek MT7620 factory partition blob.
pub fn build_synthetic_mt7620_factory() -> Vec<u8> {
    build_synthetic_mediatek_eeprom(
        MTK_CHIP_MT7620,
        [0x00, 0x0C, 0x43, 0x76, 0x20, 0x01],
        None,
        Endianness::Little,
    )
}
