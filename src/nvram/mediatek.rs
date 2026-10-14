// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::types::{Endianness, NvramEntry, NvramSourceKind};
use crate::error::{CarverError, Result};

pub const MTK_CHIP_RT2880: u16 = 0x2880;
pub const MTK_CHIP_RT3052: u16 = 0x3052;
pub const MTK_CHIP_RT3883: u16 = 0x3883;
pub const MTK_CHIP_MT7620: u16 = 0x7620;
pub const MTK_CHIP_MT7621: u16 = 0x7621;
pub const MTK_CHIP_MT7628: u16 = 0x7628;
pub const MTK_CHIP_MT7603: u16 = 0x7603;
pub const MTK_CHIP_MT7612: u16 = 0x7612;
pub const MTK_CHIP_MT7615: u16 = 0x7615;
pub const MTK_CHIP_MT7915: u16 = 0x7915;

/// Parsed MediaTek / Ralink EEPROM Factory configuration metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaTekEepromHeader {
    pub chip_id: u16,
    pub chip_name: &'static str,
    pub mac_lan: [u8; 6],
    pub mac_wan: Option<[u8; 6]>,
    pub country_region: u8,
    pub nic_config_0: u16,
    pub nic_config_1: u16,
    pub frequency_offset: u8,
    pub tx_power_ch1: u8,
    pub endianness: Endianness,
}

impl MediaTekEepromHeader {
    pub fn mac_lan_string(&self) -> String {
        format_mac(&self.mac_lan)
    }

    pub fn mac_wan_string(&self) -> Option<String> {
        self.mac_wan.as_ref().map(format_mac)
    }
}

pub fn format_mac(bytes: &[u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

fn map_chip_name(chip: u16) -> Option<&'static str> {
    match chip {
        MTK_CHIP_RT2880 => Some("Ralink RT2880"),
        MTK_CHIP_RT3052 => Some("Ralink RT3052 / RT3352"),
        MTK_CHIP_RT3883 => Some("Ralink RT3883"),
        MTK_CHIP_MT7620 => Some("MediaTek MT7620A/N"),
        MTK_CHIP_MT7621 => Some("MediaTek MT7621A/AT"),
        MTK_CHIP_MT7628 => Some("MediaTek MT7628 / MT7688"),
        MTK_CHIP_MT7603 => Some("MediaTek MT7603E"),
        MTK_CHIP_MT7612 => Some("MediaTek MT7612E"),
        MTK_CHIP_MT7615 => Some("MediaTek MT7615E / MT7622"),
        MTK_CHIP_MT7915 => Some("MediaTek MT7915E Wi-Fi 6"),
        _ => None,
    }
}

/// Probes whether a slice contains a MediaTek / Ralink factory EEPROM partition.
pub fn parse_mediatek_eeprom(data: &[u8]) -> Result<(MediaTekEepromHeader, Vec<NvramEntry>)> {
    if data.len() < 16 {
        return Err(CarverError::Nvram(
            "Buffer too short for MediaTek EEPROM (min 16 bytes)".to_string(),
        ));
    }

    // Chip ID can be at offset 0x00 or offset 0x02
    let (chip_id, endian, chip_offset) = if let Some(chip) = detect_chip_id(&data[0..4]) {
        chip
    } else {
        return Err(CarverError::Nvram(
            "Unrecognized MediaTek / Ralink chip ID in EEPROM header".to_string(),
        ));
    };

    let chip_name = map_chip_name(chip_id).unwrap_or("MediaTek Unknown SoC");

    // Primary LAN/WLAN MAC is at offset 0x04..0x0A
    let mut mac_lan = [0u8; 6];
    if data.len() >= 10 {
        mac_lan.copy_from_slice(&data[4..10]);
    }

    // Optional WAN MAC at offset 0x28..0x2E
    let mac_wan = if data.len() >= 0x2E {
        let mut wan = [0u8; 6];
        wan.copy_from_slice(&data[0x28..0x2E]);
        if wan != [0xFF; 6] && wan != [0x00; 6] {
            Some(wan)
        } else {
            None
        }
    } else {
        None
    };

    let nic_config_0 = if data.len() >= 0x36 {
        match endian {
            Endianness::Little => u16::from_le_bytes([data[0x34], data[0x35]]),
            Endianness::Big => u16::from_be_bytes([data[0x34], data[0x35]]),
        }
    } else {
        0
    };

    let nic_config_1 = if data.len() >= 0x38 {
        match endian {
            Endianness::Little => u16::from_le_bytes([data[0x36], data[0x37]]),
            Endianness::Big => u16::from_be_bytes([data[0x36], data[0x37]]),
        }
    } else {
        0
    };

    let country_region = if data.len() >= 0x39 { data[0x38] } else { 0 };
    let frequency_offset = if data.len() >= 0x53 { data[0x52] } else { 0 };
    let tx_power_ch1 = if data.len() >= 0x54 { data[0x53] } else { 0 };

    let header = MediaTekEepromHeader {
        chip_id,
        chip_name,
        mac_lan,
        mac_wan,
        country_region,
        nic_config_0,
        nic_config_1,
        frequency_offset,
        tx_power_ch1,
        endianness: endian,
    };

    let mut entries = Vec::new();
    entries.push(NvramEntry {
        key: "chip_id".to_string(),
        value: format!("0x{:04X}", chip_id),
        source: NvramSourceKind::MediatekEeprom,
        offset: chip_offset,
    });
    entries.push(NvramEntry {
        key: "chip_name".to_string(),
        value: chip_name.to_string(),
        source: NvramSourceKind::MediatekEeprom,
        offset: chip_offset,
    });
    entries.push(NvramEntry {
        key: "mac_lan".to_string(),
        value: header.mac_lan_string(),
        source: NvramSourceKind::MediatekEeprom,
        offset: 4,
    });
    if let Some(wan) = header.mac_wan_string() {
        entries.push(NvramEntry {
            key: "mac_wan".to_string(),
            value: wan,
            source: NvramSourceKind::MediatekEeprom,
            offset: 0x28,
        });
    }
    entries.push(NvramEntry {
        key: "country_region".to_string(),
        value: country_region.to_string(),
        source: NvramSourceKind::MediatekEeprom,
        offset: 0x38,
    });
    entries.push(NvramEntry {
        key: "nic_config_0".to_string(),
        value: format!("0x{:04X}", nic_config_0),
        source: NvramSourceKind::MediatekEeprom,
        offset: 0x34,
    });
    entries.push(NvramEntry {
        key: "nic_config_1".to_string(),
        value: format!("0x{:04X}", nic_config_1),
        source: NvramSourceKind::MediatekEeprom,
        offset: 0x36,
    });

    Ok((header, entries))
}

fn detect_chip_id(slice: &[u8]) -> Option<(u16, Endianness, usize)> {
    if slice.len() < 4 {
        return None;
    }
    // Check offset 0 (LE then BE)
    let id_le0 = u16::from_le_bytes([slice[0], slice[1]]);
    if map_chip_name(id_le0).is_some() {
        return Some((id_le0, Endianness::Little, 0));
    }
    let id_be0 = u16::from_be_bytes([slice[0], slice[1]]);
    if map_chip_name(id_be0).is_some() {
        return Some((id_be0, Endianness::Big, 0));
    }
    // Check offset 2 (LE then BE)
    let id_le2 = u16::from_le_bytes([slice[2], slice[3]]);
    if map_chip_name(id_le2).is_some() {
        return Some((id_le2, Endianness::Little, 2));
    }
    let id_be2 = u16::from_be_bytes([slice[2], slice[3]]);
    if map_chip_name(id_be2).is_some() {
        return Some((id_be2, Endianness::Big, 2));
    }
    None
}

/// Parses MediaTek / Ralink line-delimited `.dat` configuration files.
pub fn parse_mediatek_dat(data: &[u8]) -> Result<Vec<NvramEntry>> {
    let text = std::str::from_utf8(data)
        .map_err(|e| CarverError::Nvram(format!("Invalid UTF-8 in MediaTek .dat: {}", e)))?;

    let mut entries = Vec::new();
    let mut byte_offset = 0;

    for line in text.lines() {
        let line_len = line.len() + 1; // approximate for byte offset tracking
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            byte_offset += line_len;
            continue;
        }

        if trimmed.eq_ignore_ascii_case("default") || trimmed.eq_ignore_ascii_case("[default]") {
            entries.push(NvramEntry {
                key: "_section".to_string(),
                value: "Default".to_string(),
                source: NvramSourceKind::MediatekDat,
                offset: byte_offset,
            });
            byte_offset += line_len;
            continue;
        }

        if let Some(eq_pos) = trimmed.find('=') {
            let key = trimmed[..eq_pos].trim().to_string();
            let value = trimmed[eq_pos + 1..].trim().to_string();
            if !key.is_empty() {
                entries.push(NvramEntry {
                    key,
                    value,
                    source: NvramSourceKind::MediatekDat,
                    offset: byte_offset,
                });
            }
        }

        byte_offset += line_len;
    }

    if entries.is_empty() {
        return Err(CarverError::Nvram(
            "No valid key-value pairs parsed from MediaTek .dat".to_string(),
        ));
    }

    Ok(entries)
}

/// Checks if buffer looks like a MediaTek .dat wireless configuration file.
pub fn probe_mediatek_dat(data: &[u8]) -> bool {
    let sample_len = data.len().min(4096);
    let sample = match std::str::from_utf8(&data[..sample_len]) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let has_header = sample.lines().any(|l| {
        let t = l.trim();
        t.eq_ignore_ascii_case("default") || t.eq_ignore_ascii_case("[default]")
    });

    let known_keys = [
        "SSID1=",
        "WPAPSK1=",
        "CountryCode=",
        "BssidNum=",
        "AuthMode=",
        "EncrypType=",
        "Channel=",
        "WirelessMode=",
        "DefaultKeyID=",
    ];

    let match_count = known_keys.iter().filter(|&&k| sample.contains(k)).count();
    has_header || match_count >= 2
}
