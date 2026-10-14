// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

pub mod broadcom;
pub mod carver;
pub mod mediatek;
pub mod rules;
pub mod synth;
pub mod types;

use crate::error::{CarverError, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use zeroize::Zeroize;

pub use broadcom::{
    compute_bcm_checksum8, compute_bcm_crc8, parse_broadcom_flsh, parse_null_delimited_entries,
    scan_packed_strings_tables, BroadcomNvramHeader, BCM_NVRAM_HEADER_LEN, BCM_NVRAM_MAGIC_BE,
    BCM_NVRAM_MAGIC_LE,
};
pub use carver::{
    parse_nvram_segment_at, probe_nvram_at, scan_nvram_partitions, NvramPartitionSpan,
};
pub use mediatek::{
    format_mac, parse_mediatek_dat, parse_mediatek_eeprom, probe_mediatek_dat,
    MediaTekEepromHeader, MTK_CHIP_MT7603, MTK_CHIP_MT7612, MTK_CHIP_MT7615, MTK_CHIP_MT7620,
    MTK_CHIP_MT7621, MTK_CHIP_MT7628, MTK_CHIP_MT7915, MTK_CHIP_RT2880, MTK_CHIP_RT3052,
    MTK_CHIP_RT3883,
};
pub use rules::{verify_wps_pin_checksum, NvramRuleEngine};
pub use synth::{
    build_synthetic_broadcom_flsh, build_synthetic_hardened_nvram, build_synthetic_mediatek_dat,
    build_synthetic_mediatek_eeprom, build_synthetic_mt7620_factory,
    build_synthetic_mtk7628_factory, build_synthetic_packed_strings,
    build_synthetic_rt2880_factory, build_synthetic_vulnerable_nvram,
};
pub use types::{
    Endianness, NvramAuditReport, NvramCategory, NvramEntry, NvramSecurityIssue, NvramSeverity,
    NvramSourceKind, NvramSummary,
};

/// High-level parsed NVRAM archive and configuration container.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NvramArchive {
    pub source_kind: NvramSourceKind,
    pub endianness: Option<Endianness>,
    pub chip_id: Option<u16>,
    pub mac_address: Option<String>,
    pub entries: Vec<NvramEntry>,
}

impl Zeroize for NvramArchive {
    fn zeroize(&mut self) {
        for entry in &mut self.entries {
            entry.zeroize();
        }
        if let Some(mac) = &mut self.mac_address {
            mac.zeroize();
        }
        self.chip_id = None;
    }
}

impl NvramArchive {
    /// Automatically detects and parses an NVRAM buffer from any supported source format.
    pub fn parse(data: &[u8]) -> Result<Self> {
        // 1. Broadcom FLSH
        if let Ok((hdr, entries)) = parse_broadcom_flsh(data) {
            return Ok(Self {
                source_kind: NvramSourceKind::BroadcomFlsh,
                endianness: Some(hdr.endianness),
                chip_id: None,
                mac_address: None,
                entries,
            });
        }

        // 2. MediaTek EEPROM
        if let Ok((eeprom, entries)) = parse_mediatek_eeprom(data) {
            return Ok(Self {
                source_kind: NvramSourceKind::MediatekEeprom,
                endianness: Some(eeprom.endianness),
                chip_id: Some(eeprom.chip_id),
                mac_address: Some(eeprom.mac_lan_string()),
                entries,
            });
        }

        // 3. MediaTek .dat
        if probe_mediatek_dat(data) {
            if let Ok(entries) = parse_mediatek_dat(data) {
                return Ok(Self {
                    source_kind: NvramSourceKind::MediatekDat,
                    endianness: None,
                    chip_id: None,
                    mac_address: None,
                    entries,
                });
            }
        }

        // 4. Packed strings tables
        let tables = scan_packed_strings_tables(data, 3);
        if let Some((_, _, entries)) = tables.into_iter().next() {
            return Ok(Self {
                source_kind: NvramSourceKind::BroadcomPackedStrings,
                endianness: None,
                chip_id: None,
                mac_address: None,
                entries,
            });
        }

        Err(CarverError::Nvram(
            "Unrecognized NVRAM structure (not Broadcom FLSH, packed strings, or MediaTek .dat/EEPROM)".to_string(),
        ))
    }

    /// Explicitly parses a Broadcom FLSH formatted buffer.
    pub fn parse_broadcom(data: &[u8]) -> Result<Self> {
        let (hdr, entries) = parse_broadcom_flsh(data)?;
        Ok(Self {
            source_kind: NvramSourceKind::BroadcomFlsh,
            endianness: Some(hdr.endianness),
            chip_id: None,
            mac_address: None,
            entries,
        })
    }

    /// Explicitly parses a MediaTek buffer (.dat or EEPROM).
    pub fn parse_mediatek(data: &[u8]) -> Result<Self> {
        if let Ok((eeprom, entries)) = parse_mediatek_eeprom(data) {
            return Ok(Self {
                source_kind: NvramSourceKind::MediatekEeprom,
                endianness: Some(eeprom.endianness),
                chip_id: Some(eeprom.chip_id),
                mac_address: Some(eeprom.mac_lan_string()),
                entries,
            });
        }
        let entries = parse_mediatek_dat(data)?;
        Ok(Self {
            source_kind: NvramSourceKind::MediatekDat,
            endianness: None,
            chip_id: None,
            mac_address: None,
            entries,
        })
    }

    /// Explicitly parses contiguous packed null-delimited strings table.
    pub fn parse_packed_strings(data: &[u8]) -> Result<Self> {
        let tables = scan_packed_strings_tables(data, 2);
        if let Some((_, _, entries)) = tables.into_iter().next() {
            return Ok(Self {
                source_kind: NvramSourceKind::BroadcomPackedStrings,
                endianness: None,
                chip_id: None,
                mac_address: None,
                entries,
            });
        }
        Err(CarverError::Nvram(
            "No contiguous packed strings table found".to_string(),
        ))
    }

    /// Executes static security rule analysis on the extracted NVRAM entries.
    pub fn audit_nvram(&self) -> NvramAuditReport {
        let engine = NvramRuleEngine::new();
        let (issues, summary) = engine.evaluate(&self.entries, self.source_kind);

        NvramAuditReport {
            source_kind: self.source_kind,
            endianness: self.endianness,
            chip_id: self.chip_id,
            mac_address: self.mac_address.clone(),
            entries: self.entries.clone(),
            issues,
            summary,
        }
    }

    /// Formats human-readable key-value listing.
    pub fn format_listing(&self) -> String {
        let mut out = String::new();
        for e in &self.entries {
            out.push_str(&format!("{:<32} = {}\n", e.key, e.value));
        }
        out
    }

    /// Formats summary table of NVRAM properties.
    pub fn format_summary(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("Source Kind:     {}\n", self.source_kind.as_str()));
        if let Some(end) = self.endianness {
            out.push_str(&format!("Endianness:      {}\n", end.as_str()));
        }
        if let Some(chip) = self.chip_id {
            out.push_str(&format!("Chip ID:         0x{:04X}\n", chip));
        }
        if let Some(mac) = &self.mac_address {
            out.push_str(&format!("MAC Address:     {}\n", mac));
        }
        out.push_str(&format!("Total Entries:   {}\n", self.entries.len()));
        out
    }

    /// Formats security audit report table.
    pub fn format_audit_table(report: &NvramAuditReport) -> String {
        let mut out = String::new();
        out.push_str("=== FirmCarver NVRAM Security Audit Report ===\n");
        out.push_str(&format!(
            "Source Architecture: {}\n",
            report.source_kind.as_str()
        ));
        out.push_str(&format!("Total Keys Audited:  {}\n", report.entries.len()));
        out.push_str(&format!(
            "Findings Summary:    {} Critical | {} High | {} Medium | {} Low | {} Info\n\n",
            report.summary.critical_count,
            report.summary.high_count,
            report.summary.medium_count,
            report.summary.low_count,
            report.summary.info_count
        ));

        if report.issues.is_empty() {
            out.push_str("No security issues identified in NVRAM parameters.\n");
            return out;
        }

        out.push_str("Severity | Rule ID        | Key / Parameter      | Vulnerability Title\n");
        out.push_str(
            "--------------------------------------------------------------------------------\n",
        );
        for iss in &report.issues {
            out.push_str(&format!(
                "{:<8} | {:<14} | {:<20} | {}\n",
                iss.severity.as_str(),
                iss.rule_id,
                iss.key,
                iss.title
            ));
        }
        out
    }

    /// Exports all extracted parameters to a `.env` shell format file.
    pub fn extract_to_env_file(&self, out_path: &Path) -> Result<usize> {
        let mut content = String::new();
        content.push_str("# FirmCarver Extracted NVRAM Configuration\n");
        content.push_str(&format!("# Source: {}\n\n", self.source_kind.as_str()));

        for e in &self.entries {
            // Escape double quotes and newlines
            let escaped = e.value.replace('\"', "\\\"").replace('\n', "\\n");
            content.push_str(&format!("{}=\"{}\"\n", e.key, escaped));
        }

        fs::write(out_path, content.as_bytes()).map_err(|e| {
            CarverError::Io(std::io::Error::new(
                e.kind(),
                format!(
                    "Failed to write NVRAM env file {}: {}",
                    out_path.display(),
                    e
                ),
            ))
        })?;

        Ok(self.entries.len())
    }
}
