// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

/// Endianness configuration for multi-byte header fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Endianness {
    Little,
    Big,
}

impl Endianness {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Little => "little-endian",
            Self::Big => "big-endian",
        }
    }
}

/// Discovered NVRAM source format or partition architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NvramSourceKind {
    BroadcomFlsh,
    BroadcomPackedStrings,
    MediatekDat,
    MediatekEeprom,
}

impl NvramSourceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BroadcomFlsh => "Broadcom FLSH NVRAM Header",
            Self::BroadcomPackedStrings => "Broadcom Packed Key-Value Strings",
            Self::MediatekDat => "MediaTek / Ralink .dat Wireless Configuration",
            Self::MediatekEeprom => "MediaTek / Ralink EEPROM Factory Calibration",
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::BroadcomFlsh => "bcm-flsh",
            Self::BroadcomPackedStrings => "bcm-packed",
            Self::MediatekDat => "mtk-dat",
            Self::MediatekEeprom => "mtk-eeprom",
        }
    }
}

/// Vulnerability severity levels for NVRAM security posture auditing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum NvramSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl NvramSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }

    pub fn color_code(&self) -> &'static str {
        match self {
            Self::Critical => "\x1b[31;1mCRITICAL\x1b[0m",
            Self::High => "\x1b[31mHIGH\x1b[0m",
            Self::Medium => "\x1b[33mMEDIUM\x1b[0m",
            Self::Low => "\x1b[36mLOW\x1b[0m",
            Self::Info => "\x1b[37mINFO\x1b[0m",
        }
    }
}

/// Security vulnerability category classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NvramCategory {
    DefaultCredentials,
    WeakWireless,
    InsecureProtocol,
    BackdoorDiagnostic,
    HardcodedSecret,
    SystemConfig,
}

impl NvramCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DefaultCredentials => "Default Credentials",
            Self::WeakWireless => "Weak / Open Wireless",
            Self::InsecureProtocol => "Insecure Protocol / Remote WAN",
            Self::BackdoorDiagnostic => "Backdoor / Diagnostic Flag",
            Self::HardcodedSecret => "Hardcoded Secret / Key",
            Self::SystemConfig => "System Configuration",
        }
    }
}

/// Extracted single NVRAM key-value configuration tuple.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvramEntry {
    pub key: String,
    pub value: String,
    pub source: NvramSourceKind,
    pub offset: usize,
}

impl Zeroize for NvramEntry {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.value.zeroize();
        self.offset = 0;
    }
}

/// Security issue discovered during automated static rule engine analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvramSecurityIssue {
    pub rule_id: String,
    pub severity: NvramSeverity,
    pub category: NvramCategory,
    pub title: String,
    pub description: String,
    pub key: String,
    pub value: String,
    pub recommendation: String,
}

/// Aggregated statistical summary of extracted NVRAM contents and findings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NvramSummary {
    pub total_entries: usize,
    pub source_kind: NvramSourceKind,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
}

/// Full NVRAM security audit and parameter extraction report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NvramAuditReport {
    pub source_kind: NvramSourceKind,
    pub endianness: Option<Endianness>,
    pub chip_id: Option<u16>,
    pub mac_address: Option<String>,
    pub entries: Vec<NvramEntry>,
    pub issues: Vec<NvramSecurityIssue>,
    pub summary: NvramSummary,
}

impl fmt::Display for NvramEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.key, self.value)
    }
}
