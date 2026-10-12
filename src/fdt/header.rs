// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::error::{CarverError, Result};
use serde::{Deserialize, Serialize};

pub const FDT_MAGIC: u32 = 0xD00D_FEED;
pub const FDT_MIN_HEADER_SIZE: usize = 28;
pub const FDT_V17_HEADER_SIZE: usize = 40;

/// Represents an individual memory reservation entry in the FDT header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FdtReserveEntry {
    pub address: u64,
    pub size: u64,
}

/// Standard Flattened Device Tree (FDT / DTB) header conforming to Devicetree Spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FdtHeader {
    pub magic: u32,
    pub totalsize: u32,
    pub off_dt_struct: u32,
    pub off_dt_strings: u32,
    pub off_mem_rsvmap: u32,
    pub version: u32,
    pub last_comp_version: u32,
    pub boot_cpuid_phys: u32,
    pub size_dt_strings: u32,
    pub size_dt_struct: u32,
}

impl FdtHeader {
    /// Parses and validates an FDT header from binary slice.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < FDT_MIN_HEADER_SIZE {
            return Err(CarverError::Fdt(format!(
                "FDT data too short for header: {} bytes (required at least {})",
                data.len(),
                FDT_MIN_HEADER_SIZE
            )));
        }

        let magic = u32::from_be_bytes(
            data[0..4]
                .try_into()
                .map_err(|_| CarverError::Fdt("Failed to read FDT magic bytes".to_string()))?,
        );

        if magic != FDT_MAGIC {
            return Err(CarverError::Fdt(format!(
                "Invalid FDT magic: 0x{:08X} (expected 0x{:08X})",
                magic, FDT_MAGIC
            )));
        }

        let totalsize = u32::from_be_bytes(
            data[4..8]
                .try_into()
                .map_err(|_| CarverError::Fdt("Failed to read totalsize".to_string()))?,
        );
        let off_dt_struct = u32::from_be_bytes(
            data[8..12]
                .try_into()
                .map_err(|_| CarverError::Fdt("Failed to read off_dt_struct".to_string()))?,
        );
        let off_dt_strings = u32::from_be_bytes(
            data[12..16]
                .try_into()
                .map_err(|_| CarverError::Fdt("Failed to read off_dt_strings".to_string()))?,
        );
        let off_mem_rsvmap = u32::from_be_bytes(
            data[16..20]
                .try_into()
                .map_err(|_| CarverError::Fdt("Failed to read off_mem_rsvmap".to_string()))?,
        );
        let version = u32::from_be_bytes(
            data[20..24]
                .try_into()
                .map_err(|_| CarverError::Fdt("Failed to read version".to_string()))?,
        );
        let last_comp_version = u32::from_be_bytes(
            data[24..28]
                .try_into()
                .map_err(|_| CarverError::Fdt("Failed to read last_comp_version".to_string()))?,
        );

        if totalsize < FDT_MIN_HEADER_SIZE as u32 {
            return Err(CarverError::Fdt(format!(
                "Corrupt totalsize {} is smaller than minimum header size",
                totalsize
            )));
        }

        let available_len = data.len() as u32;
        if totalsize > available_len {
            return Err(CarverError::Fdt(format!(
                "FDT totalsize {} exceeds provided binary buffer length {}",
                totalsize, available_len
            )));
        }

        if off_dt_struct >= totalsize || off_dt_strings >= totalsize || off_mem_rsvmap >= totalsize
        {
            return Err(CarverError::Fdt(format!(
                "FDT block offset exceeds totalsize (struct: 0x{:X}, strings: 0x{:X}, rsv: 0x{:X}, totalsize: 0x{:X})",
                off_dt_struct, off_dt_strings, off_mem_rsvmap, totalsize
            )));
        }

        let mut boot_cpuid_phys = 0;
        let mut size_dt_strings = 0;
        let mut size_dt_struct = 0;

        if data.len() >= FDT_V17_HEADER_SIZE && version >= 17 {
            boot_cpuid_phys = u32::from_be_bytes(data[28..32].try_into().unwrap_or([0; 4]));
            size_dt_strings = u32::from_be_bytes(data[32..36].try_into().unwrap_or([0; 4]));
            size_dt_struct = u32::from_be_bytes(data[36..40].try_into().unwrap_or([0; 4]));
        }

        Ok(Self {
            magic,
            totalsize,
            off_dt_struct,
            off_dt_strings,
            off_mem_rsvmap,
            version,
            last_comp_version,
            boot_cpuid_phys,
            size_dt_strings,
            size_dt_struct,
        })
    }

    /// Parses the memory reservation map from the FDT blob.
    pub fn parse_mem_rsvmap(&self, data: &[u8]) -> Result<Vec<FdtReserveEntry>> {
        let mut reservations = Vec::new();
        let mut offset = self.off_mem_rsvmap as usize;
        let max_offset = (self.totalsize as usize).min(data.len());

        let mut count = 0;
        while offset + 16 <= max_offset && count < 1024 {
            let addr = u64::from_be_bytes(
                data[offset..offset + 8]
                    .try_into()
                    .map_err(|_| CarverError::Fdt("Failed reading memreserve address".into()))?,
            );
            let size = u64::from_be_bytes(
                data[offset + 8..offset + 16]
                    .try_into()
                    .map_err(|_| CarverError::Fdt("Failed reading memreserve size".into()))?,
            );

            offset += 16;
            count += 1;

            if addr == 0 && size == 0 {
                break;
            }
            reservations.push(FdtReserveEntry {
                address: addr,
                size,
            });
        }

        Ok(reservations)
    }
}
