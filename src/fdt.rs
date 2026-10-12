// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

pub mod hardware;
pub mod header;
pub mod node;
pub mod synth;

pub use hardware::{
    CpuCore, FlashPartition, MemoryRange, NetworkInterface, PeripheralMap, UartConsole,
};
pub use header::{FdtHeader, FdtReserveEntry, FDT_MAGIC};
pub use node::{FdtNode, FdtProperty};
pub use synth::{build_synthetic_fdt, DtBuilder};

use crate::error::Result;
use serde::{Deserialize, Serialize};

/// High-level parsed Device Tree Blob (FDT / DTB) archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FdtArchive {
    pub header: FdtHeader,
    pub mem_rsvmap: Vec<FdtReserveEntry>,
    pub root: FdtNode,
    pub hardware: PeripheralMap,
}

impl FdtArchive {
    /// Parses an FDT / DTB binary blob from memory.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let header = FdtHeader::parse(data)?;
        let mem_rsvmap = header.parse_mem_rsvmap(data)?;
        let root = node::parse_structure_tree(
            data,
            header.off_dt_struct as usize,
            header.off_dt_strings as usize,
            header.totalsize as usize,
        )?;
        let hardware = PeripheralMap::extract(&root, &mem_rsvmap);

        Ok(Self {
            header,
            mem_rsvmap,
            root,
            hardware,
        })
    }

    /// Formats the parsed FDT as human-readable DTS (Device Tree Source) syntax.
    pub fn format_dts(&self) -> String {
        let mut out = String::new();
        out.push_str("// Device Tree Source (DTS) Disassembled by FirmCarver\n");
        out.push_str("/dts-v1/;\n\n");

        for r in &self.mem_rsvmap {
            out.push_str(&format!(
                "/memreserve/ 0x{:08x} 0x{:08x};\n",
                r.address, r.size
            ));
        }
        if !self.mem_rsvmap.is_empty() {
            out.push('\n');
        }

        out.push_str(&self.root.format_dts(0));
        out
    }

    /// Returns a structured hardware mapping summary.
    pub fn format_hardware_summary(&self) -> String {
        self.hardware.format_summary()
    }
}
