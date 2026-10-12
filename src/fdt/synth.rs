// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::header::{FDT_MAGIC, FDT_V17_HEADER_SIZE};
use super::node::{align_4, FDT_BEGIN_NODE, FDT_END, FDT_END_NODE, FDT_PROP};
use std::collections::HashMap;

/// Helper to deterministically build a binary Flattened Device Tree blob.
pub struct DtBuilder {
    struct_data: Vec<u8>,
    strings_data: Vec<u8>,
    strings_map: HashMap<String, usize>,
}

impl Default for DtBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DtBuilder {
    pub fn new() -> Self {
        Self {
            struct_data: Vec::new(),
            strings_data: Vec::new(),
            strings_map: HashMap::new(),
        }
    }

    pub fn get_or_add_string(&mut self, name: &str) -> u32 {
        if let Some(&off) = self.strings_map.get(name) {
            return off as u32;
        }
        let off = self.strings_data.len();
        self.strings_data.extend_from_slice(name.as_bytes());
        self.strings_data.push(0);
        self.strings_map.insert(name.to_string(), off);
        off as u32
    }

    pub fn begin_node(&mut self, name: &str) {
        self.struct_data
            .extend_from_slice(&FDT_BEGIN_NODE.to_be_bytes());
        self.struct_data.extend_from_slice(name.as_bytes());
        self.struct_data.push(0);
        // Align to 4 bytes
        let aligned = align_4(self.struct_data.len());
        self.struct_data.resize(aligned, 0);
    }

    pub fn end_node(&mut self) {
        self.struct_data
            .extend_from_slice(&FDT_END_NODE.to_be_bytes());
    }

    pub fn add_prop_empty(&mut self, name: &str) {
        self.add_prop_bytes(name, &[]);
    }

    pub fn add_prop_bytes(&mut self, name: &str, bytes: &[u8]) {
        let nameoff = self.get_or_add_string(name);
        self.struct_data.extend_from_slice(&FDT_PROP.to_be_bytes());
        self.struct_data
            .extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        self.struct_data.extend_from_slice(&nameoff.to_be_bytes());
        self.struct_data.extend_from_slice(bytes);
        let aligned = align_4(self.struct_data.len());
        self.struct_data.resize(aligned, 0);
    }

    pub fn add_prop_string(&mut self, name: &str, val: &str) {
        let mut bytes = val.as_bytes().to_vec();
        bytes.push(0);
        self.add_prop_bytes(name, &bytes);
    }

    pub fn add_prop_strings(&mut self, name: &str, list: &[&str]) {
        let mut bytes = Vec::new();
        for item in list {
            bytes.extend_from_slice(item.as_bytes());
            bytes.push(0);
        }
        self.add_prop_bytes(name, &bytes);
    }

    pub fn add_prop_u32_array(&mut self, name: &str, cells: &[u32]) {
        let mut bytes = Vec::with_capacity(cells.len() * 4);
        for cell in cells {
            bytes.extend_from_slice(&cell.to_be_bytes());
        }
        self.add_prop_bytes(name, &bytes);
    }

    /// Finalizes the FDT blob including memory reservation entries and header.
    pub fn build(mut self, reservations: &[(u64, u64)]) -> Vec<u8> {
        self.struct_data.extend_from_slice(&FDT_END.to_be_bytes());

        let off_mem_rsvmap = FDT_V17_HEADER_SIZE;
        let mut rsv_block = Vec::new();
        for &(addr, sz) in reservations {
            rsv_block.extend_from_slice(&addr.to_be_bytes());
            rsv_block.extend_from_slice(&sz.to_be_bytes());
        }
        // Terminator (0, 0)
        rsv_block.extend_from_slice(&0u64.to_be_bytes());
        rsv_block.extend_from_slice(&0u64.to_be_bytes());

        let off_dt_struct = align_4(off_mem_rsvmap + rsv_block.len());
        let off_dt_strings = align_4(off_dt_struct + self.struct_data.len());
        let totalsize = off_dt_strings + self.strings_data.len();

        let mut out = Vec::with_capacity(totalsize);

        // Header (v17)
        out.extend_from_slice(&FDT_MAGIC.to_be_bytes());
        out.extend_from_slice(&(totalsize as u32).to_be_bytes());
        out.extend_from_slice(&(off_dt_struct as u32).to_be_bytes());
        out.extend_from_slice(&(off_dt_strings as u32).to_be_bytes());
        out.extend_from_slice(&(off_mem_rsvmap as u32).to_be_bytes());
        out.extend_from_slice(&17u32.to_be_bytes()); // version
        out.extend_from_slice(&16u32.to_be_bytes()); // last_comp_version
        out.extend_from_slice(&0u32.to_be_bytes()); // boot_cpuid_phys
        out.extend_from_slice(&(self.strings_data.len() as u32).to_be_bytes());
        out.extend_from_slice(&(self.struct_data.len() as u32).to_be_bytes());

        // Memory reservations
        out.extend_from_slice(&rsv_block);
        out.resize(off_dt_struct, 0);

        // Struct block
        out.extend_from_slice(&self.struct_data);
        out.resize(off_dt_strings, 0);

        // Strings block
        out.extend_from_slice(&self.strings_data);

        out
    }
}

/// Builds a deterministic synthetic Flattened Device Tree blob representing a real-world router.
pub fn build_synthetic_fdt() -> Vec<u8> {
    let mut b = DtBuilder::new();

    // Root node "/"
    b.begin_node("");
    b.add_prop_string("model", "GHSFS Industrial Gateway AX-3000");
    b.add_prop_strings("compatible", &["ghsfs,ax3000", "qcom,ipq8074"]);
    b.add_prop_u32_array("#address-cells", &[1]);
    b.add_prop_u32_array("#size-cells", &[1]);

    // /chosen
    b.begin_node("chosen");
    b.add_prop_string(
        "bootargs",
        "console=ttyMSM0,115200 root=/dev/mtdblock4 rootfstype=squashfs ro",
    );
    b.add_prop_string("stdout-path", "/soc/serial@18000000:115200");
    b.end_node();

    // /memory@80000000 (256 MB)
    b.begin_node("memory@80000000");
    b.add_prop_string("device_type", "memory");
    b.add_prop_u32_array("reg", &[0x8000_0000, 0x1000_0000]);
    b.end_node();

    // /cpus
    b.begin_node("cpus");
    b.add_prop_u32_array("#address-cells", &[1]);
    b.add_prop_u32_array("#size-cells", &[0]);

    b.begin_node("cpu@0");
    b.add_prop_string("device_type", "cpu");
    b.add_prop_string("compatible", "arm,cortex-a53");
    b.add_prop_u32_array("reg", &[0]);
    b.add_prop_u32_array("clock-frequency", &[1_400_000_000]);
    b.end_node();
    b.end_node(); // /cpus

    // /soc
    b.begin_node("soc");
    b.add_prop_string("compatible", "simple-bus");
    b.add_prop_u32_array("#address-cells", &[1]);
    b.add_prop_u32_array("#size-cells", &[1]);
    b.add_prop_empty("ranges");

    // /soc/serial@18000000
    b.begin_node("serial@18000000");
    b.add_prop_strings("compatible", &["qcom,msm-uart", "ns16550a"]);
    b.add_prop_u32_array("reg", &[0x1800_0000, 0x1000]);
    b.add_prop_u32_array("interrupts", &[0, 24, 4]);
    b.add_prop_u32_array("clock-frequency", &[48_000_000]);
    b.end_node();

    // /soc/spi@18040000
    b.begin_node("spi@18040000");
    b.add_prop_string("compatible", "qcom,spi-qup");
    b.add_prop_u32_array("reg", &[0x1804_0000, 0x1000]);
    b.add_prop_u32_array("#address-cells", &[1]);
    b.add_prop_u32_array("#size-cells", &[0]);

    // flash@0
    b.begin_node("flash@0");
    b.add_prop_string("compatible", "jedec,spi-nor");
    b.add_prop_u32_array("reg", &[0]);

    // partitions
    b.begin_node("partitions");
    b.add_prop_string("compatible", "fixed-partitions");
    b.add_prop_u32_array("#address-cells", &[1]);
    b.add_prop_u32_array("#size-cells", &[1]);

    b.begin_node("partition@0");
    b.add_prop_string("label", "u-boot");
    b.add_prop_u32_array("reg", &[0x0000_0000, 0x0008_0000]);
    b.add_prop_empty("read-only");
    b.end_node();

    b.begin_node("partition@80000");
    b.add_prop_string("label", "u-boot-env");
    b.add_prop_u32_array("reg", &[0x0008_0000, 0x0004_0000]);
    b.end_node();

    b.begin_node("partition@c0000");
    b.add_prop_string("label", "kernel");
    b.add_prop_u32_array("reg", &[0x000C_0000, 0x0040_0000]);
    b.end_node();

    b.begin_node("partition@4c0000");
    b.add_prop_string("label", "rootfs");
    b.add_prop_u32_array("reg", &[0x004C_0000, 0x00B0_0000]);
    b.end_node();

    b.begin_node("partition@fc0000");
    b.add_prop_string("label", "art");
    b.add_prop_u32_array("reg", &[0x00FC_0000, 0x0004_0000]);
    b.add_prop_empty("read-only");
    b.end_node();

    b.end_node(); // partitions
    b.end_node(); // flash@0
    b.end_node(); // spi@18040000

    // /soc/ethernet@18080000
    b.begin_node("ethernet@18080000");
    b.add_prop_string("compatible", "qcom,ipq8074-edma");
    b.add_prop_u32_array("reg", &[0x1808_0000, 0x8000]);
    b.add_prop_bytes("local-mac-address", &[0x00, 0xA0, 0xC6, 0xEB, 0x12, 0x34]);
    b.add_prop_string("phy-mode", "rgmii");
    b.end_node();

    b.end_node(); // /soc
    b.end_node(); // /

    // Memory reservations: 64 KB reserved memory at 0x80000000
    b.build(&[(0x8000_0000, 0x0001_0000)])
}
