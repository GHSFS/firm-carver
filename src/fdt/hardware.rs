// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::header::FdtReserveEntry;
use super::node::FdtNode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRange {
    pub base: u64,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UartConsole {
    pub node_name: String,
    pub compatible: Vec<String>,
    pub base_address: Option<u64>,
    pub reg_size: Option<u64>,
    pub interrupts: Option<Vec<u32>>,
    pub clock_frequency: Option<u64>,
    pub is_active_console: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlashPartition {
    pub node_name: String,
    pub label: String,
    pub offset: u64,
    pub size: u64,
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub node_name: String,
    pub compatible: Vec<String>,
    pub mac_address: Option<String>,
    pub phy_mode: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpuCore {
    pub name: String,
    pub compatible: Option<String>,
    pub clock_frequency: Option<u64>,
}

/// Comprehensive peripheral hardware map extracted from an FDT node tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeripheralMap {
    pub model: Option<String>,
    pub compatible: Vec<String>,
    pub bootargs: Option<String>,
    pub stdout_path: Option<String>,
    pub memory_reservations: Vec<FdtReserveEntry>,
    pub memory_ranges: Vec<MemoryRange>,
    pub uart_consoles: Vec<UartConsole>,
    pub flash_partitions: Vec<FlashPartition>,
    pub network_interfaces: Vec<NetworkInterface>,
    pub cpus: Vec<CpuCore>,
}

impl PeripheralMap {
    /// Extracts hardware peripheral insights from the parsed FDT node hierarchy.
    pub fn extract(root: &FdtNode, reservations: &[FdtReserveEntry]) -> Self {
        let model = root.get_string_prop("model");
        let compatible = root.get_string_list_prop("compatible").unwrap_or_default();

        let chosen = root.find_child("chosen");
        let bootargs = chosen.and_then(|c| c.get_string_prop("bootargs"));
        let stdout_path = chosen.and_then(|c| c.get_string_prop("stdout-path"));

        let mut all_nodes = Vec::new();
        root.collect_matching(&|_| true, &mut all_nodes);

        // 1. Memory Ranges
        let mut memory_ranges = Vec::new();
        for node in &all_nodes {
            let is_mem = node.name.starts_with("memory")
                || node
                    .get_string_prop("device_type")
                    .map(|d| d == "memory")
                    .unwrap_or(false);

            if is_mem {
                if let Some(cells) = node.get_u32_array_prop("reg") {
                    if cells.len() >= 2 {
                        let base = cells[0] as u64;
                        let size = cells[1] as u64;
                        memory_ranges.push(MemoryRange { base, size });
                    }
                }
            }
        }

        // 2. UART Serial Consoles
        let mut uart_consoles = Vec::new();
        for node in &all_nodes {
            let compats = node.get_string_list_prop("compatible").unwrap_or_default();
            let is_uart = compats.iter().any(|c| {
                let lower = c.to_lowercase();
                lower.contains("uart")
                    || lower.contains("serial")
                    || lower.contains("ns16550")
                    || lower.contains("pl011")
                    || lower.contains("8250")
            }) || node.name.starts_with("serial@")
                || node.name.starts_with("uart@");

            if is_uart {
                let cells = node.get_u32_array_prop("reg");
                let base = cells.as_ref().and_then(|c| c.first().map(|&v| v as u64));
                let reg_size = cells.as_ref().and_then(|c| c.get(1).map(|&v| v as u64));
                let interrupts = node.get_u32_array_prop("interrupts");
                let clock_freq = node.get_u32_prop("clock-frequency").map(|v| v as u64);

                let is_active = stdout_path
                    .as_ref()
                    .map(|s| s.contains(&node.name))
                    .unwrap_or(false)
                    || bootargs
                        .as_ref()
                        .map(|b| b.contains("console="))
                        .unwrap_or(false);

                uart_consoles.push(UartConsole {
                    node_name: node.name.clone(),
                    compatible: compats,
                    base_address: base,
                    reg_size,
                    interrupts,
                    clock_frequency: clock_freq,
                    is_active_console: is_active,
                });
            }
        }

        // 3. Flash MTD Partitions
        let mut flash_partitions = Vec::new();
        for node in &all_nodes {
            let is_part = node.name.starts_with("partition@")
                || node.has_prop("label") && node.has_prop("reg");

            if is_part {
                if let Some(cells) = node.get_u32_array_prop("reg") {
                    if cells.len() >= 2 {
                        let offset = cells[0] as u64;
                        let size = cells[1] as u64;
                        let label = node
                            .get_string_prop("label")
                            .unwrap_or_else(|| node.name.clone());
                        let read_only = node.has_prop("read-only");

                        flash_partitions.push(FlashPartition {
                            node_name: node.name.clone(),
                            label,
                            offset,
                            size,
                            read_only,
                        });
                    }
                }
            }
        }
        flash_partitions.sort_by_key(|p| p.offset);

        // 4. Network Interfaces
        let mut network_interfaces = Vec::new();
        for node in &all_nodes {
            let compats = node.get_string_list_prop("compatible").unwrap_or_default();
            let has_mac = node.find_property("local-mac-address").is_some()
                || node.find_property("mac-address").is_some();
            let is_net = has_mac
                || compats.iter().any(|c| {
                    let lower = c.to_lowercase();
                    lower.contains("ethernet")
                        || lower.contains("gmac")
                        || lower.contains("edma")
                        || lower.contains("switch")
                })
                || node.name.starts_with("ethernet@")
                || node.name.starts_with("switch@");

            if is_net {
                let mac_prop = node
                    .find_property("local-mac-address")
                    .or_else(|| node.find_property("mac-address"));

                let mac_address = mac_prop.and_then(|p| {
                    if p.data.len() == 6 {
                        Some(format!(
                            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                            p.data[0], p.data[1], p.data[2], p.data[3], p.data[4], p.data[5]
                        ))
                    } else {
                        None
                    }
                });

                let phy_mode = node.get_string_prop("phy-mode");

                network_interfaces.push(NetworkInterface {
                    node_name: node.name.clone(),
                    compatible: compats,
                    mac_address,
                    phy_mode,
                });
            }
        }

        // 5. CPUs
        let mut cpus = Vec::new();
        if let Some(cpus_node) = root.find_child("cpus") {
            for cpu in &cpus_node.children {
                let compat = cpu.get_string_prop("compatible");
                let clock_freq = cpu.get_u32_prop("clock-frequency").map(|v| v as u64);
                cpus.push(CpuCore {
                    name: cpu.name.clone(),
                    compatible: compat,
                    clock_frequency: clock_freq,
                });
            }
        }

        Self {
            model,
            compatible,
            bootargs,
            stdout_path,
            memory_reservations: reservations.to_vec(),
            memory_ranges,
            uart_consoles,
            flash_partitions,
            network_interfaces,
            cpus,
        }
    }

    /// Formats peripheral mapping as an engineer-friendly textual summary.
    pub fn format_summary(&self) -> String {
        let mut out = String::new();
        out.push_str("=== FirmCarver Hardware Peripheral Map ===\n");
        if let Some(m) = &self.model {
            out.push_str(&format!("  Board Model:         {}\n", m));
        }
        if !self.compatible.is_empty() {
            out.push_str(&format!(
                "  Board Compatible:    {}\n",
                self.compatible.join(", ")
            ));
        }
        if let Some(b) = &self.bootargs {
            out.push_str(&format!("  Boot Arguments:      {}\n", b));
        }
        if let Some(s) = &self.stdout_path {
            out.push_str(&format!("  Stdout Console:      {}\n", s));
        }

        // Memory
        out.push_str("\n[RAM & Memory Map]\n");
        if self.memory_ranges.is_empty() {
            out.push_str("  No explicit memory@... ranges found.\n");
        } else {
            for (i, m) in self.memory_ranges.iter().enumerate() {
                let mb = m.size / (1024 * 1024);
                out.push_str(&format!(
                    "  Range #{}:          0x{:08X} - 0x{:08X} ({} MB)\n",
                    i + 1,
                    m.base,
                    m.base + m.size,
                    mb
                ));
            }
        }
        for (i, r) in self.memory_reservations.iter().enumerate() {
            let kb = r.size / 1024;
            out.push_str(&format!(
                "  Reservation #{}:    0x{:08X} - 0x{:08X} ({} KB)\n",
                i + 1,
                r.address,
                r.address + r.size,
                kb
            ));
        }

        // UART
        out.push_str("\n[UART Serial Consoles]\n");
        if self.uart_consoles.is_empty() {
            out.push_str("  No serial console controllers detected.\n");
        } else {
            for u in &self.uart_consoles {
                let active = if u.is_active_console {
                    " (Active Console)"
                } else {
                    ""
                };
                let base_str = u
                    .base_address
                    .map(|b| format!("0x{:08X}", b))
                    .unwrap_or_else(|| "N/A".into());
                let size_str = u
                    .reg_size
                    .map(|s| format!("0x{:X}", s))
                    .unwrap_or_else(|| "N/A".into());
                out.push_str(&format!(
                    "  {:<18} Base: {}, Size: {}{}\n",
                    u.node_name, base_str, size_str, active
                ));
                if !u.compatible.is_empty() {
                    out.push_str(&format!(
                        "                     Driver: {}\n",
                        u.compatible.join(", ")
                    ));
                }
            }
        }

        // Flash Partitions
        out.push_str("\n[Flash MTD Partitions]\n");
        if self.flash_partitions.is_empty() {
            out.push_str("  No fixed-partitions tables detected.\n");
        } else {
            out.push_str("  Offset       Size         Label                Flags\n");
            out.push_str("  ----------------------------------------------------------\n");
            for p in &self.flash_partitions {
                let flags = if p.read_only {
                    "[read-only]"
                } else {
                    "[read-write]"
                };
                out.push_str(&format!(
                    "  0x{:08X}   0x{:08X}   {:<20} {}\n",
                    p.offset, p.size, p.label, flags
                ));
            }
        }

        // Network
        out.push_str("\n[Network Interfaces]\n");
        if self.network_interfaces.is_empty() {
            out.push_str("  No network interfaces detected.\n");
        } else {
            for net in &self.network_interfaces {
                let mac = net.mac_address.as_deref().unwrap_or("Dynamic / Unset");
                let phy = net.phy_mode.as_deref().unwrap_or("Standard");
                out.push_str(&format!(
                    "  {:<18} MAC: {}, PHY: {}\n",
                    net.node_name, mac, phy
                ));
                if !net.compatible.is_empty() {
                    out.push_str(&format!(
                        "                     Driver: {}\n",
                        net.compatible.join(", ")
                    ));
                }
            }
        }

        // CPUs
        if !self.cpus.is_empty() {
            out.push_str("\n[CPU Cores]\n");
            for cpu in &self.cpus {
                let freq = cpu
                    .clock_frequency
                    .map(|f| format!(" ({} MHz)", f / 1_000_000))
                    .unwrap_or_default();
                let comp = cpu.compatible.as_deref().unwrap_or("Generic");
                out.push_str(&format!(
                    "  {:<10} Architecture: {}{}\n",
                    cpu.name, comp, freq
                ));
            }
        }

        out
    }
}
