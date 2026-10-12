// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::error::{CarverError, Result};
use serde::{Deserialize, Serialize};

pub const FDT_BEGIN_NODE: u32 = 0x0000_0001;
pub const FDT_END_NODE: u32 = 0x0000_0002;
pub const FDT_PROP: u32 = 0x0000_0003;
pub const FDT_NOP: u32 = 0x0000_0004;
pub const FDT_END: u32 = 0x0000_0009;

/// An individual property inside an FDT node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FdtProperty {
    pub name: String,
    pub data: Vec<u8>,
}

impl FdtProperty {
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Checks if data represents a valid printable null-terminated UTF-8 string.
    pub fn as_string(&self) -> Option<&str> {
        if self.data.is_empty() || *self.data.last()? != 0 {
            return None;
        }
        let without_null = &self.data[..self.data.len() - 1];
        if without_null.contains(&0) {
            return None;
        }
        std::str::from_utf8(without_null).ok()
    }

    /// Checks if data represents one or more null-terminated strings.
    pub fn as_string_list(&self) -> Option<Vec<String>> {
        if self.data.is_empty() || *self.data.last()? != 0 {
            return None;
        }
        let mut list = Vec::new();
        let mut start = 0;
        for (i, &b) in self.data.iter().enumerate() {
            if b == 0 {
                let s = std::str::from_utf8(&self.data[start..i]).ok()?;
                // In DTS string lists, elements cannot be empty strings
                if s.is_empty()
                    || s.chars()
                        .any(|c| (c.is_control() && c != '\t' && c != '\n') || !c.is_ascii())
                {
                    return None;
                }
                list.push(s.to_string());
                start = i + 1;
            }
        }
        if list.is_empty() {
            None
        } else {
            Some(list)
        }
    }

    /// Reads data as an array of big-endian 32-bit cells.
    pub fn as_u32_slice(&self) -> Option<Vec<u32>> {
        if self.data.is_empty() || self.data.len() % 4 != 0 {
            return None;
        }
        let mut cells = Vec::with_capacity(self.data.len() / 4);
        for chunk in self.data.chunks_exact(4) {
            cells.push(u32::from_be_bytes(chunk.try_into().ok()?));
        }
        Some(cells)
    }

    /// Formats the property value for DTS source syntax output.
    pub fn format_dts_value(&self) -> String {
        if self.is_empty() {
            return String::new();
        }

        // Dedicated check for properties that are always cell arrays in Devicetree spec
        let is_cell_property = self.name.starts_with('#')
            || self.name.ends_with("-cells")
            || self.name.ends_with("-frequency")
            || self.name == "reg"
            || self.name == "interrupts"
            || self.name == "interrupt-parent"
            || self.name == "clocks";

        if is_cell_property {
            if let Some(cells) = self.as_u32_slice() {
                let formatted: Vec<String> = cells
                    .iter()
                    .map(|c| {
                        if *c < 10 {
                            format!("{}", c)
                        } else {
                            format!("0x{:x}", c)
                        }
                    })
                    .collect();
                return format!("<{}>", formatted.join(" "));
            }
        }

        // Check for MAC address format (6 bytes)
        if self.data.len() == 6 && self.name.contains("mac") {
            let hex_bytes: Vec<String> = self.data.iter().map(|b| format!("{:02x}", b)).collect();
            return format!("[{}]", hex_bytes.join(" "));
        }

        // Check if property is valid string or string list
        if let Some(strs) = self.as_string_list() {
            let formatted: Vec<String> = strs.iter().map(|s| format!("\"{}\"", s)).collect();
            return formatted.join(", ");
        }

        // Check for generic 32-bit cell array
        if let Some(cells) = self.as_u32_slice() {
            let formatted: Vec<String> = cells
                .iter()
                .map(|c| {
                    if *c < 10 {
                        format!("{}", c)
                    } else {
                        format!("0x{:x}", c)
                    }
                })
                .collect();
            return format!("<{}>", formatted.join(" "));
        }

        // Fallback to byte array
        let hex_bytes: Vec<String> = self.data.iter().map(|b| format!("{:02x}", b)).collect();
        format!("[{}]", hex_bytes.join(" "))
    }
}

/// A node in the Flattened Device Tree hierarchy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FdtNode {
    pub name: String,
    pub unit_address: Option<String>,
    pub properties: Vec<FdtProperty>,
    pub children: Vec<FdtNode>,
}

impl FdtNode {
    pub fn new(name: String) -> Self {
        let unit_address = name.split_once('@').map(|(_, addr)| addr.to_string());
        Self {
            name,
            unit_address,
            properties: Vec::new(),
            children: Vec::new(),
        }
    }

    pub fn find_property(&self, name: &str) -> Option<&FdtProperty> {
        self.properties.iter().find(|p| p.name == name)
    }

    pub fn has_prop(&self, name: &str) -> bool {
        self.find_property(name).is_some()
    }

    pub fn get_string_prop(&self, name: &str) -> Option<String> {
        self.find_property(name)?.as_string().map(|s| s.to_string())
    }

    pub fn get_string_list_prop(&self, name: &str) -> Option<Vec<String>> {
        self.find_property(name)?.as_string_list()
    }

    pub fn get_u32_array_prop(&self, name: &str) -> Option<Vec<u32>> {
        self.find_property(name)?.as_u32_slice()
    }

    pub fn get_u32_prop(&self, name: &str) -> Option<u32> {
        self.get_u32_array_prop(name)?.first().copied()
    }

    pub fn find_child(&self, name: &str) -> Option<&FdtNode> {
        self.children.iter().find(|c| c.name == name)
    }

    /// Recursively collects all nodes matching a predicate.
    pub fn collect_matching<'a, F>(&'a self, predicate: &F, out: &mut Vec<&'a FdtNode>)
    where
        F: Fn(&FdtNode) -> bool,
    {
        if predicate(self) {
            out.push(self);
        }
        for child in &self.children {
            child.collect_matching(predicate, out);
        }
    }

    /// Formats this node and all descendants as clean DTS output.
    pub fn format_dts(&self, indent_level: usize) -> String {
        let indent = "    ".repeat(indent_level);
        let node_display_name = if self.name.is_empty() {
            "/"
        } else {
            &self.name
        };

        let mut out = format!("{}{} {{\n", indent, node_display_name);

        for prop in &self.properties {
            let val = prop.format_dts_value();
            if val.is_empty() {
                out.push_str(&format!("{}    {};\n", indent, prop.name));
            } else {
                out.push_str(&format!("{}    {} = {};\n", indent, prop.name, val));
            }
        }

        if !self.properties.is_empty() && !self.children.is_empty() {
            out.push('\n');
        }

        for child in &self.children {
            out.push_str(&child.format_dts(indent_level + 1));
        }

        out.push_str(&format!("{}}};\n", indent));
        out
    }
}

/// Helper to align an offset to 4-byte boundary.
#[inline]
pub fn align_4(offset: usize) -> usize {
    (offset + 3) & !3
}

/// Parses the structure block into a hierarchical FdtNode tree.
pub fn parse_structure_tree(
    data: &[u8],
    off_struct: usize,
    off_strings: usize,
    totalsize: usize,
) -> Result<FdtNode> {
    let max_len = totalsize.min(data.len());
    let mut cursor = off_struct;

    let mut stack: Vec<FdtNode> = Vec::new();
    let mut root: Option<FdtNode> = None;
    let mut nodes_count = 0;

    while cursor + 4 <= max_len {
        let token = u32::from_be_bytes(
            data[cursor..cursor + 4]
                .try_into()
                .map_err(|_| CarverError::Fdt("Failed reading FDT token".into()))?,
        );
        cursor += 4;

        match token {
            FDT_BEGIN_NODE => {
                nodes_count += 1;
                if nodes_count > 10_000 {
                    return Err(CarverError::Fdt("Exceeded max node limit (10000)".into()));
                }

                // Read null-terminated node name
                let name_start = cursor;
                let mut name_end = name_start;
                while name_end < max_len && data[name_end] != 0 {
                    name_end += 1;
                }
                if name_end >= max_len {
                    return Err(CarverError::Fdt("Unterminated node name string".into()));
                }

                let name = String::from_utf8_lossy(&data[name_start..name_end]).to_string();
                cursor = align_4(name_end + 1);

                let node = FdtNode::new(name);
                stack.push(node);
            }
            FDT_END_NODE => {
                if let Some(finished_node) = stack.pop() {
                    if let Some(parent) = stack.last_mut() {
                        parent.children.push(finished_node);
                    } else {
                        root = Some(finished_node);
                    }
                } else {
                    return Err(CarverError::Fdt("Unbalanced FDT_END_NODE token".into()));
                }
            }
            FDT_PROP => {
                if cursor + 8 > max_len {
                    return Err(CarverError::Fdt("Truncated FDT_PROP token".into()));
                }
                let prop_len = u32::from_be_bytes(
                    data[cursor..cursor + 4]
                        .try_into()
                        .map_err(|_| CarverError::Fdt("Failed reading prop length".into()))?,
                ) as usize;
                let nameoff = u32::from_be_bytes(
                    data[cursor + 4..cursor + 8]
                        .try_into()
                        .map_err(|_| CarverError::Fdt("Failed reading prop nameoff".into()))?,
                ) as usize;
                cursor += 8;

                if cursor + prop_len > max_len {
                    return Err(CarverError::Fdt(
                        "Property length exceeds FDT boundary".into(),
                    ));
                }

                let prop_data = data[cursor..cursor + prop_len].to_vec();
                cursor = align_4(cursor + prop_len);

                // Resolve property name from strings block
                let str_start = off_strings + nameoff;
                if str_start >= max_len {
                    return Err(CarverError::Fdt(
                        "Property name offset exceeds FDT size".into(),
                    ));
                }
                let mut str_end = str_start;
                while str_end < max_len && data[str_end] != 0 {
                    str_end += 1;
                }
                let prop_name = String::from_utf8_lossy(&data[str_start..str_end]).to_string();

                if let Some(current_node) = stack.last_mut() {
                    current_node.properties.push(FdtProperty {
                        name: prop_name,
                        data: prop_data,
                    });
                }
            }
            FDT_NOP => {
                // No operation, advance to next token
            }
            FDT_END => {
                break;
            }
            unknown => {
                return Err(CarverError::Fdt(format!(
                    "Unknown or corrupted FDT token 0x{:08X} at offset 0x{:X}",
                    unknown,
                    cursor - 4
                )));
            }
        }
    }

    root.ok_or_else(|| CarverError::Fdt("No root node parsed from FDT structure block".into()))
}
