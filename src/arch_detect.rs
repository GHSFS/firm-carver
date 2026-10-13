// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

pub mod disasm;
pub mod scoring;
pub mod shellcode;
pub mod synth;

pub use disasm::{disassemble_chunk, DecodedInsn};
pub use scoring::{analyze_architecture_distribution, ArchScore, Architecture};
pub use shellcode::{
    detect_shellcode_patterns, ShellcodeCategory, ShellcodeFinding, ShellcodeSeverity,
};
pub use synth::{build_synthetic_shellcode, ShellcodeVariant};

use serde::{Deserialize, Serialize};

/// High-level audit report containing architecture identification and shellcode detections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchAuditReport {
    /// Target file name or stream identifier
    pub target_file: String,
    /// Byte offset within the container or raw binary
    pub scan_offset: usize,
    /// Scanned payload length in bytes
    pub scan_size: usize,
    /// Top detected architecture by confidence score
    pub primary_arch: Option<Architecture>,
    /// Primary architecture confidence score (0.0 to 1.0)
    pub primary_confidence: f64,
    /// Scored candidate architectures sorted by confidence descending
    pub candidates: Vec<ArchScore>,
    /// Suspicious shellcode, NOP sled, or backdoor payload detections
    pub shellcode_findings: Vec<ShellcodeFinding>,
    /// Sample disassembled instructions around entry or key offsets
    pub sample_disasm: Vec<DecodedInsn>,
}

/// Static cross-architecture shellcode detector and instruction stream analyzer.
#[derive(Debug, Default, Clone)]
pub struct ArchDetector {
    /// Minimum confidence threshold for architecture classification (0.0 to 1.0)
    pub min_confidence: f64,
}

impl ArchDetector {
    /// Creates a new detector with standard default heuristics.
    pub fn new() -> Self {
        Self {
            min_confidence: 0.30,
        }
    }

    /// Analyzes a slice of raw uncompressed machine code.
    pub fn analyze(&self, data: &[u8], target_file: &str, scan_offset: usize) -> ArchAuditReport {
        let scan_size = data.len();
        let scores = analyze_architecture_distribution(data);

        let primary = scores.first().cloned();
        let (primary_arch, primary_confidence) = match &primary {
            Some(score) if score.confidence >= self.min_confidence => {
                (Some(score.arch), score.confidence)
            }
            _ => (None, 0.0),
        };

        let target_arch = primary_arch.unwrap_or(Architecture::MipsEb);
        let shellcode_findings = detect_shellcode_patterns(data, scan_offset, primary_arch);
        let sample_disasm = disassemble_chunk(data, target_arch, 0, 16);

        ArchAuditReport {
            target_file: target_file.to_string(),
            scan_offset,
            scan_size,
            primary_arch,
            primary_confidence,
            candidates: scores,
            shellcode_findings,
            sample_disasm,
        }
    }
}

/// Formats the audit report into a clean, human-readable terminal summary.
pub fn format_arch_report(report: &ArchAuditReport) -> String {
    use std::fmt::Write;
    let mut out = String::new();

    let _ = writeln!(out, "=== FirmCarver Architecture & Shellcode Auditor ===");
    let _ = writeln!(
        out,
        "Target Stream:   {} (offset: 0x{:08X})",
        report.target_file, report.scan_offset
    );
    let _ = writeln!(out, "Analyzed Size:   {} bytes", report.scan_size);

    match report.primary_arch {
        Some(arch) => {
            let pct = (report.primary_confidence * 100.0).round();
            let _ = writeln!(
                out,
                "Identified Arch: {} (Confidence: {:.1}%)\n",
                arch.name(),
                pct
            );
        }
        None => {
            let _ = writeln!(out, "Identified Arch: Indeterminate / Mixed Bytecode\n");
        }
    }

    let _ = writeln!(out, "Architecture Candidate Distribution:");
    let _ = writeln!(
        out,
        "  Architecture                  Score   Valid%   Branches  Prologue/Epilogue  Syscalls"
    );
    let _ = writeln!(
        out,
        "  ------------------------------------------------------------------------------------"
    );
    for s in &report.candidates {
        let _ = writeln!(
            out,
            "  {:<30} {:>5.1}%  {:>5.1}%   {:>8}  {:>8}/{:<8}  {:>8}",
            s.arch.name(),
            s.confidence * 100.0,
            s.valid_ratio * 100.0,
            s.branch_count,
            s.prologue_count,
            s.epilogue_count,
            s.syscall_count
        );
    }

    let _ = writeln!(
        out,
        "\nShellcode & Exploit Payload Findings: {}",
        report.shellcode_findings.len()
    );
    if report.shellcode_findings.is_empty() {
        let _ = writeln!(
            out,
            "  No overt shellcode sequences, NOP sleds, or interactive payloads detected."
        );
    } else {
        for (idx, f) in report.shellcode_findings.iter().enumerate() {
            let sev = match f.severity {
                ShellcodeSeverity::Critical => "[CRITICAL]",
                ShellcodeSeverity::High => "[HIGH]    ",
                ShellcodeSeverity::Medium => "[MEDIUM]  ",
                ShellcodeSeverity::Low => "[LOW]     ",
            };
            let _ = writeln!(
                out,
                "  #{:02} {} at offset 0x{:08X}: {}",
                idx + 1,
                sev,
                f.offset,
                f.title
            );
            let _ = writeln!(
                out,
                "       Category:    {:?} ({})",
                f.category,
                f.architecture.name()
            );
            let _ = writeln!(out, "       Evidence:    \"{}\"", f.evidence);
            let _ = writeln!(out, "       Description: {}", f.description);
        }
    }

    if !report.sample_disasm.is_empty() {
        let _ = writeln!(
            out,
            "\nSample Disassembly Stream ({} instructions):",
            report.sample_disasm.len()
        );
        for insn in &report.sample_disasm {
            let _ = writeln!(
                out,
                "  0x{:08X}: {:<10} {:<10} {}",
                insn.offset, insn.raw_hex, insn.mnemonic, insn.operands
            );
        }
    }

    out
}
