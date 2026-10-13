// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::scoring::Architecture;
use serde::{Deserialize, Serialize};

/// High-level categorization of suspicious shellcode and exploit primitives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShellcodeCategory {
    /// Interactive or spawned shell payload (/bin/sh, /bin/busybox, etc.)
    ExecveSyscall,
    /// NOP sled sequence preceding an exploit payload
    NopSled,
    /// Function prologue or stack frame pivot
    StackPivot,
    /// Plaintext or XOR-encoded command shell string
    ShellString,
    /// Network socket connection setup (reverse shell)
    NetworkSocket,
}

/// Severity classification for discovered shellcode indicators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShellcodeSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// Detailed metadata describing a discovered shellcode pattern or exploit primitive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellcodeFinding {
    pub offset: usize,
    pub architecture: Architecture,
    pub category: ShellcodeCategory,
    pub severity: ShellcodeSeverity,
    pub title: String,
    pub description: String,
    pub evidence: String,
}

/// Scans raw binary payload for shellcode signatures, NOP sleds, and execve invocations.
pub fn detect_shellcode_patterns(
    data: &[u8],
    base_offset: usize,
    primary_arch: Option<Architecture>,
) -> Vec<ShellcodeFinding> {
    let mut findings = Vec::new();
    if data.is_empty() {
        return findings;
    }

    // 1. Scan for embedded shell strings (/bin/sh, /bin/busybox, /bin/ash)
    scan_shell_strings(data, base_offset, primary_arch, &mut findings);

    // 2. Scan for NOP sled sequences
    scan_nop_sleds(data, base_offset, primary_arch, &mut findings);

    // 3. Scan for architecture-specific Linux execve syscall sequences
    scan_execve_syscalls(data, base_offset, primary_arch, &mut findings);

    findings.sort_by_key(|f| f.offset);
    findings
}

fn scan_shell_strings(
    data: &[u8],
    base_offset: usize,
    primary_arch: Option<Architecture>,
    findings: &mut Vec<ShellcodeFinding>,
) {
    let targets = [
        (
            b"/bin/sh" as &[u8],
            "Embedded '/bin/sh' Shell String Reference",
        ),
        (
            b"/bin/busybox",
            "Embedded '/bin/busybox' Shell Binary Reference",
        ),
        (b"/bin/ash", "Embedded '/bin/ash' Almquist Shell Reference"),
        (
            b"nc -e /bin/sh",
            "Reverse Shell Command Invocation in Payload",
        ),
    ];

    let arch = primary_arch.unwrap_or(Architecture::MipsEb);

    for (needle, title) in targets {
        let mut i = 0;
        while i + needle.len() <= data.len() {
            if &data[i..i + needle.len()] == needle {
                let text = String::from_utf8_lossy(needle).to_string();
                findings.push(ShellcodeFinding {
                    offset: base_offset + i,
                    architecture: arch,
                    category: ShellcodeCategory::ShellString,
                    severity: ShellcodeSeverity::High,
                    title: title.to_string(),
                    description: format!(
                        "Binary contains raw shell string '{}' commonly loaded into registers for execve()",
                        text
                    ),
                    evidence: text,
                });
                i += needle.len();
            } else {
                i += 1;
            }
        }
    }
}

fn scan_nop_sleds(
    data: &[u8],
    base_offset: usize,
    _primary_arch: Option<Architecture>,
    findings: &mut Vec<ShellcodeFinding>,
) {
    // 4 consecutive NOPs (16 bytes for 32-bit RISC, 8 bytes for x86)
    let patterns = [
        (
            &[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ][..],
            Architecture::MipsEb,
            "MIPS NOP Sled (16+ zero bytes)",
        ),
        (
            &[
                0x00, 0x00, 0xA0, 0xE1, 0x00, 0x00, 0xA0, 0xE1, 0x00, 0x00, 0xA0, 0xE1, 0x00, 0x00,
                0xA0, 0xE1,
            ][..],
            Architecture::ArmV7,
            "ARMv7 'mov r0, r0' NOP Sled",
        ),
        (
            &[
                0x1F, 0x20, 0x03, 0xD5, 0x1F, 0x20, 0x03, 0xD5, 0x1F, 0x20, 0x03, 0xD5, 0x1F, 0x20,
                0x03, 0xD5,
            ][..],
            Architecture::AArch64,
            "AArch64 'nop' Instruction Sled",
        ),
        (
            &[
                0x13, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x13, 0x00,
                0x00, 0x00,
            ][..],
            Architecture::RiscV32,
            "RISC-V 'addi x0, x0, 0' NOP Sled",
        ),
    ];

    for (needle, arch, title) in patterns {
        let mut i = 0;
        while i + needle.len() <= data.len() {
            if &data[i..i + needle.len()] == needle {
                findings.push(ShellcodeFinding {
                    offset: base_offset + i,
                    architecture: arch,
                    category: ShellcodeCategory::NopSled,
                    severity: ShellcodeSeverity::Medium,
                    title: title.to_string(),
                    description: format!(
                        "Detected consecutive sequence of {} NOP instructions typical of exploit landing pads",
                        needle.len() / 4
                    ),
                    evidence: hex::encode(needle),
                });
                i += needle.len();
            } else {
                i += 4;
            }
        }
    }
}

fn scan_execve_syscalls(
    data: &[u8],
    base_offset: usize,
    _primary_arch: Option<Architecture>,
    findings: &mut Vec<ShellcodeFinding>,
) {
    if data.len() < 8 {
        return;
    }

    // 1. MIPS-EB Linux execve (4011): 0x24020FA7 (li $v0, 4011) near 0x0000000C (syscall)
    // 2. MIPS-EL Linux execve (4011): 0xA70F0224 near 0x0C000000
    // 3. ARMv7 Linux execve (11): 0xE3A0700B (mov r7, #11) near 0xEF000000 (svc 0)
    // 4. AArch64 Linux execve (221): 0xD2801BA8 (mov x8, #221) near 0xD4000001 (svc #0)
    // 5. RISC-V Linux execve (221): 0x0DD00893 (li a7, 221) near 0x00000073 (ecall)

    let window_size = 32;

    for i in (0..data.len().saturating_sub(4)).step_by(4) {
        let chunk4 = &data[i..i + 4];

        // MIPS-EB: li $v0, 4011 -> 24 02 0F A7
        if chunk4 == [0x24, 0x02, 0x0F, 0xA7]
            && has_subsequence(
                &data[i..data.len().min(i + window_size)],
                &[0x00, 0x00, 0x00, 0x0C],
            )
        {
            findings.push(ShellcodeFinding {
                offset: base_offset + i,
                architecture: Architecture::MipsEb,
                category: ShellcodeCategory::ExecveSyscall,
                severity: ShellcodeSeverity::Critical,
                title: "MIPS-32 (EB) Linux sys_execve (4011) Shellcode Sequence".to_string(),
                description: "Instruction sequence prepares register $v0 with syscall 4011 (sys_execve) followed by syscall".to_string(),
                evidence: "li $v0, 4011; ...; syscall".to_string(),
            });
        }

        // MIPS-EL: li $v0, 4011 -> A7 0F 02 24
        if chunk4 == [0xA7, 0x0F, 0x02, 0x24]
            && has_subsequence(
                &data[i..data.len().min(i + window_size)],
                &[0x0C, 0x00, 0x00, 0x00],
            )
        {
            findings.push(ShellcodeFinding {
                offset: base_offset + i,
                architecture: Architecture::MipsEl,
                category: ShellcodeCategory::ExecveSyscall,
                severity: ShellcodeSeverity::Critical,
                title: "MIPS-32 (EL) Linux sys_execve (4011) Shellcode Sequence".to_string(),
                description: "Instruction sequence prepares register $v0 with syscall 4011 (sys_execve) followed by syscall".to_string(),
                evidence: "li $v0, 4011; ...; syscall".to_string(),
            });
        }

        // ARMv7: mov r7, #11 -> 0B 70 A0 E3
        if chunk4 == [0x0B, 0x70, 0xA0, 0xE3]
            && has_subsequence(
                &data[i..data.len().min(i + window_size)],
                &[0x00, 0x00, 0x00, 0xEF],
            )
        {
            findings.push(ShellcodeFinding {
                offset: base_offset + i,
                architecture: Architecture::ArmV7,
                category: ShellcodeCategory::ExecveSyscall,
                severity: ShellcodeSeverity::Critical,
                title: "ARMv7 Linux sys_execve (#11) Shellcode Sequence".to_string(),
                description: "Instruction sequence prepares register r7 with syscall 11 (sys_execve) followed by svc 0".to_string(),
                evidence: "mov r7, #11; ...; svc #0".to_string(),
            });
        }

        // AArch64: mov x8, #221 -> A8 1B 80 D2
        if chunk4 == [0xA8, 0x1B, 0x80, 0xD2]
            && has_subsequence(
                &data[i..data.len().min(i + window_size)],
                &[0x01, 0x00, 0x00, 0xD4],
            )
        {
            findings.push(ShellcodeFinding {
                offset: base_offset + i,
                architecture: Architecture::AArch64,
                category: ShellcodeCategory::ExecveSyscall,
                severity: ShellcodeSeverity::Critical,
                title: "AArch64 Linux sys_execve (#221) Shellcode Sequence".to_string(),
                description:
                    "Instruction sequence loads register x8 with syscall 221 followed by svc #0"
                        .to_string(),
                evidence: "mov x8, #221; ...; svc #0".to_string(),
            });
        }

        // RISC-V: addi a7, zero, 221 -> 93 08 D0 0D
        if chunk4 == [0x93, 0x08, 0xD0, 0x0D]
            && has_subsequence(
                &data[i..data.len().min(i + window_size)],
                &[0x73, 0x00, 0x00, 0x00],
            )
        {
            findings.push(ShellcodeFinding {
                offset: base_offset + i,
                architecture: Architecture::RiscV32,
                category: ShellcodeCategory::ExecveSyscall,
                severity: ShellcodeSeverity::Critical,
                title: "RISC-V Linux sys_execve (#221) Shellcode Sequence".to_string(),
                description: "Instruction loads register a7 with syscall 221 followed by ecall"
                    .to_string(),
                evidence: "li a7, 221; ...; ecall".to_string(),
            });
        }
    }
}

fn has_subsequence(data: &[u8], sub: &[u8]) -> bool {
    if sub.len() > data.len() {
        return false;
    }
    for i in (0..=data.len() - sub.len()).step_by(4) {
        if &data[i..i + sub.len()] == sub {
            return true;
        }
    }
    false
}
