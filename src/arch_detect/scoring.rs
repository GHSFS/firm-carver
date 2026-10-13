// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use serde::{Deserialize, Serialize};

/// Supported CPU architectures for machine code detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Architecture {
    /// MIPS 32-bit Big-Endian (common in older Atheros, Broadcom, Realtek routers)
    MipsEb,
    /// MIPS 32-bit Little-Endian (common in MediaTek, Ralink SoC firmware)
    MipsEl,
    /// ARMv7 / 32-bit ARM (Cortex-A7/A9/A15 router SoCs, IoT gateways)
    ArmV7,
    /// ARM Thumb / Thumb-2 (Cortex-M microcontrollers, space-constrained payloads)
    Thumb,
    /// AArch64 / ARM 64-bit (modern router Wi-Fi 6/7 SoCs, automotive ECUs)
    AArch64,
    /// RISC-V 32-bit (RV32)
    RiscV32,
    /// RISC-V 64-bit (RV64)
    RiscV64,
}

impl Architecture {
    /// Human-friendly name of the instruction set.
    pub fn name(&self) -> &'static str {
        match self {
            Self::MipsEb => "MIPS-32 (Big-Endian)",
            Self::MipsEl => "MIPS-32 (Little-Endian)",
            Self::ArmV7 => "ARMv7 (32-bit)",
            Self::Thumb => "ARM Thumb-2",
            Self::AArch64 => "AArch64 (ARM 64-bit)",
            Self::RiscV32 => "RISC-V (RV32)",
            Self::RiscV64 => "RISC-V (RV64)",
        }
    }
}

/// Detailed evaluation metrics and confidence score for a candidate architecture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchScore {
    pub arch: Architecture,
    pub confidence: f64,
    pub valid_insn_count: usize,
    pub total_insn_count: usize,
    pub valid_ratio: f64,
    pub branch_count: usize,
    pub prologue_count: usize,
    pub epilogue_count: usize,
    pub syscall_count: usize,
    pub nop_count: usize,
}

#[derive(Default)]
struct InsnCounts {
    valid: usize,
    total: usize,
    branches: usize,
    prologues: usize,
    epilogues: usize,
    syscalls: usize,
    nops: usize,
}

/// Evaluates raw bytecode against all supported architectures and ranks them.
pub fn analyze_architecture_distribution(data: &[u8]) -> Vec<ArchScore> {
    if data.len() < 4 {
        return Vec::new();
    }

    let mut scores = vec![
        score_mips(data, true),
        score_mips(data, false),
        score_armv7(data),
        score_thumb(data),
        score_aarch64(data),
        score_riscv(data, false),
        score_riscv(data, true),
    ];

    scores.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    scores
}

fn score_mips(data: &[u8], big_endian: bool) -> ArchScore {
    let mut c = InsnCounts {
        total: data.len() / 4,
        ..Default::default()
    };

    for chunk in data.chunks_exact(4) {
        let w = if big_endian {
            u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
        } else {
            u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
        };

        if w == 0 {
            c.nops += 1;
            c.valid += 1;
            continue;
        }

        let op = w >> 26;
        let rs = (w >> 21) & 0x1F;
        let rt = (w >> 16) & 0x1F;
        let funct = w & 0x3F;

        let is_valid = match op {
            0 => {
                if funct == 12 {
                    c.syscalls += 1;
                    true
                } else if funct == 8 && rs == 31 {
                    c.epilogues += 1; // jr $ra
                    c.branches += 1;
                    true
                } else if funct == 9 {
                    c.branches += 1; // jalr
                    true
                } else {
                    matches!(funct, 0..=4 | 6..=7 | 10..=11 | 13..=27 | 32..=43)
                }
            }
            1 => {
                c.branches += 1;
                matches!(rt, 0 | 1 | 16 | 17)
            }
            2 | 3 => {
                c.branches += 1;
                true
            }
            4..=7 => {
                c.branches += 1;
                true
            }
            8 | 9 => {
                if op == 9 && rs == 29 && rt == 29 && (w as i16) < 0 {
                    c.prologues += 1;
                }
                true
            }
            10..=15 => true,
            32..=43 => true,
            _ => false,
        };

        if is_valid {
            c.valid += 1;
        }
    }

    let arch = if big_endian {
        Architecture::MipsEb
    } else {
        Architecture::MipsEl
    };
    compute_score(arch, &c)
}

fn score_armv7(data: &[u8]) -> ArchScore {
    let mut c = InsnCounts {
        total: data.len() / 4,
        ..Default::default()
    };

    for chunk in data.chunks_exact(4) {
        let w = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let cond = w >> 28;

        if cond == 0xE && (w & 0x0FFFFFFF == 0x01A00000 || w & 0x0FFF0000 == 0x03200000) {
            c.nops += 1;
            c.valid += 1;
            continue;
        }

        if (w & 0x0F000000) == 0x0F000000 {
            c.syscalls += 1;
            c.valid += 1;
            continue;
        }

        if (w & 0x0FFFFFF0) == 0x012FFF10 && (w & 0x0F) == 0xE {
            c.epilogues += 1;
            c.branches += 1;
            c.valid += 1;
            continue;
        }

        if (w & 0x0FFF0000) == 0x092D0000 && (w & 0x4000) != 0 {
            c.prologues += 1;
            c.valid += 1;
            continue;
        }

        if (w & 0x0FFF0000) == 0x08BD0000 && (w & 0x8000) != 0 {
            c.epilogues += 1;
            c.branches += 1;
            c.valid += 1;
            continue;
        }

        let cat = (w >> 25) & 0x07;
        let is_valid = match cat {
            0 | 1 => true,
            2 | 3 => true,
            4 => true,
            5 => {
                c.branches += 1;
                true
            }
            _ => false,
        };

        if is_valid {
            c.valid += 1;
        }
    }

    compute_score(Architecture::ArmV7, &c)
}

fn score_thumb(data: &[u8]) -> ArchScore {
    let mut c = InsnCounts {
        total: data.len() / 2,
        ..Default::default()
    };

    for chunk in data.chunks_exact(2) {
        let h = u16::from_le_bytes([chunk[0], chunk[1]]);
        if h == 0x46C0 || h == 0xBF00 {
            c.nops += 1;
            c.valid += 1;
            continue;
        }
        if (h & 0xFF00) == 0xDF00 {
            c.syscalls += 1;
            c.valid += 1;
            continue;
        }
        if (h & 0xFE00) == 0xB400 && (h & 0x0100) != 0 {
            c.prologues += 1;
            c.valid += 1;
            continue;
        }
        if (h & 0xFE00) == 0xBC00 && (h & 0x0100) != 0 {
            c.epilogues += 1;
            c.branches += 1;
            c.valid += 1;
            continue;
        }
        if (h & 0xFFF8) == 0x4770 {
            c.epilogues += 1;
            c.branches += 1;
            c.valid += 1;
            continue;
        }
        let top = h >> 12;
        let is_valid = match top {
            0..=3 => true,
            4 => true,
            5..=9 => true,
            10..=13 => true,
            14 => {
                c.branches += 1;
                true
            }
            _ => false,
        };
        if is_valid {
            c.valid += 1;
        }
    }

    compute_score(Architecture::Thumb, &c)
}

fn score_aarch64(data: &[u8]) -> ArchScore {
    let mut c = InsnCounts {
        total: data.len() / 4,
        ..Default::default()
    };

    for chunk in data.chunks_exact(4) {
        let w = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        if w == 0xD503201F {
            c.nops += 1;
            c.valid += 1;
            continue;
        }
        if w == 0xD65F03C0 {
            c.epilogues += 1;
            c.branches += 1;
            c.valid += 1;
            continue;
        }
        if (w & 0xFFE0001F) == 0xD4000001 {
            c.syscalls += 1;
            c.valid += 1;
            continue;
        }
        if (w & 0xFFC07FFF) == 0xA9807BFD {
            c.prologues += 1;
            c.valid += 1;
            continue;
        }

        let cat = (w >> 25) & 0x0F;
        let is_valid = match cat {
            0b1000 | 0b1001 => true,
            0b1010 | 0b1011 => {
                c.branches += 1;
                true
            }
            0b0100 | 0b0110 | 0b1100 | 0b1110 => true,
            0b0101 | 0b1101 => true,
            _ => false,
        };

        if is_valid {
            c.valid += 1;
        }
    }

    compute_score(Architecture::AArch64, &c)
}

fn score_riscv(data: &[u8], is_rv64: bool) -> ArchScore {
    let mut c = InsnCounts {
        total: data.len() / 4,
        ..Default::default()
    };

    for chunk in data.chunks_exact(4) {
        let w = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        if (w & 0x03) != 0x03 {
            continue;
        }
        if w == 0x00000013 {
            c.nops += 1;
            c.valid += 1;
            continue;
        }
        if w == 0x00008067 {
            c.epilogues += 1;
            c.branches += 1;
            c.valid += 1;
            continue;
        }
        if w == 0x00000073 {
            c.syscalls += 1;
            c.valid += 1;
            continue;
        }

        let op = w & 0x7F;
        let is_valid = match op {
            0x37 | 0x17 => true,
            0x6F => {
                c.branches += 1;
                true
            }
            0x67 => {
                c.branches += 1;
                true
            }
            0x63 => {
                c.branches += 1;
                true
            }
            0x03 | 0x23 => true,
            0x13 => {
                let rd = (w >> 7) & 0x1F;
                let rs1 = (w >> 15) & 0x1F;
                if rd == 2 && rs1 == 2 && (w as i32) < 0 {
                    c.prologues += 1;
                }
                true
            }
            0x33 => true,
            0x1B | 0x3B => is_rv64,
            _ => false,
        };

        if is_valid {
            c.valid += 1;
        }
    }

    let arch = if is_rv64 {
        Architecture::RiscV64
    } else {
        Architecture::RiscV32
    };
    compute_score(arch, &c)
}

fn compute_score(arch: Architecture, c: &InsnCounts) -> ArchScore {
    let valid_ratio = if c.total == 0 {
        0.0
    } else {
        c.valid as f64 / c.total as f64
    };
    let branch_ratio = if c.total == 0 {
        0.0
    } else {
        c.branches as f64 / c.total as f64
    };

    let mut confidence = if valid_ratio < 0.50 {
        valid_ratio * 0.30
    } else {
        valid_ratio * 0.50
    };

    if (0.02..=0.35).contains(&branch_ratio) {
        confidence += 0.10;
    }
    if c.prologues > 0 && c.epilogues > 0 {
        confidence += 0.25;
    } else if c.prologues > 0 || c.epilogues > 0 {
        confidence += 0.12;
    }
    if c.syscalls > 0 {
        confidence += 0.10;
    }
    if valid_ratio >= 0.85 {
        confidence += 0.10;
    }

    if c.total < 8 {
        confidence *= (c.total as f64 / 8.0).clamp(0.25, 1.0);
    }

    ArchScore {
        arch,
        confidence: confidence.clamp(0.0, 1.0),
        valid_insn_count: c.valid,
        total_insn_count: c.total,
        valid_ratio,
        branch_count: c.branches,
        prologue_count: c.prologues,
        epilogue_count: c.epilogues,
        syscall_count: c.syscalls,
        nop_count: c.nops,
    }
}
