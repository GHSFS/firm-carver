// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::scoring::Architecture;
use serde::{Deserialize, Serialize};

/// Disassembled instruction representation for reporting and terminal output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedInsn {
    pub offset: usize,
    pub raw_hex: String,
    pub mnemonic: String,
    pub operands: String,
}

/// Disassembles up to `max_insns` from `data` starting at `start_offset`.
pub fn disassemble_chunk(
    data: &[u8],
    arch: Architecture,
    start_offset: usize,
    max_insns: usize,
) -> Vec<DecodedInsn> {
    let mut out = Vec::new();
    if start_offset >= data.len() || max_insns == 0 {
        return out;
    }

    let slice = &data[start_offset..];
    match arch {
        Architecture::MipsEb => disasm_mips(slice, start_offset, true, max_insns, &mut out),
        Architecture::MipsEl => disasm_mips(slice, start_offset, false, max_insns, &mut out),
        Architecture::ArmV7 => disasm_arm(slice, start_offset, max_insns, &mut out),
        Architecture::Thumb => disasm_thumb(slice, start_offset, max_insns, &mut out),
        Architecture::AArch64 => disasm_aarch64(slice, start_offset, max_insns, &mut out),
        Architecture::RiscV32 | Architecture::RiscV64 => {
            disasm_riscv(slice, start_offset, max_insns, &mut out)
        }
    }

    out
}

fn disasm_mips(
    data: &[u8],
    base_offset: usize,
    big_endian: bool,
    max: usize,
    out: &mut Vec<DecodedInsn>,
) {
    for (i, chunk) in data.chunks_exact(4).enumerate().take(max) {
        let off = base_offset + (i * 4);
        let raw_hex = hex::encode(chunk);
        let w = if big_endian {
            u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
        } else {
            u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
        };

        if w == 0 {
            out.push(DecodedInsn {
                offset: off,
                raw_hex,
                mnemonic: "nop".into(),
                operands: String::new(),
            });
            continue;
        }

        let op = w >> 26;
        let rs = (w >> 21) & 0x1F;
        let rt = (w >> 16) & 0x1F;
        let rd = (w >> 11) & 0x1F;
        let funct = w & 0x3F;
        let imm = (w & 0xFFFF) as i16;

        let (mne, ops) = match op {
            0 => match funct {
                0 => ("sll", format!("${}, ${}, {}", rd, rt, (w >> 6) & 0x1F)),
                8 => ("jr", format!("${}", rs)),
                9 => ("jalr", format!("${}, ${}", rd, rs)),
                12 => ("syscall", String::new()),
                33 => ("addu", format!("${}, ${}, ${}", rd, rs, rt)),
                35 => ("subu", format!("${}, ${}, ${}", rd, rs, rt)),
                36 => ("and", format!("${}, ${}, ${}", rd, rs, rt)),
                37 => ("or", format!("${}, ${}, ${}", rd, rs, rt)),
                38 => ("xor", format!("${}, ${}, ${}", rd, rs, rt)),
                _ => ("special", format!("funct=0x{:02X}", funct)),
            },
            2 => ("j", format!("0x{:08X}", (w & 0x03FFFFFF) << 2)),
            3 => ("jal", format!("0x{:08X}", (w & 0x03FFFFFF) << 2)),
            4 => ("beq", format!("${}, ${}, {}", rs, rt, imm)),
            5 => ("bne", format!("${}, ${}, {}", rs, rt, imm)),
            9 => ("addiu", format!("${}, ${}, {}", rt, rs, imm)),
            12 => ("andi", format!("${}, ${}, 0x{:04X}", rt, rs, w & 0xFFFF)),
            13 => ("ori", format!("${}, ${}, 0x{:04X}", rt, rs, w & 0xFFFF)),
            15 => ("lui", format!("${}, 0x{:04X}", rt, w & 0xFFFF)),
            35 => ("lw", format!("${}, {}(${})", rt, imm, rs)),
            43 => ("sw", format!("${}, {}(${})", rt, imm, rs)),
            _ => ("unknown", format!("op=0x{:02X}", op)),
        };

        out.push(DecodedInsn {
            offset: off,
            raw_hex,
            mnemonic: mne.into(),
            operands: ops,
        });
    }
}

fn disasm_arm(data: &[u8], base_offset: usize, max: usize, out: &mut Vec<DecodedInsn>) {
    for (i, chunk) in data.chunks_exact(4).enumerate().take(max) {
        let off = base_offset + (i * 4);
        let raw_hex = hex::encode(chunk);
        let w = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);

        if (w & 0x0FFFFFFF) == 0x01A00000 || (w & 0x0FFF0000) == 0x03200000 {
            out.push(DecodedInsn {
                offset: off,
                raw_hex,
                mnemonic: "nop".into(),
                operands: String::new(),
            });
            continue;
        }

        if (w & 0x0F000000) == 0x0F000000 {
            out.push(DecodedInsn {
                offset: off,
                raw_hex,
                mnemonic: "svc".into(),
                operands: format!("0x{:06X}", w & 0x00FFFFFF),
            });
            continue;
        }

        if (w & 0x0FFFFFF0) == 0x012FFF10 && (w & 0x0F) == 0xE {
            out.push(DecodedInsn {
                offset: off,
                raw_hex,
                mnemonic: "bx".into(),
                operands: "lr".into(),
            });
            continue;
        }

        let cat = (w >> 25) & 0x07;
        let (mne, ops) = match cat {
            0 | 1 => {
                let op = (w >> 21) & 0x0F;
                let rd = (w >> 12) & 0x0F;
                let rn = (w >> 16) & 0x0F;
                match op {
                    2 => ("sub", format!("r{}, r{}, ...", rd, rn)),
                    4 => ("add", format!("r{}, r{}, ...", rd, rn)),
                    13 => ("mov", format!("r{}, ...", rd)),
                    _ => ("alu", format!("op={}", op)),
                }
            }
            2 | 3 => {
                let l = (w >> 20) & 1;
                let rd = (w >> 12) & 0x0F;
                let rn = (w >> 16) & 0x0F;
                if l == 1 {
                    ("ldr", format!("r{}, [r{}]", rd, rn))
                } else {
                    ("str", format!("r{}, [r{}]", rd, rn))
                }
            }
            4 => {
                let l = (w >> 20) & 1;
                if l == 1 {
                    ("ldmia", "sp!, {...}".into())
                } else {
                    ("stmdb", "sp!, {...}".into())
                }
            }
            5 => {
                let l = (w >> 24) & 1;
                if l == 1 {
                    ("bl", format!("offset={}", (w as i32) & 0x00FFFFFF))
                } else {
                    ("b", format!("offset={}", (w as i32) & 0x00FFFFFF))
                }
            }
            _ => ("unknown", format!("w=0x{:08X}", w)),
        };

        out.push(DecodedInsn {
            offset: off,
            raw_hex,
            mnemonic: mne.into(),
            operands: ops,
        });
    }
}

fn disasm_thumb(data: &[u8], base_offset: usize, max: usize, out: &mut Vec<DecodedInsn>) {
    for (i, chunk) in data.chunks_exact(2).enumerate().take(max) {
        let off = base_offset + (i * 2);
        let raw_hex = hex::encode(chunk);
        let h = u16::from_le_bytes([chunk[0], chunk[1]]);

        if h == 0x46C0 || h == 0xBF00 {
            out.push(DecodedInsn {
                offset: off,
                raw_hex,
                mnemonic: "nop".into(),
                operands: String::new(),
            });
            continue;
        }
        if (h & 0xFF00) == 0xDF00 {
            out.push(DecodedInsn {
                offset: off,
                raw_hex,
                mnemonic: "svc".into(),
                operands: format!("0x{:02X}", h & 0xFF),
            });
            continue;
        }

        let (mne, ops) = match h >> 12 {
            1 => ("add", format!("r{}, ...", (h >> 8) & 7)),
            2 => ("mov", format!("r{}, #{}", (h >> 8) & 7, h & 0xFF)),
            11 => ("push/pop", format!("regs=0x{:03X}", h & 0x1FF)),
            14 => ("b", format!("offset={}", h & 0x7FF)),
            _ => ("thumb", format!("0x{:04X}", h)),
        };

        out.push(DecodedInsn {
            offset: off,
            raw_hex,
            mnemonic: mne.into(),
            operands: ops,
        });
    }
}

fn disasm_aarch64(data: &[u8], base_offset: usize, max: usize, out: &mut Vec<DecodedInsn>) {
    for (i, chunk) in data.chunks_exact(4).enumerate().take(max) {
        let off = base_offset + (i * 4);
        let raw_hex = hex::encode(chunk);
        let w = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);

        if w == 0xD503201F {
            out.push(DecodedInsn {
                offset: off,
                raw_hex,
                mnemonic: "nop".into(),
                operands: String::new(),
            });
            continue;
        }
        if w == 0xD65F03C0 {
            out.push(DecodedInsn {
                offset: off,
                raw_hex,
                mnemonic: "ret".into(),
                operands: String::new(),
            });
            continue;
        }
        if (w & 0xFFE0001F) == 0xD4000001 {
            out.push(DecodedInsn {
                offset: off,
                raw_hex,
                mnemonic: "svc".into(),
                operands: format!("#{}", (w >> 5) & 0xFFFF),
            });
            continue;
        }

        let cat = (w >> 25) & 0x0F;
        let rd = w & 0x1F;
        let (mne, ops) = match cat {
            0b1000 | 0b1001 => {
                if (w & 0xFF800000) == 0xD2800000 {
                    ("movz", format!("x{}, #0x{:X}", rd, (w >> 5) & 0xFFFF))
                } else {
                    ("add/sub_imm", format!("x{}, ...", rd))
                }
            }
            0b1010 | 0b1011 => ("b/bl", format!("imm=0x{:07X}", w & 0x03FFFFFF)),
            0b0100 | 0b0110 | 0b1100 | 0b1110 => ("ldr/str", format!("x{}, [sp, ...]", rd)),
            _ => ("aarch64", format!("0x{:08X}", w)),
        };

        out.push(DecodedInsn {
            offset: off,
            raw_hex,
            mnemonic: mne.into(),
            operands: ops,
        });
    }
}

fn disasm_riscv(data: &[u8], base_offset: usize, max: usize, out: &mut Vec<DecodedInsn>) {
    for (i, chunk) in data.chunks_exact(4).enumerate().take(max) {
        let off = base_offset + (i * 4);
        let raw_hex = hex::encode(chunk);
        let w = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);

        if w == 0x00000013 {
            out.push(DecodedInsn {
                offset: off,
                raw_hex,
                mnemonic: "nop".into(),
                operands: String::new(),
            });
            continue;
        }
        if w == 0x00008067 {
            out.push(DecodedInsn {
                offset: off,
                raw_hex,
                mnemonic: "ret".into(),
                operands: String::new(),
            });
            continue;
        }
        if w == 0x00000073 {
            out.push(DecodedInsn {
                offset: off,
                raw_hex,
                mnemonic: "ecall".into(),
                operands: String::new(),
            });
            continue;
        }

        let op = w & 0x7F;
        let rd = (w >> 7) & 0x1F;
        let rs1 = (w >> 15) & 0x1F;
        let imm = ((w as i32) >> 20) as i16;

        let (mne, ops) = match op {
            0x13 => ("addi", format!("x{}, x{}, {}", rd, rs1, imm)),
            0x33 => ("add/sub", format!("x{}, x{}, ...", rd, rs1)),
            0x37 => ("lui", format!("x{}, 0x{:X}", rd, w >> 12)),
            0x17 => ("auipc", format!("x{}, 0x{:X}", rd, w >> 12)),
            0x6F => ("jal", format!("x{}, offset", rd)),
            0x67 => ("jalr", format!("x{}, x{}, {}", rd, rs1, imm)),
            0x63 => ("branch", format!("x{}, x{}, offset", rs1, (w >> 20) & 0x1F)),
            0x03 => ("lw", format!("x{}, {}(x{})", rd, imm, rs1)),
            0x23 => ("sw", format!("x{}, offset(x{})", (w >> 20) & 0x1F, rs1)),
            _ => ("riscv", format!("op=0x{:02X}", op)),
        };

        out.push(DecodedInsn {
            offset: off,
            raw_hex,
            mnemonic: mne.into(),
            operands: ops,
        });
    }
}
