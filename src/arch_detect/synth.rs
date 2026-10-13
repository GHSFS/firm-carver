// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::scoring::Architecture;

/// Variants of deterministic test code chunks for testing and verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellcodeVariant {
    /// Realistic Linux sys_execve payload referencing /bin/sh
    ExecveSh,
    /// 32-byte NOP sled followed by execve payload
    NopSled,
    /// Function prologue, ALU loop, and stack epilogue
    StackPivot,
}

/// Generates deterministic binary code chunks for unit tests, fixtures, and synthetic firmware images.
pub fn build_synthetic_shellcode(arch: Architecture, variant: ShellcodeVariant) -> Vec<u8> {
    match variant {
        ShellcodeVariant::NopSled => {
            let mut blob = Vec::new();
            match arch {
                Architecture::MipsEb | Architecture::MipsEl => {
                    blob.extend_from_slice(&[0x00; 32]);
                }
                Architecture::ArmV7 => {
                    for _ in 0..8 {
                        blob.extend_from_slice(&[0x00, 0x00, 0xA0, 0xE1]); // mov r0, r0
                    }
                }
                Architecture::Thumb => {
                    for _ in 0..16 {
                        blob.extend_from_slice(&[0xC0, 0x46]); // nop
                    }
                }
                Architecture::AArch64 => {
                    for _ in 0..8 {
                        blob.extend_from_slice(&[0x1F, 0x20, 0x03, 0xD5]); // nop
                    }
                }
                Architecture::RiscV32 | Architecture::RiscV64 => {
                    for _ in 0..8 {
                        blob.extend_from_slice(&[0x13, 0x00, 0x00, 0x00]); // nop
                    }
                }
            }
            blob.extend_from_slice(&build_synthetic_shellcode(arch, ShellcodeVariant::ExecveSh));
            blob
        }
        ShellcodeVariant::ExecveSh => build_execve_payload(arch),
        ShellcodeVariant::StackPivot => build_stack_pivot_payload(arch),
    }
}

fn build_execve_payload(arch: Architecture) -> Vec<u8> {
    let mut code = Vec::new();

    match arch {
        Architecture::MipsEb => {
            let insns: &[u32] = &[
                0x27BDFFE0, // addiu $sp, $sp, -32
                0xAFBF001C, // sw $ra, 28($sp)
                0x24040000, // addiu $a0, $zero, 0
                0x24050000, // addiu $a1, $zero, 0
                0x24060000, // addiu $a2, $zero, 0
                0x24020FA7, // addiu $v0, $zero, 4011 (sys_execve)
                0x0000000C, // syscall
                0x8FBF001C, // lw $ra, 28($sp)
                0x27BD0020, // addiu $sp, $sp, 32
                0x03E00008, // jr $ra
                0x00000000, // nop
            ];
            for w in insns {
                code.extend_from_slice(&w.to_be_bytes());
            }
            code.extend_from_slice(b"/bin/sh\0");
        }
        Architecture::MipsEl => {
            let insns: &[u32] = &[
                0x27BDFFE0, // addiu $sp, $sp, -32
                0xAFBF001C, // sw $ra, 28($sp)
                0x24040000, // addiu $a0, $zero, 0
                0x24050000, // addiu $a1, $zero, 0
                0x24060000, // addiu $a2, $zero, 0
                0x24020FA7, // addiu $v0, $zero, 4011
                0x0000000C, // syscall
                0x8FBF001C, // lw $ra, 28($sp)
                0x27BD0020, // addiu $sp, $sp, 32
                0x03E00008, // jr $ra
                0x00000000, // nop
            ];
            for w in insns {
                code.extend_from_slice(&w.to_le_bytes());
            }
            code.extend_from_slice(b"/bin/sh\0");
        }
        Architecture::ArmV7 => {
            let insns: &[u32] = &[
                0xE92D4010, // stmdb sp!, {r4, lr}
                0xE3A00000, // mov r0, #0
                0xE3A01000, // mov r1, #0
                0xE3A02000, // mov r2, #0
                0xE3A0700B, // mov r7, #11 (sys_execve)
                0xEF000000, // svc 0
                0xE8BD8010, // ldmia sp!, {r4, pc}
            ];
            for w in insns {
                code.extend_from_slice(&w.to_le_bytes());
            }
            code.extend_from_slice(b"/bin/sh\0");
        }
        Architecture::Thumb => {
            let halfwords: &[u16] = &[
                0xB510, // push {r4, lr}
                0x2000, // movs r0, #0
                0x2100, // movs r1, #0
                0x2200, // movs r2, #0
                0x270B, // movs r7, #11
                0xDF00, // svc 0
                0xBD10, // pop {r4, pc}
            ];
            for h in halfwords {
                code.extend_from_slice(&h.to_le_bytes());
            }
            code.extend_from_slice(b"/bin/sh\0");
        }
        Architecture::AArch64 => {
            let insns: &[u32] = &[
                0xA9BF7BFD, // stp x29, x30, [sp, #-32]!
                0xD2800000, // mov x0, #0
                0xD2800001, // mov x1, #0
                0xD2800002, // mov x2, #0
                0xD2801BA8, // mov x8, #221 (sys_execve)
                0xD4000001, // svc #0
                0xA8C27BFD, // ldp x29, x30, [sp], #32
                0xD65F03C0, // ret
            ];
            for w in insns {
                code.extend_from_slice(&w.to_le_bytes());
            }
            code.extend_from_slice(b"/bin/sh\0");
        }
        Architecture::RiscV32 | Architecture::RiscV64 => {
            let insns: &[u32] = &[
                0xFF010113, // addi sp, sp, -16
                0x00112623, // sw ra, 12(sp)
                0x00000513, // addi a0, zero, 0
                0x00000593, // addi a1, zero, 0
                0x00000613, // addi a2, zero, 0
                0x0DD00893, // addi a7, zero, 221 (sys_execve)
                0x00000073, // ecall
                0x00C12083, // lw ra, 12(sp)
                0x01010113, // addi sp, sp, 16
                0x00008067, // ret
            ];
            for w in insns {
                code.extend_from_slice(&w.to_le_bytes());
            }
            code.extend_from_slice(b"/bin/sh\0");
        }
    }

    code
}

fn build_stack_pivot_payload(arch: Architecture) -> Vec<u8> {
    let mut code = Vec::new();
    match arch {
        Architecture::MipsEb => {
            let insns: &[u32] = &[
                0x27BDFFE0, // addiu $sp, $sp, -32
                0xAFBF001C, // sw $ra, 28($sp)
                0x00851021, // addu $v0, $a0, $a1
                0x8FBF001C, // lw $ra, 28($sp)
                0x27BD0020, // addiu $sp, $sp, 32
                0x03E00008, // jr $ra
                0x00000000, // nop
            ];
            for w in insns {
                code.extend_from_slice(&w.to_be_bytes());
            }
        }
        Architecture::MipsEl => {
            let insns: &[u32] = &[
                0x27BDFFE0, 0xAFBF001C, 0x00851021, 0x8FBF001C, 0x27BD0020, 0x03E00008, 0x00000000,
            ];
            for w in insns {
                code.extend_from_slice(&w.to_le_bytes());
            }
        }
        Architecture::ArmV7 => {
            let insns: &[u32] = &[
                0xE92D4010, // stmdb sp!, {r4, lr}
                0xE0800001, // add r0, r0, r1
                0xE8BD8010, // ldmia sp!, {r4, pc}
            ];
            for w in insns {
                code.extend_from_slice(&w.to_le_bytes());
            }
        }
        Architecture::Thumb => {
            let halfwords: &[u16] = &[
                0xB510, // push {r4, lr}
                0x1840, // adds r0, r0, r1
                0xBD10, // pop {r4, pc}
            ];
            for h in halfwords {
                code.extend_from_slice(&h.to_le_bytes());
            }
        }
        Architecture::AArch64 => {
            let insns: &[u32] = &[
                0xA9BF7BFD, // stp x29, x30, [sp, #-32]!
                0x8B010000, // add x0, x0, x1
                0xA8C27BFD, // ldp x29, x30, [sp], #32
                0xD65F03C0, // ret
            ];
            for w in insns {
                code.extend_from_slice(&w.to_le_bytes());
            }
        }
        Architecture::RiscV32 | Architecture::RiscV64 => {
            let insns: &[u32] = &[
                0xFF010113, // addi sp, sp, -16
                0x00112623, // sw ra, 12(sp)
                0x00B50533, // add a0, a0, a1
                0x00C12083, // lw ra, 12(sp)
                0x01010113, // addi sp, sp, 16
                0x00008067, // ret
            ];
            for w in insns {
                code.extend_from_slice(&w.to_le_bytes());
            }
        }
    }
    code
}
