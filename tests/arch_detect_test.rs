// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use firm_carver::arch_detect::{
    build_synthetic_shellcode, disassemble_chunk, format_arch_report, ArchDetector, Architecture,
    ShellcodeCategory, ShellcodeSeverity, ShellcodeVariant,
};

#[test]
fn test_arch_detect_mips_eb_execve() {
    let payload = build_synthetic_shellcode(Architecture::MipsEb, ShellcodeVariant::ExecveSh);
    assert!(!payload.is_empty());

    let detector = ArchDetector::new();
    let report = detector.analyze(&payload, "mips_eb_sample.bin", 0);

    assert_eq!(report.primary_arch, Some(Architecture::MipsEb));
    assert!(report.primary_confidence >= 0.70);

    let has_execve = report.shellcode_findings.iter().any(|f| {
        f.category == ShellcodeCategory::ExecveSyscall && f.severity == ShellcodeSeverity::Critical
    });
    assert!(has_execve, "MIPS-EB sys_execve sequence should be detected");

    let has_sh = report
        .shellcode_findings
        .iter()
        .any(|f| f.category == ShellcodeCategory::ShellString);
    assert!(has_sh, "Embedded /bin/sh string should be detected");
}

#[test]
fn test_arch_detect_mips_el_execve() {
    let payload = build_synthetic_shellcode(Architecture::MipsEl, ShellcodeVariant::ExecveSh);
    let detector = ArchDetector::new();
    let report = detector.analyze(&payload, "mips_el_sample.bin", 0);

    assert_eq!(report.primary_arch, Some(Architecture::MipsEl));
    assert!(report.primary_confidence >= 0.70);

    let has_execve = report.shellcode_findings.iter().any(|f| {
        f.category == ShellcodeCategory::ExecveSyscall && f.architecture == Architecture::MipsEl
    });
    assert!(has_execve, "MIPS-EL sys_execve sequence should be detected");
}

#[test]
fn test_arch_detect_armv7_execve() {
    let payload = build_synthetic_shellcode(Architecture::ArmV7, ShellcodeVariant::ExecveSh);
    let detector = ArchDetector::new();
    let report = detector.analyze(&payload, "armv7_sample.bin", 0);

    assert_eq!(report.primary_arch, Some(Architecture::ArmV7));
    assert!(report.primary_confidence >= 0.70);

    let has_execve = report.shellcode_findings.iter().any(|f| {
        f.category == ShellcodeCategory::ExecveSyscall && f.architecture == Architecture::ArmV7
    });
    assert!(has_execve, "ARMv7 sys_execve sequence should be detected");
}

#[test]
fn test_arch_detect_aarch64_execve() {
    let payload = build_synthetic_shellcode(Architecture::AArch64, ShellcodeVariant::ExecveSh);
    let detector = ArchDetector::new();
    let report = detector.analyze(&payload, "aarch64_sample.bin", 0);

    assert_eq!(report.primary_arch, Some(Architecture::AArch64));
    assert!(report.primary_confidence >= 0.70);

    let has_execve = report.shellcode_findings.iter().any(|f| {
        f.category == ShellcodeCategory::ExecveSyscall && f.architecture == Architecture::AArch64
    });
    assert!(has_execve, "AArch64 sys_execve sequence should be detected");
}

#[test]
fn test_arch_detect_riscv_execve() {
    let payload = build_synthetic_shellcode(Architecture::RiscV32, ShellcodeVariant::ExecveSh);
    let detector = ArchDetector::new();
    let report = detector.analyze(&payload, "riscv_sample.bin", 0);

    assert_eq!(report.primary_arch, Some(Architecture::RiscV32));
    assert!(report.primary_confidence >= 0.70);

    let has_execve = report.shellcode_findings.iter().any(|f| {
        f.category == ShellcodeCategory::ExecveSyscall && f.architecture == Architecture::RiscV32
    });
    assert!(has_execve, "RISC-V sys_execve sequence should be detected");
}

#[test]
fn test_arch_detect_nop_sled() {
    let payload = build_synthetic_shellcode(Architecture::ArmV7, ShellcodeVariant::NopSled);
    let detector = ArchDetector::new();
    let report = detector.analyze(&payload, "arm_sled.bin", 0);

    let has_sled = report
        .shellcode_findings
        .iter()
        .any(|f| f.category == ShellcodeCategory::NopSled);
    assert!(has_sled, "ARMv7 NOP sled should be detected");
}

#[test]
fn test_arch_detect_disassembler() {
    let payload = build_synthetic_shellcode(Architecture::ArmV7, ShellcodeVariant::ExecveSh);
    let insns = disassemble_chunk(&payload, Architecture::ArmV7, 0, 8);

    assert!(!insns.is_empty());
    assert_eq!(insns[0].offset, 0);
    assert_eq!(insns[0].mnemonic, "stmdb");
    assert!(insns.iter().any(|i| i.mnemonic == "svc"));
}

#[test]
fn test_arch_detect_bounds_and_empty_input() {
    let detector = ArchDetector::new();

    let empty_report = detector.analyze(&[], "empty.bin", 0);
    assert!(empty_report.candidates.is_empty());
    assert!(empty_report.primary_arch.is_none());
    assert_eq!(empty_report.primary_confidence, 0.0);

    let random_noise = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
    let noise_report = detector.analyze(&random_noise, "noise.bin", 0);
    assert!(noise_report.primary_confidence < 0.60);
}

#[test]
fn test_format_arch_report() {
    let payload = build_synthetic_shellcode(Architecture::MipsEb, ShellcodeVariant::ExecveSh);
    let detector = ArchDetector::new();
    let report = detector.analyze(&payload, "firmware.bin", 0x1000);

    let formatted = format_arch_report(&report);
    assert!(formatted.contains("=== FirmCarver Architecture & Shellcode Auditor ==="));
    assert!(formatted.contains("MIPS-32 (Big-Endian)"));
    assert!(formatted.contains("0x00001000"));
}
