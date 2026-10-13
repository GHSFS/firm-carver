// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::common::read_firmware_file;
use firm_carver::cli::AuditArgs;
use firm_carver::error::Result;
use firm_carver::{scan_vulnerabilities, VulnSeverity};
use zeroize::Zeroize;

pub fn handle_audit(args: AuditArgs) -> Result<()> {
    let mut data = read_firmware_file(&args.file)?;
    let report = scan_vulnerabilities(&data, &args.file.to_string_lossy());

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("=== FirmCarver Static Vulnerability & Backdoor Audit ===");
        println!("Target File:   {}", report.target_file);
        println!("Scanned Size:  {} bytes", report.target_size);
        println!("Total Findings:{}", report.total_findings);
        println!(
            "Severity:      Critical: {} | High: {} | Medium: {} | Low: {}\n",
            report.critical_count, report.high_count, report.medium_count, report.low_count
        );

        if report.findings.is_empty() {
            println!(
                "No obvious static backdoors, private keys, or default shadow credentials found."
            );
        } else {
            for (idx, f) in report.findings.iter().enumerate() {
                let sev_label = match f.severity {
                    VulnSeverity::Critical => "[CRITICAL]",
                    VulnSeverity::High => "[HIGH]    ",
                    VulnSeverity::Medium => "[MEDIUM]  ",
                    VulnSeverity::Low => "[LOW]     ",
                };
                println!("#{:02} {} {} - {}", idx + 1, sev_label, f.id, f.title);
                println!("     Offset:      0x{:08X}", f.offset);
                println!("     Evidence:    \"{}\"", f.evidence);
                println!("     Description: {}", f.description);
                println!("     Remedy:      {}", f.remediation);
                println!();
            }
        }
    }
    data.zeroize();
    Ok(())
}
