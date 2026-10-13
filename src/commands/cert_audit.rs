// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use firm_carver::cert_audit::asn1::unix_time_from_ymdhms;
use firm_carver::cert_audit::{audit_cert_path, format_cert_report, CertAuditConfig, CertSeverity};
use firm_carver::cli::CertAuditArgs;
use firm_carver::error::{CarverError, Result};
use std::fs;

use zeroize::Zeroize;

pub fn handle_cert_audit(args: CertAuditArgs) -> Result<()> {
    let min_sev = args
        .min_severity
        .parse::<CertSeverity>()
        .map_err(CarverError::InvalidArgument)?;

    let mut config = CertAuditConfig {
        min_severity: min_sev,
        ..Default::default()
    };

    if let Some(ref ref_str) = args.reference_date {
        if let Ok(ts) = ref_str.parse::<i64>() {
            config.reference_timestamp = ts;
        } else if ref_str.len() >= 10
            && ref_str.as_bytes()[4] == b'-'
            && ref_str.as_bytes()[7] == b'-'
        {
            let y = ref_str[0..4].parse::<i32>().unwrap_or(2026);
            let m = ref_str[5..7].parse::<u8>().unwrap_or(1);
            let d = ref_str[8..10].parse::<u8>().unwrap_or(1);
            config.reference_timestamp = unix_time_from_ymdhms(y, m, d, 0, 0, 0);
        }
    }

    let report = audit_cert_path(&args.file, &config)?;

    if let Some(out_path) = &args.out {
        let mut json_str = serde_json::to_string_pretty(&report)?;
        fs::write(out_path, &json_str).map_err(CarverError::Io)?;
        json_str.zeroize();
        if !args.json {
            println!(
                "Wrote certificate audit report to: {}\n",
                out_path.display()
            );
        }
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", format_cert_report(&report));
    }
    Ok(())
}
