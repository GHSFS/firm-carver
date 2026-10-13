// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use firm_carver::cgi_audit::{audit_web_path, format_cgi_report, CgiAuditConfig, CgiSeverity};
use firm_carver::cli::CgiAuditArgs;
use firm_carver::error::{CarverError, Result};
use std::fs;

pub fn handle_cgi_audit(args: CgiAuditArgs) -> Result<()> {
    let min_sev = args
        .min_severity
        .parse::<CgiSeverity>()
        .map_err(CarverError::InvalidArgument)?;
    let config = CgiAuditConfig {
        min_severity: min_sev,
        ..Default::default()
    };
    let report = audit_web_path(&args.target, &config)?;

    if let Some(out_path) = &args.out {
        let json_str = serde_json::to_string_pretty(&report)?;
        fs::write(out_path, json_str).map_err(CarverError::Io)?;
        if !args.json {
            println!("Wrote CGI audit report to: {}\n", out_path.display());
        }
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", format_cgi_report(&report));
    }
    Ok(())
}
