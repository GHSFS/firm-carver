// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use firm_carver::cli::DomainAuditArgs;
use firm_carver::domain_audit::{
    audit_domain_buffer, audit_domain_path, format_domain_report, DomainAuditConfig,
    DomainSeverity, EndpointKind,
};
use firm_carver::error::{CarverError, Result};
use std::fs::{self, File};
use std::io::Read;
use std::str::FromStr;

pub fn handle_domain_audit(args: DomainAuditArgs) -> Result<()> {
    let min_severity =
        DomainSeverity::from_str(&args.min_severity).map_err(CarverError::InvalidArgument)?;

    let kind_filter = match args.filter.to_ascii_lowercase().as_str() {
        "url" => Some(EndpointKind::Url),
        "ipv4" => Some(EndpointKind::Ipv4),
        "ipv6" => Some(EndpointKind::Ipv6),
        "domain" => Some(EndpointKind::Domain),
        "all" => None,
        other => {
            return Err(CarverError::InvalidArgument(format!(
                "Invalid filter kind '{}', expected url|ipv4|ipv6|domain|all",
                other
            )))
        }
    };

    let config = DomainAuditConfig {
        min_severity,
        min_string_length: args.min_len.max(3),
        include_private_ips: !args.no_private,
        kind_filter,
    };

    let report = if let Some(offset) = args.offset {
        if !args.target.is_file() {
            return Err(CarverError::InvalidArgument(
                "--offset can only be used with single binary files".to_string(),
            ));
        }
        let mut file = File::open(&args.target)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        if offset >= buffer.len() {
            return Err(CarverError::InvalidArgument(format!(
                "Offset {} exceeds file length {}",
                offset,
                buffer.len()
            )));
        }

        audit_domain_buffer(
            &args.target.to_string_lossy(),
            &buffer[offset..],
            offset,
            &config,
        )
    } else {
        audit_domain_path(&args.target, &config)?
    };

    if let Some(out_path) = args.out {
        let json_str = serde_json::to_string_pretty(&report)?;
        fs::write(&out_path, json_str)?;
        println!("Exported domain audit report to '{}'", out_path.display());
    }

    if args.json {
        let json_str = serde_json::to_string_pretty(&report)?;
        println!("{}", json_str);
    } else {
        println!("{}", format_domain_report(&report));
    }

    Ok(())
}
