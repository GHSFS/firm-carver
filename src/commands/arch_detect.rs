// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::common::{read_firmware_file, validate_offset};
use firm_carver::arch_detect::{format_arch_report, ArchDetector};
use firm_carver::cli::ArchDetectArgs;
use firm_carver::error::Result;
use zeroize::Zeroize;

pub fn handle_arch_detect(args: ArchDetectArgs) -> Result<()> {
    let mut data = read_firmware_file(&args.file)?;
    validate_offset(args.offset, data.len())?;

    let slice = &data[args.offset..];
    let chunk_len = args.length.unwrap_or(slice.len()).min(slice.len());
    let analyze_slice = &slice[..chunk_len];

    let detector = ArchDetector {
        min_confidence: args.min_confidence,
    };
    let report = detector.analyze(analyze_slice, &args.file.to_string_lossy(), args.offset);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", format_arch_report(&report));
    }
    data.zeroize();
    Ok(())
}
