// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::common::read_firmware_file;
use firm_carver::cli::SliceArgs;
use firm_carver::error::Result;
use firm_carver::slicer::{
    analyze_and_slice, extract_sliced_partitions, format_slicer_report, SlicerConfig,
};
use zeroize::Zeroize;

pub fn handle_slice(args: SliceArgs) -> Result<()> {
    let mut data = read_firmware_file(&args.file)?;
    let config = SlicerConfig {
        window_size: args.window,
        step_size: args.step,
        threshold: args.threshold,
    };
    let report = analyze_and_slice(&data, &args.file.to_string_lossy(), &config);

    if let Some(out_dir) = &args.out {
        let written = extract_sliced_partitions(&data, &report.partitions, out_dir)?;
        if !args.json {
            println!(
                "Extracted {} partition files into: {}\n",
                written.len(),
                out_dir.display()
            );
        }
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", format_slicer_report(&report, args.plot));
    }
    data.zeroize();
    Ok(())
}
