// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::common::read_firmware_file;
use firm_carver::carve_and_extract;
use firm_carver::cli::CarveArgs;
use firm_carver::error::Result;
use zeroize::Zeroize;

pub fn handle_carve(args: CarveArgs) -> Result<()> {
    let mut data = read_firmware_file(&args.file)?;
    let manifest = carve_and_extract(&data, &args.out, &args.file.to_string_lossy())?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&manifest)?);
    } else {
        println!("=== FirmCarver Magic Stream Carving Engine ===");
        println!("Source File:      {}", args.file.display());
        println!("Output Directory: {}", args.out.display());
        println!("Carved Segments:  {}\n", manifest.carved_count);

        for (idx, seg) in manifest.segments.iter().enumerate() {
            let file_str = seg.extracted_filename.as_deref().unwrap_or("none");
            println!(
                "[{:02}] Offset: 0x{:08X} | Length: {:8} bytes | File: {}",
                idx + 1,
                seg.offset,
                seg.length,
                file_str
            );
            println!("     Info: {}", seg.description);
        }
        println!(
            "\nExtraction complete. Manifest saved to {}/manifest.json",
            args.out.display()
        );
    }
    data.zeroize();
    Ok(())
}
