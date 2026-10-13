// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::common::read_firmware_file;
use firm_carver::cli::IntegrityArgs;
use firm_carver::error::{CarverError, Result};
use firm_carver::integrity::{
    format_integrity_report, format_verification_report, generate_attestation_manifest,
    verify_attestation, AttestationManifest, HashAlgorithm,
};
use zeroize::Zeroize;

pub fn handle_integrity(args: IntegrityArgs) -> Result<()> {
    let mut data = read_firmware_file(&args.file)?;
    let algo = args
        .algo
        .parse::<HashAlgorithm>()
        .map_err(CarverError::InvalidArgument)?;

    if let Some(verify_manifest_path) = &args.verify {
        let manifest = AttestationManifest::from_file(verify_manifest_path)?;
        let report = verify_attestation(&data, &manifest);

        if args.json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            print!("{}", format_verification_report(&report));
        }

        data.zeroize();
        if !report.overall_valid {
            return Err(CarverError::Integrity(
                "Attestation verification failed: cryptographic integrity mismatch detected"
                    .to_string(),
            ));
        }
    } else {
        let target_name = args.file.file_name().unwrap_or_default().to_string_lossy();
        let manifest = generate_attestation_manifest(&target_name, &data);

        if let Some(out_path) = &args.out {
            manifest.save_to_file(out_path)?;
            if !args.json {
                println!("Wrote attestation manifest to: {}\n", out_path.display());
            }
        }

        if args.json {
            println!("{}", serde_json::to_string_pretty(&manifest)?);
        } else {
            print!("{}", format_integrity_report(&manifest, algo));
        }
        data.zeroize();
    }
    Ok(())
}
