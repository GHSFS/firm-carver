// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use firm_carver::error::{CarverError, Result};
use std::fs;
use std::path::Path;

pub fn read_firmware_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| {
        CarverError::Io(std::io::Error::new(
            e.kind(),
            format!("Failed to read {}: {}", path.display(), e),
        ))
    })
}

pub fn find_magic_or_default(data: &[u8], offset: Option<usize>, magics: &[&[u8]]) -> usize {
    if let Some(off) = offset {
        return off;
    }
    for i in 0..data.len().saturating_sub(4) {
        if magics.iter().any(|m| data[i..].starts_with(m)) {
            return i;
        }
    }
    0
}

pub fn validate_offset(offset: usize, len: usize) -> Result<()> {
    if offset >= len {
        Err(CarverError::InvalidArgument(format!(
            "Offset 0x{:08X} exceeds file size {} bytes",
            offset, len
        )))
    } else {
        Ok(())
    }
}
