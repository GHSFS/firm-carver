// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use std::fmt;

/// Custom error types for firmware container inspection, stream carving, and vulnerability auditing.
#[derive(Debug)]
pub enum CarverError {
    /// Underlying I/O error
    Io(std::io::Error),
    /// Unrecognized or invalid firmware container image
    InvalidImage(String),
    /// Corrupt header or checksum failure
    CorruptHeader(String),
    /// Payload carving or extraction failure
    ExtractionFailed(String),
    /// Invalid command-line argument or parameter
    InvalidArgument(String),
    /// SquashFS parsing or decompression error
    SquashFs(String),
    /// Flattened Device Tree (FDT/DTB) parsing or disassembly error
    Fdt(String),
}

impl fmt::Display for CarverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {}", err),
            Self::InvalidImage(msg) => write!(f, "Invalid firmware image: {}", msg),
            Self::CorruptHeader(msg) => write!(f, "Corrupt header: {}", msg),
            Self::ExtractionFailed(msg) => write!(f, "Extraction failed: {}", msg),
            Self::InvalidArgument(msg) => write!(f, "Invalid argument: {}", msg),
            Self::SquashFs(msg) => write!(f, "SquashFS error: {}", msg),
            Self::Fdt(msg) => write!(f, "FDT/DTB error: {}", msg),
        }
    }
}

impl std::error::Error for CarverError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for CarverError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<serde_json::Error> for CarverError {
    fn from(err: serde_json::Error) -> Self {
        Self::ExtractionFailed(err.to_string())
    }
}

/// Specialized Result alias for firm-carver operations.
pub type Result<T> = std::result::Result<T, CarverError>;
