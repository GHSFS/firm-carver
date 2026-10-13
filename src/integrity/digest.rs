// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::fmt;
use std::str::FromStr;

/// Supported cryptographic hash algorithm types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    /// NIST SHA-256 (32 bytes / 256 bits output)
    Sha256,
    /// NIST SHA-512 (64 bytes / 512 bits output)
    Sha512,
    /// High-performance BLAKE3 tree hash (32 bytes / 256 bits output)
    Blake3,
    /// All supported algorithms simultaneously
    All,
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha256 => write!(f, "sha256"),
            Self::Sha512 => write!(f, "sha512"),
            Self::Blake3 => write!(f, "blake3"),
            Self::All => write!(f, "all"),
        }
    }
}

impl FromStr for HashAlgorithm {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().trim() {
            "sha256" | "sha-256" | "256" => Ok(Self::Sha256),
            "sha512" | "sha-512" | "512" => Ok(Self::Sha512),
            "blake3" | "b3" => Ok(Self::Blake3),
            "all" | "*" => Ok(Self::All),
            other => Err(format!(
                "Unknown hash algorithm '{}'. Supported: sha256, sha512, blake3, all",
                other
            )),
        }
    }
}

/// Compute SHA-256 hexadecimal digest string of arbitrary byte sequence.
pub fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Compute SHA-512 hexadecimal digest string of arbitrary byte sequence.
pub fn compute_sha512(data: &[u8]) -> String {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Compute BLAKE3 hexadecimal digest string of arbitrary byte sequence.
pub fn compute_blake3(data: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(data);
    hasher.finalize().to_hex().to_string()
}

/// Constant-time string equality check protecting against timing side-channel attacks.
pub fn constant_time_eq_str(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    if a_bytes.len() != b_bytes.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a_bytes.iter().zip(b_bytes.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Comprehensive bundle of cryptographic digests computed across a binary stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestBundle {
    /// NIST SHA-256 hex digest (64 hex characters)
    pub sha256: String,
    /// NIST SHA-512 hex digest (128 hex characters)
    pub sha512: String,
    /// BLAKE3 hex digest (64 hex characters)
    pub blake3: String,
}

/// Specific digest mismatch finding during integrity verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestMismatch {
    /// Which algorithm had a mismatch
    pub algo: HashAlgorithm,
    /// The expected digest string from manifest
    pub expected: String,
    /// The actual computed digest string from binary
    pub actual: String,
}

impl DigestBundle {
    /// Compute all cryptographic digests (SHA-256, SHA-512, BLAKE3) over input bytes.
    pub fn compute(data: &[u8]) -> Self {
        Self {
            sha256: compute_sha256(data),
            sha512: compute_sha512(data),
            blake3: compute_blake3(data),
        }
    }

    /// Retrieve specific digest string by algorithm.
    pub fn get_digest(&self, algo: HashAlgorithm) -> Option<&str> {
        match algo {
            HashAlgorithm::Sha256 => Some(&self.sha256),
            HashAlgorithm::Sha512 => Some(&self.sha512),
            HashAlgorithm::Blake3 => Some(&self.blake3),
            HashAlgorithm::All => None,
        }
    }

    /// Constant-time check verifying whether all three digests match expected bundle.
    pub fn matches(&self, expected: &DigestBundle) -> bool {
        constant_time_eq_str(&self.sha256, &expected.sha256)
            && constant_time_eq_str(&self.sha512, &expected.sha512)
            && constant_time_eq_str(&self.blake3, &expected.blake3)
    }

    /// Compare digests and collect all mismatched algorithms.
    pub fn diff_mismatches(&self, expected: &DigestBundle) -> Vec<DigestMismatch> {
        let mut mismatches = Vec::new();
        if !constant_time_eq_str(&self.sha256, &expected.sha256) {
            mismatches.push(DigestMismatch {
                algo: HashAlgorithm::Sha256,
                expected: expected.sha256.clone(),
                actual: self.sha256.clone(),
            });
        }
        if !constant_time_eq_str(&self.sha512, &expected.sha512) {
            mismatches.push(DigestMismatch {
                algo: HashAlgorithm::Sha512,
                expected: expected.sha512.clone(),
                actual: self.sha512.clone(),
            });
        }
        if !constant_time_eq_str(&self.blake3, &expected.blake3) {
            mismatches.push(DigestMismatch {
                algo: HashAlgorithm::Blake3,
                expected: expected.blake3.clone(),
                actual: self.blake3.clone(),
            });
        }
        mismatches
    }
}
