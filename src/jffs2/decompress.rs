// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::error::{CarverError, Result};
use crate::jffs2::types::*;
use flate2::read::{DeflateDecoder, ZlibDecoder};
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::{Read, Write};

/// Decompresses a raw JFFS2 payload chunk based on compression opcode.
pub fn decompress_payload(payload: &[u8], compr: u8, dsize: usize) -> Result<Vec<u8>> {
    match compr {
        JFFS2_COMPR_NONE => {
            if payload.len() < dsize {
                return Err(CarverError::Jffs2(format!(
                    "Uncompressed payload length {} is shorter than expected dsize {}",
                    payload.len(),
                    dsize
                )));
            }
            Ok(payload[..dsize].to_vec())
        }
        JFFS2_COMPR_ZERO => Ok(vec![0u8; dsize]),
        JFFS2_COMPR_RTIME => decompress_rtime(payload, dsize),
        JFFS2_COMPR_ZLIB => decompress_zlib(payload, dsize),
        other => Err(CarverError::Jffs2(format!(
            "Unsupported JFFS2 compression opcode 0x{:02X}",
            other
        ))),
    }
}

/// Decompresses an RTIME-encoded byte stream with strict boundary checks (mitigating CVE-2024-57850).
pub fn decompress_rtime(payload: &[u8], dsize: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(dsize);
    let mut positions = [0usize; 256];
    let mut in_pos = 0;

    while out.len() < dsize {
        if in_pos >= payload.len() {
            return Err(CarverError::Jffs2(format!(
                "RTIME payload exhausted: needed {} bytes, recovered {}",
                dsize,
                out.len()
            )));
        }
        let value = payload[in_pos];
        in_pos += 1;
        out.push(value);

        if in_pos >= payload.len() {
            if out.len() == dsize {
                break;
            }
            return Err(CarverError::Jffs2(
                "RTIME payload truncated reading repeat length".to_string(),
            ));
        }
        let repeat = payload[in_pos] as usize;
        in_pos += 1;

        let mut backoffs = positions[value as usize];
        positions[value as usize] = out.len();

        if repeat > 0 {
            if out.len() + repeat > dsize {
                return Err(CarverError::Jffs2(format!(
                    "RTIME repeat length {} exceeds destination limit {}",
                    repeat, dsize
                )));
            }
            if backoffs >= out.len() {
                return Err(CarverError::Jffs2(format!(
                    "RTIME invalid backoff pointer {} with buffer length {}",
                    backoffs,
                    out.len()
                )));
            }
            for _ in 0..repeat {
                if backoffs >= out.len() {
                    return Err(CarverError::Jffs2(
                        "RTIME backoff overrun during dictionary replay".to_string(),
                    ));
                }
                let b = out[backoffs];
                backoffs += 1;
                out.push(b);
            }
        }
    }
    Ok(out)
}

/// Decompresses a ZLIB or raw Deflate stream.
pub fn decompress_zlib(payload: &[u8], dsize: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(dsize);
    // Attempt standard RFC 1950 Zlib header first
    let mut decoder = ZlibDecoder::new(payload);
    if decoder.read_to_end(&mut out).is_ok() && !out.is_empty() {
        if out.len() > dsize {
            out.truncate(dsize);
        }
        return Ok(out);
    }

    // Fallback to raw Deflate RFC 1951 if no Zlib header present
    out.clear();
    let mut raw_decoder = DeflateDecoder::new(payload);
    raw_decoder
        .read_to_end(&mut out)
        .map_err(|e| CarverError::Jffs2(format!("ZLIB/Deflate decompression failed: {}", e)))?;

    if out.len() > dsize {
        out.truncate(dsize);
    }
    Ok(out)
}

/// Compresses data using JFFS2 RTIME algorithm for testing and fixtures.
pub fn compress_rtime(input: &[u8]) -> Option<Vec<u8>> {
    if input.is_empty() {
        return Some(Vec::new());
    }
    let mut positions = [0usize; 256];
    let mut out = Vec::new();
    let mut pos = 0;

    while pos < input.len() {
        let value = input[pos];
        out.push(value);
        pos += 1;

        let mut backpos = positions[value as usize];
        positions[value as usize] = pos;

        let mut runlen = 0u8;
        while backpos < pos && pos < input.len() && input[pos] == input[backpos] && runlen < 255 {
            pos += 1;
            backpos += 1;
            runlen += 1;
        }
        out.push(runlen);
    }

    Some(out)
}

/// Compresses data using standard ZLIB format for testing and fixtures.
pub fn compress_zlib(input: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(input)
        .map_err(|e| CarverError::Jffs2(format!("Failed to compress ZLIB stream: {}", e)))?;
    encoder
        .finish()
        .map_err(|e| CarverError::Jffs2(format!("Failed to finalize ZLIB stream: {}", e)))
}
