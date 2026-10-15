// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::types::{Endianness, CRAMFS_BLK_FLAG_UNCOMPRESSED};
use crate::error::{CarverError, Result};
use flate2::read::ZlibDecoder;
use std::io::Read;

pub const CRAMFS_MAX_UNCOMPRESSED_FILE_SIZE: usize = 32 * 1024 * 1024; // 32 MB safety ceiling
pub const CRAMFS_BLOCK_SIZE: usize = 4096;

pub fn decompress_file_blocks(
    data: &[u8],
    file_offset: usize,
    file_size: usize,
    endian: Endianness,
    _flags: u32,
) -> Result<Vec<u8>> {
    if file_size == 0 {
        return Ok(Vec::new());
    }

    if file_size > CRAMFS_MAX_UNCOMPRESSED_FILE_SIZE {
        return Err(CarverError::CramFs(format!(
            "File size {} exceeds maximum safe limit of {} bytes",
            file_size, CRAMFS_MAX_UNCOMPRESSED_FILE_SIZE
        )));
    }

    let base_offset = file_offset;
    let num_blocks = file_size.div_ceil(CRAMFS_BLOCK_SIZE);
    let ptrs_len = num_blocks.saturating_mul(4);

    if base_offset.saturating_add(ptrs_len) > data.len() {
        return Err(CarverError::CramFs(format!(
            "Block pointer array out of bounds: offset 0x{:X} + len {} > data {}",
            base_offset,
            ptrs_len,
            data.len()
        )));
    }

    let mut block_ptrs = Vec::with_capacity(num_blocks);
    for i in 0..num_blocks {
        let ptr_pos = base_offset + i * 4;
        let ptr_raw = match endian {
            Endianness::Little => {
                u32::from_le_bytes(data[ptr_pos..ptr_pos + 4].try_into().unwrap())
            }
            Endianness::Big => u32::from_be_bytes(data[ptr_pos..ptr_pos + 4].try_into().unwrap()),
        };
        block_ptrs.push(ptr_raw);
    }

    let mut out = Vec::with_capacity(file_size);
    let mut prev_end = base_offset + ptrs_len;

    for (i, &raw_ptr) in block_ptrs.iter().enumerate() {
        let is_uncompressed = (raw_ptr & CRAMFS_BLK_FLAG_UNCOMPRESSED) != 0;
        let block_end = (raw_ptr & 0x03FF_FFFF) as usize;

        if block_end < prev_end {
            return Err(CarverError::CramFs(format!(
                "Corrupt block pointer at index {}: end 0x{:X} < start 0x{:X}",
                i, block_end, prev_end
            )));
        }

        if block_end > data.len() {
            return Err(CarverError::CramFs(format!(
                "Block offset 0x{:X} exceeds image length {}",
                block_end,
                data.len()
            )));
        }

        let compressed_chunk = &data[prev_end..block_end];
        let remaining_bytes = file_size.saturating_sub(out.len());
        let expected_chunk_size = remaining_bytes.min(CRAMFS_BLOCK_SIZE);

        if compressed_chunk.is_empty() {
            // Hole block: zero-fill
            out.resize(out.len() + expected_chunk_size, 0);
        } else if is_uncompressed {
            let take_len = compressed_chunk.len().min(expected_chunk_size);
            out.extend_from_slice(&compressed_chunk[..take_len]);
        } else {
            let mut decoder = ZlibDecoder::new(compressed_chunk);
            let mut decompressed = Vec::with_capacity(expected_chunk_size);
            match decoder.read_to_end(&mut decompressed) {
                Ok(_) => {
                    let take_len = decompressed.len().min(expected_chunk_size);
                    out.extend_from_slice(&decompressed[..take_len]);
                }
                Err(_) => {
                    // Fallback to raw copy if zlib fails and sizes match
                    let take_len = compressed_chunk.len().min(expected_chunk_size);
                    out.extend_from_slice(&compressed_chunk[..take_len]);
                }
            }
        }

        prev_end = block_end;
        if out.len() >= file_size {
            break;
        }
    }

    out.truncate(file_size);
    Ok(out)
}

pub fn decompress_symlink_target(
    data: &[u8],
    file_offset: usize,
    symlink_size: usize,
    endian: Endianness,
    flags: u32,
) -> Result<String> {
    if symlink_size == 0 {
        return Ok(String::new());
    }

    let bytes = decompress_file_blocks(data, file_offset, symlink_size, endian, flags)?;
    let target = String::from_utf8_lossy(&bytes).to_string();
    Ok(target)
}
