// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use super::superblock::{CompressionType, Endianness};
use crate::error::{CarverError, Result};
use flate2::read::DeflateDecoder;
use std::io::Read;

pub const MAX_METADATA_BLOCK_SIZE: usize = 8192;

/// Low-level sequential and random-access reader for SquashFS v4 metadata blocks.
pub struct MetadataReader<'a> {
    data: &'a [u8],
    endianness: Endianness,
    compression: CompressionType,
    cached_disk_offset: Option<usize>,
    cached_block_data: Vec<u8>,
    cached_next_disk_offset: usize,
}

impl<'a> MetadataReader<'a> {
    pub fn new(data: &'a [u8], endianness: Endianness, compression: CompressionType) -> Self {
        Self {
            data,
            endianness,
            compression,
            cached_disk_offset: None,
            cached_block_data: Vec::new(),
            cached_next_disk_offset: 0,
        }
    }

    /// Decompresses or extracts a single SquashFS metadata block at the given absolute disk offset.
    /// Returns a slice of the decompressed bytes and the disk offset of the immediately following block.
    pub fn get_block(&mut self, disk_offset: usize) -> Result<(&[u8], usize)> {
        if let Some(cached_offset) = self.cached_disk_offset {
            if cached_offset == disk_offset {
                return Ok((&self.cached_block_data, self.cached_next_disk_offset));
            }
        }

        if disk_offset + 2 > self.data.len() {
            return Err(CarverError::SquashFs(format!(
                "Metadata block header out of bounds: offset 0x{:08X} (image size 0x{:08X})",
                disk_offset,
                self.data.len()
            )));
        }

        let header_raw = [self.data[disk_offset], self.data[disk_offset + 1]];
        let header = match self.endianness {
            Endianness::Little => u16::from_le_bytes(header_raw),
            Endianness::Big => u16::from_be_bytes(header_raw),
        };

        let is_uncompressed = (header & 0x8000) != 0;
        let data_size = (header & 0x7FFF) as usize;

        if data_size > MAX_METADATA_BLOCK_SIZE {
            return Err(CarverError::SquashFs(format!(
                "Metadata block size exceeds 8KB limit: {} bytes at 0x{:08X}",
                data_size, disk_offset
            )));
        }

        let start = disk_offset + 2;
        let end = start + data_size;
        if end > self.data.len() {
            return Err(CarverError::SquashFs(format!(
                "Metadata block payload truncated: expected {} bytes at 0x{:08X}",
                data_size, start
            )));
        }

        let raw_payload = &self.data[start..end];
        let decompressed = if is_uncompressed {
            raw_payload.to_vec()
        } else {
            match self.compression {
                CompressionType::Gzip => {
                    let mut decoder = DeflateDecoder::new(raw_payload);
                    let mut decomp = Vec::with_capacity(MAX_METADATA_BLOCK_SIZE);
                    decoder.read_to_end(&mut decomp).map_err(|e| {
                        CarverError::SquashFs(format!(
                            "Deflate decompression failed at 0x{:08X}: {}",
                            disk_offset, e
                        ))
                    })?;
                    decomp
                }
                other => {
                    // Fallback attempt with deflate in case compressor tag differs
                    let mut decoder = DeflateDecoder::new(raw_payload);
                    let mut decomp = Vec::with_capacity(MAX_METADATA_BLOCK_SIZE);
                    if decoder.read_to_end(&mut decomp).is_ok() {
                        decomp
                    } else {
                        return Err(CarverError::SquashFs(format!(
                            "Unsupported metadata block compression {:?} at 0x{:08X}",
                            other, disk_offset
                        )));
                    }
                }
            }
        };

        self.cached_disk_offset = Some(disk_offset);
        self.cached_block_data = decompressed;
        self.cached_next_disk_offset = end;

        Ok((&self.cached_block_data, self.cached_next_disk_offset))
    }

    /// Reads arbitrary contiguous bytes across metadata block boundaries.
    pub fn read_bytes(
        &mut self,
        mut disk_offset: usize,
        mut in_block_offset: usize,
        mut count: usize,
    ) -> Result<Vec<u8>> {
        let mut result = Vec::with_capacity(count);

        while count > 0 {
            let (block, next_disk) = self.get_block(disk_offset)?;
            if in_block_offset >= block.len() {
                return Err(CarverError::SquashFs(format!(
                    "In-block offset {} exceeds decompressed block size {} (block 0x{:08X})",
                    in_block_offset,
                    block.len(),
                    disk_offset
                )));
            }

            let available = block.len() - in_block_offset;
            let take = available.min(count);
            result.extend_from_slice(&block[in_block_offset..in_block_offset + take]);

            count -= take;
            in_block_offset += take;

            if count > 0 {
                disk_offset = next_disk;
                in_block_offset = 0;
            }
        }

        Ok(result)
    }

    pub fn read_u16(&mut self, disk_offset: usize, in_block_offset: usize) -> Result<u16> {
        let bytes = self.read_bytes(disk_offset, in_block_offset, 2)?;
        let arr: [u8; 2] = bytes
            .try_into()
            .map_err(|_| CarverError::SquashFs("Failed to unpack u16 from metadata".to_string()))?;
        Ok(match self.endianness {
            Endianness::Little => u16::from_le_bytes(arr),
            Endianness::Big => u16::from_be_bytes(arr),
        })
    }

    pub fn read_i16(&mut self, disk_offset: usize, in_block_offset: usize) -> Result<i16> {
        let bytes = self.read_bytes(disk_offset, in_block_offset, 2)?;
        let arr: [u8; 2] = bytes
            .try_into()
            .map_err(|_| CarverError::SquashFs("Failed to unpack i16 from metadata".to_string()))?;
        Ok(match self.endianness {
            Endianness::Little => i16::from_le_bytes(arr),
            Endianness::Big => i16::from_be_bytes(arr),
        })
    }

    pub fn read_u32(&mut self, disk_offset: usize, in_block_offset: usize) -> Result<u32> {
        let bytes = self.read_bytes(disk_offset, in_block_offset, 4)?;
        let arr: [u8; 4] = bytes
            .try_into()
            .map_err(|_| CarverError::SquashFs("Failed to unpack u32 from metadata".to_string()))?;
        Ok(match self.endianness {
            Endianness::Little => u32::from_le_bytes(arr),
            Endianness::Big => u32::from_be_bytes(arr),
        })
    }

    pub fn read_u64(&mut self, disk_offset: usize, in_block_offset: usize) -> Result<u64> {
        let bytes = self.read_bytes(disk_offset, in_block_offset, 8)?;
        let arr: [u8; 8] = bytes
            .try_into()
            .map_err(|_| CarverError::SquashFs("Failed to unpack u64 from metadata".to_string()))?;
        Ok(match self.endianness {
            Endianness::Little => u64::from_le_bytes(arr),
            Endianness::Big => u64::from_be_bytes(arr),
        })
    }
}
