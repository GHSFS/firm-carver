// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use zeroize::Zeroize;

/// Extracted PEM container block with label and decoded payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PemBlock {
    pub label: String,
    pub data: Vec<u8>,
}

impl Drop for PemBlock {
    fn drop(&mut self) {
        if self.label.contains("PRIVATE KEY") {
            self.data.zeroize();
        }
    }
}

/// Decode standard RFC 4648 Base64 string into raw binary bytes.
pub fn decode_base64(input: &str) -> Option<Vec<u8>> {
    let mut clean = Vec::with_capacity(input.len());
    for b in input.bytes() {
        if !b.is_ascii_whitespace() {
            clean.push(b);
        }
    }
    if clean.is_empty() || clean.len() % 4 != 0 {
        return None;
    }

    let b64_val = |b: u8| -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };

    let mut out = Vec::with_capacity((clean.len() / 4) * 3);
    for chunk in clean.chunks(4) {
        let v0 = b64_val(chunk[0])?;
        let v1 = b64_val(chunk[1])?;
        let v2 = if chunk[2] == b'=' {
            0
        } else {
            b64_val(chunk[2])?
        };
        let v3 = if chunk[3] == b'=' {
            0
        } else {
            b64_val(chunk[3])?
        };

        let triple = ((v0 as u32) << 18) | ((v1 as u32) << 12) | ((v2 as u32) << 6) | (v3 as u32);
        out.push(((triple >> 16) & 0xFF) as u8);
        if chunk[2] != b'=' {
            out.push(((triple >> 8) & 0xFF) as u8);
        }
        if chunk[3] != b'=' {
            out.push((triple & 0xFF) as u8);
        }
    }
    clean.zeroize();
    Some(out)
}

/// Encode raw binary bytes into standard RFC 4648 Base64 string.
pub fn encode_base64(data: &[u8]) -> String {
    const CHARSET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };

        let triple = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(CHARSET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(CHARSET[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(CHARSET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(CHARSET[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Parse all PEM blocks from an ASCII / UTF-8 string buffer.
pub fn parse_pem_blocks(input: &str) -> Vec<PemBlock> {
    let mut blocks = Vec::new();
    let begin_marker = "-----BEGIN ";
    let end_marker = "-----END ";

    let mut remaining = input;
    while let Some(start_idx) = remaining.find(begin_marker) {
        let after_begin = &remaining[start_idx + begin_marker.len()..];
        let header_end = match after_begin.find("-----") {
            Some(idx) => idx,
            None => break,
        };
        let label = after_begin[..header_end].trim().to_string();
        let payload_start = &after_begin[header_end + 5..];

        let end_tag = format!("{}{}{}-----", end_marker, label, "");
        let (body, next_slice) = match payload_start.find(&end_tag) {
            Some(end_idx) => (
                &payload_start[..end_idx],
                &payload_start[end_idx + end_tag.len()..],
            ),
            None => break,
        };

        if let Some(decoded) = decode_base64(body) {
            blocks.push(PemBlock {
                label,
                data: decoded,
            });
        }
        remaining = next_slice;
    }
    blocks
}
