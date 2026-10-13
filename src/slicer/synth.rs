// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use flate2::write::DeflateEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use std::io::Write;

/// Generates a realistic synthetic bootloader code segment (entropy ~4.8 to 6.2).
pub fn build_bootloader_stage(size: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(size);

    let banner = b"U-Boot 2026.04-rc1 (ARMv7 Cortex-A7) Bootloader Image\0";
    buf.extend_from_slice(banner);

    let env_strings = [
        b"bootcmd=bootm 0x82000000 - 0x88000000\0".as_slice(),
        b"bootargs=console=ttyAMA0,115200 root=/dev/mtdblock3 rw\0".as_slice(),
        b"baudrate=115200\0".as_slice(),
        b"ethaddr=00:1A:2B:3C:4D:5E\0".as_slice(),
        b"serverip=192.168.1.1\0".as_slice(),
        b"ipaddr=192.168.1.100\0".as_slice(),
    ];

    let mut step = 0u32;
    let mut str_idx = 0;

    while buf.len() < size {
        if str_idx < env_strings.len()
            && (step % 16 == 0)
            && buf.len() + env_strings[str_idx].len() <= size
        {
            buf.extend_from_slice(env_strings[str_idx]);
            str_idx += 1;
        } else if buf.len() + 4 <= size {
            let reg = (step % 15) as u8;
            let imm = ((step.wrapping_mul(37) + 13) % 256) as u8;
            let opcode_type = step % 6;
            let insn = match opcode_type {
                0 => [imm, reg << 4, 0xA0, 0xE3],                  // mov rX, #imm
                1 => [imm, (reg << 4) | (reg & 0x0F), 0x80, 0xE2], // add rX, rX, #imm
                2 => [imm, (reg << 4) | (reg & 0x0F), 0x40, 0xE2], // sub rX, rX, #imm
                3 => [imm, reg << 4, 0x9F, 0xE5],                  // ldr rX, [pc, #imm]
                4 => [imm, reg << 4, 0x8F, 0xE5],                  // str rX, [pc, #imm]
                _ => [imm, (reg << 4) | 0x01, (step % 16) as u8, 0xEB], // bl target
            };
            buf.extend_from_slice(&insn);
            step += 1;
        } else {
            buf.push(0x00);
        }
    }

    buf.truncate(size);
    buf
}

/// Generates a padding block with repeated identical bytes (entropy 0.0).
pub fn build_padding_stage(size: usize, fill_byte: u8) -> Vec<u8> {
    vec![fill_byte; size]
}

/// Generates plaintext configuration tables or environment data (entropy ~3.5 to 4.2).
pub fn build_text_stage(size: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(size);
    let mut idx = 0;
    while buf.len() < size {
        let line = format!(
            "system.ntp.server='pool.ntp.org'\nnetwork.lan.ipaddr='192.168.1.1'\nwireless.ssid='FirmCarver_{}'\n",
            idx % 8
        );
        buf.extend_from_slice(line.as_bytes());
        idx += 1;
    }
    buf.truncate(size);
    buf
}

/// Generates a compressed payload using Deflate (entropy ~7.4 to 7.85).
pub fn build_compressed_stage(size: usize) -> Vec<u8> {
    let mut source = Vec::with_capacity(size * 4);
    for i in 0..(size * 2) as u32 {
        source.extend_from_slice(&[
            (i % 256) as u8,
            ((i / 256) % 256) as u8,
            0xAA,
            ((i.wrapping_mul(31) + 17) % 256) as u8,
            0x55,
        ]);
        if i % 8 == 0 {
            source.extend_from_slice(b"Linux vmlinux initramfs");
        }
    }

    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
    let _ = encoder.write_all(&source);
    let mut compressed = encoder.finish().unwrap_or_default();

    if compressed.len() >= size {
        compressed.truncate(size);
    } else {
        while compressed.len() < size {
            let needed = size - compressed.len();
            let mut more = DeflateEncoder::new(Vec::new(), Compression::fast());
            let _ = more.write_all(&source);
            let chunk = more.finish().unwrap_or_default();
            compressed.extend_from_slice(&chunk[..chunk.len().min(needed)]);
        }
    }

    compressed
}

/// Generates an encrypted / high-entropy cryptographic block (entropy >= 7.95).
pub fn build_encrypted_stage(size: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(size);
    let mut counter = 0u64;

    while buf.len() < size {
        let mut hasher = Sha256::new();
        hasher.update(b"ENCRYPTED_PAYLOAD_KEY_STREAM_SALT_2026_");
        hasher.update(counter.to_be_bytes());
        let digest = hasher.finalize();

        let need = size - buf.len();
        if need >= 32 {
            buf.extend_from_slice(&digest);
        } else {
            buf.extend_from_slice(&digest[..need]);
        }
        counter += 1;
    }

    buf
}

/// Builds a deterministic 5-stage synthetic firmware image with known boundaries:
/// - 0x0000..0x1000: Bootloader (4096 B, entropy ~5.4)
/// - 0x1000..0x3000: Compressed kernel (8192 B, entropy ~7.6)
/// - 0x3000..0x3800: Plaintext config data (2048 B, entropy ~4.0)
/// - 0x3800..0x3C00: Zero padding (1024 B, entropy 0.0)
/// - 0x3C00..0x4C00: Encrypted / random keystore (4096 B, entropy ~7.98)
///
/// Total size: 19,456 bytes (19 KiB)
pub fn build_synthetic_sliced_firmware() -> Vec<u8> {
    let mut blob = Vec::with_capacity(19456);

    // 1. Bootloader (4096 bytes)
    blob.extend_from_slice(&build_bootloader_stage(4096));

    // 2. Compressed kernel (8192 bytes)
    blob.extend_from_slice(&build_compressed_stage(8192));

    // 3. Plaintext config tables (2048 bytes)
    blob.extend_from_slice(&build_text_stage(2048));

    // 4. Zero-fill padding (1024 bytes)
    blob.extend_from_slice(&build_padding_stage(1024, 0x00));

    // 5. Encrypted payload (4096 bytes)
    blob.extend_from_slice(&build_encrypted_stage(4096));

    blob
}
