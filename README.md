<div align="center">

<p align="center">
  <strong>🇺🇸 English</strong> · <a href="./docs/locales/ko.md">🇰🇷 한국어</a> · <a href="./docs/locales/zh-CN.md">🇨🇳 中文</a> · <a href="./docs/locales/es.md">🇪🇸 Español</a> · <a href="./docs/locales/hi.md">🇮🇳 हिन्दी</a><br />
  <a href="./docs/locales/ar.md">🇸🇦 العربية</a> · <a href="./docs/locales/pt-BR.md">🇧🇷 Português</a> · <a href="./docs/locales/ru.md">🇷🇺 Русский</a> · <a href="./docs/locales/fr.md">🇫🇷 Français</a> · <a href="./docs/locales/id.md">🇮🇩 Bahasa Indonesia</a>
</p>

<p align="center">
  <img src="./docs/assets/locales/en/banner.svg" alt="FirmCarver (fcarver) banner" width="100%" />
</p>

# FirmCarver (fcarver)

**Zero-Dependency IoT & Embedded Firmware Unpacker, Multi-Format Magic Carver, and Static Vulnerability Auditing Engine**

[![CI](https://github.com/GHSFS/firm-carver/actions/workflows/ci.yml/badge.svg)](https://github.com/GHSFS/firm-carver/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](./Cargo.toml)
[![Zero Unsafe](https://img.shields.io/badge/Memory_Safety-100%25_Safe_Rust-10b981.svg)](./SECURITY.md)

<sub>Architected &amp; Licensed by **GHSFS** · Zero-Dependency IoT Firmware Analysis &amp; Carving</sub>

</div>

---

## 🛡️ Overview & Core Capabilities

<details open>
<summary><b>🛡️ Overview & Core Capabilities</b></summary>
<br>

firm-carver (fcarver) is a fast, memory-safe command-line utility and Rust library for offline IoT firmware container inspection, multi-format filesystem stream carving, and static security auditing without C libraries or external binwalk dependencies.

1. **Zero-Dependency Container Header Parsers (`src/image.rs`)** — Automatically detects and verifies U-Boot `uImage` (Magic `0x27051956` big-endian with dual 32-bit CRC calculation), Broadcom `TRX` headers (`0x30304448` / `HDR0` with 3 partition offsets), and Flattened Device Tree blobs (`0xD00DFEED` / FDT).
2. **Magic-Byte Stream Carving Engine (`src/carve.rs`)** — Scans raw firmware blobs for SquashFS 4.0 (`0x73717368` / `0x68737173`), CramFS (`0x28cd3d45` / `0x453dcd28`), Gzip (`0x1F8B08`), LZMA (`0x5D0000`), and XZ (`0xFD377A585A00`), extracts partitions into dedicated files, and writes structured JSON manifests.
3. **Static Firmware Vulnerability & Backdoor Auditor (`src/vuln_scan.rs`)** — Identifies hardcoded private keys (RSA, EC, OpenSSH, PKCS#8), static `/etc/shadow` root hashes, empty root accounts, unauthenticated root shells (`telnetd -l /bin/sh`), firewall flushing (`iptables -F`), and netcat reverse shells.
4. **Deterministic Firmware Synthesis (`fcarver synth-fw`)** — Generates valid synthetic firmware blobs containing headers and filesystem streams for automated CI verification and vulnerability signature validation.
5. **Entropy-Guided Bootloader & Kernel Boundary Slicer (`src/slicer/`)** — Computes sliding-window Shannon entropy profiles, detecting sharp inflection points between bootloaders, compressed kernels, and encrypted filesystems.
6. **Cryptographic Integrity & Attestation Manifest Generator (`src/integrity/`)** — Computes SHA-256, SHA-512, and BLAKE3 digests across images and carved partitions, emitting and verifying tamper-evident integrity manifests.

</details>

---

## 🏛️ Firmware Inspection & Stream Carving Architecture

<details open>
<summary><b>🏛️ Firmware Inspection & Stream Carving Architecture</b></summary>
<br>

<p align="center">
  <img src="./docs/assets/locales/en/architecture.svg" alt="Firmware Inspection & Stream Carving Architecture" width="100%" />
</p>

| # | Component | Module | Responsibility |
|---|---|---|---|
| **01** | **01 · Container Header Parser** | `src/image.rs` | Zero-dependency U-Boot uImage, Broadcom TRX & Flattened Device Tree (FDT) decoders |
| **02** | **02 · Magic Stream Carving Engine** | `src/carve.rs` | Multi-endian SquashFS v4, CramFS, Gzip, LZMA & XZ stream carver |
| **03** | **03 · Extraction & Manifest Lab** | `manifest.json` | Deterministic partition slicing, stream sizing & structured JSON extraction records |
| **04** | **04 · Vulnerability & Backdoor Audit** | `src/vuln_scan.rs` | Static sweep for embedded RSA/EC keys, /etc/shadow hashes, telnetd -l /bin/sh & reverse shells |
| **05** | **05 · Synthetic Firmware Lab** | `synth-fw & --json` | Deterministic multi-partition firmware generation & SIEM-ready structured JSON telemetry |

</details>

---

## 🚀 Quick Start & CLI Usage

<details open>
<summary><b>🚀 Quick Start & CLI Usage</b></summary>
<br>

```bash
# 1. Build the release binary
cargo build --release

# 2. Generate a deterministic sample firmware image (U-Boot or TRX)
./target/release/fcarver synth-fw sample_uboot.bin --type uboot
./target/release/fcarver synth-fw sample_trx.bin --type trx

# 3. Inspect container headers (U-Boot, TRX, FDT)
./target/release/fcarver inspect sample_uboot.bin
./target/release/fcarver inspect sample_uboot.bin --json

# 4. Carve embedded filesystems (SquashFS, CramFS) and compressed streams
./target/release/fcarver carve sample_uboot.bin --out ./extracted_fs
./target/release/fcarver carve sample_uboot.bin --out ./extracted_fs --json

# 5. Extract SquashFS directory tree, file permissions, and symlinks
./target/release/fcarver squashfs sample_uboot.bin --list
./target/release/fcarver squashfs sample_uboot.bin --json

# 6. Disassemble Device Tree Blob (FDT) into DTS or map hardware peripherals
./target/release/fcarver fdt sample_uboot.bin --dts
./target/release/fcarver fdt sample_uboot.bin --hardware
./target/release/fcarver fdt sample_uboot.bin --json

# 7. Detect CPU instruction set and scan for shellcode payloads (MIPS, ARM, AArch64, RISC-V)
./target/release/fcarver arch-detect sample_uboot.bin
./target/release/fcarver arch-detect sample_uboot.bin --json
./target/release/fcarver arch-detect sample_uboot.bin --disasm

# 8. Slice bootloader, kernel, and filesystem partitions via Shannon entropy
./target/release/fcarver slice sample_uboot.bin --plot
./target/release/fcarver slice sample_uboot.bin --json
./target/release/fcarver slice sample_uboot.bin --out ./sliced_fs

# 9. Generate and verify cryptographic digests (SHA-256, SHA-512, BLAKE3) and integrity manifests
./target/release/fcarver integrity sample_uboot.bin
./target/release/fcarver integrity sample_uboot.bin --out manifest.json
./target/release/fcarver integrity sample_uboot.bin --verify manifest.json
./target/release/fcarver integrity sample_uboot.bin --algo blake3
./target/release/fcarver integrity sample_uboot.bin --json

# 10. Audit firmware blob for embedded private keys, default credentials, and backdoors
./target/release/fcarver audit sample_uboot.bin
./target/release/fcarver audit sample_uboot.bin --json
```

</details>

---

## 📦 Module & Subcommand Reference

<details open>
<summary><b>📦 Module & Subcommand Reference</b></summary>
<br>

| Subcommand | Arguments | Description |
|---|---|---|
| `inspect` | `<file> [--json]` | Identifies container headers: U-Boot, TRX, FDT, architecture, offsets |
| `carve` | `<file> --out <dir> [--json]` | Carves embedded SquashFS, CramFS, Gzip, LZMA partitions to disk |
| `squashfs` | `<file> [--list] [--json] [--offset <bytes>]` | Extracts directory tree, inode metadata, and symlinks from SquashFS v4 |
| `fdt` | `<file> [--dts] [--hardware] [--json] [--offset <bytes>]` | Disassembles Device Tree (FDT) into DTS and maps peripheral hardware |
| `arch-detect` | `<file> [--offset <bytes>] [--length <bytes>] [--min-confidence <float>] [--disasm] [--json]` | Scores CPU architecture (MIPS/ARM/AArch64/RISC-V) and detects shellcode payloads |
| `slice` | `<file> [--window <bytes>] [--step <bytes>] [--threshold <float>] [--plot] [--out <dir>] [--json]` | Computes sliding Shannon entropy, detects bootloader/kernel boundaries, slices partitions |
| `integrity` | `<file> [--out <manifest.json>] [--verify <manifest.json>] [--algo <sha256|sha512|blake3|all>] [--json]` | Generates and verifies SHA-256, SHA-512, BLAKE3 digests and partition attestation manifests |
| `audit` | `<file> [--json]` | Scans for hardcoded credentials, private keys, backdoor commands |
| `synth-fw` | `<output> [--type <uboot|trx|fdt|squashfs|multi-stage|shellcode-mips|shellcode-arm|shellcode-aarch64|shellcode-riscv|integrity>]` | Generates a valid synthetic firmware blob for testing/analysis |


</details>

---

## 🔒 Memory Safety & Parser Hardening

<details open>
<summary><b>🔒 Memory Safety & Parser Hardening</b></summary>
<br>

- **100% Safe Rust**: No `unsafe` blocks are permitted in parser or carver code paths.
- **Slice Bounds & Integer Overflow Hardening**: All partition offsets and length calculations are guarded against integer wrapping and buffer over-reads.
- **Buffer Sanitization**: Sensitive decrypted or analyzed data buffers implement explicit zeroization on drop via `zeroize`.

See [SECURITY.md](./SECURITY.md) for our vulnerability disclosure policy and parser invariants.

</details>

---

## 📄 License & Attribution

<details open>
<summary><b>📄 License & Attribution</b></summary>
<br>

Licensed under the **Apache License, Version 2.0**. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE) for copyright and attribution details.

Check our long-term milestones in [ROADMAP.md](./ROADMAP.md).

</details>
