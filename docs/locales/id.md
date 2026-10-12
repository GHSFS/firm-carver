<p align="center">
  [🇺🇸 English](../README.md) &nbsp;•&nbsp; [🇰🇷 한국어](./ko.md) &nbsp;•&nbsp; [🇨🇳 中文](./zh-CN.md) &nbsp;•&nbsp; [🇪🇸 Español](./es.md) &nbsp;•&nbsp; [🇮🇳 हिन्दी](./hi.md) &nbsp;•&nbsp; [🇸🇦 العربية](./ar.md) &nbsp;•&nbsp; [🇧🇷 Português (Brasil)](./pt-BR.md) &nbsp;•&nbsp; [🇷🇺 Русский](./ru.md) &nbsp;•&nbsp; [🇫🇷 Français](./fr.md) &nbsp;•&nbsp; **🇮🇩 Bahasa Indonesia**
</p>


<p align="center">
  <img src="../assets/locales/id/banner.svg" alt="FirmCarver (fcarver) banner" width="100%" />
</p>

# FirmCarver (fcarver)

**Unpacker Firmware IoT Nol Ketergantungan, Pahat Aliran Multi-Format dan Mesin Audit Kerentanan Statis di Rust**

[![CI](https://github.com/GHSFS/firm-carver/actions/workflows/ci.yml/badge.svg)](https://github.com/GHSFS/firm-carver/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](./Cargo.toml)
[![Zero Unsafe](https://img.shields.io/badge/Memory_Safety-100%25_Safe_Rust-10b981.svg)](../../SECURITY.md)

---

## 🛡️ Ikhtisar & Kemampuan Inti

<details open>
<summary><b>🛡️ Ikhtisar & Kemampuan Inti</b></summary>
<br>

firm-carver (fcarver) adalah utilitas CLI dan pustaka Rust murni untuk inspeksi wadah firmware IoT offline, pemahatan aliran sistem file terkompresi, dan audit keamanan statis tanpa pustaka C eksternal atau dependensi binwalk.

1. **Zero-Dependency Container Header Parsers (`src/image.rs`)** — Automatically detects and verifies U-Boot `uImage` (Magic `0x27051956` big-endian with dual 32-bit CRC calculation), Broadcom `TRX` headers (`0x30304448` / `HDR0` with 3 partition offsets), and Flattened Device Tree blobs (`0xD00DFEED` / FDT).
2. **Magic-Byte Stream Carving Engine (`src/carve.rs`)** — Scans raw firmware blobs for SquashFS 4.0 (`0x73717368` / `0x68737173`), CramFS (`0x28cd3d45` / `0x453dcd28`), Gzip (`0x1F8B08`), LZMA (`0x5D0000`), and XZ (`0xFD377A585A00`), extracts partitions into dedicated files, and writes structured JSON manifests.
3. **Static Firmware Vulnerability & Backdoor Auditor (`src/vuln_scan.rs`)** — Identifies hardcoded private keys (RSA, EC, OpenSSH, PKCS#8), static `/etc/shadow` root hashes, empty root accounts, unauthenticated root shells (`telnetd -l /bin/sh`), firewall flushing (`iptables -F`), and netcat reverse shells.
4. **Deterministic Firmware Synthesis (`fcarver synth-fw`)** — Generates valid synthetic firmware blobs containing headers and filesystem streams for automated CI verification and vulnerability signature validation.

</details>

---

## 🏛️ Arsitektur Inspeksi Firmware & Pemahatan Aliran

<details open>
<summary><b>🏛️ Arsitektur Inspeksi Firmware & Pemahatan Aliran</b></summary>
<br>

<p align="center">
  <img src="../assets/locales/id/architecture.svg" alt="Arsitektur Inspeksi Firmware & Pemahatan Aliran" width="100%" />
</p>

| # | Component | Module | Responsibility |
|---|---|---|---|
| **01** | **01 · Pengurai Header Wadah** | `src/image.rs` | Dekoder wadah U-Boot uImage, Broadcom TRX, dan Device Tree Blob (FDT) |
| **02** | **02 · Mesin Pahat Aliran Ajaib** | `src/carve.rs` | Pencarian dan ekstraksi aliran SquashFS v4, CramFS, Gzip, LZMA, dan XZ |
| **03** | **03 · Ekstraksi & Manifest** | `manifest.json` | Pemotongan partisi deterministik dan pencatatan manifest berformat JSON |
| **04** | **04 · Auditor Kerentanan & Backdoor** | `src/vuln_scan.rs` | Pemindaian statis kunci RSA/EC, hash kata sandi shadow, dan backdoor telnetd |
| **05** | **05 · Lab Firmware Sintetis** | `synth-fw & --json` | Pembuatan sampel firmware multi-partisi dan keluaran telemetri JSON |

</details>

---

## 🚀 Panduan Cepat & Penggunaan CLI

<details open>
<summary><b>🚀 Panduan Cepat & Penggunaan CLI</b></summary>
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

# 5. Audit firmware blob for embedded private keys, default credentials, and backdoors
./target/release/fcarver audit sample_uboot.bin
./target/release/fcarver audit sample_uboot.bin --json
```

</details>

---

## 📦 Referensi Modul & Subperintah

<details open>
<summary><b>📦 Referensi Modul & Subperintah</b></summary>
<br>

| Subcommand | Arguments | Description |
|---|---|---|
| `inspect` | `<file> [--json]` | Identifies container headers: U-Boot, TRX, FDT, architecture, offsets |
| `carve` | `<file> --out <dir> [--json]` | Carves embedded SquashFS, CramFS, Gzip, LZMA partitions to disk |
| `audit` | `<file> [--json]` | Scans for hardcoded credentials, private keys, backdoor commands |
| `synth-fw` | `<output> [--type <uboot|trx>]` | Generates a valid synthetic firmware blob for testing/analysis |

</details>

---

## 🔒 Keamanan Memori & Pengerasan Parser

<details open>
<summary><b>🔒 Keamanan Memori & Pengerasan Parser</b></summary>
<br>

- **100% Safe Rust**: No `unsafe` blocks are permitted in parser or carver code paths.
- **Slice Bounds & Integer Overflow Hardening**: All partition offsets and length calculations are guarded against integer wrapping and buffer over-reads.
- **Buffer Sanitization**: Sensitive decrypted or analyzed data buffers implement explicit zeroization on drop via `zeroize`.

See [SECURITY.md](../../SECURITY.md) for our vulnerability disclosure policy and parser invariants.

</details>

---

## 📄 Lisensi & Atribusi

<details open>
<summary><b>📄 Lisensi & Atribusi</b></summary>
<br>

Licensed under the **Apache License, Version 2.0**. See [LICENSE](../../LICENSE) and [NOTICE](./NOTICE) for copyright and attribution details.

Check our long-term milestones in [ROADMAP.md](../../ROADMAP.md).

</details>
