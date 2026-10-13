# FirmCarver Roadmap

This document tracks shipped capabilities and planned firmware forensics, container parsing, and static vulnerability auditing features for `fcarver`.

---

## Shipped Capabilities

- [x] **Entropy-Guided Bootloader & Kernel Boundary Slicer (`v0.5.0`)** — Sliding-window Shannon entropy profiling and Chi-square goodness-of-fit testing; inflection point detection for compression rises, compression drops, padding entrances, and exits; automated contiguous partition slicing and disk extraction; dedicated `slice` CLI subcommand with `--window`, `--step`, `--threshold`, `--plot`, `--out`, and `--json`; deterministic synthetic multi-stage firmware fixture generator.
- [x] **MIPS / ARM / RISC-V Cross-Architecture Shellcode Detector (`v0.4.0`)** — Statistical instruction set analyzer scoring MIPS32 (EB/EL), ARMv7, Thumb-2, AArch64, RV32, and RV64; exploit payload pattern matcher identifying NOP sled landing pads, interactive `/bin/sh` or `/bin/busybox` string pointers, and architecture-specific Linux `sys_execve` syscall sequences (MIPS 4011, ARM 11, AArch64 221, RISC-V 221); pure-Rust multi-architecture disassembler; dedicated `arch-detect` CLI subcommand with `--offset`, `--length`, `--min-confidence`, `--disasm`, and `--json`.
- [x] **Device Tree Blob (FDT) Disassembler & Peripheral Hardware Mapping (`v0.3.0`)** — Standalone Flattened Device Tree parser for v1-v17 DTB containers with bounds-checked header and token parsing; memory reservation map decoder; full recursive node hierarchy parser with smart DTS value formatting (string lists, cell arrays, MAC byte sequences); hardware peripheral extractor mapping board model/compatible, chosen bootargs/stdout-path, RAM ranges, UART serial consoles, SPI flash MTD partitions, Ethernet MAC interfaces, and CPU cores; CLI subcommand `fcarver fdt` with `--dts`, `--hardware`, `--json`, and `--offset`.
- [x] **SquashFS v4 Directory & Inode Metadata Extractor (`v0.2.0`)** — Standalone parser for SquashFS 4.0 superblock, supporting little-endian and big-endian systems; multi-block `MetadataReader` with Deflate decompression; directory table walking, full file tree recovery, permissions and symlink resolution, and dedicated `squashfs` CLI subcommand (`--list`, `--json`, `--offset`).
- [x] **Core Firmware Container Parser (U-Boot/TRX/FDT), Magic-Stream Carving Engine & Vulnerability Scanner (`v0.1.0`)** — Zero-dependency U-Boot `uImage` (Magic `0x27051956` big-endian with dual 32-bit CRC calculation), Broadcom `TRX` header (`0x30304448` / `HDR0` with 3 partition offsets), and Flattened Device Tree blobs (`0xD00DFEED` / FDT); multi-format magic-byte stream carver for SquashFS 4.0 (`sqsh`/`hsqs`), CramFS, Gzip, LZMA, and XZ; static firmware vulnerability and backdoor scanner for embedded RSA/EC/OpenSSH/PKCS#8 private keys, `/etc/shadow` root password hashes, unauthenticated `telnetd -l /bin/sh` backdoors, and `nc -e /bin/sh` reverse shells; deterministic synthetic firmware generator (`fcarver synth-fw`, `inspect`, `carve`, `audit`).

---

## Planned Milestones

### Filesystem Metadata & Deep Partition Analysis

- [ ] **JFFS2 & YAFFS2 NAND/NOR Flash Filesystem Carver (`src/flash_fs.rs`)** — Carve and reconstruct raw Flash Translation Layer (FTL) partitions, assembling JFFS2 raw cleanmarker nodes and YAFFS2 chunk tags into a navigable filesystem tree.
- [ ] **UBIFS & UBI Volume Header Parser (`src/ubifs.rs`)** — Decode UBI volume identification headers, erase counters, logical eraseblock (LEB) mappings, and master nodes to inspect embedded Linux router NAND storage.
- [ ] **Ext2/Ext3/Ext4 Raw Disk Image Inode Walker (`src/extfs.rs`)** — Locate and parse standard superblock and block group descriptors in raw firmware images, recovering directory trees, file extent trees, and deleted inode traces.

### Architecture & Code Forensics
- [ ] **Cryptographic Hash Digest & Integrity Attestation Generator (`src/integrity.rs`)** — Compute SHA-256, SHA-512, and BLAKE3 digests across carved segments, generating signed attestation manifests and SBOM records compatible with SPDX 3.0.
- [ ] **ELF Header & Shared Library Dependency Resolver (`src/elf_resolver.rs`)** — Inspect carved binary executables (`0x7F454C46`), reading dynamic symbols (`DT_NEEDED`), interpreter paths (`/lib/ld-uClibc.so.0`), and non-stripped debug information.

### Web Management & Service Auditing
- [ ] **Embedded Web Management Interface & CGI Script Static Auditor (`src/cgi_audit.rs`)** — Scan embedded `/www` or `/htdocs` web trees for unauthenticated `.cgi` scripts, command injection vectors (`popen`, `system`), hardcoded session tokens, and buffer overflow prone query string parsers.
- [ ] **Hardcoded TLS Certificate & Expired Root CA Scanner (`src/cert_audit.rs`)** — Extract embedded X.509 certificates and private key pairs, validating expiration dates, weak signature algorithms (MD5/SHA-1), and self-signed certificate anomalies.
- [ ] **NVRAM Default Variable & Factory Reset Value Extractor (`src/nvram_audit.rs`)** — Parse Broadcom, MediaTek, and Realtek static NVRAM default tables, extracting default Wi-Fi PSK passphrases, WPS PINs, and diagnostic flags.
- [ ] **Hardcoded IP & External Domain Reputation Classifier (`src/domain_audit.rs`)** — Extract embedded IPv4/IPv6 addresses, external telemetry domains, and cloud server URIs, flagging insecure HTTP endpoints and unauthenticated firmware update URLs.

### Packaging & Supply Chain Security
- [ ] **Vendor Firmware Container Unpacker (`src/vendor_pkg.rs`)** — Support proprietary encapsulation headers including MikroTik NPK, AVM Fritz!Box, Netgear CHK, D-Link SHRS, and Huawei update packages.
- [ ] **Firmware Modification & Repackaging Engine (`src/repack.rs`)** — Recompute container checksums and rebuild valid U-Boot or TRX firmware blobs after modifying carved rootfs payloads or updating security configurations.
- [ ] **SARIF & CycloneDX 1.5 Firmware SBOM Exporter (`src/sbom_export.rs`)** — Export firmware vulnerability audit findings, extracted software components, and filesystem manifests into standardized SARIF and CycloneDX JSON formats.
