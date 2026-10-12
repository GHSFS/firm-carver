# Changelog

All notable changes to `firm-carver` (`fcarver`) are documented in this file.

## [0.2.0] - 2026-10-13

### Added
- **SquashFS v4 Inode & Directory Extractor (`src/squashfs.rs`, `src/squashfs/`)**:
  - Implemented standalone parser for SquashFS 4.0 superblock (96 bytes), supporting both little-endian (`sqsh`, `0x73717368`) and big-endian (`hsqs`, `0x68737173`) router and IoT images.
  - Implemented multi-block `MetadataReader` with transparent Deflate decompression (`flate2` / `miniz_oxide`) and uncompressed block pass-through for consecutive and spanned metadata chunks up to 8 KiB.
  - Implemented parsers for all SquashFS v4 inode structures: basic directories, extended directories, basic files, extended files, symlinks with target path resolution, character/block devices, and IPC nodes.
  - Implemented directory table walker that parses directory headers and variable-length directory entries without mounting or requiring Linux kernel capabilities.
  - Added full file tree reconstruction, formatted `ls -la` style file listings with permissions and timestamps, and exact file search by path.
- **Dedicated CLI Subcommand `squashfs` (`src/cli.rs`, `src/main.rs`)**:
  - `fcarver squashfs <file>`: inspects superblock geometry, compression type, and displays top recovered files and directories.
  - `fcarver squashfs <file> --list`: renders complete UNIX-style directory listings with permissions, UID/GID, byte sizes, inode numbers, and symlink destinations.
  - `fcarver squashfs <file> --json`: exports structured JSON representation of the entire recovered filesystem tree.
  - `fcarver squashfs <file> --offset <bytes>`: supports custom byte offsets or automatic signature scanning within padded firmware containers.
- **Enhanced Carving & Synthetic Testing**:
  - Enriched carved SquashFS segment manifests with accurate recovered entry counts.
  - Added synthetic SquashFS generator in `synth.rs` and CLI (`fcarver synth-fw -t squashfs <out>`) for deterministic testing across little-endian and big-endian configurations.
  - Added dedicated integration test suite (`tests/squashfs_test.rs`) covering superblock parsing, directory traversal, symlink resolution, bounds safety, and listing generation.

## [0.1.0] - 2026-10-13


### Added
- **Core Firmware Container Parsers (`src/image.rs`)**:
  - Implemented zero-dependency U-Boot `uImage` (Magic `0x27051956` big-endian) header parser with full 64-byte metadata extraction, operating system type, target CPU architecture, image type, compression flags, and dual 32-bit CRC (header CRC32 and payload data CRC32) validation.
  - Implemented Broadcom `TRX` header (Magic `0x30304448` / `HDR0`) parser with 3 partition offset resolvers, length bounds checking, and CRC32 verification.
  - Implemented Flattened Device Tree `FDT` / Device Tree Blob (Magic `0xD00DFEED`) header parser extracting total size, structure offset, strings offset, and version attributes.
  - Added deterministic synthetic firmware generator (`fcarver synth-fw <output> [--type <uboot|trx>]`) for automated CI testing and forensic reproducibility.
- **Magic-Byte Stream Carving Engine (`src/carve.rs`)**:
  - Scans raw firmware blobs for embedded filesystems and compressed streams across both little-endian and big-endian representations.
  - Supports SquashFS 4.0 (`sqsh` / `hsqs`), CramFS (`0x28cd3d45` / `0x453dcd28`), Gzip (`0x1F8B08`), LZMA (`0x5D0000`), and XZ (`0xFD377A585A00`).
  - Implemented partition boundary calculation and slice extraction to dedicated files (`carve --out <dir>`), accompanied by structured JSON manifests (`manifest.json`).
- **Static Vulnerability, Secret & Backdoor Scanner (`src/vuln_scan.rs`)**:
  - Detects hardcoded cryptographic private keys (`RSA`, `EC`, `OpenSSH`, `PKCS#8`).
  - Flags hardcoded password hashes and dangerous account configurations in `/etc/shadow` and `/etc/passwd` (`$1$` MD5, `$6$` SHA-512, empty root password `:!:`).
  - Flags unauthenticated root shell backdoors (`telnetd -l /bin/sh`), firewall flush commands (`iptables -F`), and Netcat reverse shells (`nc -e /bin/sh`).
  - Classifies findings with severity scores (`Critical`, `High`, `Medium`, `Low`) and provides structured JSON reporting.
- **Unified Command-Line Interface (`src/cli.rs`, `src/main.rs`)**:
  - Subcommands: `inspect`, `carve`, `audit`, and `synth-fw`.
  - Pure Rust implementation with zero C dependencies and zero `unsafe` blocks.
  - Integrated `zeroize` memory hygiene for analyzed firmware buffers.
