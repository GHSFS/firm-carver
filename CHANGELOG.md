# Changelog

All notable changes to `firm-carver` (`fcarver`) are documented in this file.

## [0.4.0] - 2026-10-13

### Added
- **Cross-Architecture Machine Code Scoring & Shellcode Detector (`src/arch_detect.rs`, `src/arch_detect/`)**:
  - Implemented multi-architecture instruction set statistical analyzer evaluating valid opcodes, registers, branch densities, and prologue/epilogue sequences across MIPS32 Big-Endian, MIPS32 Little-Endian, ARMv7 (32-bit), ARM Thumb/Thumb-2, AArch64 (ARM 64-bit), RISC-V 32-bit (RV32), and RISC-V 64-bit (RV64).
  - Implemented exploit payload pattern matcher identifying NOP sled landing pads, interactive `/bin/sh` or `/bin/busybox` string pointers, and architecture-specific Linux `sys_execve` syscall sequences:
    - MIPS (EB/EL): `li $v0, 4011` followed by `syscall` (`0x24020FA7` / `0xA70F0224`).
    - ARMv7: `mov r7, #11` followed by `svc 0` / `swi 0x90000B`.
    - AArch64: `mov x8, #221` followed by `svc #0`.
    - RISC-V: `addi a7, zero, 221` followed by `ecall`.
  - Implemented lightweight pure-Rust disassembler (`disasm.rs`) generating mnemonic and operand strings across all supported architectures without external C dependencies.
- **Dedicated CLI Subcommand `arch-detect` (`src/cli.rs`, `src/main.rs`)**:
  - `fcarver arch-detect <file>`: inspects uncompressed raw code segments and reports candidate instruction set confidence distribution, shellcode findings, and sample disassembled instructions.
  - `fcarver arch-detect <file> --offset <bytes> [--length <bytes>]`: focuses forensic scoring on specific carved segments or bootloader partitions.
  - `fcarver arch-detect <file> --min-confidence <float>`: configures classification threshold (default: 0.30).
  - `fcarver arch-detect <file> --json`: outputs structured JSON containing candidate scores, shellcode findings, and decoded instruction tokens.
- **Deterministic Synthetic Shellcode Generator & Integration Tests**:
  - Added synthetic shellcode generator (`synth.rs`) and CLI (`fcarver synth-fw --type shellcode-mips`, `shellcode-arm`, `shellcode-aarch64`, `shellcode-riscv`, `shellcode-sled`).
  - Added dedicated integration test suite (`tests/arch_detect_test.rs`) with 9 tests covering MIPS EB/EL, ARMv7, AArch64, RISC-V, NOP sleds, disassembler output, terminal reports, and small/noise bounds safety.

## [0.3.0] - 2026-10-13

### Added
- **Flattened Device Tree (FDT / DTB) Disassembler & Peripheral Hardware Mapping (`src/fdt.rs`, `src/fdt/`)**:
  - Implemented standalone parser for Flattened Device Tree blobs supporting format versions v1 through v17+ with strict bounds checking and buffer overflow guards.
  - Implemented memory reservation block parser (`/memreserve/`) extracting 64-bit physical address and length entries.
  - Implemented structure block parser traversing `FDT_BEGIN_NODE`, `FDT_END_NODE`, `FDT_PROP`, `FDT_NOP`, and `FDT_END` tokens with string table lookup and stack-based recursion bounds.
  - Added intelligent DTS value formatter distinguishing string lists, cell arrays (`<...>`), MAC addresses (`[...]`), empty boolean properties, and raw byte streams.
  - Added automated peripheral hardware mapping engine (`PeripheralMap`) extracting board model, compatible strings, chosen `bootargs` and `stdout-path`, RAM ranges, UART serial consoles (with active console detection), SPI flash MTD partitions (with offsets, sizes, labels, and read-only flags), Ethernet MAC interfaces (with PHY modes), and CPU cores.
- **Dedicated CLI Subcommand `fdt` (`src/cli.rs`, `src/main.rs`)**:
  - `fcarver fdt <file>`: inspects FDT header geometry and displays structured hardware peripheral breakdown.
  - `fcarver fdt <file> --dts`: disassembles binary DTB into complete, human-readable Device Tree Source (`.dts`) syntax.
  - `fcarver fdt <file> --hardware`: outputs dedicated peripheral hardware map table.
  - `fcarver fdt <file> --json`: outputs structured JSON containing header metadata, memory reservations, peripheral map, and full node tree.
  - `fcarver fdt <file> --offset <bytes>`: supports custom byte offsets or automatic signature scanning within padded firmware containers.
- **Enhanced Synthetic Generator & Test Suite**:
  - Added deterministic synthetic DTB builder (`DtBuilder` and `build_synthetic_fdt()`) modeling real-world router architectures with UART, SPI NOR flash partitions, and gigabit Ethernet.
  - Integrated `fcarver synth-fw --type fdt <output>` with full synthetic DTB generation.
  - Added dedicated integration test suite (`tests/fdt_test.rs`) with 7 tests covering header parsing, memory reservations, DTS syntax generation, peripheral mapping, hardware summaries, stream offsets, and corrupted input resilience.

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
