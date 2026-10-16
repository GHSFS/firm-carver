# Changelog

All notable changes to `firm-carver` (`fcarver`) are documented in this file.

## [0.14.0] - 2026-10-16

### Added
- **Ext2/Ext3/Ext4 Raw Superblock & Block Group Inode Walker (`src/extfs/`)**:
  - Implemented standalone zero-dependency Ext2, Ext3, and Ext4 superblock parser (`superblock.rs`, `types.rs`) supporting Little-Endian (`[0x53, 0xEF]`) and Big-Endian (`[0xEF, 0x53]`) layouts (`EXT_SUPER_MAGIC = 0xEF53`).
  - Implemented 32-bit and 64-bit Block Group Descriptor Table (GDT) parser with flexible block geometry calculation.
  - Implemented Inode parsing engine supporting both Ext2/Ext3 direct/indirect block pointers and Ext4 Extent trees (`0xF30A` header with leaf/index traversal).
  - Implemented fast inline symbolic link decoder for short symlinks stored directly in the `i_block` array (`size <= 60`).
  - Implemented recursive directory tree reconstruction engine (`reconstruct.rs`) supporting linked directory records (`ext4_dir_entry_2`), cycle detection (depth limit 32), UNIX permissions formatting, and path traversal-safe disk extraction (`extract_to_disk`, `validate_safe_path`).
  - Implemented comprehensive security auditing rules (`rules.rs`):
    - **`EXTFS-TRAV-001` (Critical)**: Path traversal symlinks escaping the archive root (e.g., `../../etc/shadow`).
    - **`EXTFS-SYMLNK-001` (Low)**: Dangling symlinks pointing to non-existent internal filesystem targets.
    - **`EXTFS-SYMLNK-002` (High)**: Symlinks pointing to sensitive hardware nodes or virtual filesystems (`/dev/`, `/proc/`, `/sys/`).
    - **`EXTFS-PERM-001` (High)**: Setuid and Setgid executables discovered in the filesystem image.
    - **`EXTFS-DEV-001` (Medium)**: Block or character device nodes placed in non-standard user directories outside `/dev/`.
    - **`EXTFS-INTEG-001` (Medium)**: Corrupt or inconsistent superblock geometry.
    - **`EXTFS-SHADOW-001` (Critical)**: Unprotected shadow password databases containing hash material.
  - Implemented continuous partition stream carver (`carver.rs`) registering `CarvedKind::ExtFs` into `src/carve.rs`.
  - Implemented deterministic synthetic builders (`synth.rs`) supporting Ext2 and Ext4 Little-Endian and Big-Endian test images, integrated with `fcarver synth-fw -t ext2`, `ext2-be`, `ext4`.
- **Dedicated CLI Subcommand `extfs` (`src/cli.rs`, `src/commands/extfs.rs`)**:
  - `fcarver extfs <image>`: inspects superblock geometry, feature flags, volume label, UUID, and summary.
  - `fcarver extfs <image> --list`: outputs full UNIX `ls -la` directory listing.
  - `fcarver extfs <image> --audit`: runs security audit rules and outputs findings table.
  - `fcarver extfs <image> --extract <dir>`: safely extracts all files and directories to disk.
  - `fcarver extfs <image> --offset <bytes>`: parses ExtFS starting from a specified byte offset.
  - `fcarver extfs <image> --json`: outputs structured JSON archive metadata and audit reports.
- **Dedicated Integration Test Suite (`tests/extfs_test.rs`)**:
  - 10 integration tests covering LE/BE Ext2, Ext4 extent trees, fast inline symlinks, security audit rules, safe disk extraction, raw firmware stream carving, corrupted input resilience, and JSON serialization.
  - Added `test_extfs_stream_carving` in `tests/image_carve_test.rs`.

## [0.13.0] - 2026-10-15

### Added
- **CramFS Deep Directory Walker & Symlink Auditor (`src/cramfs/`)**:
  - Implemented standalone zero-dependency CramFS superblock and inode parser (`superblock.rs`, `types.rs`) supporting both Little-Endian (`[0x45, 0x3d, 0xcd, 0x28]`) and Big-Endian (`[0x28, 0xcd, 0x3d, 0x45]`) on-disk magic layouts (`CRAMFS_MAGIC = 0x28cd_3d45`).
  - Implemented bitfield unpacking for CramFS 12-byte packed inodes:
    - Word 0: file mode (16-bit UNIX permission and file type flags) and UID (16-bit).
    - Word 1: uncompressed file size (24-bit, up to 16 MiB) and GID (8-bit).
    - Word 2: namelen (6-bit, word-aligned length) and payload offset (26-bit, byte offset shifted right by 2).
  - Implemented block-pointer array parser and Zlib decompression engine (`decompress.rs`):
    - Block pointer array parsing with per-block compressed length determination.
    - Transparent Zlib decompression using pure-Rust `flate2` (`miniz_oxide` backend) with a 32 MiB uncompressed file safety ceiling preventing decompression bomb attacks.
    - Inline symlink target extraction and direct ASCII string resolution.
  - Implemented recursive directory tree reconstruction engine (`reconstruct.rs`):
    - Recursive traversal recovering complete directory hierarchies, file sizes, UNIX permissions (`drwxr-xr-x`, `lrwxrwxrwx`, `-rwsr-xr-x`), and symlink target strings.
    - Directory recursion loop and cycle detection with a maximum traversal depth limit of 32.
    - Symlink path traversal auditing resolving relative path components (`../`) against the root archive boundaries.
    - Dangling symlink detection auditing targets that do not exist within the archive.
    - Safe disk extraction (`extract_to_disk`) enforcing canonical path containment via `validate_safe_path` to prevent arbitrary file writes.
  - Implemented comprehensive CramFS security auditing rule engine (`rules.rs`):
    - **`CRAMFS-TRAV-001` (Critical)**: Path traversal symlink escaping the archive root (e.g., `../../etc/shadow`).
    - **`CRAMFS-SYMLNK-001` (Low)**: Dangling symlink pointing to a non-existent path within the archive.
    - **`CRAMFS-SYMLNK-002` (High)**: Symlink pointing to sensitive system paths (`/dev/`, `/proc/`, `/sys/`, `/etc/`).
    - **`CRAMFS-PERM-001` (High)**: Setuid or Setgid binary discovered in the filesystem image.
    - **`CRAMFS-DEV-001` (Medium)**: Block or character device node residing outside the standard `/dev/` directory.
    - **`CRAMFS-INTEG-001` (Medium)**: Corrupted, non-Zlib, or unreadable block payload detected during extraction.
  - Implemented continuous raw firmware partition carver (`carver.rs`):
    - `probe_cramfs_at` and `scan_cramfs_partitions` identifying CramFS filesystem partitions in unaligned binary streams, bound to `CarvedKind::CramFs`.
  - Implemented deterministic synthetic fixture generator (`synth.rs`):
    - `build_synthetic_cramfs` producing valid Little-Endian and Big-Endian CramFS images with non-overlapping superblock (0..512), root directory table (512..1024), and payload data blocks (1024+).
    - Integrated with `fcarver synth-fw -t cramfs` and `fcarver synth-fw -t cramfs-be`.
- **Dedicated CLI Subcommand `cramfs` (`src/cli.rs`, `src/commands/cramfs.rs`)**:
  - `fcarver cramfs <target>`: parses and displays CramFS superblock metadata and entry summaries.
  - `fcarver cramfs <target> --list`: renders complete UNIX-style directory listings (`ls -la` format).
  - `fcarver cramfs <target> --audit`: executes security auditing rules and displays a severity-ranked findings table.
  - `fcarver cramfs <target> --extract <dir>`: safely extracts all files and directories to disk with path traversal defense.
  - `fcarver cramfs <target> --offset <bytes>`: parses CramFS image starting from a specified byte offset.
  - `fcarver cramfs <target> --json`: outputs structured JSON archive details and audit reports to stdout.
- **Dedicated Integration Test Suite (`tests/cramfs_walk_test.rs`)**:
  - 12 comprehensive integration tests covering Little-Endian/Big-Endian superblock parsing, Zlib decompression, symlink resolution, traversal detection, dangling link detection, SUID binary audit, safe disk extraction, raw firmware stream carving, corrupted input resilience, and JSON formatting.

## [0.12.0] - 2026-10-14

### Added
- **Hardcoded IPv4/IPv6 & External Telemetry Domain Classifier (`src/domain_audit/`)**:
  - Implemented standalone zero-dependency network endpoint extractor and domain auditor (`extractor.rs`, `types.rs`) extracting URLs, IPv4/IPv6 addresses, and hostnames from binary firmware dumps, raw flash partitions, and filesystem trees.
  - Implemented comprehensive URI parser supporting `http://`, `https://`, `ftp://`, `tftp://`, `telnet://`, `ws://`, `wss://`, `mqtt://`, and `mqtts://` schemes with port, path, query parameters, and embedded basic authentication credentials extraction.
  - Implemented RFC-compliant IP address scope classifier (`classifier.rs`):
    - IPv4 scope categorization: Public routable, Private (RFC 1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), Loopback (`127.0.0.0/8`), Link-Local (`169.254.0.0/16`), Carrier-Grade NAT (RFC 6598 `100.64.0.0/10`), Documentation (RFC 5737 `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), Multicast (`224.0.0.0/4`), Broadcast (`255.255.255.255`), and Unspecified (`0.0.0.0`).
    - IPv6 scope categorization: Global Unicast, Unique Local (RFC 4193 ULA `fc00::/7`), Link-Local (`fe80::/10`), Loopback (`::1`), Documentation (RFC 3849 `2001:db8::/32`), Multicast (`ff00::/8`), and Unspecified (`::`).
  - Implemented functional domain classification engine (`classifier.rs`):
    - Telemetry and Analytics backend detection (Crashlytics, Sentry, Datadog, Segment, Mixpanel, Firebase, Umeng, tracking endpoints).
    - Firmware Update / OTA distribution server detection (`update.*`, `firmware.*`, `download.*`, `upgrade.*`, `ota.*`).
    - Dynamic DNS (DDNS) provider categorization (DynDNS, No-IP, DDNS.net, DuckDNS, FreeDNS, ChangeIP, Asuscomm, D-Link DDNS).
    - Public Cloud & CDN infrastructure recognition (AWS, Azure, Cloudflare, CloudFront, Aliyun).
    - Network Time Protocol (NTP) pool server categorization (`pool.ntp.org`, `time.nist.gov`, `time.windows.com`, `time.google.com`).
    - Local network domain classification (`.local`, `.lan`, `.home`, `.internal`, `.corp`, `localhost`).
  - Implemented security auditing rule engine (`rules.rs`):
    - **`NET-CLEAR-001` (Critical)**: Insecure cleartext HTTP firmware update or OTA URL susceptible to Man-in-the-Middle (MitM) image tampering and malicious flashing.
    - **`NET-CLEAR-002` (Medium)**: Insecure cleartext HTTP communication with remote external APIs or reporting endpoints.
    - **`NET-HARDIP-001` (Medium / Low)**: Static public routable IP addresses hardcoded in firmware, risking hijacking upon IP reallocation and bypassing DNS failover.
    - **`NET-DDNS-001` (High)**: Hardcoded Dynamic DNS provider domains indicating diagnostic backdoors or ephemeral staging servers.
    - **`NET-INSEC-001` (High)**: Deprecated insecure plaintext transport protocols (`telnet://`, `ftp://`, `tftp://`).
    - **`NET-AUTH-001` (Critical)**: Embedded plaintext user credentials in URI authority blocks (`user:pass@host`).
    - **`NET-TELEM-001` (Info)**: External telemetry and behavioral tracking services.
  - Implemented recursive directory scanner (`scanner.rs`) with symlink loop guards, single-file text/binary analysis, and raw byte buffer carving with byte offset tracking.
  - Implemented memory zeroing (`Zeroize` & `Drop`) for sensitive discovered endpoints, credentials, and buffer slices.
- **Dedicated CLI Subcommand `domain-audit` (`src/cli.rs`, `src/commands/domain_audit.rs`)**:
  - `fcarver domain-audit <target>`: audits firmware binaries, script files, or extracted directories for network endpoints.
  - `fcarver domain-audit <target> --min-severity <critical|high|medium|low|info>`: filters findings by minimum severity threshold.
  - `fcarver domain-audit <target> --filter <url|ipv4|ipv6|domain|all>`: restricts analysis to specific endpoint types.
  - `fcarver domain-audit <target> --no-private`: suppresses RFC 1918 private and loopback addresses.
  - `fcarver domain-audit <target> --out <file.json>`: exports complete structured JSON audit report.
  - `fcarver domain-audit <target> --offset <bytes>`: analyzes firmware binary slice starting from byte offset.
  - `fcarver domain-audit <target> --json`: emits structured JSON to stdout.
- **Deterministic Synthetic Domain Fixtures (`src/domain_audit/synth.rs`, `src/commands/synth_fw.rs`)**:
  - Added deterministic fixture generators producing vulnerable firmware blobs (`synth-fw -t domain-vuln`) and hardened builds (`synth-fw -t domain-hardened`).
  - Added dedicated integration test suite (`tests/domain_audit_test.rs`) with 13 tests covering IPv4/IPv6 classification, URL parsing, cleartext OTA/API detection, hardcoded public IPs, DDNS detection, legacy protocols, URI credentials, telemetry categorization, stream carving, hardened firmware validation, and directory tree scanning.

## [0.11.0] - 2026-10-14

### Added
- **Broadcom & MediaTek NVRAM Default Table Extractor (`src/nvram/`)**:
  - Implemented standalone zero-dependency parser for Broadcom flash NVRAM headers (`FLSH` / `0x48534C46` Little-Endian and `0x464C5348` Big-Endian) (`broadcom.rs`, `types.rs`) verifying header magic, length bounds, and 8-bit additive checksums.
  - Implemented null-delimited key-value string extractor recovering standard `key=value\0` pairs with double-null (`\0\0`) block termination.
  - Implemented contiguous packed strings table scanner (`scan_packed_strings_tables`) discovering compiled static NVRAM default tables in embedded `.rodata` sections, C binaries, and raw bootloader dumps (minimum 3 valid key-value pairs).
  - Implemented MediaTek and Ralink `.dat` line-delimited configuration file parser (`mediatek.rs`) parsing `Key=Value` records across `\r\n` and `\n` line endings, recognizing standard MediaTek directives (`Default`, `SSID1`, `WPAPSK1`, `CountryCode`, `BssidNum`, `AuthMode`, `EncrypType`).
  - Implemented MediaTek Factory / EEPROM flash partition decoder (`parse_mediatek_eeprom`) reading SoC chip identifiers (MT7620, MT7628, MT7621, RT2880, MT7603, MT7612, MT7615, MT7915), primary LAN and WAN MAC addresses, NIC configuration flags, country region codes, and RF transmit power calibration tables.
  - Implemented comprehensive NVRAM security auditing rule engine (`rules.rs`):
    - **`NVRAM-WIFI-001` (Critical / High)**: Weak or default Wi-Fi preshared keys (`12345678`, `password`, `admin`, `00000000`, empty strings, predictable sequences).
    - **`NVRAM-WIFI-002` (Medium)**: Insecure open wireless networks (`AuthMode=OPEN`) and deprecated WEP encryption configurations.
    - **`NVRAM-WPS-001` (High)**: Default or static WPS device PINs (`12345670`, `00000000`, 8-digit PINs) with standard WPS checksum algorithm validation.
    - **`NVRAM-CRED-001` (Critical)**: Default web management administrative credentials (`http_username`, `http_passwd`, `admin_password` = `admin`, `root`, `password`).
    - **`NVRAM-FLAG-001` (Critical / High)**: Insecure diagnostic backdoors and exposed debug flags (`telnetd_enable=1`, `enable_telnet=1`, `factory_mode=1`, `boot_wait=on`, `debug_enable=1`, `console_enable=1`).
    - **`NVRAM-SVC-001` (High)**: Insecure remote management services (`remote_management=1`), unencrypted TR-069 management URLs (`cwmp_acs_url=http://`), and cleartext WAN PPPoE/DDNS credentials.
  - Implemented continuous flash stream carver (`carver.rs`) discovering embedded Broadcom `FLSH` headers and packed NVRAM parameter blocks in raw flash images, integrated with `CarvedKind::Nvram`.
  - Implemented safe `.env` file export (`extract_to_env_file`) with quotation escaping and strict key whitelisting against shell variable injection.
  - Implemented memory wiping (`Zeroize`) for parsed NVRAM entries, sensitive credential values, MAC addresses, and raw firmware buffers.
- **Dedicated CLI Subcommand `nvram` (`src/cli.rs`, `src/commands/nvram.rs`)**:
  - `fcarver nvram <file>`: inspects NVRAM headers, detected chip model, total keys, and sensitive parameter summary.
  - `fcarver nvram <file> --list`: displays full tabular listing of recovered key-value pairs and sensitivity tags.
  - `fcarver nvram <file> --audit`: evaluates all security rules and outputs a formatted vulnerability table with remediation advice.
  - `fcarver nvram <file> --extract <path.env>`: exports sanitized key-value parameters to a `.env` configuration file.
  - `fcarver nvram <file> --offset <bytes>`: parses NVRAM partition located at explicit byte offset.
  - `fcarver nvram <file> --format <broadcom|mediatek-dat|mediatek-eeprom|packed>`: forces specific NVRAM parser dialect.
  - `fcarver nvram <file> --json`: outputs structured JSON archive and security audit metadata to stdout.
- **Deterministic Synthetic NVRAM Fixtures (`src/nvram/synth.rs`, `src/commands/synth_fw.rs`)**:
  - Added synthetic fixture generators creating Broadcom FLSH (`synth-fw -t nvram-bcm`), MediaTek EEPROM (`synth-fw -t nvram-mtk`), and MediaTek `.dat` (`synth-fw -t nvram-dat`) images.
  - Added dedicated integration test suite (`tests/nvram_audit_test.rs`) with 11 tests covering Broadcom FLSH LE/BE, packed strings, MediaTek .dat, MediaTek EEPROM, security audit rules, hardened audit pass, WPS PIN checksum, raw flash partition carving, zeroize memory safety, corrupted input resilience, JSON serialization, and `.env` export.


### Added
- **UBI & UBIFS Volume Header Parser & Filesystem Reconstructor (`src/ubifs/`)**:
  - Implemented zero-dependency, pure-Rust UBI physical layer parser (`ubi.rs`, `types.rs`) decoding 64-byte Erase Counter headers (`UBI#` / `0x55424923`) and Volume Identifier headers (`UBI!` / `0x55424921`) with on-flash CRC32 validation.
  - Implemented UBI Volume Table parser decoding 172-byte `struct ubi_vtbl_record` structures from the Layout Volume (`0x7FFFFFFF`), recovering user volume names, volume types (dynamic vs static), and reserved eraseblock counts.
  - Added Physical Eraseblock (PEB) geometry auto-detection for NAND flash geometries (16 KiB, 64 KiB, 128 KiB, 256 KiB, 512 KiB, 2 MiB) with logical eraseblock (LEB) stream assembly.
  - Implemented UBIFS on-flash node decoder (`node.rs`) parsing 24-byte `struct ubifs_ch` common headers, Superblock nodes (`UBIFS_SB_NODE` format v4/v5, LEB geometry, filesystem UUID, compression type), Master nodes (`UBIFS_MST_NODE`, commit sequence, space accounting, highest inum), Inode nodes (`UBIFS_INO_NODE`, UNIX permissions, UID/GID, file size, inline symlink targets), and Directory Entry nodes (`UBIFS_DENT_NODE`, B-tree parent key, inum, filename).
  - Implemented directory tree reconstruction engine (`reconstruct.rs`) mapping parent-child inode graphs, generating formatted UNIX file listings (`drwxr-xr-x`, `lrwxrwxrwx`), symlink target resolution, and safe disk extraction with path traversal defenses rejecting relative path breakouts (`/../../`).
  - Implemented continuous flash partition carver (`carver.rs`) discovering embedded UBI and UBIFS partition streams within raw firmware dumps, integrated into the core carving engine under `CarvedKind::Ubi` and `CarvedKind::Ubifs`.
- **Dedicated CLI Subcommand `ubifs` (`src/cli.rs`, `src/commands/ubifs.rs`)**:
  - `fcarver ubifs <file>`: inspects UBI volume geometry, volume table records, UBIFS superblock parameters, and recovered file tree summaries.
  - `fcarver ubifs <file> --list`: displays full UNIX `ls -la` table of recovered directories, regular files, and symlinks.
  - `fcarver ubifs <file> --extract <dir>`: extracts reconstructed files and directory trees to disk with strict path traversal defenses.
  - `fcarver ubifs <file> --offset <bytes>`: parses UBI or UBIFS partition located at explicit byte offset.
  - `fcarver ubifs <file> --peb-size <bytes>`: specifies custom PEB eraseblock size for non-standard NAND architectures.
  - `fcarver ubifs <file> --json`: outputs structured JSON archive metadata to stdout.
- **Deterministic Synthetic UBI & UBIFS Fixtures (`src/ubifs/synth.rs`)**:
  - Added deterministic fixture generators producing little-endian (`synth-fw -t ubi`, `synth-fw -t ubifs`) and big-endian (`synth-fw -t ubi-be`, `synth-fw -t ubifs-be`) images with valid IEEE 802.3 CRC32 checksums across EC, VID, VTBL, and UBIFS node headers.
  - Added dedicated integration test suite (`tests/ubifs_test.rs`) with 11 tests covering EC/VID header parsing, volume table decoding, LEB stream assembly, UBIFS superblock and master node decoding, directory tree recovery, UNIX permission formatting, symlink resolution, path traversal defenses, disk extraction, stream carving, and corrupted input resilience.

## [0.9.0] - 2026-10-13

### Added
- **JFFS2 Flash Filesystem Carver & Node Reconstructor (`src/jffs2/`)**:
  - Implemented zero-dependency, pure-Rust JFFS2 parser and stream carver for embedded NOR/NAND flash images across Little-Endian (`0x85 0x19`) and Big-Endian (`0x19 0x85`) architectures (`node.rs`, `types.rs`).
  - Added on-flash CRC32 validation for 12-byte `CommonNodeHeader`, cleanmarker nodes (`0x2003`), directory entries (`0xE001`), and inode descriptors (`0xE002`).
  - Implemented multi-algorithm payload decompressor (`decompress.rs`) supporting uncompressed chunks, zero fills, Zlib/Deflate streams, and RTIME run-length decompression with rigorous boundary checking and dictionary backoff safety (mitigating CVE-2024-57850 integer and pointer overrun patterns).
  - Implemented directory tree reconstruction engine (`reconstruct.rs`) resolving directory parent-child graphs, multi-chunk inode data reassembly by version ordering, deletion tombstone filtering (`ino == 0`), symbolic link target extraction, and standard UNIX mode formatting (`drwxr-xr-x`, `lrwxrwxrwx`).
  - Added path traversal defense in extraction logic preventing malicious symlink or relative path escapes (`/../../`).
  - Implemented continuous flash partition carver (`carver.rs`) discovering JFFS2 node chains within unaligned, padded, or concatenated firmware dumps, integrated with `scan_carvable_streams`.
- **Dedicated CLI Subcommand `jffs2` (`src/cli.rs`, `src/commands/jffs2.rs`)**:
  - `fcarver jffs2 <file>`: inspects JFFS2 flash filesystem headers, partition statistics, and recovered files.
  - `fcarver jffs2 <file> --list`: displays full UNIX `ls -la` table of recovered directories, regular files, and symlinks.
  - `fcarver jffs2 <file> --extract <dir>`: safely extracts all reconstructed files and directory trees to disk with path traversal guards.
  - `fcarver jffs2 <file> --offset <bytes>`: parses JFFS2 filesystem located at explicit byte offset.
  - `fcarver jffs2 <file> --json`: outputs structured JSON archive metadata to stdout.
- **Deterministic Synthetic JFFS2 Fixtures (`src/jffs2/synth.rs`)**:
  - Added deterministic fixture generator creating little-endian (`synth-fw -t jffs2`) and big-endian (`synth-fw -t jffs2-be`) JFFS2 images with valid CRC32 headers, cleanmarkers, directories (`/etc`, `/bin`), RTIME-compressed banners, Zlib-compressed busybox binaries, multi-chunk hosts files, deletion tombstones, and symlinks.
  - Added dedicated integration test suite (`tests/jffs2_test.rs`) with 11 tests covering LE/BE parsing, RTIME decompression bounds safety, Zlib decompression, multi-chunk reassembly, tombstone filtering, symlink resolution, path traversal defense, stream carving, corrupted input resilience, and report formatting.

## [0.8.0] - 2026-10-13

### Added
- **Hardcoded TLS Certificate & Expired Root CA Scanner (`src/cert_audit/`)**:
  - Implemented zero-dependency, pure-Rust ASN.1 DER parser and RFC 4648 Base64 PEM decoder (`asn1.rs`) supporting X.509 certificate structures, SubjectPublicKeyInfo, signature algorithms, Distinguished Names (CN, O, OU, C, ST, L), and RFC 5280 validity dates (UTCTime and GeneralizedTime).
  - Implemented PKCS#1 and PKCS#8 private key parsing (`RSAPrivateKey`, `PrivateKeyInfo`, `ECPrivateKey`), extracting raw RSA modulus bytes and bit lengths.
  - Implemented security audit rule engine (`rules.rs`) checking:
    - **`CERT-EXP-001` (Critical / High)**: Expired certificates exceeding reference audit date.
    - **`CERT-EXP-002` (Medium)**: Impending certificate expiration (< 30 days remaining).
    - **`CERT-SIG-001` (Critical)**: Broken cryptographic signature hash algorithms (MD2, MD5).
    - **`CERT-SIG-002` (High)**: Deprecated signature hash algorithms (SHA-1).
    - **`CERT-KEY-001` (Critical)**: Vulnerable RSA public key lengths (< 1024 bits, e.g. 512-bit).
    - **`CERT-KEY-002` (High)**: Deprecated RSA public key lengths (1024 bits).
    - **`CERT-SELF-001` (High)**: Self-signed certificates deployed in production firmware.
    - **`CERT-PRIV-001` (Critical)**: Hardcoded private keys discovered in firmware matching certificate public keys or leaked in filesystem trees.
    - **`CERT-VAL-001` (Medium)**: Anomalous validity periods (> 25 years duration or post-dated start timestamps).
  - Implemented recursive directory scanner, single-file bundle parser, and raw binary buffer stream carver (`scanner.rs`) discovering embedded DER/PEM certificates and private keys directly within raw firmware dumps and flash partitions.
  - Added formatted terminal reporting (`format_cert_report`) with severity breakdowns, certificate details, discovered private key fingerprints, and actionable remediation guidance.
- **Dedicated CLI Subcommand `cert-audit` (`src/cli.rs`, `src/commands/cert_audit.rs`)**:
  - `fcarver cert-audit <file>`: inspects certificates in single files, PEM bundles, directories, or raw firmware dumps.
  - `fcarver cert-audit <file> --min-severity <critical|high|medium|low|info>`: filters findings by minimum severity threshold.
  - `fcarver cert-audit <file> --reference-date <date|timestamp>`: evaluates validity against custom reference date (RFC 3339 or unix epoch).
  - `fcarver cert-audit <file> --out <report.json>`: exports comprehensive findings to structured JSON file.
  - `fcarver cert-audit <file> --json`: outputs structured JSON audit report to stdout.
- **Deterministic Certificate Fixtures & Synthetic Generation**:
  - Added deterministic fixture generator (`synth.rs`, `fcarver synth-fw -t cert-store` and `fcarver synth-fw -t cert-blob`) generating valid, expired, expiring-soon, weak MD5/SHA-1, weak RSA-512/1024, self-signed certificates, and paired private keys.
  - Added dedicated integration test suite (`tests/cert_audit_test.rs`) with 9 tests covering PEM/DER parsing, expiration detection, weak signature detection, weak RSA key identification, self-signed cert detection, private key pairing, stream carving, corrupted input resilience, and report formatting.
- **CLI Command Architecture Decomposition (`src/commands/`)**:
  - Refactored command dispatch from monolithic `src/main.rs` into modular `src/commands/` handlers, reducing `src/main.rs` to 18 lines adhering to the project modular guide.

## [0.7.0] - 2026-10-13

### Added
- **Embedded Web Management Interface & CGI Script Static Auditor (`src/cgi_audit/`)**:
  - Implemented static security analysis engine (`rules.rs`, `scanner.rs`) auditing extracted router `/www` web hierarchies, shell CGI scripts, and embedded web handlers without external dependencies.
  - Implemented static vulnerability detectors covering critical embedded web weakness patterns:
    - **Command Injection (CWE-78)**: Unsanitized HTTP environment variables (`$QUERY_STRING`, `$POST_DATA`, HTTP headers) interpolated into shell subshells or command pipelines (`ping`, `traceroute`, `cat`, `iptables`).
    - **Process Execution Sinks (CWE-78)**: Dangerous system execution sinks (`system()`, `popen()`, `passthru()`, `shell_exec()`, `io.popen()`) invoked with variable arguments.
    - **Embedded Web Engine Sinks (CWE-78)**: GoAhead WebServer, Boa, and mini_httpd variable getters (`websGetVar`, `cgiFormString`, `aspFormProcess`) piped to shell execution sinks.
    - **Authentication Bypass & Backdoor Cookies (CWE-306)**: Detection of known administrative backdoor cookies (`dlink_uid=0`), magic parameters (`super_admin=1`, `admin_bypass`), and unauthenticated administrative routes (`reboot`, `factory_reset`, `upgrade`, `backup`).
    - **Hardcoded Administrative Credentials (CWE-798)**: Static credential comparisons (`admin:admin`, `password == "admin"`) embedded in web authentication logic.
    - **Path Traversal & Arbitrary File Reads (CWE-22)**: Parameter-controlled file reads (`cat $file`, `readfile()`) lacking directory traversal guards and basename sanitization.
    - **Sensitive System Asset Disclosure (CWE-200)**: Direct exposure of `/etc/shadow`, `/tmp/nvram`, and kernel diagnostic buffers (`/proc/kmsg`).
    - **Debug Daemon Activations (CWE-16)**: Web scripts activating remote root shells (`telnetd -l /bin/sh`) or flushing firewall policies.
  - Added recursive filesystem tree walker with symlink loop detection and in-memory virtual tree auditing for extracted filesystems and raw firmware streams.
  - Added formatted terminal reporting (`format_cgi_report`) with severity breakdown, CWE mappings, matched evidence snippets, and actionable remediation guidance.
- **Dedicated CLI Subcommand `cgi-audit` (`src/cli.rs`, `src/main.rs`)**:
  - `fcarver cgi-audit <target>`: recursively audits web root directory or individual CGI script.
  - `fcarver cgi-audit <target> --min-severity <critical|high|medium|low|info>`: filters findings by minimum severity threshold.
  - `fcarver cgi-audit <target> --out <report.json>`: exports comprehensive static audit findings to structured JSON file.
  - `fcarver cgi-audit <target> --json`: outputs structured JSON audit report to stdout for CI/CD integration.
- **Deterministic Synthetic Web Tree & Integration Test Suite**:
  - Added synthetic embedded router `/www` fixture generator (`synth.rs`, `fcarver synth-fw -t cgi-tree` and `fcarver synth-fw -t vuln-cgi`).
  - Added dedicated integration test suite (`tests/cgi_audit_test.rs`) with 9 tests covering command injection detection, unauthenticated administrative route identification, backdoor cookie matching, hardcoded credential parsing, path traversal detection, sensitive information disclosure, safe script false-positive suppression, virtual tree severity filtering, and end-to-end directory audits.

## [0.6.0] - 2026-10-13

### Added
- **Cryptographic Hash Digest & Integrity Attestation Generator (`src/integrity/`)**:
  - Implemented multi-algorithm cryptographic hashing engine (`digest.rs`) providing NIST SHA-256 (32 bytes), NIST SHA-512 (64 bytes), and tree-hashing BLAKE3 (32 bytes) digests.
  - Implemented constant-time string comparison (`constant_time_eq_str`) across digest verification routines to eliminate side-channel timing leaks.
  - Implemented verifiable attestation manifest generator (`manifest.rs`) assembling hierarchical integrity manifests (`AttestationManifest`) containing whole-file cryptographic digests alongside individual offsets, byte sizes, and digests for all detected container headers (U-Boot, TRX, FDT) and carved payloads (SquashFS, CramFS, Gzip, LZMA, XZ).
  - Implemented attestation verification engine (`verify_attestation`) evaluating firmware binaries against recorded manifest schemas, with automated detection of content tampering, boundary overruns, and file truncations.
  - Added formatted terminal reporting utilities (`format_integrity_report`, `format_verification_report`) generating aligned tables with algorithm filtering.
- **Dedicated CLI Subcommand `integrity` (`src/cli.rs`, `src/main.rs`)**:
  - `fcarver integrity <file>`: inspects binary and renders aligned terminal table of file and partition digests.
  - `fcarver integrity <file> --algo <sha256|sha512|blake3|all>`: filters display by specific cryptographic hash algorithm.
  - `fcarver integrity <file> --out <manifest.json>`: exports signed cryptographic attestation manifest to file.
  - `fcarver integrity <file> --verify <manifest.json>`: verifies image against manifest, reporting per-partition verification outcomes and exits with error on integrity mismatch.
  - `fcarver integrity <file> --json`: outputs structured JSON attestation manifest directly to stdout.
- **Deterministic Attestation Fixtures & Integration Tests**:
  - Added deterministic multi-stage attested firmware fixture builder (`synth.rs`, `fcarver synth-fw -t integrity`).
  - Added dedicated integration test suite (`tests/integrity_test.rs`) with 8 tests covering RFC test vectors for SHA-256, SHA-512, and BLAKE3, constant-time comparisons, manifest generation, clean verification passes, byte-level tamper detection, truncation boundary handling, JSON serialization roundtrips, and report formatting.

## [0.5.0] - 2026-10-13

### Added
- **Entropy-Guided Bootloader & Kernel Boundary Slicer (`src/slicer/`)**:
  - Implemented pure-Rust sliding-window Shannon entropy profiler (`entropy.rs`) with configurable window and step sizes, computing bit-level information density curves (0.0 to 8.0 bits/byte) and Chi-square goodness-of-fit statistics against uniform distributions.
  - Implemented boundary and inflection detector (`boundary.rs`) discovering sharp transitions between regions:
    - `CompressionRise`: sharp upward transitions from bootloader/uncompressed code into compressed kernel or encrypted streams.
    - `CompressionDrop`: sharp downward transitions leaving compressed payloads into uncompressed configurations or padding.
    - `PaddingEnter`: transitions into zero-filled or erased flash padding (`0x00`/`0xFF`).
    - `PaddingExit`: transitions out of padding into active executable code or ciphertext.
  - Implemented contiguous partition slicer segmenting entire firmware blobs into discrete partitions (`Padding`, `TextOrData`, `Bootloader`, `CompressedKernel`, `EncryptedOrRandom`) with mean/min/max entropy statistics and descriptive metadata.
  - Implemented partition slice extractor exporting discrete partition binaries to disk (`--out <dir>`) with human-readable filenames.
  - Implemented terminal ASCII entropy curve visualizer (`render_ascii_entropy_plot`) plotting 8-level height curves directly in terminal output.
- **Dedicated CLI Subcommand `slice` (`src/cli.rs`, `src/main.rs`)**:
  - `fcarver slice <file>`: inspects global entropy, discovers contiguous partitions, and detects sharp inflection boundaries.
  - `fcarver slice <file> --window <bytes> --step <bytes>`: custom sliding-window geometry (default: 512B window, 256B stride).
  - `fcarver slice <file> --threshold <float>`: configurable inflection delta sensitivity (default: 0.80).
  - `fcarver slice <file> --plot`: displays high-resolution ASCII entropy curve in terminal.
  - `fcarver slice <file> --out <dir>`: extracts carved partitions into individual `.bin` files.
  - `fcarver slice <file> --json`: outputs structured JSON telemetry with partitions, boundaries, and optional window telemetry.
- **Deterministic Multi-Stage Firmware Fixture Generator & Integration Tests**:
  - Added deterministic 5-stage synthetic firmware fixture generator (`synth.rs`, `fcarver synth-fw -t multi-stage`).
  - Added dedicated integration test suite (`tests/slicer_test.rs`) with 8 tests covering entropy calculations, sliding-window profiles, boundary detection, partition classification, disk extraction, terminal ASCII plots, and corrupted input resilience.

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
