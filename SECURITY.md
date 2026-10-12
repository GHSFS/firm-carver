# Security Policy

## Supported Versions

Security updates are applied to the latest release series on the `main` branch.

| Version | Supported          |
| ------- | ------------------ |
| Latest (`0.x`) | :white_check_mark: |
| `< 0.1.0` | :x:                |

## Memory Safety & Firmware Parser Invariants

1. **Zero Unsafe Code**: All container header decoders (U-Boot, TRX, FDT), magic byte carvers, and vulnerability inspection routines are implemented in 100% safe Rust without `unsafe` blocks.
2. **Strict Bounds Protection**: All slice indices, length offsets, and container partition sizes enforce bounds checking against remaining buffer lengths, preventing out-of-bounds reads and panics on malformed images.
3. **Memory Exhaustion Defense**: Carving offsets and uncompressed chunk extraction enforce explicit maximum size caps to prevent disk or memory exhaustion from maliciously crafted headers.
4. **Zeroize Memory Hygiene**: Sensitive temporary keys, discovered credentials, and cryptographic digests enforce secure zeroization on drop.

## Reporting a Vulnerability

If you discover a potential parser bug, denial-of-service vector, or security issue:

1. **Do not open a public issue** with exploit details before a fix is available.
2. Report the finding via [GitHub Security Advisories](../../security/advisories/new) or contact the maintainers directly with a minimal firmware reproduction blob.
3. We review reports promptly and coordinate fixes and release notes upon resolution.
