# Security Policy

## Supported Versions

Security updates are applied to the latest release series on the `main` branch.

| Version | Supported          |
| ------- | ------------------ |
| Latest (`0.x`) | :white_check_mark: |
| `< 0.1.0` | :x:                |

## Memory Safety & Firmware Parser Invariants

1. **Zero Unsafe Code**: All container header decoders (U-Boot, TRX, FDT), magic byte carvers, ASN.1 DER decoders, and vulnerability inspection routines are implemented in 100% safe Rust without `unsafe` blocks.
2. **Strict Bounds & Overflow Protection**: All slice indices, length offsets, TLV tag length decoders, and container partition sizes enforce explicit bounds checking and checked integer arithmetic (`checked_add`, `checked_mul`) against remaining buffer lengths, preventing out-of-bounds reads and panics on malformed images.
3. **Memory Exhaustion & Cycle Defense**: Carving offsets and uncompressed chunk extraction enforce explicit maximum size caps. Recursive filesystem directory walks employ path canonicalization, a visited path set, and a strict depth ceiling of 16 levels to guarantee immunity against symlink loops and directory cycle denial-of-service.
4. **Zeroize Memory Hygiene**: Discovered private key blocks, scraped sensitive credentials, and intermediate byte buffers enforce secure memory wiping via `Zeroize` and `Drop`.
5. **Constant-Time Verification**: Cryptographic digest checks and key material correlations utilize constant-time comparison algorithms to mitigate timing side-channel attacks.

## Reporting a Vulnerability

If you discover a potential parser bug, denial-of-service vector, or security issue:

1. **Do not open a public issue** with exploit details before a fix is available.
2. Report the finding via [GitHub Security Advisories](../../security/advisories/new) or contact the maintainers directly with a minimal firmware reproduction blob.
3. We review reports promptly and coordinate fixes and release notes upon resolution.
