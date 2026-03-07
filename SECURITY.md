# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |

## Reporting a Vulnerability

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please email: **security@lattice-safe.dev**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

We will acknowledge receipt within **48 hours** and aim to release a patch within **7 days** for critical issues.

## Security Measures

This crate implements the following security guarantees:

- `#![forbid(unsafe_code)]` — zero unsafe blocks in production code
- All private key material implements `ZeroizeOnDrop`
- `private_key_bytes()` returns `Zeroizing<Vec<u8>>`
- Constant-time signature comparison via `subtle::ConstantTimeEq`
- EIP-2 Low-S normalization (Ethereum)
- Strict DER encoding (Bitcoin)
- RFC 6979 deterministic nonces (ECDSA)
- BLS Proof-of-Possession awareness for aggregation
- `cargo-deny` + `cargo-audit` in CI for dependency scanning
