# trad-signer

> Unified, secure multi-chain signing library for Rust.

[![CI](https://github.com/lattice-safe/trad-signer/actions/workflows/ci.yml/badge.svg)](https://github.com/lattice-safe/trad-signer/actions)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](LICENSE)

## Overview

**trad-signer** consolidates all major blockchain signing algorithms into a single, reliable Rust crate with a unified trait-based API. Every module is feature-gated so you only compile what you need.

| Algorithm | Curve | Hash | Blockchain | Feature |
|-----------|-------|------|------------|---------|
| ECDSA | secp256k1 | Keccak-256 | Ethereum | `ethereum` |
| ECDSA | secp256k1 | Double SHA-256 | Bitcoin | `bitcoin` |
| Schnorr | secp256k1 (BIP-340) | Tagged SHA-256 | Bitcoin | `bitcoin` |
| ECDSA | P-256 | SHA-256 | NEO | `neo` |
| ECDSA | secp256k1 | SHA-512 half | XRP | `xrp` |
| EdDSA | Ed25519 | — | XRP, Solana | `xrp`, `solana` |
| BLS | BLS12-381 | SHA-256 | Ethereum PoS | `bls` |

## Quick Start

```toml
[dependencies]
trad-signer = { version = "0.1", features = ["ethereum", "solana"] }
```

### Ethereum ECDSA

```rust
use trad_signer::ethereum::EthereumSigner;
use trad_signer::traits::{KeyPair, Signer};

let signer = EthereumSigner::generate()?;
let sig = signer.sign(b"hello ethereum")?;
println!("Address: 0x{}", hex::encode(signer.address()));
println!("v={}, r={}, s={}", sig.v, hex::encode(sig.r), hex::encode(sig.s));
```

### EIP-712 Typed Data

```rust
use trad_signer::ethereum::{EthereumSigner, Eip712Domain};
use trad_signer::traits::KeyPair;

let signer = EthereumSigner::generate()?;
let domain = Eip712Domain {
    name: "MyDapp",
    version: "1",
    chain_id: 1,
    verifying_contract: &[0xCC; 20],
};
let sig = signer.sign_typed_data(&domain.separator(), &struct_hash)?;
```

### Solana Ed25519

```rust
use trad_signer::solana::SolanaSigner;
use trad_signer::traits::{KeyPair, Signer};

let signer = SolanaSigner::generate()?;
let sig = signer.sign(b"hello solana")?;
```

### Bitcoin Schnorr (BIP-340)

```rust
use trad_signer::bitcoin::schnorr::SchnorrSigner;
use trad_signer::traits::{KeyPair, Signer};

let signer = SchnorrSigner::generate()?;
let sig = signer.sign(b"hello bitcoin")?;
assert_eq!(signer.public_key_bytes().len(), 32); // x-only
```

### BLS Signature Aggregation

```rust
use trad_signer::bls::{BlsSigner, aggregate_signatures, verify_aggregated};
use trad_signer::traits::{KeyPair, Signer};

let s1 = BlsSigner::generate()?;
let s2 = BlsSigner::generate()?;
let msg = b"consensus message";

let sig1 = s1.sign(msg)?;
let sig2 = s2.sign(msg)?;
let agg = aggregate_signatures(&[sig1, sig2])?;
assert!(verify_aggregated(&[s1.public_key(), s2.public_key()], msg, &agg)?);
```

## Dual-Mode Signing

Every module supports both raw messages and pre-hashed digests:

```rust
// Raw — module applies chain-specific hashing internally
let sig = signer.sign(b"raw message")?;

// Pre-hashed — you provide the digest directly
let sig = signer.sign_prehashed(&digest)?;
```

## Security

| Guarantee | Implementation |
|-----------|---------------|
| No unsafe code | `#![forbid(unsafe_code)]` |
| Key zeroization | All signers implement `ZeroizeOnDrop` |
| Constant-time comparison | `subtle::ConstantTimeEq` |
| No panics | `#![deny(clippy::unwrap_used)]` |
| Signature malleability | EIP-2 Low-S, strict DER, Ed25519 strict verification |
| Dependency audit | `cargo-deny` + `cargo-audit` in CI |

## Feature Flags

```toml
[features]
default = ["std", "ethereum", "bitcoin", "solana", "xrp", "neo", "bls"]
serde = ["dep:serde"]  # Optional private key serialization
```

## Test Vectors

All implementations are validated against official standards:

- **RFC 6979** — ECDSA deterministic nonces (Bitcoin, Ethereum)
- **BIP-340** — Schnorr test vectors 0–6 (Bitcoin)
- **RFC 8032 §7.1** — Ed25519 vectors 1–3 (Solana, XRP)
- **FIPS 186-4** — P-256 ECDSA (NEO)
- **ETH2 Consensus Spec** — BLS12-381 DST + aggregation

## License

MIT OR Apache-2.0
