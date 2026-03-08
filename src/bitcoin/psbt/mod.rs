//! **BIP-174/370/371** — Partially Signed Bitcoin Transactions (PSBT v0 + v2 + Taproot).
//!
//! Implements the core PSBT data structure for multi-party transaction signing:
//! - **v0** (BIP-174): Traditional PSBT with embedded unsigned transaction
//! - **v2** (BIP-370): Constructor-based PSBT for interactive signing (CoinJoin/Payjoin)
//! - BIP-371 Taproot extensions for both versions

pub mod v0;
pub mod v2;
