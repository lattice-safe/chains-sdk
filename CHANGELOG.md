# Changelog

## [0.5.0] — 2026-03-08

### ⚠ Breaking Changes
- `to_wif()` now returns `Zeroizing<String>` instead of `String`
- `to_xprv()` now returns `Zeroizing<String>` instead of `String`

### Added — Round 3
- **BIP-322 Verification**: `verify_simple_p2wpkh()` and `verify_simple_p2tr()` counterparts to the signing functions
- **PSBT Signing**: `Psbt::sign_segwit_input()` for P2WPKH and `Psbt::sign_taproot_input()` for P2TR — auto-compute sighash and store signatures
- **Taproot Address from xpub**: `ExtendedPublicKey::p2tr_address()` and `p2wpkh_address()` for watch-only address derivation
- **Transaction Parser**: `parse_unsigned_tx()` — deserialize raw unsigned transactions

### Added — Round 2
- **BIP-342**: `taproot_script_path_sighash()` — script-path spending with tapleaf hash, key_version, codesep_pos
- **ExtendedPublicKey Tests**: 10 dedicated tests (derivation consistency, xpub round-trip, chain derivation)
- **Fuzz Targets**: 4 targets (`fuzz_from_wif`, `fuzz_from_xprv`, `fuzz_psbt_deserialize`, `fuzz_mnemonic_from_phrase`)

### Added — Round 1
- **Transaction Builder**: `transaction.rs` with legacy + SegWit serialization, txid, wtxid, vsize
- **BIP-143/341 Sighash**: `sighash.rs` with `segwit_v0_sighash()` and `taproot_key_path_sighash()`
- **BIP-322 Signing**: `sign_simple_p2wpkh()` and `sign_simple_p2tr()`
- **ExtendedPublicKey**: xpub serialization, normal child derivation, BIP-32 public key derivation
- **PSBT Parser**: `Psbt::deserialize()` with BIP-371 Taproot extensions
- **Doc-tests**: Converted 10 `ignore` examples to `no_run`

### Fixed
- All clippy warnings resolved (0 warnings across all targets)
- `#[must_use]` on 10+ functions
- Constant-time checksum comparisons via `subtle`
- `div_ceil` migration from manual to std

## [0.4.0]

Initial release with multi-chain signing support.
