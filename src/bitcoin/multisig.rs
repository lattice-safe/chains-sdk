//! Bitcoin multisig support: P2SH, P2WSH, and P2SH-P2WSH (nested SegWit).
//!
//! Implements m-of-n OP_CHECKMULTISIG scripts and the three standard
//! wrapping formats used by wallets and custodians.
//!
//! # Example
//! ```no_run
//! use chains_sdk::bitcoin::multisig::*;
//!
//! let pubkeys: Vec<[u8; 33]> = vec![[0x02; 33]; 3];
//! let redeem = multisig_redeem_script(2, &pubkeys).unwrap();
//! let address = p2sh_address(&redeem, false);
//! ```

use crate::encoding;
use crate::error::SignerError;
use sha2::{Digest, Sha256};

// ═══════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════

/// Maximum number of public keys in a standard multisig (consensus rule).
pub const MAX_MULTISIG_KEYS: usize = 15;

/// Maximum redeem script size for P2SH (consensus: 520 bytes).
pub const MAX_REDEEM_SCRIPT_SIZE: usize = 520;

// ═══════════════════════════════════════════════════════════════════
// Redeem Script Construction
// ═══════════════════════════════════════════════════════════════════

/// Build a standard m-of-n `OP_CHECKMULTISIG` redeem script.
///
/// Script: `OP_m <pubkey1> <pubkey2> ... <pubkeyn> OP_n OP_CHECKMULTISIG`
///
/// # Arguments
/// - `threshold` — Number of required signatures (`m`)
/// - `pubkeys` — Compressed public keys (33 bytes each)
///
/// # Errors
/// - `threshold == 0` or `threshold > pubkeys.len()`
/// - `pubkeys.len() > 15` (consensus limit)
/// - Empty `pubkeys`
pub fn multisig_redeem_script(
    threshold: usize,
    pubkeys: &[[u8; 33]],
) -> Result<Vec<u8>, SignerError> {
    let n = pubkeys.len();

    if n == 0 {
        return Err(SignerError::ParseError("no public keys provided".into()));
    }
    if n > MAX_MULTISIG_KEYS {
        return Err(SignerError::ParseError(format!(
            "too many public keys: {n} (max {MAX_MULTISIG_KEYS})"
        )));
    }
    if threshold == 0 {
        return Err(SignerError::ParseError("threshold must be >= 1".into()));
    }
    if threshold > n {
        return Err(SignerError::ParseError(format!(
            "threshold {threshold} exceeds key count {n}"
        )));
    }

    // OP_m (OP_1..OP_16)
    let op_m = 0x50 + threshold as u8;
    let op_n = 0x50 + n as u8;

    // Size: 1 (OP_m) + n*(1+33) (push + key) + 1 (OP_n) + 1 (OP_CHECKMULTISIG)
    let mut script = Vec::with_capacity(3 + n * 34);
    script.push(op_m);

    for pk in pubkeys {
        script.push(33); // push 33 bytes
        script.extend_from_slice(pk);
    }

    script.push(op_n);
    script.push(0xAE); // OP_CHECKMULTISIG

    if script.len() > MAX_REDEEM_SCRIPT_SIZE {
        return Err(SignerError::ParseError(format!(
            "redeem script too large: {} bytes (max {MAX_REDEEM_SCRIPT_SIZE})",
            script.len()
        )));
    }

    Ok(script)
}

// ═══════════════════════════════════════════════════════════════════
// Script Hashing
// ═══════════════════════════════════════════════════════════════════

/// Compute the HASH160 of a script (for P2SH).
///
/// `HASH160(script) = RIPEMD160(SHA256(script))`
pub fn script_hash160(script: &[u8]) -> [u8; 20] {
    super::hash160(script)
}

/// Compute the SHA256 of a witness script (for P2WSH).
///
/// P2WSH uses single SHA256 (not HASH160) of the witness script.
pub fn witness_script_hash(script: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(script);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// ═══════════════════════════════════════════════════════════════════
// ScriptPubKey Construction
// ═══════════════════════════════════════════════════════════════════

/// Build a P2SH scriptPubKey from a script hash.
///
/// Format: `OP_HASH160 PUSH20 <script_hash> OP_EQUAL`
#[must_use]
pub fn p2sh_script_pubkey(script_hash: &[u8; 20]) -> Vec<u8> {
    let mut spk = Vec::with_capacity(23);
    spk.push(0xA9); // OP_HASH160
    spk.push(0x14); // PUSH 20 bytes
    spk.extend_from_slice(script_hash);
    spk.push(0x87); // OP_EQUAL
    spk
}

/// Build a P2WSH scriptPubKey from a witness script hash.
///
/// Format: `OP_0 PUSH32 <sha256(witness_script)>`
#[must_use]
pub fn p2wsh_script_pubkey(script_hash: &[u8; 32]) -> Vec<u8> {
    let mut spk = Vec::with_capacity(34);
    spk.push(0x00); // OP_0 (witness version 0)
    spk.push(0x20); // PUSH 32 bytes
    spk.extend_from_slice(script_hash);
    spk
}

/// Build a P2SH-P2WSH (nested SegWit) scriptPubKey.
///
/// The "inner" P2WSH scriptPubKey is wrapped in P2SH:
/// 1. Build P2WSH scriptPubKey from witness script hash
/// 2. HASH160 the P2WSH scriptPubKey → redeem script hash
/// 3. Build P2SH scriptPubKey from the redeem script hash
#[must_use]
pub fn p2sh_p2wsh_script_pubkey(witness_script_hash: &[u8; 32]) -> Vec<u8> {
    // The redeem script IS the P2WSH scriptPubKey
    let inner = p2wsh_script_pubkey(witness_script_hash);
    let hash = script_hash160(&inner);
    p2sh_script_pubkey(&hash)
}

// ═══════════════════════════════════════════════════════════════════
// Address Generation
// ═══════════════════════════════════════════════════════════════════

/// Generate a P2SH address from a redeem script.
///
/// - Mainnet: version byte `0x05`, addresses start with `3`
/// - Testnet: version byte `0xC4`, addresses start with `2`
#[must_use]
pub fn p2sh_address(redeem_script: &[u8], testnet: bool) -> String {
    let hash = script_hash160(redeem_script);
    let version = if testnet { 0xC4 } else { 0x05 };
    encoding::base58check_encode(version, &hash)
}

/// Generate a P2WSH (native SegWit) address from a witness script.
///
/// Uses Bech32 encoding with witness version 0 and a 32-byte program.
///
/// - Mainnet: `bc1q...` (actually `bc1q` for v0 with 32-byte program)
/// - Testnet: `tb1q...`
pub fn p2wsh_address(witness_script: &[u8], testnet: bool) -> Result<String, SignerError> {
    let hash = witness_script_hash(witness_script);
    let hrp = if testnet { "tb" } else { "bc" };
    encoding::bech32_encode(hrp, 0, &hash)
}

/// Generate a P2SH-P2WSH (nested SegWit) address from a witness script.
///
/// The P2WSH scriptPubKey (OP_0 || 32-byte hash) is used as the redeem script,
/// then wrapped in P2SH.
///
/// - Mainnet: addresses start with `3`
/// - Testnet: addresses start with `2`
#[must_use]
pub fn p2sh_p2wsh_address(witness_script: &[u8], testnet: bool) -> String {
    let wsh = witness_script_hash(witness_script);
    let inner = p2wsh_script_pubkey(&wsh);
    p2sh_address(&inner, testnet)
}

// ═══════════════════════════════════════════════════════════════════
// Witness Construction
// ═══════════════════════════════════════════════════════════════════

/// Build the witness stack for spending a P2WSH multisig output.
///
/// Witness: `<empty> <sig1> <sig2> ... <sigm> <witness_script>`
///
/// The leading empty element is required by the OP_CHECKMULTISIG off-by-one bug.
///
/// # Arguments
/// - `signatures` — DER-encoded signatures (with sighash byte appended)
/// - `witness_script` — The full witness script (m-of-n OP_CHECKMULTISIG)
#[must_use]
pub fn multisig_witness(signatures: &[Vec<u8>], witness_script: &[u8]) -> Vec<Vec<u8>> {
    let mut witness = Vec::with_capacity(2 + signatures.len());
    witness.push(vec![]); // OP_0 dummy (CHECKMULTISIG bug)
    for sig in signatures {
        witness.push(sig.clone());
    }
    witness.push(witness_script.to_vec());
    witness
}

/// Build the scriptSig for spending a P2SH multisig output.
///
/// scriptSig: `OP_0 <sig1> <sig2> ... <sigm> <serialized_redeem_script>`
///
/// Each element is length-prefixed with PUSHDATA opcodes as needed.
#[must_use]
pub fn multisig_script_sig(signatures: &[Vec<u8>], redeem_script: &[u8]) -> Vec<u8> {
    let mut script_sig = Vec::new();
    script_sig.push(0x00); // OP_0 dummy

    for sig in signatures {
        push_data_script(&mut script_sig, sig);
    }
    push_data_script(&mut script_sig, redeem_script);

    script_sig
}

/// Build the P2SH-P2WSH scriptSig (just the redeem script push).
///
/// scriptSig: `<serialized P2WSH scriptPubKey>`
///
/// The actual signatures go in the witness.
#[must_use]
pub fn p2sh_p2wsh_script_sig(witness_script_hash: &[u8; 32]) -> Vec<u8> {
    let inner = p2wsh_script_pubkey(witness_script_hash);
    let mut script_sig = Vec::with_capacity(1 + inner.len());
    push_data_script(&mut script_sig, &inner);
    script_sig
}

// ═══════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════

/// Push data with appropriate PUSHDATA opcodes.
fn push_data_script(script: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len <= 75 {
        script.push(len as u8);
    } else if len <= 255 {
        script.push(0x4C); // OP_PUSHDATA1
        script.push(len as u8);
    } else if len <= 65535 {
        script.push(0x4D); // OP_PUSHDATA2
        script.extend_from_slice(&(len as u16).to_le_bytes());
    }
    script.extend_from_slice(data);
}

/// Check if a script is a valid P2SH scriptPubKey.
///
/// P2SH: `OP_HASH160 <20 bytes> OP_EQUAL` (exactly 23 bytes)
#[must_use]
pub fn is_p2sh(script: &[u8]) -> bool {
    script.len() == 23 && script[0] == 0xA9 && script[1] == 0x14 && script[22] == 0x87
}

/// Check if a script is a valid P2WSH scriptPubKey.
///
/// P2WSH: `OP_0 <32 bytes>` (exactly 34 bytes)
#[must_use]
pub fn is_p2wsh(script: &[u8]) -> bool {
    script.len() == 34 && script[0] == 0x00 && script[1] == 0x20
}

/// Decode the threshold and key count from a standard multisig redeem script.
///
/// Returns `Some((m, n))` if the script is a standard m-of-n multisig,
/// or `None` if the script is not recognized.
pub fn decode_multisig_script(script: &[u8]) -> Option<(usize, usize)> {
    // Minimum: OP_m OP_n OP_CHECKMULTISIG = 3 bytes
    if script.len() < 3 {
        return None;
    }

    let last = script[script.len() - 1];
    if last != 0xAE {
        // OP_CHECKMULTISIG
        return None;
    }

    let op_m = script[0];
    let op_n = script[script.len() - 2];

    // OP_1..OP_16 = 0x51..0x60
    if !(0x51..=0x60).contains(&op_m) || !(0x51..=0x60).contains(&op_n) {
        return None;
    }

    let m = (op_m - 0x50) as usize;
    let n = (op_n - 0x50) as usize;

    if m > n || n > MAX_MULTISIG_KEYS {
        return None;
    }

    // Verify the script has the expected length: 1 + n*(1+33) + 1 + 1
    let expected_len = 3 + n * 34;
    if script.len() != expected_len {
        return None;
    }

    // Verify each key push is 33 bytes
    let mut pos = 1;
    for _ in 0..n {
        if pos >= script.len() || script[pos] != 33 {
            return None;
        }
        pos += 34; // push byte + 33 key bytes
    }

    Some((m, n))
}

/// Extract public keys from a standard multisig redeem script.
///
/// Returns `None` if the script is not a valid standard multisig.
pub fn extract_pubkeys(script: &[u8]) -> Option<Vec<[u8; 33]>> {
    let (_, n) = decode_multisig_script(script)?;

    let mut keys = Vec::with_capacity(n);
    let mut pos = 1; // skip OP_m
    for _ in 0..n {
        if script[pos] != 33 {
            return None;
        }
        let mut key = [0u8; 33];
        key.copy_from_slice(&script[pos + 1..pos + 34]);
        keys.push(key);
        pos += 34;
    }

    Some(keys)
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn dummy_keys(n: usize) -> Vec<[u8; 33]> {
        (0..n)
            .map(|i| {
                let mut key = [0x02u8; 33];
                key[32] = i as u8;
                key
            })
            .collect()
    }

    // Real secp256k1 compressed public keys (from BIP-11 / Bitcoin Core test vectors)
    fn real_pubkeys() -> Vec<[u8; 33]> {
        let hex_keys = [
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", // G point
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5", // 2G
            "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", // 3G
        ];
        hex_keys
            .iter()
            .map(|h| {
                let bytes = hex::decode(h).unwrap();
                let mut key = [0u8; 33];
                key.copy_from_slice(&bytes);
                key
            })
            .collect()
    }

    // ─── Redeem Script Construction ──────────────────────────────

    #[test]
    fn test_multisig_2_of_3() {
        let keys = dummy_keys(3);
        let script = multisig_redeem_script(2, &keys).unwrap();
        assert_eq!(script[0], 0x52); // OP_2
        assert_eq!(script[script.len() - 2], 0x53); // OP_3
        assert_eq!(script[script.len() - 1], 0xAE); // OP_CHECKMULTISIG
        assert_eq!(script.len(), 3 + 3 * 34);
    }

    #[test]
    fn test_multisig_1_of_1() {
        let keys = dummy_keys(1);
        let script = multisig_redeem_script(1, &keys).unwrap();
        assert_eq!(script[0], 0x51);
        assert_eq!(script[script.len() - 2], 0x51);
    }

    #[test]
    fn test_multisig_15_of_15() {
        let keys = dummy_keys(15);
        let script = multisig_redeem_script(15, &keys).unwrap();
        assert_eq!(script[0], 0x5F);
        assert_eq!(script[script.len() - 2], 0x5F);
    }

    #[test]
    fn test_multisig_threshold_zero() {
        let keys = dummy_keys(3);
        assert!(multisig_redeem_script(0, &keys).is_err());
    }

    #[test]
    fn test_multisig_threshold_exceeds_n() {
        let keys = dummy_keys(2);
        assert!(multisig_redeem_script(3, &keys).is_err());
    }

    #[test]
    fn test_multisig_empty_keys() {
        assert!(multisig_redeem_script(1, &[]).is_err());
    }

    #[test]
    fn test_multisig_too_many_keys() {
        let keys = dummy_keys(16);
        assert!(multisig_redeem_script(1, &keys).is_err());
    }

    #[test]
    fn test_multisig_contains_all_keys() {
        let keys = dummy_keys(3);
        let script = multisig_redeem_script(2, &keys).unwrap();
        for key in &keys {
            assert!(script.windows(33).any(|w| w == key));
        }
    }

    // ─── Test Vector: Real Secp256k1 Keys ────────────────────────

    #[test]
    fn test_real_pubkey_2_of_3_redeem_script() {
        let keys = real_pubkeys();
        let script = multisig_redeem_script(2, &keys).unwrap();
        // Byte-level verification: OP_2 <33> <pk1> <33> <pk2> <33> <pk3> OP_3 OP_CHECKMULTISIG
        assert_eq!(script[0], 0x52); // OP_2
        assert_eq!(script[1], 33); // push length
        assert_eq!(&script[2..35], &keys[0]);
        assert_eq!(script[35], 33);
        assert_eq!(&script[36..69], &keys[1]);
        assert_eq!(script[69], 33);
        assert_eq!(&script[70..103], &keys[2]);
        assert_eq!(script[103], 0x53); // OP_3
        assert_eq!(script[104], 0xAE); // OP_CHECKMULTISIG
        assert_eq!(script.len(), 105);
    }

    #[test]
    fn test_real_pubkey_p2sh_address_stable() {
        let keys = real_pubkeys();
        let script = multisig_redeem_script(2, &keys).unwrap();
        let addr = p2sh_address(&script, false);
        // Same keys always produce the same P2SH address
        let addr2 = p2sh_address(&script, false);
        assert_eq!(addr, addr2);
        assert!(addr.starts_with('3'));
        // P2SH addresses are 34 chars (base58check of 1+20+4 bytes)
        assert_eq!(addr.len(), 34);
    }

    #[test]
    fn test_real_pubkey_p2wsh_address_length() {
        let keys = real_pubkeys();
        let script = multisig_redeem_script(2, &keys).unwrap();
        let addr = p2wsh_address(&script, false).unwrap();
        // Bech32 P2WSH addresses: bc1q + 58 chars = 62 total
        assert!(addr.starts_with("bc1q"));
        assert_eq!(addr.len(), 62);
    }

    #[test]
    fn test_real_pubkey_decode_roundtrip() {
        let keys = real_pubkeys();
        let script = multisig_redeem_script(2, &keys).unwrap();
        let (m, n) = decode_multisig_script(&script).unwrap();
        assert_eq!(m, 2);
        assert_eq!(n, 3);
        let extracted = extract_pubkeys(&script).unwrap();
        assert_eq!(extracted, keys);
    }

    // ─── Exhaustive m-of-n Combinations ──────────────────────────

    #[test]
    fn test_all_valid_thresholds_1_to_15() {
        for n in 1..=15usize {
            let keys = dummy_keys(n);
            for m in 1..=n {
                let script = multisig_redeem_script(m, &keys).unwrap();
                assert_eq!(script[0], 0x50 + m as u8, "OP_m for {m}-of-{n}");
                assert_eq!(
                    script[script.len() - 2],
                    0x50 + n as u8,
                    "OP_n for {m}-of-{n}"
                );
                assert_eq!(script[script.len() - 1], 0xAE, "OP_CMS for {m}-of-{n}");
                assert_eq!(script.len(), 3 + n * 34, "length for {m}-of-{n}");

                // Roundtrip decode
                let (dm, dn) = decode_multisig_script(&script).unwrap();
                assert_eq!(dm, m, "decoded m for {m}-of-{n}");
                assert_eq!(dn, n, "decoded n for {m}-of-{n}");

                // Extract keys roundtrip
                let extracted = extract_pubkeys(&script).unwrap();
                assert_eq!(extracted.len(), n);
                assert_eq!(extracted, keys, "keys roundtrip for {m}-of-{n}");
            }
        }
    }

    // ─── SHA256 Known Test Vector ────────────────────────────────

    #[test]
    fn test_witness_script_hash_known_vector() {
        // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = witness_script_hash(b"");
        assert_eq!(
            hex::encode(hash),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_witness_script_hash_abc() {
        // SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let hash = witness_script_hash(b"abc");
        assert_eq!(
            hex::encode(hash),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    // ─── Script Hashing ──────────────────────────────────────────

    #[test]
    fn test_script_hash160_deterministic() {
        let data = b"test script";
        assert_eq!(script_hash160(data), script_hash160(data));
    }

    #[test]
    fn test_witness_script_hash_deterministic() {
        let data = b"test witness script";
        assert_eq!(witness_script_hash(data), witness_script_hash(data));
    }

    #[test]
    fn test_witness_script_hash_differs_from_hash160() {
        let data = b"test";
        let h160 = script_hash160(data);
        let wsh = witness_script_hash(data);
        assert_ne!(&h160[..], &wsh[..20]);
    }

    #[test]
    fn test_hash160_empty_input() {
        // HASH160("") is deterministic — known value
        let h = script_hash160(b"");
        assert_eq!(h.len(), 20);
        // Verify it matches RIPEMD160(SHA256(""))
        let expected = "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb";
        assert_eq!(hex::encode(h), expected);
    }

    // ─── ScriptPubKey Construction ───────────────────────────────

    #[test]
    fn test_p2sh_script_pubkey_structure() {
        let hash = [0xAA; 20];
        let spk = p2sh_script_pubkey(&hash);
        assert_eq!(spk.len(), 23);
        assert_eq!(spk[0], 0xA9);
        assert_eq!(spk[1], 0x14);
        assert_eq!(&spk[2..22], &hash);
        assert_eq!(spk[22], 0x87);
    }

    #[test]
    fn test_p2wsh_script_pubkey_structure() {
        let hash = [0xBB; 32];
        let spk = p2wsh_script_pubkey(&hash);
        assert_eq!(spk.len(), 34);
        assert_eq!(spk[0], 0x00);
        assert_eq!(spk[1], 0x20);
        assert_eq!(&spk[2..34], &hash);
    }

    #[test]
    fn test_p2sh_p2wsh_script_pubkey_is_p2sh() {
        let wsh = [0xCC; 32];
        let spk = p2sh_p2wsh_script_pubkey(&wsh);
        assert!(is_p2sh(&spk));
    }

    #[test]
    fn test_p2sh_script_pubkey_hex_encoding() {
        // Known P2SH script: OP_HASH160 <20 zero bytes> OP_EQUAL
        let hash = [0u8; 20];
        let spk = p2sh_script_pubkey(&hash);
        let expected = "a914000000000000000000000000000000000000000087";
        assert_eq!(hex::encode(&spk), expected);
    }

    #[test]
    fn test_p2wsh_script_pubkey_hex_encoding() {
        // Known P2WSH script: OP_0 <32 zero bytes>
        let hash = [0u8; 32];
        let spk = p2wsh_script_pubkey(&hash);
        let expected = "00200000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(hex::encode(&spk), expected);
    }

    // ─── Address Generation ──────────────────────────────────────

    #[test]
    fn test_p2sh_address_mainnet_starts_with_3() {
        let keys = dummy_keys(2);
        let script = multisig_redeem_script(2, &keys).unwrap();
        let addr = p2sh_address(&script, false);
        assert!(addr.starts_with('3'));
    }

    #[test]
    fn test_p2sh_address_testnet_starts_with_2() {
        let keys = dummy_keys(2);
        let script = multisig_redeem_script(2, &keys).unwrap();
        let addr = p2sh_address(&script, true);
        assert!(addr.starts_with('2'));
    }

    #[test]
    fn test_p2wsh_address_mainnet_starts_with_bc1() {
        let keys = dummy_keys(2);
        let script = multisig_redeem_script(2, &keys).unwrap();
        let addr = p2wsh_address(&script, false).unwrap();
        assert!(addr.starts_with("bc1"));
    }

    #[test]
    fn test_p2wsh_address_testnet_starts_with_tb1() {
        let keys = dummy_keys(2);
        let script = multisig_redeem_script(2, &keys).unwrap();
        let addr = p2wsh_address(&script, true).unwrap();
        assert!(addr.starts_with("tb1"));
    }

    #[test]
    fn test_p2sh_p2wsh_address_mainnet() {
        let keys = dummy_keys(3);
        let script = multisig_redeem_script(2, &keys).unwrap();
        let addr = p2sh_p2wsh_address(&script, false);
        assert!(addr.starts_with('3'));
    }

    #[test]
    fn test_p2sh_p2wsh_address_testnet() {
        let keys = dummy_keys(3);
        let script = multisig_redeem_script(2, &keys).unwrap();
        let addr = p2sh_p2wsh_address(&script, true);
        assert!(addr.starts_with('2'));
    }

    #[test]
    fn test_different_wrapping_produces_different_addresses() {
        let keys = dummy_keys(2);
        let script = multisig_redeem_script(2, &keys).unwrap();
        let a1 = p2sh_address(&script, false);
        let a2 = p2wsh_address(&script, false).unwrap();
        let a3 = p2sh_p2wsh_address(&script, false);
        assert_ne!(a1, a2);
        assert_ne!(a1, a3);
        assert_ne!(a2, a3);
    }

    #[test]
    fn test_mainnet_vs_testnet_addresses_differ() {
        let keys = dummy_keys(2);
        let script = multisig_redeem_script(2, &keys).unwrap();
        assert_ne!(p2sh_address(&script, false), p2sh_address(&script, true));
        assert_ne!(
            p2wsh_address(&script, false).unwrap(),
            p2wsh_address(&script, true).unwrap()
        );
        assert_ne!(
            p2sh_p2wsh_address(&script, false),
            p2sh_p2wsh_address(&script, true),
        );
    }

    // ─── Witness / ScriptSig ─────────────────────────────────────

    #[test]
    fn test_multisig_witness_structure() {
        let sigs = vec![vec![0x30; 71], vec![0x30; 72]];
        let script = vec![0xAE; 10];
        let witness = multisig_witness(&sigs, &script);
        assert_eq!(witness.len(), 4);
        assert!(witness[0].is_empty());
        assert_eq!(witness[1], sigs[0]);
        assert_eq!(witness[2], sigs[1]);
        assert_eq!(witness[3], script);
    }

    #[test]
    fn test_multisig_witness_single_sig() {
        let sigs = vec![vec![0x30; 72]];
        let script = vec![0xAE];
        let witness = multisig_witness(&sigs, &script);
        assert_eq!(witness.len(), 3); // empty + 1 sig + script
    }

    #[test]
    fn test_multisig_witness_empty_sigs() {
        let witness = multisig_witness(&[], &[0xAE]);
        assert_eq!(witness.len(), 2); // empty + script
        assert!(witness[0].is_empty());
        assert_eq!(witness[1], vec![0xAE]);
    }

    #[test]
    fn test_multisig_script_sig_structure() {
        let sigs = vec![vec![0x30, 0x44], vec![0x30, 0x45]];
        let redeem = vec![0xAE; 10];
        let script_sig = multisig_script_sig(&sigs, &redeem);
        assert_eq!(script_sig[0], 0x00);
        assert!(script_sig.len() > 3 + sigs[0].len() + sigs[1].len() + redeem.len());
    }

    #[test]
    fn test_multisig_script_sig_with_real_script() {
        let keys = dummy_keys(3);
        let redeem = multisig_redeem_script(2, &keys).unwrap();
        // Mock DER sigs (30 44 ... 01 = DER + SIGHASH_ALL)
        let sig1 = vec![0x30; 72];
        let sig2 = vec![0x30; 71];
        let ss = multisig_script_sig(&[sig1.clone(), sig2.clone()], &redeem);

        // OP_0 + push(sig1) + push(sig2) + OP_PUSHDATA1(redeem)
        assert_eq!(ss[0], 0x00);
        // sig1 is 72 bytes → push byte 72
        assert_eq!(ss[1], 72);
        assert_eq!(&ss[2..74], &sig1[..]);
        // sig2 is 71 bytes → push byte 71
        assert_eq!(ss[74], 71);
        assert_eq!(&ss[75..146], &sig2[..]);
        // redeem is 105 bytes → OP_PUSHDATA1 (0x4C) then length
        assert_eq!(ss[146], 0x4C);
        assert_eq!(ss[147], 105);
    }

    #[test]
    fn test_p2sh_p2wsh_script_sig_structure() {
        let wsh = [0xCC; 32];
        let script_sig = p2sh_p2wsh_script_sig(&wsh);
        assert_eq!(script_sig[0], 34);
        assert_eq!(script_sig[1], 0x00);
        assert_eq!(script_sig[2], 0x20);
        assert_eq!(script_sig.len(), 35);
        // Verify embedded WSH
        assert_eq!(&script_sig[3..35], &wsh);
    }

    // ─── Script Detection ────────────────────────────────────────

    #[test]
    fn test_is_p2sh() {
        let hash = [0xAA; 20];
        let spk = p2sh_script_pubkey(&hash);
        assert!(is_p2sh(&spk));
        assert!(!is_p2sh(&[0u8; 34]));
        assert!(!is_p2sh(&[]));
    }

    #[test]
    fn test_is_p2sh_wrong_length() {
        assert!(!is_p2sh(&[0xA9, 0x14, 0x00])); // too short
        let mut too_long = vec![0xA9, 0x14];
        too_long.extend_from_slice(&[0; 20]);
        too_long.push(0x87);
        too_long.push(0xFF); // extra byte
        assert!(!is_p2sh(&too_long));
    }

    #[test]
    fn test_is_p2sh_wrong_opcodes() {
        let mut bad = vec![0x00, 0x14]; // wrong first opcode
        bad.extend_from_slice(&[0; 20]);
        bad.push(0x87);
        assert!(!is_p2sh(&bad));
    }

    #[test]
    fn test_is_p2wsh() {
        let hash = [0xBB; 32];
        let spk = p2wsh_script_pubkey(&hash);
        assert!(is_p2wsh(&spk));
        assert!(!is_p2wsh(&[0u8; 23]));
        assert!(!is_p2wsh(&[]));
    }

    #[test]
    fn test_is_p2wsh_wrong_version() {
        let mut bad = vec![0x01, 0x20]; // witness version 1, not 0
        bad.extend_from_slice(&[0; 32]);
        assert!(!is_p2wsh(&bad));
    }

    // ─── Decode Multisig Script ──────────────────────────────────

    #[test]
    fn test_decode_multisig_2_of_3() {
        let keys = dummy_keys(3);
        let script = multisig_redeem_script(2, &keys).unwrap();
        let (m, n) = decode_multisig_script(&script).unwrap();
        assert_eq!(m, 2);
        assert_eq!(n, 3);
    }

    #[test]
    fn test_decode_multisig_1_of_1() {
        let keys = dummy_keys(1);
        let script = multisig_redeem_script(1, &keys).unwrap();
        let (m, n) = decode_multisig_script(&script).unwrap();
        assert_eq!(m, 1);
        assert_eq!(n, 1);
    }

    #[test]
    fn test_decode_multisig_invalid() {
        assert!(decode_multisig_script(&[]).is_none());
        assert!(decode_multisig_script(&[0x00, 0x00]).is_none());
        assert!(decode_multisig_script(&[0x52, 0x53, 0xAB]).is_none());
    }

    #[test]
    fn test_decode_multisig_corrupted_push_byte() {
        let keys = dummy_keys(2);
        let mut script = multisig_redeem_script(2, &keys).unwrap();
        // Corrupt the push byte of the first key
        script[1] = 32; // should be 33
        assert!(decode_multisig_script(&script).is_none());
    }

    #[test]
    fn test_decode_multisig_wrong_length() {
        // Script that claims 2-of-3 but has wrong length
        let mut script = vec![0x52]; // OP_2
        script.push(33);
        script.extend_from_slice(&[0x02; 33]);
        // Only 1 key, so OP_3 + OP_CMS would be wrong
        script.push(0x53);
        script.push(0xAE);
        assert!(decode_multisig_script(&script).is_none());
    }

    #[test]
    fn test_decode_m_greater_than_n() {
        // Manually craft a script with m > n (invalid but well-formed bytes)
        // OP_3 <key1> OP_2 OP_CHECKMULTISIG — 3 > 2 but only 1 key
        let mut script = vec![0x53]; // OP_3
        script.push(33);
        script.extend_from_slice(&[0x02; 33]);
        script.push(0x52); // OP_2
        script.push(0xAE);
        assert!(decode_multisig_script(&script).is_none());
    }

    // ─── Extract Pubkeys ─────────────────────────────────────────

    #[test]
    fn test_extract_pubkeys() {
        let keys = dummy_keys(3);
        let script = multisig_redeem_script(2, &keys).unwrap();
        let extracted = extract_pubkeys(&script).unwrap();
        assert_eq!(extracted.len(), 3);
        assert_eq!(extracted, keys);
    }

    #[test]
    fn test_extract_pubkeys_invalid() {
        assert!(extract_pubkeys(&[]).is_none());
    }

    #[test]
    fn test_extract_pubkeys_real_keys() {
        let keys = real_pubkeys();
        let script = multisig_redeem_script(2, &keys).unwrap();
        let extracted = extract_pubkeys(&script).unwrap();
        assert_eq!(extracted[0], keys[0]);
        assert_eq!(extracted[1], keys[1]);
        assert_eq!(extracted[2], keys[2]);
    }

    // ─── End-to-End Flows ────────────────────────────────────────

    #[test]
    fn test_full_p2sh_multisig_flow() {
        let keys = dummy_keys(3);
        let script = multisig_redeem_script(2, &keys).unwrap();
        let addr = p2sh_address(&script, false);
        assert!(addr.starts_with('3'));

        let sigs = vec![vec![0x30; 71], vec![0x30; 72]];
        let ss = multisig_script_sig(&sigs, &script);
        assert!(!ss.is_empty());

        let (m, n) = decode_multisig_script(&script).unwrap();
        assert_eq!(m, 2);
        assert_eq!(n, 3);
    }

    #[test]
    fn test_full_p2wsh_multisig_flow() {
        let keys = dummy_keys(3);
        let ws = multisig_redeem_script(2, &keys).unwrap();
        let addr = p2wsh_address(&ws, false).unwrap();
        assert!(addr.starts_with("bc1"));

        let sigs = vec![vec![0x30; 71], vec![0x30; 72]];
        let witness = multisig_witness(&sigs, &ws);
        assert_eq!(witness.len(), 4);
    }

    #[test]
    fn test_full_p2sh_p2wsh_flow() {
        let keys = dummy_keys(3);
        let ws = multisig_redeem_script(2, &keys).unwrap();
        let wsh = witness_script_hash(&ws);
        let addr = p2sh_p2wsh_address(&ws, false);
        assert!(addr.starts_with('3'));

        let ss = p2sh_p2wsh_script_sig(&wsh);
        assert_eq!(ss.len(), 35);

        let sigs = vec![vec![0x30; 71], vec![0x30; 72]];
        let witness = multisig_witness(&sigs, &ws);
        assert_eq!(witness.len(), 4);
    }

    #[test]
    fn test_full_flow_real_keys() {
        let keys = real_pubkeys();

        // P2SH
        let script = multisig_redeem_script(2, &keys).unwrap();
        let p2sh_addr = p2sh_address(&script, false);
        assert!(p2sh_addr.starts_with('3'));

        // P2WSH
        let p2wsh_addr = p2wsh_address(&script, false).unwrap();
        assert!(p2wsh_addr.starts_with("bc1q"));

        // P2SH-P2WSH
        let p2sh_p2wsh_addr = p2sh_p2wsh_address(&script, false);
        assert!(p2sh_p2wsh_addr.starts_with('3'));

        // All different
        assert_ne!(p2sh_addr, p2sh_p2wsh_addr);
        assert_ne!(p2sh_addr, p2wsh_addr);

        // ScriptPubKey detection
        let wsh = witness_script_hash(&script);
        let spk_p2sh = p2sh_script_pubkey(&script_hash160(&script));
        let spk_p2wsh = p2wsh_script_pubkey(&wsh);
        assert!(is_p2sh(&spk_p2sh));
        assert!(is_p2wsh(&spk_p2wsh));
        assert!(!is_p2sh(&spk_p2wsh));
        assert!(!is_p2wsh(&spk_p2sh));
    }

    // ─── Push Data ───────────────────────────────────────────────

    #[test]
    fn test_push_data_small() {
        let mut s = Vec::new();
        push_data_script(&mut s, &[0xAA; 10]);
        assert_eq!(s[0], 10);
        assert_eq!(&s[1..], &[0xAA; 10]);
    }

    #[test]
    fn test_push_data_boundary_75() {
        // 75 bytes is the max for direct push
        let mut s = Vec::new();
        let data = vec![0xBB; 75];
        push_data_script(&mut s, &data);
        assert_eq!(s[0], 75);
        assert_eq!(s.len(), 76);
    }

    #[test]
    fn test_push_data_boundary_76() {
        // 76 bytes triggers OP_PUSHDATA1
        let mut s = Vec::new();
        let data = vec![0xBB; 76];
        push_data_script(&mut s, &data);
        assert_eq!(s[0], 0x4C); // OP_PUSHDATA1
        assert_eq!(s[1], 76);
        assert_eq!(s.len(), 78);
    }

    #[test]
    fn test_push_data_medium() {
        let mut s = Vec::new();
        let data = vec![0xBB; 100];
        push_data_script(&mut s, &data);
        assert_eq!(s[0], 0x4C);
        assert_eq!(s[1], 100);
        assert_eq!(&s[2..], &data[..]);
    }

    #[test]
    fn test_push_data_boundary_255() {
        let mut s = Vec::new();
        let data = vec![0xCC; 255];
        push_data_script(&mut s, &data);
        assert_eq!(s[0], 0x4C); // Still OP_PUSHDATA1
        assert_eq!(s[1], 255);
    }

    #[test]
    fn test_push_data_boundary_256() {
        // 256 bytes triggers OP_PUSHDATA2
        let mut s = Vec::new();
        let data = vec![0xCC; 256];
        push_data_script(&mut s, &data);
        assert_eq!(s[0], 0x4D);
        let len = u16::from_le_bytes([s[1], s[2]]);
        assert_eq!(len, 256);
        assert_eq!(s.len(), 259);
    }

    #[test]
    fn test_push_data_large() {
        let mut s = Vec::new();
        let data = vec![0xCC; 300];
        push_data_script(&mut s, &data);
        assert_eq!(s[0], 0x4D);
        let len = u16::from_le_bytes([s[1], s[2]]);
        assert_eq!(len, 300);
    }

    #[test]
    fn test_push_data_empty() {
        let mut s = Vec::new();
        push_data_script(&mut s, &[]);
        assert_eq!(s, vec![0x00]); // push 0 bytes
    }

    #[test]
    fn test_push_data_single_byte() {
        let mut s = Vec::new();
        push_data_script(&mut s, &[0xFF]);
        assert_eq!(s, vec![0x01, 0xFF]);
    }

    // ─── Deterministic Addresses ─────────────────────────────────

    #[test]
    fn test_same_keys_same_address() {
        let keys = dummy_keys(3);
        let s1 = multisig_redeem_script(2, &keys).unwrap();
        let s2 = multisig_redeem_script(2, &keys).unwrap();
        assert_eq!(p2sh_address(&s1, false), p2sh_address(&s2, false));
    }

    #[test]
    fn test_different_threshold_different_address() {
        let keys = dummy_keys(3);
        let s1 = multisig_redeem_script(1, &keys).unwrap();
        let s2 = multisig_redeem_script(2, &keys).unwrap();
        assert_ne!(p2sh_address(&s1, false), p2sh_address(&s2, false));
    }

    #[test]
    fn test_different_key_order_different_address() {
        let keys1 = dummy_keys(3);
        let mut keys2 = keys1.clone();
        keys2.swap(0, 1);
        let s1 = multisig_redeem_script(2, &keys1).unwrap();
        let s2 = multisig_redeem_script(2, &keys2).unwrap();
        assert_ne!(p2sh_address(&s1, false), p2sh_address(&s2, false));
    }

    // ─── Cross-wrapping Consistency ──────────────────────────────

    #[test]
    fn test_p2sh_p2wsh_is_hash_of_p2wsh() {
        let keys = dummy_keys(3);
        let script = multisig_redeem_script(2, &keys).unwrap();
        let wsh = witness_script_hash(&script);

        // The P2SH-P2WSH address wraps the P2WSH scriptPubKey
        let p2wsh_spk = p2wsh_script_pubkey(&wsh);
        let wrapped_addr = p2sh_address(&p2wsh_spk, false);
        let direct_addr = p2sh_p2wsh_address(&script, false);
        assert_eq!(wrapped_addr, direct_addr);
    }

    #[test]
    fn test_p2sh_p2wsh_script_pubkey_consistency() {
        let keys = dummy_keys(2);
        let script = multisig_redeem_script(2, &keys).unwrap();
        let wsh = witness_script_hash(&script);

        // Build P2SH-P2WSH scriptPubKey two ways
        let spk1 = p2sh_p2wsh_script_pubkey(&wsh);
        let inner = p2wsh_script_pubkey(&wsh);
        let spk2 = p2sh_script_pubkey(&script_hash160(&inner));
        assert_eq!(spk1, spk2);
    }

    // ─── Script Size Limits ──────────────────────────────────────

    #[test]
    fn test_redeem_script_size_under_520() {
        // 15 keys = 3 + 15*34 = 513 bytes < 520
        let keys = dummy_keys(15);
        let script = multisig_redeem_script(1, &keys).unwrap();
        assert!(script.len() <= MAX_REDEEM_SCRIPT_SIZE);
        assert_eq!(script.len(), 513);
    }

    #[test]
    fn test_threshold_equal_to_n() {
        // m == n is valid
        let keys = dummy_keys(5);
        let script = multisig_redeem_script(5, &keys).unwrap();
        let (m, n) = decode_multisig_script(&script).unwrap();
        assert_eq!(m, 5);
        assert_eq!(n, 5);
    }

    #[test]
    fn test_threshold_1_of_15() {
        let keys = dummy_keys(15);
        let script = multisig_redeem_script(1, &keys).unwrap();
        let (m, n) = decode_multisig_script(&script).unwrap();
        assert_eq!(m, 1);
        assert_eq!(n, 15);
    }

    // ─── Error Message Content ───────────────────────────────────

    #[test]
    fn test_error_message_empty_keys() {
        let err = multisig_redeem_script(1, &[]).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("no public keys"), "got: {msg}");
    }

    #[test]
    fn test_error_message_too_many() {
        let keys = dummy_keys(16);
        let err = multisig_redeem_script(1, &keys).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("too many") || msg.contains("16"), "got: {msg}");
    }

    #[test]
    fn test_error_message_threshold_zero() {
        let keys = dummy_keys(2);
        let err = multisig_redeem_script(0, &keys).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("threshold") || msg.contains(">= 1"),
            "got: {msg}"
        );
    }

    #[test]
    fn test_error_message_threshold_exceeds() {
        let keys = dummy_keys(2);
        let err = multisig_redeem_script(5, &keys).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("exceeds") || msg.contains("5"), "got: {msg}");
    }
}
