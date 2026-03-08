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
        return Err(SignerError::ParseError(
            format!("too many public keys: {n} (max {MAX_MULTISIG_KEYS})"),
        ));
    }
    if threshold == 0 {
        return Err(SignerError::ParseError("threshold must be >= 1".into()));
    }
    if threshold > n {
        return Err(SignerError::ParseError(
            format!("threshold {threshold} exceeds key count {n}"),
        ));
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
        return Err(SignerError::ParseError(
            format!(
                "redeem script too large: {} bytes (max {MAX_REDEEM_SCRIPT_SIZE})",
                script.len()
            ),
        ));
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

    // ─── Redeem Script Construction ──────────────────────────────

    #[test]
    fn test_multisig_2_of_3() {
        let keys = dummy_keys(3);
        let script = multisig_redeem_script(2, &keys).unwrap();
        // OP_2 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG
        assert_eq!(script[0], 0x52); // OP_2
        assert_eq!(script[script.len() - 2], 0x53); // OP_3
        assert_eq!(script[script.len() - 1], 0xAE); // OP_CHECKMULTISIG
        assert_eq!(script.len(), 3 + 3 * 34);
    }

    #[test]
    fn test_multisig_1_of_1() {
        let keys = dummy_keys(1);
        let script = multisig_redeem_script(1, &keys).unwrap();
        assert_eq!(script[0], 0x51); // OP_1
        assert_eq!(script[script.len() - 2], 0x51); // OP_1
    }

    #[test]
    fn test_multisig_15_of_15() {
        let keys = dummy_keys(15);
        let script = multisig_redeem_script(15, &keys).unwrap();
        assert_eq!(script[0], 0x5F); // OP_15
        assert_eq!(script[script.len() - 2], 0x5F); // OP_15
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
        // Different lengths, different algorithms
        assert_ne!(&h160[..], &wsh[..20]);
    }

    // ─── ScriptPubKey Construction ───────────────────────────────

    #[test]
    fn test_p2sh_script_pubkey_structure() {
        let hash = [0xAA; 20];
        let spk = p2sh_script_pubkey(&hash);
        assert_eq!(spk.len(), 23);
        assert_eq!(spk[0], 0xA9); // OP_HASH160
        assert_eq!(spk[1], 0x14); // PUSH 20
        assert_eq!(&spk[2..22], &hash);
        assert_eq!(spk[22], 0x87); // OP_EQUAL
    }

    #[test]
    fn test_p2wsh_script_pubkey_structure() {
        let hash = [0xBB; 32];
        let spk = p2wsh_script_pubkey(&hash);
        assert_eq!(spk.len(), 34);
        assert_eq!(spk[0], 0x00); // OP_0
        assert_eq!(spk[1], 0x20); // PUSH 32
        assert_eq!(&spk[2..34], &hash);
    }

    #[test]
    fn test_p2sh_p2wsh_script_pubkey_is_p2sh() {
        let wsh = [0xCC; 32];
        let spk = p2sh_p2wsh_script_pubkey(&wsh);
        assert!(is_p2sh(&spk));
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

    // ─── Witness / ScriptSig ─────────────────────────────────────

    #[test]
    fn test_multisig_witness_structure() {
        let sigs = vec![vec![0x30; 71], vec![0x30; 72]];
        let script = vec![0xAE; 10];
        let witness = multisig_witness(&sigs, &script);
        // [empty, sig1, sig2, script]
        assert_eq!(witness.len(), 4);
        assert!(witness[0].is_empty()); // OP_0 dummy
        assert_eq!(witness[1], sigs[0]);
        assert_eq!(witness[2], sigs[1]);
        assert_eq!(witness[3], script);
    }

    #[test]
    fn test_multisig_script_sig_structure() {
        let sigs = vec![vec![0x30, 0x44], vec![0x30, 0x45]];
        let redeem = vec![0xAE; 10];
        let script_sig = multisig_script_sig(&sigs, &redeem);
        // First byte should be OP_0
        assert_eq!(script_sig[0], 0x00);
        // Should contain both sigs and the redeem script
        assert!(script_sig.len() > 3 + sigs[0].len() + sigs[1].len() + redeem.len());
    }

    #[test]
    fn test_p2sh_p2wsh_script_sig_structure() {
        let wsh = [0xCC; 32];
        let script_sig = p2sh_p2wsh_script_sig(&wsh);
        // Should be: push(34-byte P2WSH scriptPubKey)
        // P2WSH = OP_0 + 0x20 + 32 bytes = 34 bytes
        assert_eq!(script_sig[0], 34); // push 34 bytes
        assert_eq!(script_sig[1], 0x00); // OP_0
        assert_eq!(script_sig[2], 0x20); // PUSH 32
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
    fn test_is_p2wsh() {
        let hash = [0xBB; 32];
        let spk = p2wsh_script_pubkey(&hash);
        assert!(is_p2wsh(&spk));
        assert!(!is_p2wsh(&[0u8; 23]));
        assert!(!is_p2wsh(&[]));
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
        assert!(decode_multisig_script(&[0x52, 0x53, 0xAB]).is_none()); // wrong opcode
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

    // ─── End-to-End Flows ────────────────────────────────────────

    #[test]
    fn test_full_p2sh_multisig_flow() {
        let keys = dummy_keys(3);
        let script = multisig_redeem_script(2, &keys).unwrap();
        let addr = p2sh_address(&script, false);
        assert!(addr.starts_with('3'));

        // Build scriptSig with 2 dummy signatures
        let sigs = vec![vec![0x30; 71], vec![0x30; 72]];
        let ss = multisig_script_sig(&sigs, &script);
        assert!(ss.len() > 0);

        // Decode the script
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

        // Build witness with 2 dummy signatures
        let sigs = vec![vec![0x30; 71], vec![0x30; 72]];
        let witness = multisig_witness(&sigs, &ws);
        assert_eq!(witness.len(), 4); // empty + 2 sigs + script
    }

    #[test]
    fn test_full_p2sh_p2wsh_flow() {
        let keys = dummy_keys(3);
        let ws = multisig_redeem_script(2, &keys).unwrap();
        let wsh = witness_script_hash(&ws);
        let addr = p2sh_p2wsh_address(&ws, false);
        assert!(addr.starts_with('3'));

        // ScriptSig is just the P2WSH scriptPubKey
        let ss = p2sh_p2wsh_script_sig(&wsh);
        assert_eq!(ss.len(), 35); // 1 push byte + 34 P2WSH scriptPubKey

        // Witness has the actual sigs
        let sigs = vec![vec![0x30; 71], vec![0x30; 72]];
        let witness = multisig_witness(&sigs, &ws);
        assert_eq!(witness.len(), 4);
    }

    // ─── Push Data ───────────────────────────────────────────────

    #[test]
    fn test_push_data_small() {
        let mut s = Vec::new();
        push_data_script(&mut s, &[0xAA; 10]);
        assert_eq!(s[0], 10); // direct push
        assert_eq!(&s[1..], &[0xAA; 10]);
    }

    #[test]
    fn test_push_data_medium() {
        let mut s = Vec::new();
        let data = vec![0xBB; 100];
        push_data_script(&mut s, &data);
        assert_eq!(s[0], 0x4C); // OP_PUSHDATA1
        assert_eq!(s[1], 100);
        assert_eq!(&s[2..], &data[..]);
    }

    #[test]
    fn test_push_data_large() {
        let mut s = Vec::new();
        let data = vec![0xCC; 300];
        push_data_script(&mut s, &data);
        assert_eq!(s[0], 0x4D); // OP_PUSHDATA2
        let len = u16::from_le_bytes([s[1], s[2]]);
        assert_eq!(len, 300);
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
        let mut keys1 = dummy_keys(3);
        let mut keys2 = keys1.clone();
        keys2.swap(0, 1);
        let s1 = multisig_redeem_script(2, &keys1).unwrap();
        let s2 = multisig_redeem_script(2, &keys2).unwrap();
        // Different key order = different script = different address
        assert_ne!(p2sh_address(&s1, false), p2sh_address(&s2, false));
    }
}
