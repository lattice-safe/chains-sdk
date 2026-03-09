//! Bitcoin Lightning Network script helpers.
//!
//! Implements anchor output scripts, commitment transaction components,
//! and HTLC scripts as defined in BOLT #3.
//!
//! # Example
//! ```no_run
//! use chains_sdk::bitcoin::lightning::*;
//!
//! let local_key = [0x02; 33];
//! let script = to_local_script(&local_key, 144, &local_key);
//! ```

// ═══════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════

/// Anchor output value in satoshis (330 sat — dust limit for P2WSH).
pub const ANCHOR_VALUE: u64 = 330;

/// Default `to_self_delay` for commitment transactions (144 blocks ≈ 1 day).
pub const DEFAULT_TO_SELF_DELAY: u16 = 144;

// ═══════════════════════════════════════════════════════════════════
// Anchor Outputs (BOLT #3 — Anchor Channels)
// ═══════════════════════════════════════════════════════════════════

/// Build an anchor output script.
///
/// Script:
/// ```text
/// <funding_pubkey> OP_CHECKSIG
/// OP_IFDUP OP_NOTIF
///   OP_16 OP_CSV
/// OP_ENDIF
/// ```
///
/// The anchor can be spent immediately by the owner, or by anyone after 16 blocks.
/// This allows CPFP fee-bumping of commitment transactions.
///
/// # Arguments
/// - `funding_pubkey` — 33-byte compressed public key of the channel participant
#[must_use]
pub fn anchor_script(funding_pubkey: &[u8; 33]) -> Vec<u8> {
    let mut script = Vec::with_capacity(40);

    // <funding_pubkey> OP_CHECKSIG
    script.push(33); // push 33 bytes
    script.extend_from_slice(funding_pubkey);
    script.push(0xAC); // OP_CHECKSIG

    // OP_IFDUP OP_NOTIF
    script.push(0x73); // OP_IFDUP
    script.push(0x64); // OP_NOTIF

    // OP_16 OP_CSV
    script.push(0x60); // OP_16
    script.push(0xB2); // OP_CHECKSEQUENCEVERIFY

    // OP_ENDIF
    script.push(0x68); // OP_ENDIF

    script
}

// ═══════════════════════════════════════════════════════════════════
// Commitment Transaction Scripts (BOLT #3)
// ═══════════════════════════════════════════════════════════════════

/// Build the `to_local` output script for commitment transactions.
///
/// Script:
/// ```text
/// OP_IF
///   <revocation_pubkey>
/// OP_ELSE
///   <to_self_delay> OP_CSV OP_DROP
///   <local_delayed_pubkey>
/// OP_ENDIF
/// OP_CHECKSIG
/// ```
///
/// If the counterparty publishes a revoked commitment, the revocation key
/// can spend immediately. Otherwise, the local party must wait `to_self_delay`.
///
/// # Arguments
/// - `revocation_pubkey` — 33-byte compressed revocation public key
/// - `to_self_delay` — Number of blocks to wait (CSV relative timelock)
/// - `local_delayed_pubkey` — 33-byte compressed local delayed public key
#[must_use]
pub fn to_local_script(
    revocation_pubkey: &[u8; 33],
    to_self_delay: u16,
    local_delayed_pubkey: &[u8; 33],
) -> Vec<u8> {
    let mut script = Vec::with_capacity(80);

    // OP_IF <revocation_pubkey>
    script.push(0x63); // OP_IF
    script.push(33);
    script.extend_from_slice(revocation_pubkey);

    // OP_ELSE <delay> OP_CSV OP_DROP <local_delayed_pubkey>
    script.push(0x67); // OP_ELSE
    push_csv_delay(&mut script, to_self_delay);
    script.push(0xB2); // OP_CHECKSEQUENCEVERIFY
    script.push(0x75); // OP_DROP
    script.push(33);
    script.extend_from_slice(local_delayed_pubkey);

    // OP_ENDIF OP_CHECKSIG
    script.push(0x68); // OP_ENDIF
    script.push(0xAC); // OP_CHECKSIG

    script
}

/// Build the `to_remote` output script (simple P2WPKH scriptPubKey).
///
/// The `to_remote` output in non-anchor channels is just a P2WPKH output.
/// In anchor channels, it becomes `<remote_pubkey> OP_CHECKSIGVERIFY OP_1 OP_CSV`.
///
/// # Arguments
/// - `remote_pubkey` — 33-byte compressed public key of the remote party
/// - `anchor_channel` — Whether this is an anchor-style commitment
#[must_use]
pub fn to_remote_script(remote_pubkey: &[u8; 33], anchor_channel: bool) -> Vec<u8> {
    if anchor_channel {
        // Anchor: <remote_pubkey> OP_CHECKSIGVERIFY OP_1 OP_CSV
        let mut script = Vec::with_capacity(37);
        script.push(33);
        script.extend_from_slice(remote_pubkey);
        script.push(0xAD); // OP_CHECKSIGVERIFY
        script.push(0x51); // OP_1 (CSV delay = 1)
        script.push(0xB2); // OP_CHECKSEQUENCEVERIFY
        script
    } else {
        // Non-anchor: just the raw pubkey push (will be used in P2WPKH)
        let hash = super::hash160(&remote_pubkey[..]);
        let mut script = Vec::with_capacity(25);
        script.push(0x76); // OP_DUP
        script.push(0xA9); // OP_HASH160
        script.push(0x14); // PUSH 20 bytes
        script.extend_from_slice(&hash);
        script.push(0x88); // OP_EQUALVERIFY
        script.push(0xAC); // OP_CHECKSIG
        script
    }
}

// ═══════════════════════════════════════════════════════════════════
// HTLC Scripts (BOLT #3)
// ═══════════════════════════════════════════════════════════════════

/// Build an offered HTLC output script (BOLT #3).
///
/// Script:
/// ```text
/// OP_DUP OP_HASH160 <revocation_hash> OP_EQUAL
/// OP_IF
///   OP_CHECKSIG
/// OP_ELSE
///   <remote_htlc_key> OP_SWAP OP_SIZE 32 OP_EQUAL
///   OP_NOTIF
///     OP_DROP OP_2 OP_SWAP <local_htlc_key> OP_2 OP_CHECKMULTISIG
///   OP_ELSE
///     OP_HASH160 <payment_hash> OP_EQUALVERIFY
///     OP_CHECKSIG
///   OP_ENDIF
/// OP_ENDIF
/// ```
///
/// # Arguments
/// - `revocation_pubkey` — For breach remediation
/// - `remote_htlc_pubkey` — Remote party's HTLC public key
/// - `local_htlc_pubkey` — Local party's HTLC public key
/// - `payment_hash` — RIPEMD160 of the preimage (20 bytes)
#[must_use]
pub fn offered_htlc_script(
    revocation_pubkey: &[u8; 33],
    remote_htlc_pubkey: &[u8; 33],
    local_htlc_pubkey: &[u8; 33],
    payment_hash: &[u8; 20],
) -> Vec<u8> {
    let revocation_hash = super::hash160(&revocation_pubkey[..]);
    let mut script = Vec::with_capacity(130);

    // OP_DUP OP_HASH160 <revocation_hash> OP_EQUAL
    script.push(0x76); // OP_DUP
    script.push(0xA9); // OP_HASH160
    script.push(0x14); // push 20 bytes
    script.extend_from_slice(&revocation_hash);
    script.push(0x87); // OP_EQUAL

    // OP_IF OP_CHECKSIG
    script.push(0x63); // OP_IF
    script.push(0xAC); // OP_CHECKSIG

    // OP_ELSE
    script.push(0x67); // OP_ELSE
    script.push(33);
    script.extend_from_slice(remote_htlc_pubkey);
    script.push(0x7C); // OP_SWAP
    script.push(0x82); // OP_SIZE
    script.push(0x01); // push 1 byte
    script.push(0x20); // 32
    script.push(0x87); // OP_EQUAL

    // OP_NOTIF
    script.push(0x64); // OP_NOTIF
    script.push(0x75); // OP_DROP
    script.push(0x52); // OP_2
    script.push(0x7C); // OP_SWAP
    script.push(33);
    script.extend_from_slice(local_htlc_pubkey);
    script.push(0x52); // OP_2
    script.push(0xAE); // OP_CHECKMULTISIG

    // OP_ELSE
    script.push(0x67); // OP_ELSE
    script.push(0xA9); // OP_HASH160
    script.push(0x14); // push 20 bytes
    script.extend_from_slice(payment_hash);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xAC); // OP_CHECKSIG

    // OP_ENDIF OP_ENDIF
    script.push(0x68); // OP_ENDIF
    script.push(0x68); // OP_ENDIF

    script
}

/// Build a received HTLC output script (BOLT #3).
///
/// Similar to offered HTLC but with CLTV timeout on the timeout path.
///
/// # Arguments
/// - `revocation_pubkey` — For breach remediation
/// - `remote_htlc_pubkey` — Remote party's HTLC public key
/// - `local_htlc_pubkey` — Local party's HTLC public key
/// - `payment_hash` — RIPEMD160 of the preimage (20 bytes)
/// - `cltv_expiry` — CLTV timeout for the refund path
#[must_use]
pub fn received_htlc_script(
    revocation_pubkey: &[u8; 33],
    remote_htlc_pubkey: &[u8; 33],
    local_htlc_pubkey: &[u8; 33],
    payment_hash: &[u8; 20],
    cltv_expiry: u32,
) -> Vec<u8> {
    let revocation_hash = super::hash160(&revocation_pubkey[..]);
    let mut script = Vec::with_capacity(140);

    // OP_DUP OP_HASH160 <revocation_hash> OP_EQUAL
    script.push(0x76); // OP_DUP
    script.push(0xA9); // OP_HASH160
    script.push(0x14);
    script.extend_from_slice(&revocation_hash);
    script.push(0x87); // OP_EQUAL

    // OP_IF OP_CHECKSIG
    script.push(0x63); // OP_IF
    script.push(0xAC); // OP_CHECKSIG

    // OP_ELSE
    script.push(0x67); // OP_ELSE
    script.push(33);
    script.extend_from_slice(remote_htlc_pubkey);
    script.push(0x7C); // OP_SWAP
    script.push(0x82); // OP_SIZE
    script.push(0x01);
    script.push(0x20); // 32
    script.push(0x87); // OP_EQUAL

    // OP_IF — hashlock path
    script.push(0x63); // OP_IF
    script.push(0xA9); // OP_HASH160
    script.push(0x14);
    script.extend_from_slice(payment_hash);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0x52); // OP_2
    script.push(0x7C); // OP_SWAP
    script.push(33);
    script.extend_from_slice(local_htlc_pubkey);
    script.push(0x52); // OP_2
    script.push(0xAE); // OP_CHECKMULTISIG

    // OP_ELSE — timeout path
    script.push(0x67); // OP_ELSE
    script.push(0x75); // OP_DROP
    push_cltv_timeout(&mut script, cltv_expiry);
    script.push(0xB1); // OP_CHECKLOCKTIMEVERIFY
    script.push(0x75); // OP_DROP
    script.push(0xAC); // OP_CHECKSIG

    // OP_ENDIF OP_ENDIF
    script.push(0x68);
    script.push(0x68);

    script
}

// ═══════════════════════════════════════════════════════════════════
// Funding Transaction Helpers
// ═══════════════════════════════════════════════════════════════════

/// Build the 2-of-2 funding output script for a Lightning channel.
///
/// Script: `OP_2 <pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG`
///
/// Per BOLT #3, keys MUST be lexicographically sorted.
///
/// # Arguments
/// - `pubkey1` — First funding public key (33 bytes)
/// - `pubkey2` — Second funding public key (33 bytes)
#[must_use]
pub fn funding_script(pubkey1: &[u8; 33], pubkey2: &[u8; 33]) -> Vec<u8> {
    let mut script = Vec::with_capacity(71);
    script.push(0x52); // OP_2

    // Lexicographic ordering per BOLT #3
    if pubkey1[..] <= pubkey2[..] {
        script.push(33);
        script.extend_from_slice(pubkey1);
        script.push(33);
        script.extend_from_slice(pubkey2);
    } else {
        script.push(33);
        script.extend_from_slice(pubkey2);
        script.push(33);
        script.extend_from_slice(pubkey1);
    }

    script.push(0x52); // OP_2
    script.push(0xAE); // OP_CHECKMULTISIG
    script
}

// ═══════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════

/// Push a CSV delay as a minimal script number.
fn push_csv_delay(script: &mut Vec<u8>, delay: u16) {
    if (1..=16).contains(&delay) {
        script.push(0x50 + delay as u8);
    } else {
        let bytes = delay.to_le_bytes();
        if delay <= 0x7F {
            script.push(1);
            script.push(bytes[0]);
        } else if delay <= 0x7FFF {
            script.push(2);
            script.extend_from_slice(&bytes);
        } else {
            // Need 3 bytes (add sign byte)
            script.push(3);
            script.extend_from_slice(&bytes);
            script.push(0x00); // sign extension
        }
    }
}

/// Push a CLTV timeout as a minimal script number.
fn push_cltv_timeout(script: &mut Vec<u8>, timeout: u32) {
    if (1..=16).contains(&timeout) {
        script.push(0x50 + timeout as u8);
    } else {
        let le = timeout.to_le_bytes();
        // Find minimal encoding length
        let mut len = 4;
        while len > 1 && le[len - 1] == 0 && (le[len - 2] & 0x80) == 0 {
            len -= 1;
        }
        // Need sign extension if high bit set
        if le[len - 1] & 0x80 != 0 {
            script.push((len + 1) as u8);
            script.extend_from_slice(&le[..len]);
            script.push(0x00);
        } else {
            script.push(len as u8);
            script.extend_from_slice(&le[..len]);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const PK1: [u8; 33] = [0x02; 33];
    const PK2: [u8; 33] = [0x03; 33];
    const PK3: [u8; 33] = {
        let mut k = [0x02; 33];
        k[32] = 0xFF;
        k
    };

    // ─── Anchor Script ───────────────────────────────────────────

    #[test]
    fn test_anchor_script_structure() {
        let script = anchor_script(&PK1);
        assert!(script.contains(&0xAC)); // OP_CHECKSIG
        assert!(script.contains(&0x73)); // OP_IFDUP
        assert!(script.contains(&0x64)); // OP_NOTIF
        assert!(script.contains(&0x60)); // OP_16
        assert!(script.contains(&0xB2)); // OP_CSV
        assert!(script.contains(&0x68)); // OP_ENDIF
    }

    #[test]
    fn test_anchor_script_byte_level() {
        let script = anchor_script(&PK1);
        // Exact byte sequence: PUSH33 <pk> OP_CHECKSIG OP_IFDUP OP_NOTIF OP_16 OP_CSV OP_ENDIF
        assert_eq!(script[0], 33);                 // push length
        assert_eq!(&script[1..34], &PK1[..]);      // pubkey
        assert_eq!(script[34], 0xAC);              // OP_CHECKSIG
        assert_eq!(script[35], 0x73);              // OP_IFDUP
        assert_eq!(script[36], 0x64);              // OP_NOTIF
        assert_eq!(script[37], 0x60);              // OP_16
        assert_eq!(script[38], 0xB2);              // OP_CSV
        assert_eq!(script[39], 0x68);              // OP_ENDIF
        assert_eq!(script.len(), 40);
    }

    #[test]
    fn test_anchor_script_contains_pubkey() {
        let script = anchor_script(&PK1);
        assert!(script.windows(33).any(|w| w == PK1));
    }

    #[test]
    fn test_anchor_script_different_keys() {
        let s1 = anchor_script(&PK1);
        let s2 = anchor_script(&PK2);
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_anchor_script_deterministic() {
        assert_eq!(anchor_script(&PK1), anchor_script(&PK1));
    }

    #[test]
    fn test_anchor_value() {
        assert_eq!(ANCHOR_VALUE, 330);
    }

    // ─── To Local Script ─────────────────────────────────────────

    #[test]
    fn test_to_local_script_structure() {
        let script = to_local_script(&PK1, 144, &PK2);
        assert!(script.contains(&0x63)); // OP_IF
        assert!(script.contains(&0x67)); // OP_ELSE
        assert!(script.contains(&0x68)); // OP_ENDIF
        assert!(script.contains(&0xAC)); // OP_CHECKSIG
        assert!(script.contains(&0xB2)); // OP_CSV
        assert!(script.contains(&0x75)); // OP_DROP
    }

    #[test]
    fn test_to_local_script_byte_level() {
        let script = to_local_script(&PK1, 144, &PK2);
        // OP_IF
        assert_eq!(script[0], 0x63);
        // PUSH33 <revocation_key>
        assert_eq!(script[1], 33);
        assert_eq!(&script[2..35], &PK1[..]);
        // OP_ELSE
        assert_eq!(script[35], 0x67);
        // CSV delay encoding for 144 (=0x90, needs sign byte: 02 90 00)
        assert_eq!(script[36], 2);     // 2 bytes
        assert_eq!(script[37], 0x90);
        assert_eq!(script[38], 0x00);  // sign extension
        // OP_CSV OP_DROP
        assert_eq!(script[39], 0xB2);
        assert_eq!(script[40], 0x75);
        // PUSH33 <local_delayed_key>
        assert_eq!(script[41], 33);
        assert_eq!(&script[42..75], &PK2[..]);
        // OP_ENDIF OP_CHECKSIG
        assert_eq!(script[75], 0x68);
        assert_eq!(script[76], 0xAC);
        assert_eq!(script.len(), 77);
    }

    #[test]
    fn test_to_local_contains_both_keys() {
        let script = to_local_script(&PK1, 144, &PK2);
        assert!(script.windows(33).any(|w| w == PK1));
        assert!(script.windows(33).any(|w| w == PK2));
    }

    #[test]
    fn test_to_local_different_delays() {
        let s1 = to_local_script(&PK1, 144, &PK2);
        let s2 = to_local_script(&PK1, 288, &PK2);
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_to_local_small_delay() {
        let script = to_local_script(&PK1, 1, &PK2);
        assert!(script.contains(&0x51)); // OP_1
    }

    #[test]
    fn test_to_local_delay_16() {
        let script = to_local_script(&PK1, 16, &PK2);
        assert!(script.contains(&0x60)); // OP_16
    }

    #[test]
    fn test_to_local_swapped_keys_differ() {
        let s1 = to_local_script(&PK1, 144, &PK2);
        let s2 = to_local_script(&PK2, 144, &PK1);
        assert_ne!(s1, s2);
    }

    // ─── To Remote Script ────────────────────────────────────────

    #[test]
    fn test_to_remote_anchor_contains_csv() {
        let script = to_remote_script(&PK1, true);
        assert!(script.contains(&0xAD)); // OP_CHECKSIGVERIFY
        assert!(script.contains(&0x51)); // OP_1
        assert!(script.contains(&0xB2)); // OP_CSV
    }

    #[test]
    fn test_to_remote_anchor_byte_level() {
        let script = to_remote_script(&PK1, true);
        // PUSH33 <pk> OP_CHECKSIGVERIFY OP_1 OP_CSV
        assert_eq!(script[0], 33);
        assert_eq!(&script[1..34], &PK1[..]);
        assert_eq!(script[34], 0xAD); // OP_CHECKSIGVERIFY
        assert_eq!(script[35], 0x51); // OP_1
        assert_eq!(script[36], 0xB2); // OP_CSV
        assert_eq!(script.len(), 37);
    }

    #[test]
    fn test_to_remote_non_anchor_is_p2pkh_like() {
        let script = to_remote_script(&PK1, false);
        assert!(script.contains(&0x76)); // OP_DUP
        assert!(script.contains(&0xA9)); // OP_HASH160
        assert!(script.contains(&0x88)); // OP_EQUALVERIFY
        assert!(script.contains(&0xAC)); // OP_CHECKSIG
    }

    #[test]
    fn test_to_remote_non_anchor_byte_level() {
        let script = to_remote_script(&PK1, false);
        // OP_DUP OP_HASH160 PUSH20 <hash> OP_EQUALVERIFY OP_CHECKSIG
        assert_eq!(script[0], 0x76);
        assert_eq!(script[1], 0xA9);
        assert_eq!(script[2], 0x14); // push 20 bytes
        // 20 bytes of hash160
        assert_eq!(script[23], 0x88);
        assert_eq!(script[24], 0xAC);
        assert_eq!(script.len(), 25);
    }

    #[test]
    fn test_to_remote_anchor_vs_non_anchor_differ() {
        let s1 = to_remote_script(&PK1, true);
        let s2 = to_remote_script(&PK1, false);
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_to_remote_non_anchor_deterministic_hash() {
        let s1 = to_remote_script(&PK1, false);
        let s2 = to_remote_script(&PK1, false);
        assert_eq!(s1, s2);
    }

    // ─── Offered HTLC ────────────────────────────────────────────

    #[test]
    fn test_offered_htlc_structure() {
        let hash = [0xAA; 20];
        let script = offered_htlc_script(&PK1, &PK2, &PK3, &hash);
        assert!(script.contains(&0x76)); // OP_DUP
        assert!(script.contains(&0xA9)); // OP_HASH160
        assert!(script.contains(&0x63)); // OP_IF
        assert!(script.contains(&0x67)); // OP_ELSE
        assert!(script.contains(&0xAE)); // OP_CHECKMULTISIG
        assert!(script.contains(&0x88)); // OP_EQUALVERIFY
    }

    #[test]
    fn test_offered_htlc_contains_payment_hash() {
        let hash = [0xBB; 20];
        let script = offered_htlc_script(&PK1, &PK2, &PK3, &hash);
        assert!(script.windows(20).any(|w| w == hash));
    }

    #[test]
    fn test_offered_htlc_different_hashes() {
        let h1 = [0xAA; 20];
        let h2 = [0xBB; 20];
        let s1 = offered_htlc_script(&PK1, &PK2, &PK3, &h1);
        let s2 = offered_htlc_script(&PK1, &PK2, &PK3, &h2);
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_offered_htlc_contains_both_htlc_keys() {
        let hash = [0xAA; 20];
        let script = offered_htlc_script(&PK1, &PK2, &PK3, &hash);
        assert!(script.windows(33).any(|w| w == PK2)); // remote htlc key
        assert!(script.windows(33).any(|w| w == PK3)); // local htlc key
    }

    #[test]
    fn test_offered_htlc_has_2_of_2_multisig() {
        let hash = [0xAA; 20];
        let script = offered_htlc_script(&PK1, &PK2, &PK3, &hash);
        // Should contain OP_2 ... OP_2 OP_CHECKMULTISIG
        assert!(script.contains(&0x52)); // OP_2
        assert!(script.contains(&0xAE)); // OP_CHECKMULTISIG
    }

    #[test]
    fn test_offered_htlc_deterministic() {
        let hash = [0xAA; 20];
        let s1 = offered_htlc_script(&PK1, &PK2, &PK3, &hash);
        let s2 = offered_htlc_script(&PK1, &PK2, &PK3, &hash);
        assert_eq!(s1, s2);
    }

    // ─── Received HTLC ───────────────────────────────────────────

    #[test]
    fn test_received_htlc_structure() {
        let hash = [0xAA; 20];
        let script = received_htlc_script(&PK1, &PK2, &PK3, &hash, 500_000);
        assert!(script.contains(&0xB1)); // OP_CLTV
        assert!(script.contains(&0xAE)); // OP_CHECKMULTISIG
        assert!(script.contains(&0xA9)); // OP_HASH160
    }

    #[test]
    fn test_received_htlc_different_timeouts() {
        let hash = [0xAA; 20];
        let s1 = received_htlc_script(&PK1, &PK2, &PK3, &hash, 100_000);
        let s2 = received_htlc_script(&PK1, &PK2, &PK3, &hash, 200_000);
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_received_htlc_contains_hash_and_keys() {
        let hash = [0xCC; 20];
        let script = received_htlc_script(&PK1, &PK2, &PK3, &hash, 500_000);
        assert!(script.windows(20).any(|w| w == hash));
        assert!(script.windows(33).any(|w| w == PK2));
        assert!(script.windows(33).any(|w| w == PK3));
    }

    #[test]
    fn test_received_htlc_has_cltv_and_multisig() {
        let hash = [0xAA; 20];
        let script = received_htlc_script(&PK1, &PK2, &PK3, &hash, 500_000);
        assert!(script.contains(&0xB1)); // OP_CHECKLOCKTIMEVERIFY
        assert!(script.contains(&0x52)); // OP_2
        assert!(script.contains(&0xAE)); // OP_CHECKMULTISIG
    }

    #[test]
    fn test_received_htlc_small_timeout() {
        let hash = [0xAA; 20];
        let script = received_htlc_script(&PK1, &PK2, &PK3, &hash, 5);
        // timeout=5 → OP_5 (0x55)
        assert!(script.contains(&0x55));
    }

    #[test]
    fn test_received_htlc_deterministic() {
        let hash = [0xAA; 20];
        let s1 = received_htlc_script(&PK1, &PK2, &PK3, &hash, 800_000);
        let s2 = received_htlc_script(&PK1, &PK2, &PK3, &hash, 800_000);
        assert_eq!(s1, s2);
    }

    // ─── Funding Script ──────────────────────────────────────────

    #[test]
    fn test_funding_script_2_of_2() {
        let script = funding_script(&PK1, &PK2);
        assert_eq!(script[0], 0x52);
        assert_eq!(script[script.len() - 2], 0x52);
        assert_eq!(script[script.len() - 1], 0xAE);
        assert_eq!(script.len(), 3 + 2 * 34);
    }

    #[test]
    fn test_funding_script_byte_level() {
        let script = funding_script(&PK1, &PK2);
        // PK1 < PK2 lexicographically (0x02 < 0x03)
        assert_eq!(script[0], 0x52);              // OP_2
        assert_eq!(script[1], 33);                 // push length
        assert_eq!(&script[2..35], &PK1[..]);      // first key (smaller)
        assert_eq!(script[35], 33);
        assert_eq!(&script[36..69], &PK2[..]);     // second key (larger)
        assert_eq!(script[69], 0x52);              // OP_2
        assert_eq!(script[70], 0xAE);              // OP_CHECKMULTISIG
    }

    #[test]
    fn test_funding_script_lexicographic_order() {
        let s1 = funding_script(&PK1, &PK2);
        let s2 = funding_script(&PK2, &PK1);
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_funding_script_same_key_both_slots() {
        let script = funding_script(&PK1, &PK1);
        assert_eq!(script[0], 0x52);
        assert_eq!(script.len(), 3 + 2 * 34);
    }

    #[test]
    fn test_funding_script_key_order_verified() {
        // pk_a = 0x02..00, pk_b = 0x02..FF → pk_a < pk_b
        let pk_a = PK1;
        let pk_b = PK3; // 0x02...FF
        let script = funding_script(&pk_b, &pk_a);
        // pk_a should come first
        assert_eq!(&script[2..35], &pk_a[..]);
        assert_eq!(&script[36..69], &pk_b[..]);
    }

    // ─── CSV Delay Encoding ──────────────────────────────────────

    #[test]
    fn test_csv_delay_small() {
        let mut s = Vec::new();
        push_csv_delay(&mut s, 1);
        assert_eq!(s, vec![0x51]); // OP_1
    }

    #[test]
    fn test_csv_delay_16() {
        let mut s = Vec::new();
        push_csv_delay(&mut s, 16);
        assert_eq!(s, vec![0x60]); // OP_16
    }

    #[test]
    fn test_csv_delay_17() {
        // 17 is past OP_16 range → needs explicit push
        let mut s = Vec::new();
        push_csv_delay(&mut s, 17);
        assert_eq!(s[0], 1); // 1 byte
        assert_eq!(s[1], 17);
    }

    #[test]
    fn test_csv_delay_127() {
        // 127 = 0x7F, fits in 1 byte (no sign bit issue)
        let mut s = Vec::new();
        push_csv_delay(&mut s, 127);
        assert_eq!(s[0], 1);
        assert_eq!(s[1], 0x7F);
    }

    #[test]
    fn test_csv_delay_128() {
        // 128 = 0x80, high bit set → needs 2 bytes
        let mut s = Vec::new();
        push_csv_delay(&mut s, 128);
        assert_eq!(s[0], 2);
        assert_eq!(s[1], 0x80);
        assert_eq!(s[2], 0x00);
    }

    #[test]
    fn test_csv_delay_144() {
        let mut s = Vec::new();
        push_csv_delay(&mut s, 144);
        assert_eq!(s[0], 2);
        assert_eq!(s[1], 0x90);
        assert_eq!(s[2], 0x00);
    }

    #[test]
    fn test_csv_delay_255() {
        // 255 = 0xFF, high bit set → 2 bytes
        let mut s = Vec::new();
        push_csv_delay(&mut s, 255);
        assert_eq!(s[0], 2);
        assert_eq!(s[1], 0xFF);
        assert_eq!(s[2], 0x00);
    }

    #[test]
    fn test_csv_delay_256() {
        // 256 = 0x0100 LE, no sign issue
        let mut s = Vec::new();
        push_csv_delay(&mut s, 256);
        assert_eq!(s[0], 2);
        assert_eq!(s[1], 0x00);
        assert_eq!(s[2], 0x01);
    }

    #[test]
    fn test_csv_delay_32767() {
        // 0x7FFF — max 2-byte positive
        let mut s = Vec::new();
        push_csv_delay(&mut s, 32767);
        assert_eq!(s[0], 2);
        assert_eq!(s[1], 0xFF);
        assert_eq!(s[2], 0x7F);
    }

    #[test]
    fn test_csv_delay_32768() {
        // 0x8000 — needs 3 bytes (sign extension)
        let mut s = Vec::new();
        push_csv_delay(&mut s, 32768);
        assert_eq!(s[0], 3);
        assert_eq!(s[1], 0x00);
        assert_eq!(s[2], 0x80);
        assert_eq!(s[3], 0x00);
    }

    #[test]
    fn test_csv_delay_65535() {
        // Max u16 = 0xFFFF, high bit set → 3 bytes
        let mut s = Vec::new();
        push_csv_delay(&mut s, 65535);
        assert_eq!(s[0], 3);
        assert_eq!(s[1], 0xFF);
        assert_eq!(s[2], 0xFF);
        assert_eq!(s[3], 0x00);
    }

    // ─── CLTV Timeout Encoding ───────────────────────────────────

    #[test]
    fn test_cltv_timeout_small() {
        let mut s = Vec::new();
        push_cltv_timeout(&mut s, 5);
        assert_eq!(s, vec![0x55]); // OP_5
    }

    #[test]
    fn test_cltv_timeout_17() {
        let mut s = Vec::new();
        push_cltv_timeout(&mut s, 17);
        assert_eq!(s[0], 1);
        assert_eq!(s[1], 17);
    }

    #[test]
    fn test_cltv_timeout_128() {
        // 128 = 0x80, high bit → needs sign extension
        let mut s = Vec::new();
        push_cltv_timeout(&mut s, 128);
        assert_eq!(s[0], 2);
        assert_eq!(s[1], 0x80);
        assert_eq!(s[2], 0x00);
    }

    #[test]
    fn test_cltv_timeout_large() {
        let mut s = Vec::new();
        push_cltv_timeout(&mut s, 500_000);
        assert_eq!(s[0], 3);
        assert_eq!(s[1], 0x20);
        assert_eq!(s[2], 0xA1);
        assert_eq!(s[3], 0x07);
    }

    #[test]
    fn test_cltv_timeout_block_height() {
        // Typical block height: 800_000 = 0x0C3500
        let mut s = Vec::new();
        push_cltv_timeout(&mut s, 800_000);
        let val = 800_000u32.to_le_bytes();
        assert_eq!(s[1], val[0]); // 0x00
        assert_eq!(s[2], val[1]); // 0x35
        assert_eq!(s[3], val[2]); // 0x0C
    }

    #[test]
    fn test_cltv_timeout_max_u32() {
        let mut s = Vec::new();
        push_cltv_timeout(&mut s, u32::MAX);
        // 0xFFFFFFFF all sign bits set → needs 5 bytes
        assert_eq!(s[0], 5);
    }

    // ─── Default Constants ───────────────────────────────────────

    #[test]
    fn test_default_delay() {
        assert_eq!(DEFAULT_TO_SELF_DELAY, 144);
    }

    // ─── E2E Commitment Flow ─────────────────────────────────────

    #[test]
    fn test_e2e_commitment_scripts() {
        let local_pk = PK1;
        let remote_pk = PK2;
        let revocation_pk = PK3;
        let delay = DEFAULT_TO_SELF_DELAY;

        // Build all scripts for a commitment transaction
        let to_local = to_local_script(&revocation_pk, delay, &local_pk);
        let to_remote_anchor = to_remote_script(&remote_pk, true);
        let to_remote_non_anchor = to_remote_script(&remote_pk, false);
        let anchor_local = anchor_script(&local_pk);
        let anchor_remote = anchor_script(&remote_pk);
        let funding = funding_script(&local_pk, &remote_pk);

        // All scripts are non-empty
        assert!(!to_local.is_empty());
        assert!(!to_remote_anchor.is_empty());
        assert!(!to_remote_non_anchor.is_empty());
        assert!(!anchor_local.is_empty());
        assert!(!anchor_remote.is_empty());
        assert!(!funding.is_empty());

        // All different
        assert_ne!(to_local, to_remote_anchor);
        assert_ne!(anchor_local, anchor_remote);
        assert_ne!(to_remote_anchor, to_remote_non_anchor);
    }

    #[test]
    fn test_e2e_htlc_pair() {
        let payment_hash = [0xAA; 20];
        let timeout = 500_000u32;

        let offered = offered_htlc_script(&PK1, &PK2, &PK3, &payment_hash);
        let received = received_htlc_script(&PK1, &PK2, &PK3, &payment_hash, timeout);

        // Both contain the payment hash
        assert!(offered.windows(20).any(|w| w == payment_hash));
        assert!(received.windows(20).any(|w| w == payment_hash));

        // Different scripts (offered vs received have structural differences)
        assert_ne!(offered, received);
        // Received is longer (has CLTV timeout)
        assert!(received.len() > offered.len());
    }
}
