//! XRP transaction serialization, Payment/TrustSet encoding, and multisign.
//!
//! Implements the XRP Ledger binary codec for transaction types:
//! - **Payment**: XRP-to-XRP and issued currency transfers
//! - **TrustSet**: Trust line management
//! - **Multisign**: Multi-signature helpers
//!
//! Field encoding follows the XRPL serialization format specification.

use crate::error::SignerError;

// ═══════════════════════════════════════════════════════════════════
// Binary Codec — Field Encoding
// ═══════════════════════════════════════════════════════════════════

/// XRPL field type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FieldType {
    /// 16-bit unsigned integer.
    UInt16 = 1,
    /// 32-bit unsigned integer.
    UInt32 = 2,
    /// 64-bit unsigned amount.
    Amount = 6,
    /// Variable-length blob.
    Blob = 7,
    /// 160-bit account ID.
    AccountID = 8,
    /// 256-bit hash.
    Hash256 = 5,
}

/// Encode a field ID for XRPL serialization.
///
/// XRPL uses a compact encoding: if both type_code and field_code fit
/// in 4 bits, they combine into a single byte.
#[must_use]
pub fn encode_field_id(type_code: u8, field_code: u8) -> Vec<u8> {
    if type_code < 16 && field_code < 16 {
        vec![(type_code << 4) | field_code]
    } else if type_code < 16 {
        vec![type_code << 4, field_code]
    } else if field_code < 16 {
        vec![field_code, type_code]
    } else {
        vec![0, type_code, field_code]
    }
}

/// Encode a UInt32 field.
#[must_use]
pub fn encode_uint32(type_code: u8, field_code: u8, value: u32) -> Vec<u8> {
    let mut buf = encode_field_id(type_code, field_code);
    buf.extend_from_slice(&value.to_be_bytes());
    buf
}

/// Encode a UInt16 field.
#[must_use]
pub fn encode_uint16(type_code: u8, field_code: u8, value: u16) -> Vec<u8> {
    let mut buf = encode_field_id(type_code, field_code);
    buf.extend_from_slice(&value.to_be_bytes());
    buf
}

/// Encode an XRP amount (drops) for serialization.
///
/// XRP amounts are encoded as 64-bit values with the high bit set
/// and the second-highest bit indicating positive.
#[must_use]
pub fn encode_xrp_amount(drops: u64) -> Vec<u8> {
    // Set bit 62 (positive) and bit 63 (not IOU)
    let encoded = drops | 0x4000_0000_0000_0000;
    encoded.to_be_bytes().to_vec()
}

/// Encode an AccountID field (20 bytes).
#[must_use]
pub fn encode_account_id(type_code: u8, field_code: u8, account: &[u8; 20]) -> Vec<u8> {
    let mut buf = encode_field_id(type_code, field_code);
    buf.push(20); // length prefix
    buf.extend_from_slice(account);
    buf
}

/// Encode a variable-length blob.
#[must_use]
pub fn encode_blob(type_code: u8, field_code: u8, data: &[u8]) -> Vec<u8> {
    let mut buf = encode_field_id(type_code, field_code);
    encode_vl_length(&mut buf, data.len());
    buf.extend_from_slice(data);
    buf
}

fn encode_vl_length(buf: &mut Vec<u8>, len: usize) {
    if len <= 192 {
        buf.push(len as u8);
    } else if len <= 12_480 {
        let adjusted = len - 193;
        buf.push((adjusted >> 8) as u8 + 193);
        buf.push((adjusted & 0xFF) as u8);
    } else {
        let adjusted = len - 12_481;
        buf.push(241u8 + (adjusted >> 16) as u8);
        buf.push(((adjusted >> 8) & 0xFF) as u8);
        buf.push((adjusted & 0xFF) as u8);
    }
}

// ═══════════════════════════════════════════════════════════════════
// Payment Transaction
// ═══════════════════════════════════════════════════════════════════

/// Well-known XRPL field codes for Payment transactions.
mod fields {
    // Type 1 (UInt16): TransactionType = field 2
    pub const TRANSACTION_TYPE: (u8, u8) = (1, 2);
    // Type 2 (UInt32): Flags = field 2, Sequence = field 4, Fee = field 8
    pub const FLAGS: (u8, u8) = (2, 2);
    pub const SEQUENCE: (u8, u8) = (2, 4);
    pub const LAST_LEDGER_SEQUENCE: (u8, u8) = (2, 27);
    // Type 6 (Amount): Amount = field 1, Fee = field 8
    pub const AMOUNT: (u8, u8) = (6, 1);
    pub const FEE: (u8, u8) = (6, 8);
    // Type 8 (AccountID): Account = field 1, Destination = field 3
    pub const ACCOUNT: (u8, u8) = (8, 1);
    pub const DESTINATION: (u8, u8) = (8, 3);
}

/// XRPL Transaction types.
pub const TT_PAYMENT: u16 = 0;
/// XRPL TrustSet transaction type code.
pub const TT_TRUST_SET: u16 = 20;

/// Build a serialized XRP Payment transaction (for signing).
///
/// # Arguments
/// - `account` — Sender account ID (20 bytes)
/// - `destination` — Recipient account ID (20 bytes)
/// - `amount_drops` — XRP amount in drops
/// - `fee_drops` — Transaction fee in drops
/// - `sequence` — Account sequence number
/// - `last_ledger_sequence` — Maximum ledger for inclusion
pub fn serialize_payment(
    account: &[u8; 20],
    destination: &[u8; 20],
    amount_drops: u64,
    fee_drops: u64,
    sequence: u32,
    last_ledger_sequence: u32,
) -> Vec<u8> {
    let mut buf = Vec::new();

    // Fields must be serialized in canonical order (by type code, then field code)
    // Type 1: TransactionType
    buf.extend_from_slice(&encode_uint16(
        fields::TRANSACTION_TYPE.0,
        fields::TRANSACTION_TYPE.1,
        TT_PAYMENT,
    ));
    // Type 2: Flags, Sequence, LastLedgerSequence
    buf.extend_from_slice(&encode_uint32(fields::FLAGS.0, fields::FLAGS.1, 0));
    buf.extend_from_slice(&encode_uint32(
        fields::SEQUENCE.0,
        fields::SEQUENCE.1,
        sequence,
    ));
    buf.extend_from_slice(&encode_uint32(
        fields::LAST_LEDGER_SEQUENCE.0,
        fields::LAST_LEDGER_SEQUENCE.1,
        last_ledger_sequence,
    ));
    // Type 6: Amount, Fee
    let mut amount_field = encode_field_id(fields::AMOUNT.0, fields::AMOUNT.1);
    amount_field.extend_from_slice(&encode_xrp_amount(amount_drops));
    buf.extend_from_slice(&amount_field);

    let mut fee_field = encode_field_id(fields::FEE.0, fields::FEE.1);
    fee_field.extend_from_slice(&encode_xrp_amount(fee_drops));
    buf.extend_from_slice(&fee_field);

    // Type 8: Account, Destination
    buf.extend_from_slice(&encode_account_id(
        fields::ACCOUNT.0,
        fields::ACCOUNT.1,
        account,
    ));
    buf.extend_from_slice(&encode_account_id(
        fields::DESTINATION.0,
        fields::DESTINATION.1,
        destination,
    ));

    buf
}

// ═══════════════════════════════════════════════════════════════════
// TrustSet Transaction
// ═══════════════════════════════════════════════════════════════════

/// An XRPL issued currency amount.
#[derive(Debug, Clone)]
pub struct IssuedAmount {
    /// Currency code (3-letter ISO or 20-byte hex).
    pub currency: [u8; 20],
    /// Issuer account ID.
    pub issuer: [u8; 20],
    /// Value as a string (e.g., "100.5").
    pub value: String,
}

/// Build a serialized TrustSet transaction.
///
/// # Arguments
/// - `account` — Account setting the trust line
/// - `limit_amount` — The trust line limit
/// - `fee_drops` — Transaction fee in drops
/// - `sequence` — Account sequence
/// - `last_ledger_sequence` — Maximum ledger
pub fn serialize_trust_set(
    account: &[u8; 20],
    limit_amount: &IssuedAmount,
    fee_drops: u64,
    sequence: u32,
    last_ledger_sequence: u32,
) -> Result<Vec<u8>, SignerError> {
    let mut buf = Vec::new();

    // TransactionType
    buf.extend_from_slice(&encode_uint16(
        fields::TRANSACTION_TYPE.0,
        fields::TRANSACTION_TYPE.1,
        TT_TRUST_SET,
    ));
    // Flags
    buf.extend_from_slice(&encode_uint32(fields::FLAGS.0, fields::FLAGS.1, 0));
    // Sequence
    buf.extend_from_slice(&encode_uint32(
        fields::SEQUENCE.0,
        fields::SEQUENCE.1,
        sequence,
    ));
    // LastLedgerSequence
    buf.extend_from_slice(&encode_uint32(
        fields::LAST_LEDGER_SEQUENCE.0,
        fields::LAST_LEDGER_SEQUENCE.1,
        last_ledger_sequence,
    ));
    // Fee
    let mut fee_field = encode_field_id(fields::FEE.0, fields::FEE.1);
    fee_field.extend_from_slice(&encode_xrp_amount(fee_drops));
    buf.extend_from_slice(&fee_field);
    // Account
    buf.extend_from_slice(&encode_account_id(
        fields::ACCOUNT.0,
        fields::ACCOUNT.1,
        account,
    ));

    // LimitAmount is encoded as an object (type 14, field 3)
    // For simplicity, we encode the currency/issuer/value inline
    buf.extend_from_slice(&encode_field_id(14, 3)); // LimitAmount object marker
                                                    // Encode issued amount: 48 bytes (8 value + 20 currency + 20 issuer)
    let encoded_amount = encode_issued_amount(limit_amount)?;
    buf.extend_from_slice(&encoded_amount);

    Ok(buf)
}

fn encode_issued_amount(amount: &IssuedAmount) -> Result<Vec<u8>, SignerError> {
    let mut buf = Vec::new();
    // Encode value as IOU amount per XRPL serialization spec
    let value_bytes = encode_iou_value(&amount.value)?;
    buf.extend_from_slice(&value_bytes);
    buf.extend_from_slice(&amount.currency);
    buf.extend_from_slice(&amount.issuer);
    Ok(buf)
}

/// Parse a decimal string into (is_negative, mantissa, exponent) per XRPL spec.
///
/// XRPL IOU amounts are canonical when mantissa is in [1e15, 1e16).
/// Exponent range is [-96, 80].
fn parse_xrpl_decimal(value: &str) -> Result<(bool, u64, i8), SignerError> {
    let s = value.trim();
    if s.is_empty() {
        return Err(SignerError::ParseError("empty IOU value".into()));
    }

    let (negative, abs_str) = if let Some(rest) = s.strip_prefix('-') {
        (true, rest)
    } else {
        (false, s)
    };

    // Split into integer and fractional parts
    let (int_part, frac_part) = if let Some((i, f)) = abs_str.split_once('.') {
        (i, f)
    } else {
        (abs_str, "")
    };

    // Validate all characters are digits
    if !int_part.chars().all(|c| c.is_ascii_digit())
        || !frac_part.chars().all(|c| c.is_ascii_digit())
    {
        return Err(SignerError::ParseError(format!(
            "invalid IOU value: {value}"
        )));
    }
    if int_part.is_empty() && frac_part.is_empty() {
        return Err(SignerError::ParseError(format!(
            "invalid IOU value: {value}"
        )));
    }

    // Concatenate digits to form the full integer and track the exponent offset
    let combined = format!("{int_part}{frac_part}");
    let frac_len = frac_part.len() as i32;

    // Strip leading zeros
    let stripped = combined.trim_start_matches('0');
    if stripped.is_empty() {
        // Value is zero
        return Ok((false, 0, 0));
    }

    // Parse the stripped digits as mantissa
    let mut mantissa: u64 = stripped
        .parse()
        .map_err(|_| SignerError::ParseError(format!("IOU value too large: {value}")))?;
    let mut exponent: i32 = -(frac_len) + (combined.len() as i32 - stripped.len() as i32);

    // Normalize: mantissa must be in [1e15, 1e16)
    const MIN_MANTISSA: u64 = 1_000_000_000_000_000;
    const MAX_MANTISSA: u64 = 10_000_000_000_000_000;

    while mantissa < MIN_MANTISSA {
        mantissa *= 10;
        exponent -= 1;
    }
    while mantissa >= MAX_MANTISSA {
        mantissa /= 10;
        exponent += 1;
    }

    // Validate exponent range
    if !(-96..=80).contains(&exponent) {
        return Err(SignerError::ParseError(format!(
            "IOU exponent {exponent} out of range [-96, 80]"
        )));
    }

    Ok((negative, mantissa, exponent as i8))
}

fn encode_iou_value(value: &str) -> Result<[u8; 8], SignerError> {
    let (negative, mantissa, exponent) = parse_xrpl_decimal(value)?;

    if mantissa == 0 {
        return Ok(0x8000_0000_0000_0000u64.to_be_bytes());
    }

    // Bit 63: always 1 (IOU flag)
    // Bit 62: 1 if positive, 0 if negative
    // Bits 54–61: exponent + 97 (biased, 8 bits)
    // Bits 0–53: mantissa (54 bits)
    let mut encoded: u64 = 0x8000_0000_0000_0000; // IOU flag
    if !negative {
        encoded |= 0x4000_0000_0000_0000; // positive flag
    }
    let biased_exp = (exponent as i32 + 97) as u64;
    encoded |= (biased_exp & 0xFF) << 54;
    encoded |= mantissa & 0x003F_FFFF_FFFF_FFFF;

    Ok(encoded.to_be_bytes())
}

// ═══════════════════════════════════════════════════════════════════
// Multisign Helpers
// ═══════════════════════════════════════════════════════════════════

/// Compute the multisign prefix for XRP multisigning.
///
/// XRPL multisign hashes: `SHA-512Half(SIGNER_PREFIX || tx_blob || account_id)`
///
/// The `SIGNER_PREFIX` is `0x53545800` ("STX\0").
pub const MULTISIGN_PREFIX: [u8; 4] = [0x53, 0x54, 0x58, 0x00];

/// Compute the signing hash for XRP multisign.
///
/// Returns the hash that each signer should sign.
pub fn multisign_hash(tx_blob: &[u8], signer_account: &[u8; 20]) -> [u8; 32] {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(MULTISIGN_PREFIX);
    hasher.update(tx_blob);
    hasher.update(signer_account);
    let full = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&full[..32]);
    out
}

/// A signer entry for multisign transactions.
#[derive(Debug, Clone)]
pub struct SignerEntry {
    /// Signer's account ID.
    pub account: [u8; 20],
    /// Signer's weight.
    pub weight: u16,
}

/// Build a SignerListSet transaction payload.
///
/// Sets the list of signers and quorum on an account.
pub fn serialize_signer_list(signers: &[SignerEntry], quorum: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&quorum.to_be_bytes());
    for signer in signers {
        buf.extend_from_slice(&signer.account);
        buf.extend_from_slice(&signer.weight.to_be_bytes());
    }
    buf
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ─── Binary Codec Tests ────────────────────────────────────────

    #[test]
    fn test_field_id_compact() {
        // type=1, field=2 -> 0x12
        assert_eq!(encode_field_id(1, 2), vec![0x12]);
    }

    #[test]
    fn test_field_id_large_field() {
        // type=1, field=27 -> [0x10, 27]
        assert_eq!(encode_field_id(1, 27), vec![0x10, 27]);
    }

    #[test]
    fn test_xrp_amount_encoding() {
        let drops = 1_000_000u64; // 1 XRP
        let encoded = encode_xrp_amount(drops);
        assert_eq!(encoded.len(), 8);
        // Bit 62 should be set (positive)
        let val = u64::from_be_bytes(encoded.try_into().unwrap());
        assert!(val & 0x4000_0000_0000_0000 != 0);
    }

    #[test]
    fn test_uint32_encoding() {
        let encoded = encode_uint32(2, 4, 42);
        assert_eq!(encoded[0], 0x24); // type 2, field 4
        assert_eq!(&encoded[1..5], &42u32.to_be_bytes());
    }

    #[test]
    fn test_account_id_encoding() {
        let account = [0xAA; 20];
        let encoded = encode_account_id(8, 1, &account);
        assert_eq!(encoded[0], 0x81); // type 8, field 1
        assert_eq!(encoded[1], 20); // length
        assert_eq!(&encoded[2..22], &account);
    }

    #[test]
    fn test_vl_length_small() {
        let mut buf = Vec::new();
        encode_vl_length(&mut buf, 10);
        assert_eq!(buf, vec![10]);
    }

    #[test]
    fn test_vl_length_medium() {
        let mut buf = Vec::new();
        encode_vl_length(&mut buf, 200);
        assert_eq!(buf.len(), 2);
    }

    // ─── Payment Transaction Tests ─────────────────────────────────

    #[test]
    fn test_payment_serialization() {
        let from = [0xAA; 20];
        let to = [0xBB; 20];
        let blob = serialize_payment(&from, &to, 1_000_000, 12, 1, 100);
        assert!(!blob.is_empty());
        // First field should be TransactionType (0x12 = type 1, field 2)
        assert_eq!(blob[0], 0x12);
    }

    #[test]
    fn test_payment_different_amount() {
        let from = [0xAA; 20];
        let to = [0xBB; 20];
        let blob1 = serialize_payment(&from, &to, 1_000, 12, 1, 100);
        let blob2 = serialize_payment(&from, &to, 2_000, 12, 1, 100);
        assert_ne!(blob1, blob2);
    }

    // ─── TrustSet Transaction Tests ────────────────────────────────

    #[test]
    fn test_trust_set_serialization() {
        let account = [0xAA; 20];
        let limit = IssuedAmount {
            currency: {
                let mut c = [0u8; 20];
                c[12..15].copy_from_slice(b"USD");
                c
            },
            issuer: [0xBB; 20],
            value: "100".to_string(),
        };
        let blob = serialize_trust_set(&account, &limit, 12, 1, 100).unwrap();
        assert!(!blob.is_empty());
    }

    #[test]
    fn test_iou_zero_encoding() {
        let result = encode_iou_value("0").unwrap();
        assert_eq!(result, 0x8000_0000_0000_0000u64.to_be_bytes());
    }

    #[test]
    fn test_iou_positive_value() {
        let result = encode_iou_value("100").unwrap();
        let val = u64::from_be_bytes(result);
        // Must have IOU flag (bit 63) and positive flag (bit 62)
        assert!(val & 0x8000_0000_0000_0000 != 0);
        assert!(val & 0x4000_0000_0000_0000 != 0);
    }

    #[test]
    fn test_iou_negative_value() {
        let result = encode_iou_value("-50.5").unwrap();
        let val = u64::from_be_bytes(result);
        // Must have IOU flag but NOT positive flag
        assert!(val & 0x8000_0000_0000_0000 != 0);
        assert!(val & 0x4000_0000_0000_0000 == 0);
    }

    #[test]
    fn test_iou_invalid_value_rejected() {
        assert!(encode_iou_value("abc").is_err());
        assert!(encode_iou_value("").is_err());
    }

    #[test]
    fn test_iou_decimal_precision() {
        // "0.001" should not silently become 0
        let result = encode_iou_value("0.001").unwrap();
        assert_ne!(result, 0x8000_0000_0000_0000u64.to_be_bytes());
    }

    // ─── Multisign Tests ───────────────────────────────────────────

    #[test]
    fn test_multisign_prefix() {
        assert_eq!(&MULTISIGN_PREFIX, b"STX\0");
    }

    #[test]
    fn test_multisign_hash_deterministic() {
        let tx_blob = vec![0xAA; 100];
        let account = [0xBB; 20];
        let h1 = multisign_hash(&tx_blob, &account);
        let h2 = multisign_hash(&tx_blob, &account);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_multisign_hash_different_account() {
        let tx_blob = vec![0xAA; 100];
        let h1 = multisign_hash(&tx_blob, &[0xBB; 20]);
        let h2 = multisign_hash(&tx_blob, &[0xCC; 20]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_signer_list() {
        let signers = vec![
            SignerEntry {
                account: [0xAA; 20],
                weight: 1,
            },
            SignerEntry {
                account: [0xBB; 20],
                weight: 2,
            },
        ];
        let data = serialize_signer_list(&signers, 3);
        // 4 bytes quorum + 2 * (20 + 2) = 48
        assert_eq!(data.len(), 48);
    }
}
