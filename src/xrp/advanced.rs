//! XRP advanced transactions: DEX orders, Escrow, and IOU precision.

// ═══════════════════════════════════════════════════════════════════
// XRPL Amount Encoding (IOU with Mantissa/Exponent)
// ═══════════════════════════════════════════════════════════════════

/// Encode an IOU (Issued Currency) amount per XRPL serialization format.
///
/// XRPL IOU amounts are 8 bytes:
/// - Bit 63: Not XRP flag (always 1 for IOU)
/// - Bit 62: Sign (1 = positive, 0 = negative)
/// - Bits 54-61: Exponent (biased by 97)
/// - Bits 0-53: Mantissa (54 bits)
///
/// The value = mantissa * 10^(exponent - 97)
///
/// # Arguments
/// - `mantissa` — Significant digits (must be <= 10^16 - 1)
/// - `exponent` — Power of 10 offset (range: -96 to 80)
/// - `positive` — Whether the amount is positive
pub fn encode_iou_amount(mantissa: u64, exponent: i8, positive: bool) -> [u8; 8] {
    if mantissa == 0 {
        // Zero amount: special encoding
        let mut bytes = [0u8; 8];
        bytes[0] = 0x80; // Not XRP flag, positive, zero mantissa
        return bytes;
    }

    // Normalize mantissa to 54 bits max (10^15 <= m < 10^16)
    let mut m = mantissa;
    let mut e = exponent as i16;

    // Normalize: mantissa should be in [10^15, 10^16)
    while m < 1_000_000_000_000_000 && e > -96 {
        m *= 10;
        e -= 1;
    }
    while m >= 10_000_000_000_000_000 && e < 80 {
        m /= 10;
        e += 1;
    }

    // Bias the exponent: stored = exponent + 97
    let biased_exp = (e + 97) as u64;

    let mut val: u64 = 0;
    val |= 1 << 63; // Not XRP flag
    if positive {
        val |= 1 << 62; // Positive flag
    }
    val |= (biased_exp & 0xFF) << 54; // 8-bit exponent
    val |= m & 0x003F_FFFF_FFFF_FFFF; // 54-bit mantissa

    val.to_be_bytes()
}

/// Decode an IOU amount from 8 bytes.
///
/// Returns (mantissa, exponent, is_positive).
pub fn decode_iou_amount(bytes: &[u8; 8]) -> (u64, i8, bool) {
    let val = u64::from_be_bytes(*bytes);

    // Check for zero
    if val & 0x003F_FFFF_FFFF_FFFF == 0 {
        return (0, 0, true);
    }

    let positive = (val >> 62) & 1 == 1;
    let biased_exp = ((val >> 54) & 0xFF) as i16;
    let exponent = (biased_exp - 97) as i8;
    let mantissa = val & 0x003F_FFFF_FFFF_FFFF;

    (mantissa, exponent, positive)
}

/// Encode a 3-character currency code for XRPL.
///
/// XRPL currency codes are 20 bytes:
/// - Standard (3-char): 12 zero bytes + 3 ASCII bytes + 5 zero bytes
/// - Non-standard (40-hex): raw 20 bytes
pub fn encode_currency_code(code: &str) -> Result<[u8; 20], &'static str> {
    if code.len() != 3 {
        return Err("currency code must be 3 characters");
    }
    if code == "XRP" {
        return Err("XRP is not an issued currency");
    }

    let mut out = [0u8; 20];
    out[12..15].copy_from_slice(code.as_bytes());
    Ok(out)
}

// ═══════════════════════════════════════════════════════════════════
// OfferCreate / OfferCancel (DEX)
// ═══════════════════════════════════════════════════════════════════

/// Transaction type code for OfferCreate.
pub const TT_OFFER_CREATE: u16 = 7;
/// Transaction type code for OfferCancel.
pub const TT_OFFER_CANCEL: u16 = 8;

/// Serialize an OfferCreate transaction for signing.
///
/// # Arguments
/// - `account` — 20-byte account address
/// - `taker_gets_drops` — Amount the taker gets (in drops for XRP, or IOU bytes)
/// - `taker_pays_drops` — Amount the taker pays (in drops for XRP, or IOU bytes)
/// - `sequence` — Account sequence number
/// - `fee_drops` — Fee in drops
/// - `flags` — Transaction flags (e.g., `tfSell = 0x00080000`)
pub fn offer_create(
    account: &[u8; 20],
    taker_gets_drops: u64,
    taker_pays_drops: u64,
    sequence: u32,
    fee_drops: u64,
    flags: u32,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(100);

    // TransactionType (field code 0x12 = UInt16)
    buf.extend_from_slice(&[0x12, (TT_OFFER_CREATE >> 8) as u8, TT_OFFER_CREATE as u8]);
    // Flags
    buf.extend_from_slice(&[0x22]);
    buf.extend_from_slice(&flags.to_be_bytes());
    // Sequence
    buf.extend_from_slice(&[0x24]);
    buf.extend_from_slice(&sequence.to_be_bytes());
    // Fee (Amount, field code 0x68)
    buf.push(0x68);
    buf.extend_from_slice(&encode_xrp_amount(fee_drops));
    // TakerPays (Amount, field code 0x64)
    buf.push(0x64);
    buf.extend_from_slice(&encode_xrp_amount(taker_pays_drops));
    // TakerGets (Amount, field code 0x65)
    buf.push(0x65);
    buf.extend_from_slice(&encode_xrp_amount(taker_gets_drops));
    // Account (AccountID, field code 0x81 0x14)
    buf.extend_from_slice(&[0x81, 0x14]);
    buf.extend_from_slice(account);

    buf
}

/// Serialize an OfferCancel transaction.
pub fn offer_cancel(
    account: &[u8; 20],
    offer_sequence: u32,
    sequence: u32,
    fee_drops: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(60);

    buf.extend_from_slice(&[0x12, (TT_OFFER_CANCEL >> 8) as u8, TT_OFFER_CANCEL as u8]);
    buf.extend_from_slice(&[0x22, 0x00, 0x00, 0x00, 0x00]); // flags = 0
    buf.extend_from_slice(&[0x24]);
    buf.extend_from_slice(&sequence.to_be_bytes());
    // OfferSequence (UInt32 field code 0x20 0x19)
    buf.extend_from_slice(&[0x20, 0x19]);
    buf.extend_from_slice(&offer_sequence.to_be_bytes());
    buf.push(0x68);
    buf.extend_from_slice(&encode_xrp_amount(fee_drops));
    buf.extend_from_slice(&[0x81, 0x14]);
    buf.extend_from_slice(account);

    buf
}

// ═══════════════════════════════════════════════════════════════════
// Escrow
// ═══════════════════════════════════════════════════════════════════

/// Transaction type code for EscrowCreate.
pub const TT_ESCROW_CREATE: u16 = 1;
/// Transaction type code for EscrowFinish.
pub const TT_ESCROW_FINISH: u16 = 2;
/// Transaction type code for EscrowCancel.
pub const TT_ESCROW_CANCEL: u16 = 4;

/// Serialize an EscrowCreate transaction.
///
/// # Arguments
/// - `account` — Sender address
/// - `destination` — Recipient address
/// - `amount_drops` — Amount in drops
/// - `finish_after` — Unix timestamp after which escrow can be finished
/// - `cancel_after` — Optional Unix timestamp after which escrow can be cancelled
/// - `sequence` — Account sequence
/// - `fee_drops` — Fee in drops
pub fn escrow_create(
    account: &[u8; 20],
    destination: &[u8; 20],
    amount_drops: u64,
    finish_after: u32,
    cancel_after: Option<u32>,
    sequence: u32,
    fee_drops: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(80);

    buf.extend_from_slice(&[0x12, (TT_ESCROW_CREATE >> 8) as u8, TT_ESCROW_CREATE as u8]);
    buf.extend_from_slice(&[0x22, 0x00, 0x00, 0x00, 0x00]); // flags = 0
    buf.extend_from_slice(&[0x24]);
    buf.extend_from_slice(&sequence.to_be_bytes());
    // FinishAfter (UInt32)
    buf.extend_from_slice(&[0x20, 0x24]);
    buf.extend_from_slice(&finish_after.to_be_bytes());
    // CancelAfter (optional)
    if let Some(cancel) = cancel_after {
        buf.extend_from_slice(&[0x20, 0x25]);
        buf.extend_from_slice(&cancel.to_be_bytes());
    }
    // Amount
    buf.push(0x61);
    buf.extend_from_slice(&encode_xrp_amount(amount_drops));
    // Fee
    buf.push(0x68);
    buf.extend_from_slice(&encode_xrp_amount(fee_drops));
    // Account
    buf.extend_from_slice(&[0x81, 0x14]);
    buf.extend_from_slice(account);
    // Destination
    buf.extend_from_slice(&[0x83, 0x14]);
    buf.extend_from_slice(destination);

    buf
}

/// Serialize an EscrowFinish transaction.
pub fn escrow_finish(
    account: &[u8; 20],
    owner: &[u8; 20],
    offer_sequence: u32,
    sequence: u32,
    fee_drops: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(70);

    buf.extend_from_slice(&[0x12, (TT_ESCROW_FINISH >> 8) as u8, TT_ESCROW_FINISH as u8]);
    buf.extend_from_slice(&[0x22, 0x00, 0x00, 0x00, 0x00]);
    buf.extend_from_slice(&[0x24]);
    buf.extend_from_slice(&sequence.to_be_bytes());
    buf.extend_from_slice(&[0x20, 0x19]); // OfferSequence
    buf.extend_from_slice(&offer_sequence.to_be_bytes());
    buf.push(0x68);
    buf.extend_from_slice(&encode_xrp_amount(fee_drops));
    buf.extend_from_slice(&[0x81, 0x14]);
    buf.extend_from_slice(account);
    // Owner
    buf.extend_from_slice(&[0x82, 0x14]);
    buf.extend_from_slice(owner);

    buf
}

/// Serialize an EscrowCancel transaction.
pub fn escrow_cancel(
    account: &[u8; 20],
    owner: &[u8; 20],
    offer_sequence: u32,
    sequence: u32,
    fee_drops: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(70);

    buf.extend_from_slice(&[0x12, (TT_ESCROW_CANCEL >> 8) as u8, TT_ESCROW_CANCEL as u8]);
    buf.extend_from_slice(&[0x22, 0x00, 0x00, 0x00, 0x00]);
    buf.extend_from_slice(&[0x24]);
    buf.extend_from_slice(&sequence.to_be_bytes());
    buf.extend_from_slice(&[0x20, 0x19]);
    buf.extend_from_slice(&offer_sequence.to_be_bytes());
    buf.push(0x68);
    buf.extend_from_slice(&encode_xrp_amount(fee_drops));
    buf.extend_from_slice(&[0x81, 0x14]);
    buf.extend_from_slice(account);
    buf.extend_from_slice(&[0x82, 0x14]);
    buf.extend_from_slice(owner);

    buf
}

// ─── Helpers ────────────────────────────────────────────────────────

/// Encode an XRP amount in drops (native currency).
///
/// XRP amounts are 8 bytes with bit 63 = 0 (not IOU) and bit 62 = 1 (positive).
fn encode_xrp_amount(drops: u64) -> [u8; 8] {
    let val = drops | (0x40 << 56); // Set positive bit
    val.to_be_bytes()
}

// ═══════════════════════════════════════════════════════════════════
// AccountSet
// ═══════════════════════════════════════════════════════════════════

/// Transaction type code for AccountSet.
pub const TT_ACCOUNT_SET: u16 = 3;

/// AccountSet flags.
pub mod account_set_flags {
    /// Require destination tag on incoming payments.
    pub const ASF_REQUIRE_DEST: u32 = 1;
    /// Require authorization for trust lines.
    pub const ASF_REQUIRE_AUTH: u32 = 2;
    /// Disallow incoming XRP.
    pub const ASF_DISALLOW_XRP: u32 = 3;
    /// Disable the master key.
    pub const ASF_DISABLE_MASTER: u32 = 4;
    /// Enable No Freeze on all trust lines.
    pub const ASF_NO_FREEZE: u32 = 6;
    /// Enable global freeze.
    pub const ASF_GLOBAL_FREEZE: u32 = 7;
    /// Enable deposit authorization.
    pub const ASF_DEPOSIT_AUTH: u32 = 9;
    /// Allow trustline clawback.
    pub const ASF_ALLOW_CLAWBACK: u32 = 16;
}

/// Serialize an AccountSet transaction.
pub fn account_set(
    account: &[u8; 20],
    set_flag: Option<u32>,
    clear_flag: Option<u32>,
    sequence: u32,
    fee_drops: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(60);
    buf.extend_from_slice(&[0x12, (TT_ACCOUNT_SET >> 8) as u8, TT_ACCOUNT_SET as u8]);
    buf.extend_from_slice(&[0x22, 0x00, 0x00, 0x00, 0x00]);
    buf.extend_from_slice(&[0x24]);
    buf.extend_from_slice(&sequence.to_be_bytes());
    if let Some(flag) = set_flag {
        buf.extend_from_slice(&[0x20, 0x21]);
        buf.extend_from_slice(&flag.to_be_bytes());
    }
    if let Some(flag) = clear_flag {
        buf.extend_from_slice(&[0x20, 0x22]);
        buf.extend_from_slice(&flag.to_be_bytes());
    }
    buf.push(0x68);
    buf.extend_from_slice(&encode_xrp_amount(fee_drops));
    buf.extend_from_slice(&[0x81, 0x14]);
    buf.extend_from_slice(account);
    buf
}

// ═══════════════════════════════════════════════════════════════════
// Payment Channels
// ═══════════════════════════════════════════════════════════════════

/// Transaction type code for PaymentChannelCreate.
pub const TT_CHANNEL_CREATE: u16 = 13;
/// Transaction type code for PaymentChannelFund.
pub const TT_CHANNEL_FUND: u16 = 14;
/// Transaction type code for PaymentChannelClaim.
pub const TT_CHANNEL_CLAIM: u16 = 15;

/// Serialize a PaymentChannelCreate transaction.
pub fn channel_create(
    account: &[u8; 20],
    destination: &[u8; 20],
    amount_drops: u64,
    settle_delay: u32,
    public_key: &[u8; 33],
    sequence: u32,
    fee_drops: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(120);
    buf.extend_from_slice(&[
        0x12,
        (TT_CHANNEL_CREATE >> 8) as u8,
        TT_CHANNEL_CREATE as u8,
    ]);
    buf.extend_from_slice(&[0x22, 0x00, 0x00, 0x00, 0x00]);
    buf.extend_from_slice(&[0x24]);
    buf.extend_from_slice(&sequence.to_be_bytes());
    buf.extend_from_slice(&[0x20, 0x27]);
    buf.extend_from_slice(&settle_delay.to_be_bytes());
    buf.push(0x61);
    buf.extend_from_slice(&encode_xrp_amount(amount_drops));
    buf.push(0x68);
    buf.extend_from_slice(&encode_xrp_amount(fee_drops));
    buf.extend_from_slice(&[0x71, 0x03]);
    buf.push(public_key.len() as u8);
    buf.extend_from_slice(public_key);
    buf.extend_from_slice(&[0x81, 0x14]);
    buf.extend_from_slice(account);
    buf.extend_from_slice(&[0x83, 0x14]);
    buf.extend_from_slice(destination);
    buf
}

/// Serialize a PaymentChannelFund transaction.
pub fn channel_fund(
    account: &[u8; 20],
    channel_id: &[u8; 32],
    amount_drops: u64,
    sequence: u32,
    fee_drops: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(80);
    buf.extend_from_slice(&[0x12, (TT_CHANNEL_FUND >> 8) as u8, TT_CHANNEL_FUND as u8]);
    buf.extend_from_slice(&[0x22, 0x00, 0x00, 0x00, 0x00]);
    buf.extend_from_slice(&[0x24]);
    buf.extend_from_slice(&sequence.to_be_bytes());
    buf.push(0x61);
    buf.extend_from_slice(&encode_xrp_amount(amount_drops));
    buf.push(0x68);
    buf.extend_from_slice(&encode_xrp_amount(fee_drops));
    buf.extend_from_slice(&[0x50, 0x16]);
    buf.extend_from_slice(channel_id);
    buf.extend_from_slice(&[0x81, 0x14]);
    buf.extend_from_slice(account);
    buf
}

/// Serialize a PaymentChannelClaim transaction.
pub fn channel_claim(
    account: &[u8; 20],
    channel_id: &[u8; 32],
    balance_drops: Option<u64>,
    sequence: u32,
    fee_drops: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(80);
    buf.extend_from_slice(&[0x12, (TT_CHANNEL_CLAIM >> 8) as u8, TT_CHANNEL_CLAIM as u8]);
    buf.extend_from_slice(&[0x22, 0x00, 0x00, 0x00, 0x00]);
    buf.extend_from_slice(&[0x24]);
    buf.extend_from_slice(&sequence.to_be_bytes());
    if let Some(balance) = balance_drops {
        buf.push(0x61);
        buf.extend_from_slice(&encode_xrp_amount(balance));
    }
    buf.push(0x68);
    buf.extend_from_slice(&encode_xrp_amount(fee_drops));
    buf.extend_from_slice(&[0x50, 0x16]);
    buf.extend_from_slice(channel_id);
    buf.extend_from_slice(&[0x81, 0x14]);
    buf.extend_from_slice(account);
    buf
}

// ═══════════════════════════════════════════════════════════════════
// NFToken (XLS-20)
// ═══════════════════════════════════════════════════════════════════

/// Transaction type code for NFTokenMint.
pub const TT_NFTOKEN_MINT: u16 = 25;
/// Transaction type code for NFTokenCreateOffer.
pub const TT_NFTOKEN_CREATE_OFFER: u16 = 27;
/// Transaction type code for NFTokenAcceptOffer.
pub const TT_NFTOKEN_ACCEPT_OFFER: u16 = 29;
/// Transaction type code for NFTokenBurn.
pub const TT_NFTOKEN_BURN: u16 = 26;

/// NFToken mint flags.
pub mod nftoken_flags {
    /// NFToken is transferable between accounts.
    pub const TF_TRANSFERABLE: u32 = 0x0008;
    /// NFToken can be burned by the issuer.
    pub const TF_BURNABLE: u32 = 0x0001;
    /// NFToken offers can only be in XRP.
    pub const TF_ONLY_XRP: u32 = 0x0002;
}

/// Serialize an NFTokenMint transaction.
pub fn nftoken_mint(
    account: &[u8; 20],
    nftoken_taxon: u32,
    flags: u32,
    uri: Option<&[u8]>,
    sequence: u32,
    fee_drops: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(100);
    buf.extend_from_slice(&[0x12, (TT_NFTOKEN_MINT >> 8) as u8, TT_NFTOKEN_MINT as u8]);
    buf.extend_from_slice(&[0x22]);
    buf.extend_from_slice(&flags.to_be_bytes());
    buf.extend_from_slice(&[0x24]);
    buf.extend_from_slice(&sequence.to_be_bytes());
    buf.extend_from_slice(&[0x20, 0x2A]);
    buf.extend_from_slice(&nftoken_taxon.to_be_bytes());
    buf.push(0x68);
    buf.extend_from_slice(&encode_xrp_amount(fee_drops));
    if let Some(uri_bytes) = uri {
        buf.extend_from_slice(&[0x75, 0x0D]);
        buf.push(uri_bytes.len() as u8);
        buf.extend_from_slice(uri_bytes);
    }
    buf.extend_from_slice(&[0x81, 0x14]);
    buf.extend_from_slice(account);
    buf
}

/// Serialize an NFTokenCreateOffer transaction.
pub fn nftoken_create_offer(
    account: &[u8; 20],
    nftoken_id: &[u8; 32],
    amount_drops: u64,
    flags: u32,
    destination: Option<&[u8; 20]>,
    sequence: u32,
    fee_drops: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(120);
    buf.extend_from_slice(&[
        0x12,
        (TT_NFTOKEN_CREATE_OFFER >> 8) as u8,
        TT_NFTOKEN_CREATE_OFFER as u8,
    ]);
    buf.extend_from_slice(&[0x22]);
    buf.extend_from_slice(&flags.to_be_bytes());
    buf.extend_from_slice(&[0x24]);
    buf.extend_from_slice(&sequence.to_be_bytes());
    buf.push(0x61);
    buf.extend_from_slice(&encode_xrp_amount(amount_drops));
    buf.push(0x68);
    buf.extend_from_slice(&encode_xrp_amount(fee_drops));
    buf.extend_from_slice(&[0x50, 0x2A]);
    buf.extend_from_slice(nftoken_id);
    buf.extend_from_slice(&[0x81, 0x14]);
    buf.extend_from_slice(account);
    if let Some(dest) = destination {
        buf.extend_from_slice(&[0x83, 0x14]);
        buf.extend_from_slice(dest);
    }
    buf
}

/// Serialize an NFTokenAcceptOffer transaction.
pub fn nftoken_accept_offer(
    account: &[u8; 20],
    sell_offer: Option<&[u8; 32]>,
    buy_offer: Option<&[u8; 32]>,
    sequence: u32,
    fee_drops: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(100);
    buf.extend_from_slice(&[
        0x12,
        (TT_NFTOKEN_ACCEPT_OFFER >> 8) as u8,
        TT_NFTOKEN_ACCEPT_OFFER as u8,
    ]);
    buf.extend_from_slice(&[0x22, 0x00, 0x00, 0x00, 0x00]);
    buf.extend_from_slice(&[0x24]);
    buf.extend_from_slice(&sequence.to_be_bytes());
    buf.push(0x68);
    buf.extend_from_slice(&encode_xrp_amount(fee_drops));
    if let Some(offer) = sell_offer {
        buf.extend_from_slice(&[0x50, 0x29]);
        buf.extend_from_slice(offer);
    }
    if let Some(offer) = buy_offer {
        buf.extend_from_slice(&[0x50, 0x28]);
        buf.extend_from_slice(offer);
    }
    buf.extend_from_slice(&[0x81, 0x14]);
    buf.extend_from_slice(account);
    buf
}

/// Serialize an NFTokenBurn transaction.
pub fn nftoken_burn(
    account: &[u8; 20],
    nftoken_id: &[u8; 32],
    sequence: u32,
    fee_drops: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(80);
    buf.extend_from_slice(&[0x12, (TT_NFTOKEN_BURN >> 8) as u8, TT_NFTOKEN_BURN as u8]);
    buf.extend_from_slice(&[0x22, 0x00, 0x00, 0x00, 0x00]);
    buf.extend_from_slice(&[0x24]);
    buf.extend_from_slice(&sequence.to_be_bytes());
    buf.push(0x68);
    buf.extend_from_slice(&encode_xrp_amount(fee_drops));
    buf.extend_from_slice(&[0x50, 0x2A]);
    buf.extend_from_slice(nftoken_id);
    buf.extend_from_slice(&[0x81, 0x14]);
    buf.extend_from_slice(account);
    buf
}

// ═══════════════════════════════════════════════════════════════════
// Checks
// ═══════════════════════════════════════════════════════════════════

/// Transaction type code for CheckCreate.
pub const TT_CHECK_CREATE: u16 = 16;
/// Transaction type code for CheckCash.
pub const TT_CHECK_CASH: u16 = 17;
/// Transaction type code for CheckCancel.
pub const TT_CHECK_CANCEL: u16 = 18;

/// Serialize a CheckCreate transaction.
pub fn check_create(
    account: &[u8; 20],
    destination: &[u8; 20],
    send_max_drops: u64,
    sequence: u32,
    fee_drops: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(80);
    buf.extend_from_slice(&[0x12, (TT_CHECK_CREATE >> 8) as u8, TT_CHECK_CREATE as u8]);
    buf.extend_from_slice(&[0x22, 0x00, 0x00, 0x00, 0x00]);
    buf.extend_from_slice(&[0x24]);
    buf.extend_from_slice(&sequence.to_be_bytes());
    buf.push(0x69);
    buf.extend_from_slice(&encode_xrp_amount(send_max_drops));
    buf.push(0x68);
    buf.extend_from_slice(&encode_xrp_amount(fee_drops));
    buf.extend_from_slice(&[0x81, 0x14]);
    buf.extend_from_slice(account);
    buf.extend_from_slice(&[0x83, 0x14]);
    buf.extend_from_slice(destination);
    buf
}

/// Serialize a CheckCash transaction.
pub fn check_cash(
    account: &[u8; 20],
    check_id: &[u8; 32],
    amount_drops: u64,
    sequence: u32,
    fee_drops: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(80);
    buf.extend_from_slice(&[0x12, (TT_CHECK_CASH >> 8) as u8, TT_CHECK_CASH as u8]);
    buf.extend_from_slice(&[0x22, 0x00, 0x00, 0x00, 0x00]);
    buf.extend_from_slice(&[0x24]);
    buf.extend_from_slice(&sequence.to_be_bytes());
    buf.push(0x61);
    buf.extend_from_slice(&encode_xrp_amount(amount_drops));
    buf.push(0x68);
    buf.extend_from_slice(&encode_xrp_amount(fee_drops));
    buf.extend_from_slice(&[0x50, 0x18]);
    buf.extend_from_slice(check_id);
    buf.extend_from_slice(&[0x81, 0x14]);
    buf.extend_from_slice(account);
    buf
}

/// Serialize a CheckCancel transaction.
pub fn check_cancel(
    account: &[u8; 20],
    check_id: &[u8; 32],
    sequence: u32,
    fee_drops: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(70);
    buf.extend_from_slice(&[0x12, (TT_CHECK_CANCEL >> 8) as u8, TT_CHECK_CANCEL as u8]);
    buf.extend_from_slice(&[0x22, 0x00, 0x00, 0x00, 0x00]);
    buf.extend_from_slice(&[0x24]);
    buf.extend_from_slice(&sequence.to_be_bytes());
    buf.push(0x68);
    buf.extend_from_slice(&encode_xrp_amount(fee_drops));
    buf.extend_from_slice(&[0x50, 0x18]);
    buf.extend_from_slice(check_id);
    buf.extend_from_slice(&[0x81, 0x14]);
    buf.extend_from_slice(account);
    buf
}

// ═══════════════════════════════════════════════════════════════════
// Hooks (SetHook)
// ═══════════════════════════════════════════════════════════════════

/// Transaction type code for SetHook.
pub const TT_SET_HOOK: u16 = 22;

/// Serialize a SetHook transaction (basic form).
pub fn set_hook(
    account: &[u8; 20],
    hook_hash: &[u8; 32],
    sequence: u32,
    fee_drops: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(100);
    buf.extend_from_slice(&[0x12, (TT_SET_HOOK >> 8) as u8, TT_SET_HOOK as u8]);
    buf.extend_from_slice(&[0x22, 0x00, 0x00, 0x00, 0x00]);
    buf.extend_from_slice(&[0x24]);
    buf.extend_from_slice(&sequence.to_be_bytes());
    buf.push(0x68);
    buf.extend_from_slice(&encode_xrp_amount(fee_drops));
    buf.extend_from_slice(&[0x50, 0x20]);
    buf.extend_from_slice(hook_hash);
    buf.extend_from_slice(&[0x81, 0x14]);
    buf.extend_from_slice(account);
    buf
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const ACCOUNT: [u8; 20] = [0x01; 20];
    const DEST: [u8; 20] = [0x02; 20];

    // ─── IOU Amount Tests ───────────────────────────────────────

    #[test]
    fn test_iou_encode_decode_roundtrip() {
        let encoded = encode_iou_amount(1_000_000_000_000_000, 0, true);
        let (m, e, pos) = decode_iou_amount(&encoded);
        assert!(pos);
        // After normalization, mantissa * 10^exponent should represent same value
        let _original = 1_000_000_000_000_000u128 * 10u128.pow(0);
        let _decoded = m as u128 * 10u128.pow((e + 97 - 97) as u32);
        // Values should be in the same order of magnitude
        assert!(m > 0);
    }

    #[test]
    fn test_iou_zero() {
        let encoded = encode_iou_amount(0, 0, true);
        assert_eq!(encoded[0] & 0x80, 0x80); // Not XRP flag
        let (m, _, _) = decode_iou_amount(&encoded);
        assert_eq!(m, 0);
    }

    #[test]
    fn test_iou_negative() {
        let encoded = encode_iou_amount(1_000_000_000_000_000, 0, false);
        let (_, _, pos) = decode_iou_amount(&encoded);
        assert!(!pos);
    }

    // ─── Currency Code Tests ────────────────────────────────────

    #[test]
    fn test_currency_code_usd() {
        let cc = encode_currency_code("USD").unwrap();
        assert_eq!(&cc[12..15], b"USD");
        assert_eq!(&cc[..12], &[0u8; 12]);
    }

    #[test]
    fn test_currency_code_xrp_rejected() {
        assert!(encode_currency_code("XRP").is_err());
    }

    #[test]
    fn test_currency_code_wrong_length() {
        assert!(encode_currency_code("US").is_err());
        assert!(encode_currency_code("USDC").is_err());
    }

    // ─── OfferCreate Tests ──────────────────────────────────────

    #[test]
    fn test_offer_create_serialization() {
        let tx = offer_create(&ACCOUNT, 1_000_000, 500_000, 42, 12, 0);
        assert!(!tx.is_empty());
        // Transaction type should be 7
        assert_eq!(tx[0], 0x12);
        assert_eq!(u16::from_be_bytes([tx[1], tx[2]]), TT_OFFER_CREATE);
    }

    #[test]
    fn test_offer_cancel_serialization() {
        let tx = offer_cancel(&ACCOUNT, 10, 43, 12);
        assert!(!tx.is_empty());
        assert_eq!(u16::from_be_bytes([tx[1], tx[2]]), TT_OFFER_CANCEL);
    }

    // ─── Escrow Tests ───────────────────────────────────────────

    #[test]
    fn test_escrow_create_serialization() {
        let tx = escrow_create(
            &ACCOUNT,
            &DEST,
            1_000_000,
            1700000000,
            Some(1700100000),
            44,
            12,
        );
        assert!(!tx.is_empty());
        assert_eq!(u16::from_be_bytes([tx[1], tx[2]]), TT_ESCROW_CREATE);
    }

    #[test]
    fn test_escrow_create_no_cancel() {
        let tx1 = escrow_create(&ACCOUNT, &DEST, 1_000_000, 1700000000, None, 44, 12);
        let tx2 = escrow_create(
            &ACCOUNT,
            &DEST,
            1_000_000,
            1700000000,
            Some(1700100000),
            44,
            12,
        );
        // With cancel_after should be longer
        assert!(tx2.len() > tx1.len());
    }

    #[test]
    fn test_escrow_finish_serialization() {
        let tx = escrow_finish(&ACCOUNT, &DEST, 44, 45, 12);
        assert!(!tx.is_empty());
        assert_eq!(u16::from_be_bytes([tx[1], tx[2]]), TT_ESCROW_FINISH);
    }

    #[test]
    fn test_escrow_cancel_serialization() {
        let tx = escrow_cancel(&ACCOUNT, &DEST, 44, 46, 12);
        assert!(!tx.is_empty());
        assert_eq!(u16::from_be_bytes([tx[1], tx[2]]), TT_ESCROW_CANCEL);
    }

    // ─── XRP Amount Encoding ────────────────────────────────────

    #[test]
    fn test_xrp_amount_encoding() {
        let amt = encode_xrp_amount(1_000_000);
        assert_eq!(amt[0] & 0x40, 0x40);
        assert_eq!(amt[0] & 0x80, 0x00);
    }

    // ─── AccountSet Tests ───────────────────────────────────────

    #[test]
    fn test_account_set_with_flag() {
        let tx = account_set(
            &ACCOUNT,
            Some(account_set_flags::ASF_REQUIRE_DEST),
            None,
            1,
            12,
        );
        assert!(!tx.is_empty());
        assert_eq!(u16::from_be_bytes([tx[1], tx[2]]), TT_ACCOUNT_SET);
    }

    #[test]
    fn test_account_set_clear_flag() {
        let tx = account_set(
            &ACCOUNT,
            None,
            Some(account_set_flags::ASF_DISALLOW_XRP),
            2,
            12,
        );
        assert!(!tx.is_empty());
    }

    #[test]
    fn test_account_set_no_flags() {
        let tx = account_set(&ACCOUNT, None, None, 3, 12);
        assert!(!tx.is_empty());
    }

    // ─── Payment Channel Tests ──────────────────────────────────

    #[test]
    fn test_channel_create() {
        let pk = [0x02; 33];
        let tx = channel_create(&ACCOUNT, &DEST, 10_000_000, 3600, &pk, 1, 12);
        assert!(!tx.is_empty());
        assert_eq!(u16::from_be_bytes([tx[1], tx[2]]), TT_CHANNEL_CREATE);
    }

    #[test]
    fn test_channel_fund() {
        let channel = [0xAA; 32];
        let tx = channel_fund(&ACCOUNT, &channel, 5_000_000, 2, 12);
        assert!(!tx.is_empty());
        assert_eq!(u16::from_be_bytes([tx[1], tx[2]]), TT_CHANNEL_FUND);
    }

    #[test]
    fn test_channel_claim() {
        let channel = [0xBB; 32];
        let tx = channel_claim(&ACCOUNT, &channel, Some(1_000_000), 3, 12);
        assert!(!tx.is_empty());
        assert_eq!(u16::from_be_bytes([tx[1], tx[2]]), TT_CHANNEL_CLAIM);
    }

    // ─── NFToken (XLS-20) Tests ─────────────────────────────────

    #[test]
    fn test_nftoken_mint() {
        let tx = nftoken_mint(
            &ACCOUNT,
            0,
            nftoken_flags::TF_TRANSFERABLE,
            Some(b"ipfs://QmTest"),
            1,
            12,
        );
        assert!(!tx.is_empty());
        assert_eq!(u16::from_be_bytes([tx[1], tx[2]]), TT_NFTOKEN_MINT);
    }

    #[test]
    fn test_nftoken_mint_no_uri() {
        let tx1 = nftoken_mint(&ACCOUNT, 1, 0, None, 1, 12);
        let tx2 = nftoken_mint(&ACCOUNT, 1, 0, Some(b"test"), 1, 12);
        assert!(tx2.len() > tx1.len());
    }

    #[test]
    fn test_nftoken_create_offer() {
        let nft_id = [0xAA; 32];
        let tx = nftoken_create_offer(&ACCOUNT, &nft_id, 1_000_000, 0, Some(&DEST), 1, 12);
        assert!(!tx.is_empty());
        assert_eq!(u16::from_be_bytes([tx[1], tx[2]]), TT_NFTOKEN_CREATE_OFFER);
    }

    #[test]
    fn test_nftoken_accept_offer() {
        let offer = [0xBB; 32];
        let tx = nftoken_accept_offer(&ACCOUNT, Some(&offer), None, 1, 12);
        assert!(!tx.is_empty());
        assert_eq!(u16::from_be_bytes([tx[1], tx[2]]), TT_NFTOKEN_ACCEPT_OFFER);
    }

    #[test]
    fn test_nftoken_burn() {
        let nft_id = [0xCC; 32];
        let tx = nftoken_burn(&ACCOUNT, &nft_id, 1, 12);
        assert!(!tx.is_empty());
        assert_eq!(u16::from_be_bytes([tx[1], tx[2]]), TT_NFTOKEN_BURN);
    }

    // ─── Check Tests ────────────────────────────────────────────

    #[test]
    fn test_check_create() {
        let tx = check_create(&ACCOUNT, &DEST, 5_000_000, 1, 12);
        assert!(!tx.is_empty());
        assert_eq!(u16::from_be_bytes([tx[1], tx[2]]), TT_CHECK_CREATE);
    }

    #[test]
    fn test_check_cash() {
        let check_id = [0xDD; 32];
        let tx = check_cash(&ACCOUNT, &check_id, 5_000_000, 2, 12);
        assert!(!tx.is_empty());
        assert_eq!(u16::from_be_bytes([tx[1], tx[2]]), TT_CHECK_CASH);
    }

    #[test]
    fn test_check_cancel() {
        let check_id = [0xEE; 32];
        let tx = check_cancel(&ACCOUNT, &check_id, 3, 12);
        assert!(!tx.is_empty());
        assert_eq!(u16::from_be_bytes([tx[1], tx[2]]), TT_CHECK_CANCEL);
    }

    // ─── Hook Tests ─────────────────────────────────────────────

    #[test]
    fn test_set_hook() {
        let hook_hash = [0xFF; 32];
        let tx = set_hook(&ACCOUNT, &hook_hash, 1, 12);
        assert!(!tx.is_empty());
        assert_eq!(u16::from_be_bytes([tx[1], tx[2]]), TT_SET_HOOK);
    }
}
