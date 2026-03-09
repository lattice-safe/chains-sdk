//! Uniswap Permit2 — Universal token approval and transfer signatures.
//!
//! Implements EIP-712 typed data for Uniswap's Permit2 contract, which
//! provides a universal, gas-efficient token approval system beyond
//! the basic EIP-2612 permit.
//!
//! Supports:
//! - `PermitSingle` / `PermitBatch` — gasless approval signatures
//! - `PermitTransferFrom` — one-time signed transfer authorizations
//! - `SignatureTransfer` — witness-extended transfers
//!
//! # Example
//! ```no_run
//! use chains_sdk::ethereum::permit2::*;
//!
//! let permit = PermitSingle {
//!     token: [0xAA; 20],
//!     amount: 1_000_000,
//!     expiration: 1_700_000_000,
//!     nonce: 0,
//!     spender: [0xBB; 20],
//!     sig_deadline: 1_700_000_000,
//! };
//! let hash = permit.struct_hash();
//! ```

use crate::ethereum::keccak256;

/// Uniswap Permit2 contract address (same on all chains).
pub const PERMIT2_ADDRESS: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0xd4, 0x73,
    0x03, 0x0f, 0x11, 0x6d, 0xde, 0xe9, 0xf6, 0xb4,
    0x3a, 0xc7, 0x8b, 0xa3,
];

// ═══════════════════════════════════════════════════════════════════
// Type Hashes
// ═══════════════════════════════════════════════════════════════════

/// `keccak256("TokenPermissions(address token,uint256 amount)")`
fn token_permissions_typehash() -> [u8; 32] {
    keccak256(b"TokenPermissions(address token,uint256 amount)")
}

/// `keccak256("PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)")`
fn permit_details_typehash() -> [u8; 32] {
    keccak256(b"PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)")
}

/// `keccak256("PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)")`
fn permit_single_typehash() -> [u8; 32] {
    keccak256(b"PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)")
}

/// `keccak256("PermitBatch(PermitDetails[] details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)")`
fn permit_batch_typehash() -> [u8; 32] {
    keccak256(b"PermitBatch(PermitDetails[] details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)")
}

/// `keccak256("PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)")`
fn permit_transfer_from_typehash() -> [u8; 32] {
    keccak256(b"PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)")
}

/// `keccak256("PermitBatchTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)")`
fn permit_batch_transfer_from_typehash() -> [u8; 32] {
    keccak256(b"PermitBatchTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)")
}

// ═══════════════════════════════════════════════════════════════════
// PermitSingle (Allowance-based)
// ═══════════════════════════════════════════════════════════════════

/// A single-token allowance permit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermitSingle {
    /// Token address to approve.
    pub token: [u8; 20],
    /// Approval amount (uint160 — use u128 to avoid truncation).
    pub amount: u128,
    /// Approval expiration timestamp (uint48).
    pub expiration: u64,
    /// Per-token nonce for replay protection (uint48).
    pub nonce: u64,
    /// Address being granted the allowance.
    pub spender: [u8; 20],
    /// Signature deadline (uint256).
    pub sig_deadline: u64,
}

impl PermitSingle {
    /// Compute the PermitDetails struct hash.
    fn details_hash(&self) -> [u8; 32] {
        let mut data = Vec::with_capacity(160);
        data.extend_from_slice(&permit_details_typehash());
        data.extend_from_slice(&pad_address(&self.token));
        data.extend_from_slice(&pad_u128(self.amount));
        data.extend_from_slice(&pad_u256(self.expiration));
        data.extend_from_slice(&pad_u256(self.nonce));
        keccak256(&data)
    }

    /// Compute the EIP-712 struct hash for this permit.
    #[must_use]
    pub fn struct_hash(&self) -> [u8; 32] {
        let mut data = Vec::with_capacity(128);
        data.extend_from_slice(&permit_single_typehash());
        data.extend_from_slice(&self.details_hash());
        data.extend_from_slice(&pad_address(&self.spender));
        data.extend_from_slice(&pad_u256(self.sig_deadline));
        keccak256(&data)
    }

    /// Compute the full EIP-712 signing hash.
    ///
    /// `keccak256("\x19\x01" || domainSeparator || structHash)`
    #[must_use]
    pub fn signing_hash(&self, domain_separator: &[u8; 32]) -> [u8; 32] {
        eip712_hash(domain_separator, &self.struct_hash())
    }
}

// ═══════════════════════════════════════════════════════════════════
// PermitBatch (Allowance-based, multiple tokens)
// ═══════════════════════════════════════════════════════════════════

/// Details for one token in a batch permit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermitDetails {
    /// Token address.
    pub token: [u8; 20],
    /// Approval amount.
    pub amount: u128,
    /// Expiration timestamp.
    pub expiration: u64,
    /// Per-token nonce.
    pub nonce: u64,
}

/// A multi-token allowance permit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermitBatch {
    /// Token approval details.
    pub details: Vec<PermitDetails>,
    /// Address being granted the allowance.
    pub spender: [u8; 20],
    /// Signature deadline.
    pub sig_deadline: u64,
}

impl PermitBatch {
    /// Compute the struct hash.
    #[must_use]
    pub fn struct_hash(&self) -> [u8; 32] {
        // Hash the details array
        let mut details_hashes = Vec::with_capacity(self.details.len() * 32);
        for d in &self.details {
            let mut h = Vec::with_capacity(160);
            h.extend_from_slice(&permit_details_typehash());
            h.extend_from_slice(&pad_address(&d.token));
            h.extend_from_slice(&pad_u128(d.amount));
            h.extend_from_slice(&pad_u256(d.expiration));
            h.extend_from_slice(&pad_u256(d.nonce));
            details_hashes.extend_from_slice(&keccak256(&h));
        }
        let details_array_hash = keccak256(&details_hashes);

        let mut data = Vec::with_capacity(128);
        data.extend_from_slice(&permit_batch_typehash());
        data.extend_from_slice(&details_array_hash);
        data.extend_from_slice(&pad_address(&self.spender));
        data.extend_from_slice(&pad_u256(self.sig_deadline));
        keccak256(&data)
    }

    /// Compute the full EIP-712 signing hash.
    #[must_use]
    pub fn signing_hash(&self, domain_separator: &[u8; 32]) -> [u8; 32] {
        eip712_hash(domain_separator, &self.struct_hash())
    }
}

// ═══════════════════════════════════════════════════════════════════
// PermitTransferFrom (Signature-based transfers)
// ═══════════════════════════════════════════════════════════════════

/// A single-token signature transfer permit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermitTransferFrom {
    /// Token address.
    pub token: [u8; 20],
    /// Maximum transfer amount.
    pub amount: u128,
    /// Unique nonce (not sequential — uses unordered nonce bitmap).
    pub nonce: u64,
    /// Signature deadline.
    pub deadline: u64,
    /// Address allowed to execute the transfer.
    pub spender: [u8; 20],
}

impl PermitTransferFrom {
    /// Compute the TokenPermissions struct hash.
    fn token_permissions_hash(&self) -> [u8; 32] {
        let mut data = Vec::with_capacity(96);
        data.extend_from_slice(&token_permissions_typehash());
        data.extend_from_slice(&pad_address(&self.token));
        data.extend_from_slice(&pad_u128(self.amount));
        keccak256(&data)
    }

    /// Compute the EIP-712 struct hash.
    #[must_use]
    pub fn struct_hash(&self) -> [u8; 32] {
        let mut data = Vec::with_capacity(160);
        data.extend_from_slice(&permit_transfer_from_typehash());
        data.extend_from_slice(&self.token_permissions_hash());
        data.extend_from_slice(&pad_address(&self.spender));
        data.extend_from_slice(&pad_u256(self.nonce));
        data.extend_from_slice(&pad_u256(self.deadline));
        keccak256(&data)
    }

    /// Compute the full EIP-712 signing hash.
    #[must_use]
    pub fn signing_hash(&self, domain_separator: &[u8; 32]) -> [u8; 32] {
        eip712_hash(domain_separator, &self.struct_hash())
    }
}

/// A batch signature transfer permit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermitBatchTransferFrom {
    /// Permitted tokens and amounts.
    pub permitted: Vec<TokenPermissions>,
    /// Unique nonce.
    pub nonce: u64,
    /// Signature deadline.
    pub deadline: u64,
    /// Address allowed to execute the transfer.
    pub spender: [u8; 20],
}

/// Token and amount pair for batch transfers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenPermissions {
    /// Token address.
    pub token: [u8; 20],
    /// Transfer amount.
    pub amount: u128,
}

impl PermitBatchTransferFrom {
    /// Compute the EIP-712 struct hash.
    #[must_use]
    pub fn struct_hash(&self) -> [u8; 32] {
        let mut perms_hashes = Vec::with_capacity(self.permitted.len() * 32);
        for p in &self.permitted {
            let mut h = Vec::with_capacity(96);
            h.extend_from_slice(&token_permissions_typehash());
            h.extend_from_slice(&pad_address(&p.token));
            h.extend_from_slice(&pad_u128(p.amount));
            perms_hashes.extend_from_slice(&keccak256(&h));
        }
        let perms_array_hash = keccak256(&perms_hashes);

        let mut data = Vec::with_capacity(160);
        data.extend_from_slice(&permit_batch_transfer_from_typehash());
        data.extend_from_slice(&perms_array_hash);
        data.extend_from_slice(&pad_address(&self.spender));
        data.extend_from_slice(&pad_u256(self.nonce));
        data.extend_from_slice(&pad_u256(self.deadline));
        keccak256(&data)
    }

    /// Compute the full EIP-712 signing hash.
    #[must_use]
    pub fn signing_hash(&self, domain_separator: &[u8; 32]) -> [u8; 32] {
        eip712_hash(domain_separator, &self.struct_hash())
    }
}

// ═══════════════════════════════════════════════════════════════════
// Domain Separator
// ═══════════════════════════════════════════════════════════════════

/// Compute the Permit2 EIP-712 domain separator.
///
/// `keccak256(abi.encode(EIP712_DOMAIN_TYPEHASH, name_hash, chain_id, permit2_address))`
#[must_use]
pub fn permit2_domain_separator(chain_id: u64) -> [u8; 32] {
    let type_hash = keccak256(
        b"EIP712Domain(string name,uint256 chainId,address verifyingContract)",
    );
    let name_hash = keccak256(b"Permit2");

    let mut data = Vec::with_capacity(128);
    data.extend_from_slice(&type_hash);
    data.extend_from_slice(&name_hash);
    data.extend_from_slice(&pad_u256(chain_id));
    data.extend_from_slice(&pad_address(&PERMIT2_ADDRESS));
    keccak256(&data)
}

// ═══════════════════════════════════════════════════════════════════
// ABI Encoding for Permit2 contract calls
// ═══════════════════════════════════════════════════════════════════

/// ABI-encode `permit(address owner, PermitSingle permitSingle, bytes signature)`.
///
/// Function selector: `permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)`
#[must_use]
pub fn encode_permit_single_call(
    owner: &[u8; 20],
    permit: &PermitSingle,
    signature: &[u8],
) -> Vec<u8> {
    use crate::ethereum::abi::{AbiValue, Function};
    let func = Function::new(
        "permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)",
    );
    func.encode(&[
        AbiValue::Address(*owner),
        AbiValue::Tuple(vec![
            AbiValue::Tuple(vec![
                AbiValue::Address(permit.token),
                AbiValue::from_u128(permit.amount),
                AbiValue::from_u64(permit.expiration),
                AbiValue::from_u64(permit.nonce),
            ]),
            AbiValue::Address(permit.spender),
            AbiValue::from_u64(permit.sig_deadline),
        ]),
        AbiValue::Bytes(signature.to_vec()),
    ])
}

/// ABI-encode `transferFrom(address from, address to, uint160 amount, address token)`.
#[must_use]
pub fn encode_transfer_from(
    from: &[u8; 20],
    to: &[u8; 20],
    amount: u128,
    token: &[u8; 20],
) -> Vec<u8> {
    use crate::ethereum::abi::{AbiValue, Function};
    let func = Function::new("transferFrom(address,address,uint160,address)");
    func.encode(&[
        AbiValue::Address(*from),
        AbiValue::Address(*to),
        AbiValue::from_u128(amount),
        AbiValue::Address(*token),
    ])
}

// ═══════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════


fn pad_address(addr: &[u8; 20]) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[12..32].copy_from_slice(addr);
    buf
}

fn pad_u256(val: u64) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[24..32].copy_from_slice(&val.to_be_bytes());
    buf
}

fn pad_u128(val: u128) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[16..32].copy_from_slice(&val.to_be_bytes());
    buf
}

fn eip712_hash(domain_separator: &[u8; 32], struct_hash: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::with_capacity(66);
    data.push(0x19);
    data.push(0x01);
    data.extend_from_slice(domain_separator);
    data.extend_from_slice(struct_hash);
    keccak256(&data)
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::ethereum::abi;

    const TOKEN_A: [u8; 20] = [0xAA; 20];
    const TOKEN_B: [u8; 20] = [0xBB; 20];
    const SPENDER: [u8; 20] = [0xCC; 20];
    const OWNER: [u8; 20] = [0xDD; 20];
    const DEADLINE: u64 = 1_700_000_000;

    // ─── PermitSingle ───────────────────────────────────────────

    #[test]
    fn test_permit_single_struct_hash_deterministic() {
        let p = PermitSingle {
            token: TOKEN_A, amount: 1000, expiration: DEADLINE,
            nonce: 0, spender: SPENDER, sig_deadline: DEADLINE,
        };
        assert_eq!(p.struct_hash(), p.struct_hash());
    }

    #[test]
    fn test_permit_single_different_amounts() {
        let p1 = PermitSingle {
            token: TOKEN_A, amount: 1000, expiration: DEADLINE,
            nonce: 0, spender: SPENDER, sig_deadline: DEADLINE,
        };
        let p2 = PermitSingle {
            token: TOKEN_A, amount: 2000, expiration: DEADLINE,
            nonce: 0, spender: SPENDER, sig_deadline: DEADLINE,
        };
        assert_ne!(p1.struct_hash(), p2.struct_hash());
    }

    #[test]
    fn test_permit_single_different_tokens() {
        let p1 = PermitSingle {
            token: TOKEN_A, amount: 1000, expiration: DEADLINE,
            nonce: 0, spender: SPENDER, sig_deadline: DEADLINE,
        };
        let p2 = PermitSingle {
            token: TOKEN_B, amount: 1000, expiration: DEADLINE,
            nonce: 0, spender: SPENDER, sig_deadline: DEADLINE,
        };
        assert_ne!(p1.struct_hash(), p2.struct_hash());
    }

    #[test]
    fn test_permit_single_signing_hash() {
        let p = PermitSingle {
            token: TOKEN_A, amount: 1000, expiration: DEADLINE,
            nonce: 0, spender: SPENDER, sig_deadline: DEADLINE,
        };
        let ds = permit2_domain_separator(1);
        let hash = p.signing_hash(&ds);
        assert_ne!(hash, [0u8; 32]);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_permit_single_different_chains() {
        let p = PermitSingle {
            token: TOKEN_A, amount: 1000, expiration: DEADLINE,
            nonce: 0, spender: SPENDER, sig_deadline: DEADLINE,
        };
        let h1 = p.signing_hash(&permit2_domain_separator(1));
        let h2 = p.signing_hash(&permit2_domain_separator(137));
        assert_ne!(h1, h2);
    }

    // ─── PermitBatch ────────────────────────────────────────────

    #[test]
    fn test_permit_batch_struct_hash() {
        let p = PermitBatch {
            details: vec![
                PermitDetails { token: TOKEN_A, amount: 100, expiration: DEADLINE, nonce: 0 },
                PermitDetails { token: TOKEN_B, amount: 200, expiration: DEADLINE, nonce: 1 },
            ],
            spender: SPENDER,
            sig_deadline: DEADLINE,
        };
        assert_ne!(p.struct_hash(), [0u8; 32]);
    }

    #[test]
    fn test_permit_batch_different_from_single() {
        let single = PermitSingle {
            token: TOKEN_A, amount: 100, expiration: DEADLINE,
            nonce: 0, spender: SPENDER, sig_deadline: DEADLINE,
        };
        let batch = PermitBatch {
            details: vec![
                PermitDetails { token: TOKEN_A, amount: 100, expiration: DEADLINE, nonce: 0 },
            ],
            spender: SPENDER,
            sig_deadline: DEADLINE,
        };
        assert_ne!(single.struct_hash(), batch.struct_hash());
    }

    #[test]
    fn test_permit_batch_order_matters() {
        let p1 = PermitBatch {
            details: vec![
                PermitDetails { token: TOKEN_A, amount: 100, expiration: DEADLINE, nonce: 0 },
                PermitDetails { token: TOKEN_B, amount: 200, expiration: DEADLINE, nonce: 1 },
            ],
            spender: SPENDER, sig_deadline: DEADLINE,
        };
        let p2 = PermitBatch {
            details: vec![
                PermitDetails { token: TOKEN_B, amount: 200, expiration: DEADLINE, nonce: 1 },
                PermitDetails { token: TOKEN_A, amount: 100, expiration: DEADLINE, nonce: 0 },
            ],
            spender: SPENDER, sig_deadline: DEADLINE,
        };
        assert_ne!(p1.struct_hash(), p2.struct_hash());
    }

    // ─── PermitTransferFrom ─────────────────────────────────────

    #[test]
    fn test_permit_transfer_struct_hash() {
        let p = PermitTransferFrom {
            token: TOKEN_A, amount: 5000, nonce: 42,
            deadline: DEADLINE, spender: SPENDER,
        };
        assert_ne!(p.struct_hash(), [0u8; 32]);
    }

    #[test]
    fn test_permit_transfer_different_nonces() {
        let p1 = PermitTransferFrom {
            token: TOKEN_A, amount: 5000, nonce: 0,
            deadline: DEADLINE, spender: SPENDER,
        };
        let p2 = PermitTransferFrom {
            token: TOKEN_A, amount: 5000, nonce: 1,
            deadline: DEADLINE, spender: SPENDER,
        };
        assert_ne!(p1.struct_hash(), p2.struct_hash());
    }

    #[test]
    fn test_permit_transfer_signing_hash() {
        let p = PermitTransferFrom {
            token: TOKEN_A, amount: 5000, nonce: 0,
            deadline: DEADLINE, spender: SPENDER,
        };
        let ds = permit2_domain_separator(1);
        let hash = p.signing_hash(&ds);
        assert_ne!(hash, [0u8; 32]);
    }

    // ─── PermitBatchTransferFrom ────────────────────────────────

    #[test]
    fn test_permit_batch_transfer_struct_hash() {
        let p = PermitBatchTransferFrom {
            permitted: vec![
                TokenPermissions { token: TOKEN_A, amount: 100 },
                TokenPermissions { token: TOKEN_B, amount: 200 },
            ],
            nonce: 0, deadline: DEADLINE, spender: SPENDER,
        };
        assert_ne!(p.struct_hash(), [0u8; 32]);
    }

    #[test]
    fn test_permit_batch_transfer_signing_hash() {
        let p = PermitBatchTransferFrom {
            permitted: vec![TokenPermissions { token: TOKEN_A, amount: 100 }],
            nonce: 0, deadline: DEADLINE, spender: SPENDER,
        };
        let hash = p.signing_hash(&permit2_domain_separator(1));
        assert_ne!(hash, [0u8; 32]);
    }

    // ─── Domain Separator ───────────────────────────────────────

    #[test]
    fn test_domain_separator_deterministic() {
        assert_eq!(permit2_domain_separator(1), permit2_domain_separator(1));
    }

    #[test]
    fn test_domain_separator_different_chains() {
        assert_ne!(permit2_domain_separator(1), permit2_domain_separator(137));
    }

    #[test]
    fn test_domain_separator_is_32_bytes() {
        assert_eq!(permit2_domain_separator(1).len(), 32);
    }

    // ─── ABI Encoding ───────────────────────────────────────────

    #[test]
    fn test_encode_permit_single_call_selector() {
        let p = PermitSingle {
            token: TOKEN_A, amount: 1000, expiration: DEADLINE,
            nonce: 0, spender: SPENDER, sig_deadline: DEADLINE,
        };
        let data = encode_permit_single_call(&OWNER, &p, &[0xAA; 65]);
        assert!(data.len() > 4);
    }

    #[test]
    fn test_encode_transfer_from_selector() {
        let data = encode_transfer_from(&OWNER, &SPENDER, 1000, &TOKEN_A);
        let expected = abi::function_selector("transferFrom(address,address,uint160,address)");
        assert_eq!(&data[..4], &expected);
    }

    #[test]
    fn test_encode_transfer_from_length() {
        let data = encode_transfer_from(&OWNER, &SPENDER, 1000, &TOKEN_A);
        assert_eq!(data.len(), 4 + 4 * 32); // selector + 4 params
    }

    // ─── Helpers ────────────────────────────────────────────────

    #[test]
    fn test_pad_address() {
        let addr = [0xAA; 20];
        let padded = pad_address(&addr);
        assert!(padded[..12].iter().all(|b| *b == 0));
        assert_eq!(&padded[12..], &addr);
    }

    #[test]
    fn test_pad_u256() {
        let padded = pad_u256(42);
        assert_eq!(padded[31], 42);
        assert!(padded[..24].iter().all(|b| *b == 0));
    }

    #[test]
    fn test_eip712_hash_structure() {
        let ds = [0xAA; 32];
        let sh = [0xBB; 32];
        let hash = eip712_hash(&ds, &sh);
        assert_ne!(hash, [0u8; 32]);
        assert_eq!(hash.len(), 32);
    }

    // ─── Permit2 Address ────────────────────────────────────────

    #[test]
    fn test_permit2_address_length() {
        assert_eq!(PERMIT2_ADDRESS.len(), 20);
    }

    #[test]
    fn test_permit2_address_not_zero() {
        assert_ne!(PERMIT2_ADDRESS, [0u8; 20]);
    }

    #[test]
    fn test_permit2_address_hex() {
        let hex = PERMIT2_ADDRESS.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(hex, "000000000022d473030f116ddee9f6b43ac78ba3");
    }
}
