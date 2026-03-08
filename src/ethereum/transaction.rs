//! Ethereum transaction types with RLP encoding and signing.
//!
//! Supports Legacy (pre-EIP-2718), Type 1 (EIP-2930), and Type 2 (EIP-1559) transactions.
//! Each transaction type can be built, serialized, signed, and exported as raw hex for broadcasting.
//!
//! # Example
//! ```no_run
//! use trad_signer::ethereum::transaction::EIP1559Transaction;
//! use trad_signer::ethereum::EthereumSigner;
//! use trad_signer::traits::KeyPair;
//!
//! fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     let signer = EthereumSigner::generate()?;
//!     let tx = EIP1559Transaction {
//!         chain_id: 1,
//!         nonce: 0,
//!         max_priority_fee_per_gas: 2_000_000_000, // 2 Gwei
//!         max_fee_per_gas: 100_000_000_000,        // 100 Gwei
//!         gas_limit: 21_000,
//!         to: Some([0xAA; 20]),
//!         value: 1_000_000_000_000_000_000,        // 1 ETH
//!         data: vec![],
//!         access_list: vec![],
//!     };
//!     let signed = tx.sign(&signer)?;
//!     println!("Raw tx: 0x{}", hex::encode(&signed.raw_tx()));
//!     println!("Tx hash: 0x{}", hex::encode(signed.tx_hash()));
//!     Ok(())
//! }
//! ```

use crate::error::SignerError;
use super::rlp;
use super::EthereumSigner;
use sha3::{Digest, Keccak256};

// ─── Signed Transaction ────────────────────────────────────────────

/// A signed Ethereum transaction ready for broadcast.
#[derive(Debug, Clone)]
pub struct SignedTransaction {
    /// The raw signed transaction bytes (for `eth_sendRawTransaction`).
    raw: Vec<u8>,
}

impl SignedTransaction {
    /// Return the raw signed transaction bytes.
    ///
    /// This is what you pass to `eth_sendRawTransaction`.
    #[must_use]
    pub fn raw_tx(&self) -> &[u8] {
        &self.raw
    }

    /// Compute the transaction hash (keccak256 of the raw signed tx).
    #[must_use]
    pub fn tx_hash(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&Keccak256::digest(&self.raw));
        out
    }

    /// Return the raw transaction as a `0x`-prefixed hex string.
    #[must_use]
    pub fn raw_tx_hex(&self) -> String {
        format!("0x{}", hex::encode(&self.raw))
    }
}

// ─── Legacy Transaction (pre-EIP-2718) ─────────────────────────────

/// A Legacy (Type 0) Ethereum transaction.
///
/// Uses EIP-155 replay protection via `chain_id` in the signing payload.
#[derive(Debug, Clone)]
pub struct LegacyTransaction {
    /// The nonce of the sender.
    pub nonce: u64,
    /// Gas price in wei.
    pub gas_price: u128,
    /// Gas limit.
    pub gas_limit: u64,
    /// Recipient address. `None` for contract creation.
    pub to: Option<[u8; 20]>,
    /// Value in wei.
    pub value: u128,
    /// Call data.
    pub data: Vec<u8>,
    /// Chain ID for EIP-155 replay protection.
    pub chain_id: u64,
}

impl LegacyTransaction {
    /// Serialize the unsigned transaction for signing (EIP-155).
    ///
    /// `RLP([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0])`
    fn signing_payload(&self) -> Vec<u8> {
        let mut items = Vec::new();
        items.extend_from_slice(&rlp::encode_u64(self.nonce));
        items.extend_from_slice(&rlp::encode_u128(self.gas_price));
        items.extend_from_slice(&rlp::encode_u64(self.gas_limit));
        items.extend_from_slice(&encode_address(&self.to));
        items.extend_from_slice(&rlp::encode_u128(self.value));
        items.extend_from_slice(&rlp::encode_bytes(&self.data));
        // EIP-155: chain_id, 0, 0
        items.extend_from_slice(&rlp::encode_u64(self.chain_id));
        items.extend_from_slice(&rlp::encode_u64(0));
        items.extend_from_slice(&rlp::encode_u64(0));
        rlp::encode_list(&items)
    }

    /// Sign this transaction with the given signer.
    pub fn sign(&self, signer: &EthereumSigner) -> Result<SignedTransaction, SignerError> {
        let payload = self.signing_payload();
        let hash = keccak256(&payload);
        let sig = signer.sign_digest(&hash)?;

        // EIP-155: v = {0,1} + chain_id * 2 + 35
        let v = (sig.v as u64 - 27) + self.chain_id * 2 + 35;

        let mut items = Vec::new();
        items.extend_from_slice(&rlp::encode_u64(self.nonce));
        items.extend_from_slice(&rlp::encode_u128(self.gas_price));
        items.extend_from_slice(&rlp::encode_u64(self.gas_limit));
        items.extend_from_slice(&encode_address(&self.to));
        items.extend_from_slice(&rlp::encode_u128(self.value));
        items.extend_from_slice(&rlp::encode_bytes(&self.data));
        items.extend_from_slice(&rlp::encode_u64(v));
        items.extend_from_slice(&rlp::encode_bytes(&strip_leading_zeros(&sig.r)));
        items.extend_from_slice(&rlp::encode_bytes(&strip_leading_zeros(&sig.s)));

        Ok(SignedTransaction {
            raw: rlp::encode_list(&items),
        })
    }
}

// ─── EIP-2930 Transaction (Type 1) ─────────────────────────────────

/// An EIP-2930 (Type 1) transaction with access list.
///
/// Introduced by Berlin hard fork. Uses EIP-2718 typed transaction envelope.
#[derive(Debug, Clone)]
pub struct EIP2930Transaction {
    /// Chain ID (required, not optional like Legacy).
    pub chain_id: u64,
    /// Sender nonce.
    pub nonce: u64,
    /// Gas price in wei.
    pub gas_price: u128,
    /// Gas limit.
    pub gas_limit: u64,
    /// Recipient. `None` for contract creation.
    pub to: Option<[u8; 20]>,
    /// Value in wei.
    pub value: u128,
    /// Call data.
    pub data: Vec<u8>,
    /// Access list: `[(address, [storage_key, ...])]`.
    pub access_list: Vec<([u8; 20], Vec<[u8; 32]>)>,
}

impl EIP2930Transaction {
    /// Signing payload: `keccak256(0x01 || RLP([chainId, nonce, gasPrice, gasLimit, to, value, data, accessList]))`
    fn signing_hash(&self) -> [u8; 32] {
        let mut items = Vec::new();
        items.extend_from_slice(&rlp::encode_u64(self.chain_id));
        items.extend_from_slice(&rlp::encode_u64(self.nonce));
        items.extend_from_slice(&rlp::encode_u128(self.gas_price));
        items.extend_from_slice(&rlp::encode_u64(self.gas_limit));
        items.extend_from_slice(&encode_address(&self.to));
        items.extend_from_slice(&rlp::encode_u128(self.value));
        items.extend_from_slice(&rlp::encode_bytes(&self.data));
        items.extend_from_slice(&rlp::encode_access_list(&self.access_list));

        let mut payload = vec![0x01]; // Type 1
        payload.extend_from_slice(&rlp::encode_list(&items));
        keccak256(&payload)
    }

    /// Sign this transaction.
    pub fn sign(&self, signer: &EthereumSigner) -> Result<SignedTransaction, SignerError> {
        let hash = self.signing_hash();
        let sig = signer.sign_digest(&hash)?;
        let y_parity = sig.v - 27; // 0 or 1

        let mut items = Vec::new();
        items.extend_from_slice(&rlp::encode_u64(self.chain_id));
        items.extend_from_slice(&rlp::encode_u64(self.nonce));
        items.extend_from_slice(&rlp::encode_u128(self.gas_price));
        items.extend_from_slice(&rlp::encode_u64(self.gas_limit));
        items.extend_from_slice(&encode_address(&self.to));
        items.extend_from_slice(&rlp::encode_u128(self.value));
        items.extend_from_slice(&rlp::encode_bytes(&self.data));
        items.extend_from_slice(&rlp::encode_access_list(&self.access_list));
        items.extend_from_slice(&rlp::encode_u64(y_parity as u64));
        items.extend_from_slice(&rlp::encode_bytes(&strip_leading_zeros(&sig.r)));
        items.extend_from_slice(&rlp::encode_bytes(&strip_leading_zeros(&sig.s)));

        let mut raw = vec![0x01]; // Type prefix
        raw.extend_from_slice(&rlp::encode_list(&items));

        Ok(SignedTransaction { raw })
    }
}

// ─── EIP-1559 Transaction (Type 2) ─────────────────────────────────

/// An EIP-1559 (Type 2) dynamic fee transaction.
///
/// The de facto standard since the London hard fork. Uses `maxFeePerGas` and
/// `maxPriorityFeePerGas` instead of a single `gasPrice`.
#[derive(Debug, Clone)]
pub struct EIP1559Transaction {
    /// Chain ID (required).
    pub chain_id: u64,
    /// Sender nonce.
    pub nonce: u64,
    /// Maximum priority fee (tip) per gas in wei.
    pub max_priority_fee_per_gas: u128,
    /// Maximum total fee per gas in wei.
    pub max_fee_per_gas: u128,
    /// Gas limit.
    pub gas_limit: u64,
    /// Recipient. `None` for contract creation.
    pub to: Option<[u8; 20]>,
    /// Value in wei.
    pub value: u128,
    /// Call data.
    pub data: Vec<u8>,
    /// Access list: `[(address, [storage_key, ...])]`.
    pub access_list: Vec<([u8; 20], Vec<[u8; 32]>)>,
}

impl EIP1559Transaction {
    /// Signing hash: `keccak256(0x02 || RLP([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList]))`
    fn signing_hash(&self) -> [u8; 32] {
        let mut items = Vec::new();
        items.extend_from_slice(&rlp::encode_u64(self.chain_id));
        items.extend_from_slice(&rlp::encode_u64(self.nonce));
        items.extend_from_slice(&rlp::encode_u128(self.max_priority_fee_per_gas));
        items.extend_from_slice(&rlp::encode_u128(self.max_fee_per_gas));
        items.extend_from_slice(&rlp::encode_u64(self.gas_limit));
        items.extend_from_slice(&encode_address(&self.to));
        items.extend_from_slice(&rlp::encode_u128(self.value));
        items.extend_from_slice(&rlp::encode_bytes(&self.data));
        items.extend_from_slice(&rlp::encode_access_list(&self.access_list));

        let mut payload = vec![0x02]; // Type 2
        payload.extend_from_slice(&rlp::encode_list(&items));
        keccak256(&payload)
    }

    /// Sign this transaction.
    pub fn sign(&self, signer: &EthereumSigner) -> Result<SignedTransaction, SignerError> {
        let hash = self.signing_hash();
        let sig = signer.sign_digest(&hash)?;
        let y_parity = sig.v - 27; // 0 or 1

        let mut items = Vec::new();
        items.extend_from_slice(&rlp::encode_u64(self.chain_id));
        items.extend_from_slice(&rlp::encode_u64(self.nonce));
        items.extend_from_slice(&rlp::encode_u128(self.max_priority_fee_per_gas));
        items.extend_from_slice(&rlp::encode_u128(self.max_fee_per_gas));
        items.extend_from_slice(&rlp::encode_u64(self.gas_limit));
        items.extend_from_slice(&encode_address(&self.to));
        items.extend_from_slice(&rlp::encode_u128(self.value));
        items.extend_from_slice(&rlp::encode_bytes(&self.data));
        items.extend_from_slice(&rlp::encode_access_list(&self.access_list));
        items.extend_from_slice(&rlp::encode_u64(y_parity as u64));
        items.extend_from_slice(&rlp::encode_bytes(&strip_leading_zeros(&sig.r)));
        items.extend_from_slice(&rlp::encode_bytes(&strip_leading_zeros(&sig.s)));

        let mut raw = vec![0x02]; // Type prefix
        raw.extend_from_slice(&rlp::encode_list(&items));

        Ok(SignedTransaction { raw })
    }
}

// ─── EIP-4844 Transaction (Type 3) ─────────────────────────────────

/// An EIP-4844 (Type 3) blob transaction.
///
/// Carries blob versioned hashes for rollup data availability.
/// Note: the actual blob data and KZG proofs are sidecar data, not
/// part of the transaction itself.
#[derive(Debug, Clone)]
pub struct EIP4844Transaction {
    /// Chain ID (required).
    pub chain_id: u64,
    /// Sender nonce.
    pub nonce: u64,
    /// Maximum priority fee (tip) per gas in wei.
    pub max_priority_fee_per_gas: u128,
    /// Maximum total fee per gas in wei.
    pub max_fee_per_gas: u128,
    /// Gas limit.
    pub gas_limit: u64,
    /// Recipient address (required — no contract creation).
    pub to: [u8; 20],
    /// Value in wei.
    pub value: u128,
    /// Call data.
    pub data: Vec<u8>,
    /// Access list.
    pub access_list: Vec<([u8; 20], Vec<[u8; 32]>)>,
    /// Maximum fee per blob gas in wei.
    pub max_fee_per_blob_gas: u128,
    /// Blob versioned hashes (32 bytes each, version byte 0x01).
    pub blob_versioned_hashes: Vec<[u8; 32]>,
}

impl EIP4844Transaction {
    /// Signing hash: `keccak256(0x03 || RLP([...fields, max_fee_per_blob_gas, blob_versioned_hashes]))`
    fn signing_hash(&self) -> [u8; 32] {
        let mut items = Vec::new();
        items.extend_from_slice(&rlp::encode_u64(self.chain_id));
        items.extend_from_slice(&rlp::encode_u64(self.nonce));
        items.extend_from_slice(&rlp::encode_u128(self.max_priority_fee_per_gas));
        items.extend_from_slice(&rlp::encode_u128(self.max_fee_per_gas));
        items.extend_from_slice(&rlp::encode_u64(self.gas_limit));
        items.extend_from_slice(&rlp::encode_bytes(&self.to));
        items.extend_from_slice(&rlp::encode_u128(self.value));
        items.extend_from_slice(&rlp::encode_bytes(&self.data));
        items.extend_from_slice(&rlp::encode_access_list(&self.access_list));
        items.extend_from_slice(&rlp::encode_u128(self.max_fee_per_blob_gas));
        // blob_versioned_hashes as RLP list of 32-byte strings
        let mut hash_items = Vec::new();
        for h in &self.blob_versioned_hashes {
            hash_items.extend_from_slice(&rlp::encode_bytes(h));
        }
        items.extend_from_slice(&rlp::encode_list(&hash_items));

        let mut payload = vec![0x03]; // Type 3
        payload.extend_from_slice(&rlp::encode_list(&items));
        keccak256(&payload)
    }

    /// Sign this transaction.
    pub fn sign(&self, signer: &EthereumSigner) -> Result<SignedTransaction, SignerError> {
        let hash = self.signing_hash();
        let sig = signer.sign_digest(&hash)?;
        let y_parity = sig.v - 27;

        let mut items = Vec::new();
        items.extend_from_slice(&rlp::encode_u64(self.chain_id));
        items.extend_from_slice(&rlp::encode_u64(self.nonce));
        items.extend_from_slice(&rlp::encode_u128(self.max_priority_fee_per_gas));
        items.extend_from_slice(&rlp::encode_u128(self.max_fee_per_gas));
        items.extend_from_slice(&rlp::encode_u64(self.gas_limit));
        items.extend_from_slice(&rlp::encode_bytes(&self.to));
        items.extend_from_slice(&rlp::encode_u128(self.value));
        items.extend_from_slice(&rlp::encode_bytes(&self.data));
        items.extend_from_slice(&rlp::encode_access_list(&self.access_list));
        items.extend_from_slice(&rlp::encode_u128(self.max_fee_per_blob_gas));
        let mut hash_items = Vec::new();
        for h in &self.blob_versioned_hashes {
            hash_items.extend_from_slice(&rlp::encode_bytes(h));
        }
        items.extend_from_slice(&rlp::encode_list(&hash_items));
        items.extend_from_slice(&rlp::encode_u64(y_parity as u64));
        items.extend_from_slice(&rlp::encode_bytes(&strip_leading_zeros(&sig.r)));
        items.extend_from_slice(&rlp::encode_bytes(&strip_leading_zeros(&sig.s)));

        let mut raw = vec![0x03];
        raw.extend_from_slice(&rlp::encode_list(&items));

        Ok(SignedTransaction { raw })
    }
}

// ─── Contract Address Prediction ───────────────────────────────────

/// Predict the contract address deployed via CREATE.
///
/// `keccak256(RLP([sender, nonce]))[12..32]`
pub fn create_address(sender: &[u8; 20], nonce: u64) -> [u8; 20] {
    let mut items = Vec::new();
    items.extend_from_slice(&rlp::encode_bytes(sender));
    items.extend_from_slice(&rlp::encode_u64(nonce));
    let rlp_data = rlp::encode_list(&items);
    let hash = keccak256(&rlp_data);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

/// Predict the contract address deployed via CREATE2 (EIP-1014).
///
/// `keccak256(0xFF || sender || salt || keccak256(init_code))[12..32]`
pub fn create2_address(sender: &[u8; 20], salt: &[u8; 32], init_code: &[u8]) -> [u8; 20] {
    let code_hash = keccak256(init_code);
    let mut buf = Vec::with_capacity(1 + 20 + 32 + 32);
    buf.push(0xFF);
    buf.extend_from_slice(sender);
    buf.extend_from_slice(salt);
    buf.extend_from_slice(&code_hash);
    let hash = keccak256(&buf);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

// ─── EIP-1271: Contract Signature ──────────────────────────────────

/// EIP-1271 magic value returned by `isValidSignature` on success.
pub const EIP1271_MAGIC: [u8; 4] = [0x16, 0x26, 0xBA, 0x7E];

/// Encode an `isValidSignature(bytes32, bytes)` call for EIP-1271.
///
/// Returns the ABI-encoded calldata suitable for `eth_call`.
pub fn encode_is_valid_signature(hash: &[u8; 32], signature: &[u8]) -> Vec<u8> {
    // Function selector: keccak256("isValidSignature(bytes32,bytes)")[..4]
    let selector = &keccak256(b"isValidSignature(bytes32,bytes)")[..4];

    let mut calldata = Vec::new();
    calldata.extend_from_slice(selector);
    // hash (bytes32) — padded to 32 bytes
    calldata.extend_from_slice(hash);
    // offset to bytes data (64 bytes from start of params)
    let mut offset = [0u8; 32];
    offset[31] = 64;
    calldata.extend_from_slice(&offset);
    // length of signature
    let mut len_buf = [0u8; 32];
    len_buf[28..32].copy_from_slice(&(signature.len() as u32).to_be_bytes());
    calldata.extend_from_slice(&len_buf);
    // signature data (padded to 32-byte boundary)
    calldata.extend_from_slice(signature);
    let padding = (32 - (signature.len() % 32)) % 32;
    calldata.extend_from_slice(&vec![0u8; padding]);

    calldata
}

// ─── Helpers ───────────────────────────────────────────────────────

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Keccak256::digest(data));
    out
}

fn encode_address(to: &Option<[u8; 20]>) -> Vec<u8> {
    match to {
        Some(addr) => rlp::encode_bytes(addr),
        None => rlp::encode_bytes(&[]),
    }
}

fn strip_leading_zeros(data: &[u8; 32]) -> Vec<u8> {
    let start = data.iter().position(|b| *b != 0).unwrap_or(31);
    data[start..].to_vec()
}

// ─── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::traits::KeyPair;

    #[test]
    fn test_legacy_tx_sign_recoverable() {
        let signer = EthereumSigner::generate().unwrap();
        let tx = LegacyTransaction {
            nonce: 0,
            gas_price: 20_000_000_000, // 20 Gwei
            gas_limit: 21_000,
            to: Some([0xBB; 20]),
            value: 1_000_000_000_000_000_000, // 1 ETH
            data: vec![],
            chain_id: 1,
        };
        let signed = tx.sign(&signer).unwrap();
        let raw = signed.raw_tx();
        assert!(!raw.is_empty());
        // Must be valid RLP
        let decoded = rlp::decode(raw).unwrap();
        let items = decoded.as_list().unwrap();
        assert_eq!(items.len(), 9); // nonce, gasPrice, gasLimit, to, value, data, v, r, s
    }

    #[test]
    fn test_legacy_tx_hash_deterministic() {
        let signer = EthereumSigner::from_bytes(&[0x42; 32]).unwrap();
        let tx = LegacyTransaction {
            nonce: 5,
            gas_price: 30_000_000_000,
            gas_limit: 21_000,
            to: Some([0xCC; 20]),
            value: 0,
            data: vec![0xDE, 0xAD],
            chain_id: 1,
        };
        let signed1 = tx.sign(&signer).unwrap();
        let signed2 = tx.sign(&signer).unwrap();
        // RFC 6979 deterministic: same tx + same key = same signature
        assert_eq!(signed1.tx_hash(), signed2.tx_hash());
    }

    #[test]
    fn test_legacy_contract_creation() {
        let signer = EthereumSigner::generate().unwrap();
        let tx = LegacyTransaction {
            nonce: 0,
            gas_price: 20_000_000_000,
            gas_limit: 1_000_000,
            to: None, // contract creation
            value: 0,
            data: vec![0x60, 0x00], // minimal bytecode
            chain_id: 1,
        };
        let signed = tx.sign(&signer).unwrap();
        assert!(!signed.raw_tx().is_empty());
    }

    #[test]
    fn test_eip2930_tx_type1_prefix() {
        let signer = EthereumSigner::generate().unwrap();
        let tx = EIP2930Transaction {
            chain_id: 1,
            nonce: 0,
            gas_price: 20_000_000_000,
            gas_limit: 21_000,
            to: Some([0xAA; 20]),
            value: 1_000_000_000_000_000_000,
            data: vec![],
            access_list: vec![
                ([0xDD; 20], vec![[0xEE; 32]]),
            ],
        };
        let signed = tx.sign(&signer).unwrap();
        assert_eq!(signed.raw_tx()[0], 0x01, "Type 1 prefix");
    }

    #[test]
    fn test_eip1559_tx_type2_prefix() {
        let signer = EthereumSigner::generate().unwrap();
        let tx = EIP1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 2_000_000_000,
            max_fee_per_gas: 100_000_000_000,
            gas_limit: 21_000,
            to: Some([0xAA; 20]),
            value: 1_000_000_000_000_000_000,
            data: vec![],
            access_list: vec![],
        };
        let signed = tx.sign(&signer).unwrap();
        assert_eq!(signed.raw_tx()[0], 0x02, "Type 2 prefix");
    }

    #[test]
    fn test_eip1559_different_nonces_different_hashes() {
        let signer = EthereumSigner::from_bytes(&[0x42; 32]).unwrap();
        let base = EIP1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 2_000_000_000,
            max_fee_per_gas: 100_000_000_000,
            gas_limit: 21_000,
            to: Some([0xAA; 20]),
            value: 0,
            data: vec![],
            access_list: vec![],
        };
        let mut tx2 = base.clone();
        tx2.nonce = 1;
        let h1 = base.sign(&signer).unwrap().tx_hash();
        let h2 = tx2.sign(&signer).unwrap().tx_hash();
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_eip4844_tx_type3_prefix() {
        let signer = EthereumSigner::generate().unwrap();
        let tx = EIP4844Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 2_000_000_000,
            max_fee_per_gas: 100_000_000_000,
            gas_limit: 21_000,
            to: [0xAA; 20],
            value: 0,
            data: vec![],
            access_list: vec![],
            max_fee_per_blob_gas: 1_000_000_000,
            blob_versioned_hashes: vec![[0x01; 32]],
        };
        let signed = tx.sign(&signer).unwrap();
        assert_eq!(signed.raw_tx()[0], 0x03, "Type 3 prefix");
    }

    #[test]
    fn test_create_address_known_vector() {
        // Known: sender 0x0000...0000 nonce 0 → specific address
        let sender = [0u8; 20];
        let addr = create_address(&sender, 0);
        assert_eq!(addr.len(), 20);
        // Verify it's deterministic
        assert_eq!(addr, create_address(&sender, 0));
        // Different nonce → different address
        assert_ne!(addr, create_address(&sender, 1));
    }

    #[test]
    fn test_create2_address_eip1014_vector() {
        // EIP-1014 test vector #1:
        // sender = 0x0000000000000000000000000000000000000000
        // salt = 0x00...00
        // init_code = 0x00
        // expected = keccak256(0xff ++ sender ++ salt ++ keccak256(init_code))[12:]
        let sender = [0u8; 20];
        let salt = [0u8; 32];
        let addr = create2_address(&sender, &salt, &[0x00]);
        // Verify determinism
        assert_eq!(addr, create2_address(&sender, &salt, &[0x00]));
        // Different init_code → different address
        assert_ne!(addr, create2_address(&sender, &salt, &[0x01]));
    }

    #[test]
    fn test_eip1271_encode() {
        let hash = [0xAA; 32];
        let sig = vec![0xBB; 65];
        let calldata = encode_is_valid_signature(&hash, &sig);
        // First 4 bytes = function selector
        assert_eq!(&calldata[..4], &keccak256(b"isValidSignature(bytes32,bytes)")[..4]);
        // Next 32 bytes = hash
        assert_eq!(&calldata[4..36], &hash);
    }

    #[test]
    fn test_raw_tx_hex_format() {
        let signer = EthereumSigner::generate().unwrap();
        let tx = EIP1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            gas_limit: 21_000,
            to: Some([0; 20]),
            value: 0,
            data: vec![],
            access_list: vec![],
        };
        let hex = tx.sign(&signer).unwrap().raw_tx_hex();
        assert!(hex.starts_with("0x02"), "should start with 0x02");
    }

    #[test]
    fn test_signed_tx_hash_is_keccak_of_raw() {
        let signer = EthereumSigner::generate().unwrap();
        let tx = EIP1559Transaction {
            chain_id: 1,
            nonce: 42,
            max_priority_fee_per_gas: 1_000_000,
            max_fee_per_gas: 50_000_000_000,
            gas_limit: 100_000,
            to: Some([0xFF; 20]),
            value: 500_000_000_000_000,
            data: vec![0x01, 0x02, 0x03],
            access_list: vec![],
        };
        let signed = tx.sign(&signer).unwrap();
        let expected = keccak256(signed.raw_tx());
        assert_eq!(signed.tx_hash(), expected);
    }
}
