//! NEO N3 transaction building, NEP-17 token helpers, and contract invocation.
//!
//! Provides:
//! - **NEP-17**: Standard token transfer/balanceOf encoding
//! - **Transaction builder**: NEO N3 transaction construction
//! - **Script builder**: NeoVM opcode encoding for contract calls

use crate::error::SignerError;

// ═══════════════════════════════════════════════════════════════════
// NeoVM Script Builder
// ═══════════════════════════════════════════════════════════════════

/// NeoVM opcode constants.
pub mod opcode {
    /// Push zero onto the stack.
    pub const PUSH0: u8 = 0x00;
    /// Push data with 1-byte length prefix.
    pub const PUSHDATA1: u8 = 0x0C;
    /// Push integer 1.
    pub const PUSH1: u8 = 0x11;
    /// Push integer 2.
    pub const PUSH2: u8 = 0x12;
    /// Push integer 3.
    pub const PUSH3: u8 = 0x13;
    /// Push integer 4.
    pub const PUSH4: u8 = 0x14;
    /// Push integer 5.
    pub const PUSH5: u8 = 0x15;
    /// Push integer 8.
    pub const PUSH8: u8 = 0x18;
    /// Push integer 16.
    pub const PUSH16: u8 = 0x20;
    /// No operation.
    pub const NOP: u8 = 0x21;
    /// Create a new array.
    pub const NEWARRAY: u8 = 0xC5;
    /// Pack stack items into an array.
    pub const PACK: u8 = 0xC1;
    /// System call opcode.
    pub const SYSCALL: u8 = 0x41;
}

/// Build a NeoVM invocation script.
#[derive(Debug, Clone, Default)]
pub struct ScriptBuilder {
    data: Vec<u8>,
}

impl ScriptBuilder {
    /// Create a new empty script builder.
    #[must_use]
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Push a raw byte (opcode).
    pub fn emit(&mut self, op: u8) -> &mut Self {
        self.data.push(op);
        self
    }

    /// Push an integer onto the stack.
    pub fn emit_push_integer(&mut self, value: i64) -> &mut Self {
        if value == -1 {
            self.data.push(0x0F); // PUSHM1
        } else if value == 0 {
            self.data.push(opcode::PUSH0);
        } else if (1..=16).contains(&value) {
            self.data.push(opcode::PUSH1 + (value as u8 - 1));
        } else {
            // Encode as variable-length integer
            let bytes = int_to_bytes(value);
            self.emit_push_bytes(&bytes);
        }
        self
    }

    /// Push bytes onto the stack.
    pub fn emit_push_bytes(&mut self, data: &[u8]) -> &mut Self {
        let len = data.len();
        if len <= 0xFF {
            self.data.push(opcode::PUSHDATA1);
            self.data.push(len as u8);
        }
        self.data.extend_from_slice(data);
        self
    }

    /// Push a 20-byte script hash.
    pub fn emit_push_hash160(&mut self, hash: &[u8; 20]) -> &mut Self {
        self.emit_push_bytes(hash)
    }

    /// Emit a syscall by its 4-byte hash.
    pub fn emit_syscall(&mut self, method_hash: u32) -> &mut Self {
        self.data.push(opcode::SYSCALL);
        self.data.extend_from_slice(&method_hash.to_le_bytes());
        self
    }

    /// Emit a contract call: `System.Contract.Call`.
    ///
    /// Hash of `System.Contract.Call` = `0x627d5b52`
    pub fn emit_contract_call(
        &mut self,
        contract_hash: &[u8; 20],
        method: &str,
        args_count: usize,
    ) -> &mut Self {
        // Push args count onto stack for PACK
        self.emit_push_integer(args_count as i64);
        self.emit(opcode::PACK);
        // Push method name
        self.emit_push_bytes(method.as_bytes());
        // Push contract hash (little-endian)
        self.emit_push_hash160(contract_hash);
        // Syscall System.Contract.Call
        self.emit_syscall(0x627d5b52);
        self
    }

    /// Get the built script bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }
}

fn int_to_bytes(value: i64) -> Vec<u8> {
    if value == 0 { return vec![0]; }
    let mut val = value;
    let mut bytes = Vec::new();
    let negative = val < 0;
    while val != 0 && val != -1 {
        bytes.push(val as u8);
        val >>= 8;
    }
    // Sign bit handling
    if !negative && (bytes.last().is_some_and(|b| b & 0x80 != 0)) {
        bytes.push(0);
    }
    if negative && (bytes.last().is_some_and(|b| b & 0x80 == 0)) {
        bytes.push(0xFF);
    }
    bytes
}

// ═══════════════════════════════════════════════════════════════════
// NEP-17 Token Helpers
// ═══════════════════════════════════════════════════════════════════

/// Well-known NEO N3 contract hashes (little-endian).
pub mod contracts {
    /// NEO native token script hash.
    pub const NEO_TOKEN: [u8; 20] = [
        0xf5, 0x63, 0xea, 0x40, 0xbc, 0x28, 0x3d, 0x4d,
        0x0e, 0x05, 0xc4, 0x8e, 0xa3, 0x05, 0xb3, 0xf2,
        0xa0, 0x73, 0x40, 0xef,
    ];

    /// GAS native token script hash.
    pub const GAS_TOKEN: [u8; 20] = [
        0xcf, 0x76, 0xe2, 0x8b, 0xd0, 0x06, 0x2c, 0x4a,
        0x47, 0x8e, 0xe3, 0x55, 0x61, 0x01, 0x13, 0x19,
        0xf3, 0xcf, 0xa4, 0xd2,
    ];
}

/// Build a NEP-17 `transfer` invocation script.
///
/// # Arguments
/// - `token_hash` — Contract script hash (20 bytes, little-endian)
/// - `from` — Sender script hash
/// - `to` — Recipient script hash
/// - `amount` — Transfer amount (in token's smallest unit)
pub fn nep17_transfer(
    token_hash: &[u8; 20],
    from: &[u8; 20],
    to: &[u8; 20],
    amount: i64,
) -> Vec<u8> {
    let mut sb = ScriptBuilder::new();
    // Push arguments in reverse order for NeoVM
    sb.emit(opcode::PUSH0); // data (null for simple transfer)
    sb.emit_push_integer(amount);
    sb.emit_push_hash160(to);
    sb.emit_push_hash160(from);
    sb.emit_contract_call(token_hash, "transfer", 4);
    sb.to_bytes()
}

/// Build a NEP-17 `balanceOf` invocation script.
pub fn nep17_balance_of(
    token_hash: &[u8; 20],
    account: &[u8; 20],
) -> Vec<u8> {
    let mut sb = ScriptBuilder::new();
    sb.emit_push_hash160(account);
    sb.emit_contract_call(token_hash, "balanceOf", 1);
    sb.to_bytes()
}

/// Build a NEP-17 `symbol` invocation script.
pub fn nep17_symbol(token_hash: &[u8; 20]) -> Vec<u8> {
    let mut sb = ScriptBuilder::new();
    sb.emit_contract_call(token_hash, "symbol", 0);
    sb.to_bytes()
}

/// Build a NEP-17 `decimals` invocation script.
pub fn nep17_decimals(token_hash: &[u8; 20]) -> Vec<u8> {
    let mut sb = ScriptBuilder::new();
    sb.emit_contract_call(token_hash, "decimals", 0);
    sb.to_bytes()
}

/// Build a NEP-17 `totalSupply` invocation script.
pub fn nep17_total_supply(token_hash: &[u8; 20]) -> Vec<u8> {
    let mut sb = ScriptBuilder::new();
    sb.emit_contract_call(token_hash, "totalSupply", 0);
    sb.to_bytes()
}

// ═══════════════════════════════════════════════════════════════════
// Transaction Builder
// ═══════════════════════════════════════════════════════════════════

/// NEO N3 transaction.
#[derive(Debug, Clone)]
pub struct NeoTransaction {
    /// Transaction version (currently 0).
    pub version: u8,
    /// Nonce for uniqueness.
    pub nonce: u32,
    /// System fee in fractions of GAS.
    pub system_fee: i64,
    /// Network fee in fractions of GAS.
    pub network_fee: i64,
    /// Valid until this block height.
    pub valid_until_block: u32,
    /// Transaction signers.
    pub signers: Vec<TransactionSigner>,
    /// Transaction attributes.
    pub attributes: Vec<TransactionAttribute>,
    /// The invocation script.
    pub script: Vec<u8>,
}

/// A transaction signer.
#[derive(Debug, Clone)]
pub struct TransactionSigner {
    /// Account script hash.
    pub account: [u8; 20],
    /// Witness scope.
    pub scope: WitnessScope,
    /// Allowed contracts (for CustomContracts scope).
    pub allowed_contracts: Vec<[u8; 20]>,
}

/// Witness scope for transaction signers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WitnessScope {
    /// No restrictions.
    None = 0x00,
    /// Only the entry contract.
    CalledByEntry = 0x01,
    /// Custom contracts list.
    CustomContracts = 0x10,
    /// Global scope.
    Global = 0x80,
}

/// Transaction attribute (extensible).
#[derive(Debug, Clone)]
pub struct TransactionAttribute {
    /// Attribute type.
    pub attr_type: u8,
    /// Attribute data.
    pub data: Vec<u8>,
}

impl NeoTransaction {
    /// Create a new transaction with default values.
    #[must_use]
    pub fn new(script: Vec<u8>) -> Self {
        Self {
            version: 0,
            nonce: 0,
            system_fee: 0,
            network_fee: 0,
            valid_until_block: 0,
            signers: vec![],
            attributes: vec![],
            script,
        }
    }

    /// Serialize the transaction for signing (without witnesses).
    #[must_use]
    pub fn serialize_unsigned(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.version);
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        buf.extend_from_slice(&self.system_fee.to_le_bytes());
        buf.extend_from_slice(&self.network_fee.to_le_bytes());
        buf.extend_from_slice(&self.valid_until_block.to_le_bytes());

        // Signers
        write_var_int(&mut buf, self.signers.len() as u64);
        for signer in &self.signers {
            buf.extend_from_slice(&signer.account);
            buf.push(signer.scope as u8);
            if signer.scope == WitnessScope::CustomContracts {
                write_var_int(&mut buf, signer.allowed_contracts.len() as u64);
                for c in &signer.allowed_contracts {
                    buf.extend_from_slice(c);
                }
            }
        }

        // Attributes
        write_var_int(&mut buf, self.attributes.len() as u64);
        for attr in &self.attributes {
            buf.push(attr.attr_type);
            write_var_int(&mut buf, attr.data.len() as u64);
            buf.extend_from_slice(&attr.data);
        }

        // Script
        write_var_int(&mut buf, self.script.len() as u64);
        buf.extend_from_slice(&self.script);

        buf
    }

    /// Compute the transaction hash (SHA-256 of serialized unsigned tx).
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let data = self.serialize_unsigned();
        let mut out = [0u8; 32];
        out.copy_from_slice(&Sha256::digest(data));
        out
    }

    /// Sign the transaction with a NEO signer.
    pub fn sign(
        &self,
        signer: &super::NeoSigner,
    ) -> Result<super::NeoSignature, SignerError> {
        let hash = self.hash();
        signer.sign_digest(&hash)
    }
}

fn write_var_int(buf: &mut Vec<u8>, val: u64) {
    if val < 0xFD {
        buf.push(val as u8);
    } else if val <= 0xFFFF {
        buf.push(0xFD);
        buf.extend_from_slice(&(val as u16).to_le_bytes());
    } else if val <= 0xFFFF_FFFF {
        buf.push(0xFE);
        buf.extend_from_slice(&(val as u32).to_le_bytes());
    } else {
        buf.push(0xFF);
        buf.extend_from_slice(&val.to_le_bytes());
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::traits::KeyPair;

    // ─── Script Builder Tests ──────────────────────────────────────

    #[test]
    fn test_script_builder_push_integer() {
        let mut sb = ScriptBuilder::new();
        sb.emit_push_integer(0);
        assert_eq!(sb.to_bytes(), vec![opcode::PUSH0]);
    }

    #[test]
    fn test_script_builder_push_integer_range() {
        for i in 1..=16 {
            let mut sb = ScriptBuilder::new();
            sb.emit_push_integer(i);
            let bytes = sb.to_bytes();
            assert_eq!(bytes.len(), 1);
            assert_eq!(bytes[0], opcode::PUSH1 + (i as u8 - 1));
        }
    }

    #[test]
    fn test_script_builder_push_bytes() {
        let mut sb = ScriptBuilder::new();
        sb.emit_push_bytes(b"hello");
        let bytes = sb.to_bytes();
        assert_eq!(bytes[0], opcode::PUSHDATA1);
        assert_eq!(bytes[1], 5);
        assert_eq!(&bytes[2..], b"hello");
    }

    #[test]
    fn test_script_builder_syscall() {
        let mut sb = ScriptBuilder::new();
        sb.emit_syscall(0x627d5b52);
        let bytes = sb.to_bytes();
        assert_eq!(bytes[0], opcode::SYSCALL);
        assert_eq!(&bytes[1..5], &0x627d5b52u32.to_le_bytes());
    }

    // ─── NEP-17 Tests ──────────────────────────────────────────────

    #[test]
    fn test_nep17_transfer_script() {
        let from = [0xAA; 20];
        let to = [0xBB; 20];
        let script = nep17_transfer(&contracts::NEO_TOKEN, &from, &to, 10);
        assert!(!script.is_empty());
        // Should contain "transfer" method name
        let s = String::from_utf8_lossy(&script);
        assert!(s.contains("transfer"));
    }

    #[test]
    fn test_nep17_balance_of_script() {
        let account = [0xCC; 20];
        let script = nep17_balance_of(&contracts::GAS_TOKEN, &account);
        assert!(!script.is_empty());
        let s = String::from_utf8_lossy(&script);
        assert!(s.contains("balanceOf"));
    }

    #[test]
    fn test_nep17_symbol() {
        let script = nep17_symbol(&contracts::NEO_TOKEN);
        assert!(!script.is_empty());
        let s = String::from_utf8_lossy(&script);
        assert!(s.contains("symbol"));
    }

    #[test]
    fn test_nep17_decimals() {
        let script = nep17_decimals(&contracts::GAS_TOKEN);
        let s = String::from_utf8_lossy(&script);
        assert!(s.contains("decimals"));
    }

    #[test]
    fn test_nep17_total_supply() {
        let script = nep17_total_supply(&contracts::NEO_TOKEN);
        let s = String::from_utf8_lossy(&script);
        assert!(s.contains("totalSupply"));
    }

    // ─── Transaction Tests ─────────────────────────────────────────

    #[test]
    fn test_neo_transaction_serialization() {
        let script = nep17_transfer(
            &contracts::NEO_TOKEN,
            &[0xAA; 20],
            &[0xBB; 20],
            1,
        );
        let tx = NeoTransaction {
            version: 0,
            nonce: 12345,
            system_fee: 100_000,
            network_fee: 50_000,
            valid_until_block: 1000,
            signers: vec![TransactionSigner {
                account: [0xAA; 20],
                scope: WitnessScope::CalledByEntry,
                allowed_contracts: vec![],
            }],
            attributes: vec![],
            script,
        };
        let serialized = tx.serialize_unsigned();
        assert!(!serialized.is_empty());
        assert_eq!(serialized[0], 0); // version 0
    }

    #[test]
    fn test_neo_transaction_hash_deterministic() {
        let script = nep17_transfer(
            &contracts::GAS_TOKEN,
            &[0xAA; 20],
            &[0xBB; 20],
            100,
        );
        let tx = NeoTransaction::new(script);
        assert_eq!(tx.hash(), tx.hash());
    }

    #[test]
    fn test_neo_transaction_sign() {
        let signer = super::super::NeoSigner::generate().unwrap();
        let script_hash = signer.script_hash();
        let script = nep17_transfer(
            &contracts::NEO_TOKEN,
            &script_hash,
            &[0xBB; 20],
            1,
        );
        let tx = NeoTransaction::new(script);
        let sig = tx.sign(&signer).unwrap();
        assert_eq!(sig.to_bytes().len(), 64);
    }

    #[test]
    fn test_neo_transaction_different_nonce_different_hash() {
        let script = vec![0x00];
        let mut tx1 = NeoTransaction::new(script.clone());
        tx1.nonce = 1;
        let mut tx2 = NeoTransaction::new(script);
        tx2.nonce = 2;
        assert_ne!(tx1.hash(), tx2.hash());
    }
}
