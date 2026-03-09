//! ERC-4337 Account Abstraction — UserOperation builder and helpers.
//!
//! Implements the ERC-4337 UserOperation struct with ABI encoding,
//! `userOpHash` computation, and callData builders for smart account
//! `execute()` / `executeBatch()`.
//!
//! Supports both v0.6 (unpacked) and v0.7 (packed) formats.
//!
//! # Example
//! ```no_run
//! use chains_sdk::ethereum::userop::*;
//!
//! let mut op = UserOperation::new([0xAA; 20]);
//! op.nonce = 1;
//! op.call_data = encode_execute(&[0xBB; 20], 0, &[]);
//! let hash = op.hash(&ENTRY_POINT_V06, 1);
//! ```

use crate::ethereum::abi::{self, AbiValue};
use crate::ethereum::keccak256;

// ═══════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════

/// EntryPoint v0.6 address (ERC-4337).
pub const ENTRY_POINT_V06: [u8; 20] = [
    0x5f, 0xf1, 0x37, 0xd4, 0xb0, 0xfd, 0xcd, 0x49, 0xdc, 0xa3, 0x0c, 0x7c, 0xf5, 0x7e, 0x57, 0x8a,
    0x02, 0x6d, 0x27, 0x89,
];

/// EntryPoint v0.7 address.
pub const ENTRY_POINT_V07: [u8; 20] = [
    0x00, 0x00, 0x00, 0x71, 0x72, 0x7d, 0xe2, 0x2e, 0x5e, 0x94, 0x87, 0xd0, 0x7b, 0x26, 0x00, 0xf6,
    0xbc, 0x22, 0x30, 0xb0,
];

// ═══════════════════════════════════════════════════════════════════
// UserOperation (v0.6)
// ═══════════════════════════════════════════════════════════════════

/// An ERC-4337 UserOperation (v0.6 format).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserOperation {
    /// Smart account address.
    pub sender: [u8; 20],
    /// Anti-replay nonce (key + sequence).
    pub nonce: u64,
    /// Factory + factoryData for account creation (empty if account exists).
    pub init_code: Vec<u8>,
    /// Encoded function call on the smart account.
    pub call_data: Vec<u8>,
    /// Gas limit for the execution phase.
    pub call_gas_limit: u64,
    /// Gas for validation (validateUserOp + validatePaymasterUserOp).
    pub verification_gas_limit: u64,
    /// Gas paid for the bundle tx overhead.
    pub pre_verification_gas: u64,
    /// Maximum fee per gas (EIP-1559).
    pub max_fee_per_gas: u64,
    /// Maximum priority fee per gas.
    pub max_priority_fee_per_gas: u64,
    /// Paymaster address + data (empty if self-paying).
    pub paymaster_and_data: Vec<u8>,
    /// Signature over the UserOp hash.
    pub signature: Vec<u8>,
}

impl UserOperation {
    /// Create a new UserOperation with default gas values.
    #[must_use]
    pub fn new(sender: [u8; 20]) -> Self {
        Self {
            sender,
            nonce: 0,
            init_code: Vec::new(),
            call_data: Vec::new(),
            call_gas_limit: 100_000,
            verification_gas_limit: 100_000,
            pre_verification_gas: 21_000,
            max_fee_per_gas: 1_000_000_000, // 1 gwei
            max_priority_fee_per_gas: 1_000_000_000,
            paymaster_and_data: Vec::new(),
            signature: Vec::new(),
        }
    }

    /// Compute the `userOpHash` for signing.
    ///
    /// `keccak256(abi.encode(pack(userOp), entryPoint, chainId))`
    ///
    /// This is the hash that the account validates in `validateUserOp`.
    #[must_use]
    pub fn hash(&self, entry_point: &[u8; 20], chain_id: u64) -> [u8; 32] {
        // Step 1: Pack the UserOp (hash dynamic fields)
        let packed_hash = self.pack_hash();

        // Step 2: Encode (packedHash, entryPoint, chainId)
        let mut entry_point_padded = [0u8; 32];
        entry_point_padded[12..32].copy_from_slice(entry_point);

        let encoded = abi::encode(&[
            AbiValue::Uint256(packed_hash),
            AbiValue::Uint256(entry_point_padded),
            AbiValue::from_u64(chain_id),
        ]);

        keccak256(&encoded)
    }

    /// Compute the pack hash: hash of the UserOp with dynamic fields hashed.
    fn pack_hash(&self) -> [u8; 32] {
        let mut sender_padded = [0u8; 32];
        sender_padded[12..32].copy_from_slice(&self.sender);

        let values = vec![
            AbiValue::Uint256(sender_padded),
            AbiValue::from_u64(self.nonce),
            AbiValue::Uint256(keccak256(&self.init_code)),
            AbiValue::Uint256(keccak256(&self.call_data)),
            AbiValue::from_u64(self.call_gas_limit),
            AbiValue::from_u64(self.verification_gas_limit),
            AbiValue::from_u64(self.pre_verification_gas),
            AbiValue::from_u64(self.max_fee_per_gas),
            AbiValue::from_u64(self.max_priority_fee_per_gas),
            AbiValue::Uint256(keccak256(&self.paymaster_and_data)),
        ];

        keccak256(&abi::encode(&values))
    }

    /// ABI-encode the full UserOperation for bundler submission.
    ///
    /// Encodes as a tuple matching the Solidity struct layout.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut sender_padded = [0u8; 32];
        sender_padded[12..32].copy_from_slice(&self.sender);

        abi::encode(&[
            AbiValue::Uint256(sender_padded),
            AbiValue::from_u64(self.nonce),
            AbiValue::Bytes(self.init_code.clone()),
            AbiValue::Bytes(self.call_data.clone()),
            AbiValue::from_u64(self.call_gas_limit),
            AbiValue::from_u64(self.verification_gas_limit),
            AbiValue::from_u64(self.pre_verification_gas),
            AbiValue::from_u64(self.max_fee_per_gas),
            AbiValue::from_u64(self.max_priority_fee_per_gas),
            AbiValue::Bytes(self.paymaster_and_data.clone()),
            AbiValue::Bytes(self.signature.clone()),
        ])
    }
}

// ═══════════════════════════════════════════════════════════════════
// PackedUserOperation (v0.7)
// ═══════════════════════════════════════════════════════════════════

/// An ERC-4337 v0.7 PackedUserOperation.
///
/// In v0.7, gas fields are packed into 32-byte combined values:
/// - `accountGasLimits` = `verificationGasLimit (16 bytes) || callGasLimit (16 bytes)`
/// - `gasFees` = `maxPriorityFeePerGas (16 bytes) || maxFeePerGas (16 bytes)`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackedUserOperation {
    /// Smart account address.
    pub sender: [u8; 20],
    /// Anti-replay nonce.
    pub nonce: [u8; 32],
    /// Factory + factoryData for account creation (empty if exists).
    pub init_code: Vec<u8>,
    /// Encoded function call on the smart account.
    pub call_data: Vec<u8>,
    /// `verificationGasLimit (16) || callGasLimit (16)`
    pub account_gas_limits: [u8; 32],
    /// Pre-verification gas.
    pub pre_verification_gas: u64,
    /// `maxPriorityFeePerGas (16) || maxFeePerGas (16)`
    pub gas_fees: [u8; 32],
    /// Paymaster + data.
    pub paymaster_and_data: Vec<u8>,
    /// Signature.
    pub signature: Vec<u8>,
}

/// Pack two u128 gas values into a 32-byte field.
///
/// `result = high (16 bytes BE) || low (16 bytes BE)`
#[must_use]
pub fn pack_gas(high: u128, low: u128) -> [u8; 32] {
    let mut result = [0u8; 32];
    result[..16].copy_from_slice(&high.to_be_bytes());
    result[16..].copy_from_slice(&low.to_be_bytes());
    result
}

/// Pack `verificationGasLimit` and `callGasLimit` into `accountGasLimits`.
#[must_use]
pub fn pack_account_gas_limits(verification_gas: u128, call_gas: u128) -> [u8; 32] {
    pack_gas(verification_gas, call_gas)
}

/// Pack `maxPriorityFeePerGas` and `maxFeePerGas` into `gasFees`.
#[must_use]
pub fn pack_gas_fees(max_priority_fee: u128, max_fee: u128) -> [u8; 32] {
    pack_gas(max_priority_fee, max_fee)
}

// ═══════════════════════════════════════════════════════════════════
// CallData Builders
// ═══════════════════════════════════════════════════════════════════

/// Encode a single `execute(address dest, uint256 value, bytes calldata func)`.
///
/// Standard SimpleAccount execute function.
#[must_use]
pub fn encode_execute(dest: &[u8; 20], value: u64, func: &[u8]) -> Vec<u8> {
    let execute = abi::Function::new("execute(address,uint256,bytes)");
    execute.encode(&[
        AbiValue::Address(*dest),
        AbiValue::from_u64(value),
        AbiValue::Bytes(func.to_vec()),
    ])
}

/// Encode `executeBatch(address[] dest, uint256[] values, bytes[] func)`.
///
/// Batch execution for multiple calls in a single UserOp.
#[must_use]
pub fn encode_execute_batch(targets: &[[u8; 20]], values: &[u64], data: &[Vec<u8>]) -> Vec<u8> {
    let batch = abi::Function::new("executeBatch(address[],uint256[],bytes[])");

    let targets_abi: Vec<AbiValue> = targets.iter().map(|t| AbiValue::Address(*t)).collect();
    let values_abi: Vec<AbiValue> = values.iter().map(|v| AbiValue::from_u64(*v)).collect();
    let data_abi: Vec<AbiValue> = data.iter().map(|d| AbiValue::Bytes(d.clone())).collect();

    batch.encode(&[
        AbiValue::Array(targets_abi),
        AbiValue::Array(values_abi),
        AbiValue::Array(data_abi),
    ])
}

/// Encode an ERC-20 `approve(address spender, uint256 amount)` call.
#[must_use]
pub fn encode_erc20_approve(spender: &[u8; 20], amount: u64) -> Vec<u8> {
    let approve = abi::Function::new("approve(address,uint256)");
    approve.encode(&[AbiValue::Address(*spender), AbiValue::from_u64(amount)])
}

/// Encode an ERC-20 `transfer(address to, uint256 amount)` call.
#[must_use]
pub fn encode_erc20_transfer(to: &[u8; 20], amount: u64) -> Vec<u8> {
    let transfer = abi::Function::new("transfer(address,uint256)");
    transfer.encode(&[AbiValue::Address(*to), AbiValue::from_u64(amount)])
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const SENDER: [u8; 20] = [0xAA; 20];
    const DEST: [u8; 20] = [0xBB; 20];

    // ─── UserOperation Creation ─────────────────────────────────

    #[test]
    fn test_new_user_op_defaults() {
        let op = UserOperation::new(SENDER);
        assert_eq!(op.sender, SENDER);
        assert_eq!(op.nonce, 0);
        assert!(op.init_code.is_empty());
        assert!(op.call_data.is_empty());
        assert!(op.paymaster_and_data.is_empty());
        assert!(op.signature.is_empty());
    }

    #[test]
    fn test_user_op_gas_defaults() {
        let op = UserOperation::new(SENDER);
        assert_eq!(op.call_gas_limit, 100_000);
        assert_eq!(op.verification_gas_limit, 100_000);
        assert_eq!(op.pre_verification_gas, 21_000);
    }

    // ─── UserOp Hash ────────────────────────────────────────────

    #[test]
    fn test_user_op_hash_deterministic() {
        let op = UserOperation::new(SENDER);
        let h1 = op.hash(&ENTRY_POINT_V06, 1);
        let h2 = op.hash(&ENTRY_POINT_V06, 1);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_user_op_hash_different_chain_ids() {
        let op = UserOperation::new(SENDER);
        let h1 = op.hash(&ENTRY_POINT_V06, 1);
        let h2 = op.hash(&ENTRY_POINT_V06, 137);
        assert_ne!(h1, h2, "different chains should produce different hashes");
    }

    #[test]
    fn test_user_op_hash_different_entry_points() {
        let op = UserOperation::new(SENDER);
        let h1 = op.hash(&ENTRY_POINT_V06, 1);
        let h2 = op.hash(&ENTRY_POINT_V07, 1);
        assert_ne!(
            h1, h2,
            "different entry points should produce different hashes"
        );
    }

    #[test]
    fn test_user_op_hash_different_nonces() {
        let mut op1 = UserOperation::new(SENDER);
        let mut op2 = UserOperation::new(SENDER);
        op1.nonce = 0;
        op2.nonce = 1;
        assert_ne!(op1.hash(&ENTRY_POINT_V06, 1), op2.hash(&ENTRY_POINT_V06, 1),);
    }

    #[test]
    fn test_user_op_hash_different_call_data() {
        let mut op1 = UserOperation::new(SENDER);
        let mut op2 = UserOperation::new(SENDER);
        op1.call_data = vec![0x01];
        op2.call_data = vec![0x02];
        assert_ne!(op1.hash(&ENTRY_POINT_V06, 1), op2.hash(&ENTRY_POINT_V06, 1),);
    }

    #[test]
    fn test_user_op_hash_is_32_bytes() {
        let op = UserOperation::new(SENDER);
        assert_eq!(op.hash(&ENTRY_POINT_V06, 1).len(), 32);
    }

    // ─── UserOp Encoding ────────────────────────────────────────

    #[test]
    fn test_user_op_encode_not_empty() {
        let op = UserOperation::new(SENDER);
        let encoded = op.encode();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_user_op_encode_deterministic() {
        let op = UserOperation::new(SENDER);
        assert_eq!(op.encode(), op.encode());
    }

    #[test]
    fn test_user_op_encode_changes_with_data() {
        let mut op1 = UserOperation::new(SENDER);
        let mut op2 = UserOperation::new(SENDER);
        op2.call_data = vec![0xDE, 0xAD];
        assert_ne!(op1.encode(), op2.encode());
        // Ignore the unused assignment — op1 is used in the assert above
        op1.nonce = 99;
        assert_ne!(op1.encode(), op2.encode());
    }

    // ─── Execute Encoding ───────────────────────────────────────

    #[test]
    fn test_encode_execute_selector() {
        let data = encode_execute(&DEST, 0, &[]);
        // execute(address,uint256,bytes) selector
        let expected = abi::function_selector("execute(address,uint256,bytes)");
        assert_eq!(&data[..4], &expected);
    }

    #[test]
    fn test_encode_execute_not_empty() {
        let data = encode_execute(&DEST, 1_000_000, &[0xAB, 0xCD]);
        assert!(data.len() > 4); // selector + encoded params
    }

    #[test]
    fn test_encode_execute_deterministic() {
        let d1 = encode_execute(&DEST, 0, &[]);
        let d2 = encode_execute(&DEST, 0, &[]);
        assert_eq!(d1, d2);
    }

    // ─── ExecuteBatch Encoding ──────────────────────────────────

    #[test]
    fn test_encode_execute_batch_selector() {
        let data = encode_execute_batch(&[DEST], &[0], &[vec![]]);
        let expected = abi::function_selector("executeBatch(address[],uint256[],bytes[])");
        assert_eq!(&data[..4], &expected);
    }

    #[test]
    fn test_encode_execute_batch_multiple_targets() {
        let targets = [DEST, [0xCC; 20]];
        let values = [100, 200];
        let datas = [vec![0x01], vec![0x02]];
        let data = encode_execute_batch(&targets, &values, &datas);
        assert!(data.len() > 100);
    }

    // ─── ERC-20 Helpers ─────────────────────────────────────────

    #[test]
    fn test_encode_erc20_approve_selector() {
        let data = encode_erc20_approve(&DEST, 1000);
        let expected = abi::function_selector("approve(address,uint256)");
        assert_eq!(&data[..4], &expected);
    }

    #[test]
    fn test_encode_erc20_transfer_selector() {
        let data = encode_erc20_transfer(&DEST, 500);
        let expected = abi::function_selector("transfer(address,uint256)");
        assert_eq!(&data[..4], &expected);
    }

    // ─── Gas Packing ────────────────────────────────────────────

    #[test]
    fn test_pack_gas_basic() {
        let packed = pack_gas(100, 200);
        let high = u128::from_be_bytes(packed[..16].try_into().unwrap());
        let low = u128::from_be_bytes(packed[16..].try_into().unwrap());
        assert_eq!(high, 100);
        assert_eq!(low, 200);
    }

    #[test]
    fn test_pack_gas_zero() {
        let packed = pack_gas(0, 0);
        assert_eq!(packed, [0u8; 32]);
    }

    #[test]
    fn test_pack_account_gas_limits() {
        let packed = pack_account_gas_limits(100_000, 200_000);
        let high = u128::from_be_bytes(packed[..16].try_into().unwrap());
        let low = u128::from_be_bytes(packed[16..].try_into().unwrap());
        assert_eq!(high, 100_000);
        assert_eq!(low, 200_000);
    }

    #[test]
    fn test_pack_gas_fees() {
        let packed = pack_gas_fees(1_000_000_000, 30_000_000_000);
        let priority = u128::from_be_bytes(packed[..16].try_into().unwrap());
        let max_fee = u128::from_be_bytes(packed[16..].try_into().unwrap());
        assert_eq!(priority, 1_000_000_000);
        assert_eq!(max_fee, 30_000_000_000);
    }

    // ─── Entry Points ───────────────────────────────────────────

    #[test]
    fn test_entry_point_addresses_different() {
        assert_ne!(ENTRY_POINT_V06, ENTRY_POINT_V07);
    }

    #[test]
    fn test_entry_point_v06_length() {
        assert_eq!(ENTRY_POINT_V06.len(), 20);
    }

    #[test]
    fn test_entry_point_v07_length() {
        assert_eq!(ENTRY_POINT_V07.len(), 20);
    }

    // ─── End-to-End ─────────────────────────────────────────────

    #[test]
    fn test_e2e_user_op_with_execute() {
        let mut op = UserOperation::new(SENDER);
        op.nonce = 1;
        op.call_data = encode_execute(&DEST, 1_000_000, &[]);
        op.call_gas_limit = 200_000;
        let hash = op.hash(&ENTRY_POINT_V06, 1);
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_e2e_user_op_with_batch() {
        let mut op = UserOperation::new(SENDER);
        op.call_data = encode_execute_batch(
            &[DEST, [0xCC; 20]],
            &[100, 200],
            &[encode_erc20_transfer(&[0xDD; 20], 500), vec![]],
        );
        let hash = op.hash(&ENTRY_POINT_V06, 1);
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_e2e_user_op_with_paymaster() {
        let mut op = UserOperation::new(SENDER);
        op.paymaster_and_data = vec![0xFF; 52]; // paymaster (20) + data (32)
        let h1 = op.hash(&ENTRY_POINT_V06, 1);

        let op2 = UserOperation::new(SENDER);
        let h2 = op2.hash(&ENTRY_POINT_V06, 1);
        assert_ne!(h1, h2, "paymaster should affect hash");
    }
}
