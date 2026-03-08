//! Solana transaction building, signing, and program interaction helpers.
//!
//! Implements the Solana transaction wire format including:
//! - Compact-u16 encoding
//! - Instructions and message serialization (legacy + v0 versioned)
//! - System Program helpers (transfer, create_account, allocate)
//! - SPL Token helpers (transfer, approve, mint_to)
//! - Compute Budget (priority fees)
//! - Address Lookup Table references (versioned transactions)
//!
//! # Example
//! ```no_run
//! use trad_signer::solana::transaction::*;
//! use trad_signer::solana::SolanaSigner;
//! use trad_signer::traits::KeyPair;
//!
//! fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     let signer = SolanaSigner::generate()?;
//!     let to = [0xBB; 32];
//!     let ix = system_program::transfer(&signer.public_key_bytes_32(), &to, 1_000_000);
//!     let msg = Message::new(&[ix], signer.public_key_bytes_32());
//!     let tx = Transaction::sign(&msg, &[&signer], [0u8; 32])?;
//!     let raw = tx.serialize();
//!     Ok(())
//! }
//! ```

use crate::error::SignerError;
use super::SolanaSigner;
use ed25519_dalek::Signer as DalekSigner;

// ─── Compact-u16 Encoding ──────────────────────────────────────────

/// Encode a `u16` as a Solana compact-u16 (variable-length encoding).
///
/// Used throughout Solana wire format for lengths.
#[must_use]
pub fn encode_compact_u16(val: u16) -> Vec<u8> {
    if val < 0x80 {
        vec![val as u8]
    } else if val < 0x4000 {
        vec![(val & 0x7F | 0x80) as u8, (val >> 7) as u8]
    } else {
        vec![(val & 0x7F | 0x80) as u8, ((val >> 7) & 0x7F | 0x80) as u8, (val >> 14) as u8]
    }
}

/// Decode a compact-u16 from bytes. Returns (value, bytes_consumed).
pub fn decode_compact_u16(data: &[u8]) -> Result<(u16, usize), SignerError> {
    if data.is_empty() {
        return Err(SignerError::ParseError("compact-u16: empty".into()));
    }
    let b0 = data[0] as u16;
    if b0 < 0x80 {
        return Ok((b0, 1));
    }
    if data.len() < 2 {
        return Err(SignerError::ParseError("compact-u16: truncated".into()));
    }
    let b1 = data[1] as u16;
    if b1 < 0x80 {
        return Ok(((b0 & 0x7F) | (b1 << 7), 2));
    }
    if data.len() < 3 {
        return Err(SignerError::ParseError("compact-u16: truncated".into()));
    }
    let b2 = data[2] as u16;
    Ok(((b0 & 0x7F) | ((b1 & 0x7F) << 7) | (b2 << 14), 3))
}

// ─── Account Meta ──────────────────────────────────────────────────

/// An account reference in a Solana instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountMeta {
    /// 32-byte public key.
    pub pubkey: [u8; 32],
    /// Whether this account is a signer.
    pub is_signer: bool,
    /// Whether this account is writable.
    pub is_writable: bool,
}

impl AccountMeta {
    /// Create a writable signer account.
    #[must_use]
    pub fn new(pubkey: [u8; 32], is_signer: bool) -> Self {
        Self { pubkey, is_signer, is_writable: true }
    }

    /// Create a read-only account.
    #[must_use]
    pub fn new_readonly(pubkey: [u8; 32], is_signer: bool) -> Self {
        Self { pubkey, is_signer, is_writable: false }
    }
}

// ─── Instruction ───────────────────────────────────────────────────

/// A Solana instruction.
#[derive(Debug, Clone)]
pub struct Instruction {
    /// Program ID (32 bytes).
    pub program_id: [u8; 32],
    /// Account references.
    pub accounts: Vec<AccountMeta>,
    /// Instruction data.
    pub data: Vec<u8>,
}

// ─── Message ───────────────────────────────────────────────────────

/// A Solana transaction message (legacy format).
#[derive(Debug, Clone)]
pub struct Message {
    /// Number of required signatures.
    pub num_required_signatures: u8,
    /// Number of read-only signed accounts.
    pub num_readonly_signed_accounts: u8,
    /// Number of read-only unsigned accounts.
    pub num_readonly_unsigned_accounts: u8,
    /// All account keys referenced by the message.
    pub account_keys: Vec<[u8; 32]>,
    /// Recent blockhash (32 bytes).
    pub recent_blockhash: [u8; 32],
    /// Compiled instructions.
    pub instructions: Vec<CompiledInstruction>,
}

/// A compiled instruction (indices into account_keys array).
#[derive(Debug, Clone)]
pub struct CompiledInstruction {
    /// Index of the program ID in account_keys.
    pub program_id_index: u8,
    /// Indices of accounts in account_keys.
    pub accounts: Vec<u8>,
    /// Instruction data.
    pub data: Vec<u8>,
}

impl Message {
    /// Build a message from instructions and a fee payer.
    ///
    /// Deduplicates accounts and sorts them per Solana's rules:
    /// 1. Writable signers (fee payer first)
    /// 2. Read-only signers
    /// 3. Writable non-signers
    /// 4. Read-only non-signers
    #[must_use]
    pub fn new(instructions: &[Instruction], fee_payer: [u8; 32]) -> Self {
        let mut writable_signers: Vec<[u8; 32]> = vec![fee_payer];
        let mut readonly_signers: Vec<[u8; 32]> = Vec::new();
        let mut writable_nonsigners: Vec<[u8; 32]> = Vec::new();
        let mut readonly_nonsigners: Vec<[u8; 32]> = Vec::new();

        for ix in instructions {
            for acc in &ix.accounts {
                // Skip if already fee payer
                if acc.pubkey == fee_payer { continue; }
                match (acc.is_signer, acc.is_writable) {
                    (true, true) => { if !writable_signers.contains(&acc.pubkey) { writable_signers.push(acc.pubkey); } }
                    (true, false) => { if !readonly_signers.contains(&acc.pubkey) { readonly_signers.push(acc.pubkey); } }
                    (false, true) => { if !writable_nonsigners.contains(&acc.pubkey) { writable_nonsigners.push(acc.pubkey); } }
                    (false, false) => { if !readonly_nonsigners.contains(&acc.pubkey) { readonly_nonsigners.push(acc.pubkey); } }
                }
            }
            // Add program IDs as read-only non-signers
            if !writable_signers.contains(&ix.program_id)
                && !readonly_signers.contains(&ix.program_id)
                && !writable_nonsigners.contains(&ix.program_id)
                && !readonly_nonsigners.contains(&ix.program_id) {
                readonly_nonsigners.push(ix.program_id);
            }
        }

        let num_required_signatures = (writable_signers.len() + readonly_signers.len()) as u8;
        let num_readonly_signed = readonly_signers.len() as u8;
        let num_readonly_unsigned = readonly_nonsigners.len() as u8;

        let mut account_keys = Vec::new();
        account_keys.extend_from_slice(&writable_signers);
        account_keys.extend_from_slice(&readonly_signers);
        account_keys.extend_from_slice(&writable_nonsigners);
        account_keys.extend_from_slice(&readonly_nonsigners);

        // Compile instructions
        let compiled = instructions.iter().map(|ix| {
            let program_id_index = account_keys.iter().position(|k| *k == ix.program_id).unwrap_or(0) as u8;
            let accounts: Vec<u8> = ix.accounts.iter().map(|a| {
                account_keys.iter().position(|k| *k == a.pubkey).unwrap_or(0) as u8
            }).collect();
            CompiledInstruction {
                program_id_index,
                accounts,
                data: ix.data.clone(),
            }
        }).collect();

        Self {
            num_required_signatures,
            num_readonly_signed_accounts: num_readonly_signed,
            num_readonly_unsigned_accounts: num_readonly_unsigned,
            account_keys,
            recent_blockhash: [0u8; 32], // set later
            instructions: compiled,
        }
    }

    /// Serialize the message to bytes for signing.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.num_required_signatures);
        buf.push(self.num_readonly_signed_accounts);
        buf.push(self.num_readonly_unsigned_accounts);

        buf.extend_from_slice(&encode_compact_u16(self.account_keys.len() as u16));
        for key in &self.account_keys {
            buf.extend_from_slice(key);
        }

        buf.extend_from_slice(&self.recent_blockhash);

        buf.extend_from_slice(&encode_compact_u16(self.instructions.len() as u16));
        for ix in &self.instructions {
            buf.push(ix.program_id_index);
            buf.extend_from_slice(&encode_compact_u16(ix.accounts.len() as u16));
            buf.extend_from_slice(&ix.accounts);
            buf.extend_from_slice(&encode_compact_u16(ix.data.len() as u16));
            buf.extend_from_slice(&ix.data);
        }
        buf
    }
}

// ─── Transaction ───────────────────────────────────────────────────

/// A signed Solana transaction.
#[derive(Debug, Clone)]
pub struct Transaction {
    /// Ed25519 signatures (64 bytes each).
    pub signatures: Vec<[u8; 64]>,
    /// The message that was signed.
    pub message: Message,
}

impl Transaction {
    /// Sign a message with one or more signers.
    pub fn sign(
        message: &Message,
        signers: &[&SolanaSigner],
        recent_blockhash: [u8; 32],
    ) -> Result<Self, SignerError> {
        let mut msg = message.clone();
        msg.recent_blockhash = recent_blockhash;
        let serialized = msg.serialize();

        let mut signatures = Vec::new();
        for signer in signers {
            let sig = signer.signing_key.sign(&serialized);
            signatures.push(sig.to_bytes());
        }

        Ok(Self { signatures, message: msg })
    }

    /// Serialize the transaction for sending via `sendTransaction` RPC.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&encode_compact_u16(self.signatures.len() as u16));
        for sig in &self.signatures {
            buf.extend_from_slice(sig);
        }
        buf.extend_from_slice(&self.message.serialize());
        buf
    }
}

// ═══════════════════════════════════════════════════════════════════
// System Program
// ═══════════════════════════════════════════════════════════════════

/// Solana System Program helpers.
pub mod system_program {
    use super::*;

    /// System Program ID: `11111111111111111111111111111111`
    pub const ID: [u8; 32] = [0; 32];

    /// Create a SOL transfer instruction.
    ///
    /// # Arguments
    /// - `from` — Sender pubkey (must be signer)
    /// - `to` — Recipient pubkey
    /// - `lamports` — Amount in lamports (1 SOL = 1_000_000_000 lamports)
    #[must_use]
    pub fn transfer(from: &[u8; 32], to: &[u8; 32], lamports: u64) -> Instruction {
        let mut data = vec![2, 0, 0, 0]; // Transfer instruction index
        data.extend_from_slice(&lamports.to_le_bytes());
        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new(*from, true),
                AccountMeta::new(*to, false),
            ],
            data,
        }
    }

    /// Create a `CreateAccount` instruction.
    #[must_use]
    pub fn create_account(
        from: &[u8; 32],
        new_account: &[u8; 32],
        lamports: u64,
        space: u64,
        owner: &[u8; 32],
    ) -> Instruction {
        let mut data = vec![0, 0, 0, 0]; // CreateAccount instruction index
        data.extend_from_slice(&lamports.to_le_bytes());
        data.extend_from_slice(&space.to_le_bytes());
        data.extend_from_slice(owner);
        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new(*from, true),
                AccountMeta::new(*new_account, true),
            ],
            data,
        }
    }

    /// Create an `Allocate` instruction.
    #[must_use]
    pub fn allocate(account: &[u8; 32], space: u64) -> Instruction {
        let mut data = vec![8, 0, 0, 0]; // Allocate instruction index
        data.extend_from_slice(&space.to_le_bytes());
        Instruction {
            program_id: ID,
            accounts: vec![AccountMeta::new(*account, true)],
            data,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// SPL Token Program
// ═══════════════════════════════════════════════════════════════════

/// SPL Token Program helpers.
pub mod spl_token {
    use super::*;

    /// SPL Token Program ID: `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`
    pub const ID: [u8; 32] = [
        0x06, 0xDD, 0xF6, 0xE1, 0xD7, 0x65, 0xA1, 0x93,
        0xD9, 0xCB, 0xE1, 0x46, 0xCE, 0xEB, 0x79, 0xAC,
        0x1C, 0xB4, 0x85, 0xED, 0x5F, 0x5B, 0x37, 0x91,
        0x3A, 0x8C, 0xF5, 0x85, 0x7E, 0xFF, 0x00, 0xA9,
    ];

    /// Create an SPL Token `Transfer` instruction.
    ///
    /// # Arguments
    /// - `source` — Source token account
    /// - `destination` — Destination token account
    /// - `authority` — Owner of the source account (signer)
    /// - `amount` — Token amount (in smallest unit)
    #[must_use]
    pub fn transfer(
        source: &[u8; 32],
        destination: &[u8; 32],
        authority: &[u8; 32],
        amount: u64,
    ) -> Instruction {
        let mut data = vec![3]; // Transfer instruction discriminator
        data.extend_from_slice(&amount.to_le_bytes());
        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new(*source, false),
                AccountMeta::new(*destination, false),
                AccountMeta::new_readonly(*authority, true),
            ],
            data,
        }
    }

    /// Create an SPL Token `Approve` instruction.
    #[must_use]
    pub fn approve(
        source: &[u8; 32],
        delegate: &[u8; 32],
        authority: &[u8; 32],
        amount: u64,
    ) -> Instruction {
        let mut data = vec![4]; // Approve instruction discriminator
        data.extend_from_slice(&amount.to_le_bytes());
        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new(*source, false),
                AccountMeta::new_readonly(*delegate, false),
                AccountMeta::new_readonly(*authority, true),
            ],
            data,
        }
    }

    /// Create an SPL Token `MintTo` instruction.
    #[must_use]
    pub fn mint_to(
        mint: &[u8; 32],
        destination: &[u8; 32],
        authority: &[u8; 32],
        amount: u64,
    ) -> Instruction {
        let mut data = vec![7]; // MintTo instruction discriminator
        data.extend_from_slice(&amount.to_le_bytes());
        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new(*mint, false),
                AccountMeta::new(*destination, false),
                AccountMeta::new_readonly(*authority, true),
            ],
            data,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Compute Budget (Priority Fees)
// ═══════════════════════════════════════════════════════════════════

/// Compute Budget program helpers for priority fees.
pub mod compute_budget {
    use super::*;

    /// Compute Budget Program ID.
    pub const ID: [u8; 32] = [
        0x03, 0x06, 0x46, 0x6F, 0xE5, 0x21, 0x17, 0x32,
        0xFF, 0xEC, 0xAD, 0xBA, 0x72, 0xC3, 0x9B, 0xE7,
        0xBC, 0x8C, 0xE5, 0xBB, 0xC5, 0xF7, 0x12, 0x6B,
        0x2C, 0x43, 0x9B, 0x3A, 0x40, 0x00, 0x00, 0x00,
    ];

    /// Set the compute unit limit.
    #[must_use]
    pub fn set_compute_unit_limit(units: u32) -> Instruction {
        let mut data = vec![2]; // SetComputeUnitLimit
        data.extend_from_slice(&units.to_le_bytes());
        Instruction {
            program_id: ID,
            accounts: vec![],
            data,
        }
    }

    /// Set the compute unit price (priority fee in micro-lamports).
    #[must_use]
    pub fn set_compute_unit_price(micro_lamports: u64) -> Instruction {
        let mut data = vec![3]; // SetComputeUnitPrice
        data.extend_from_slice(&micro_lamports.to_le_bytes());
        Instruction {
            program_id: ID,
            accounts: vec![],
            data,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Versioned Transactions (v0)
// ═══════════════════════════════════════════════════════════════════

/// Address lookup table reference for versioned transactions.
#[derive(Debug, Clone)]
pub struct AddressLookupTable {
    /// Account key of the lookup table.
    pub account_key: [u8; 32],
    /// Indices of writable accounts in the table.
    pub writable_indexes: Vec<u8>,
    /// Indices of read-only accounts in the table.
    pub readonly_indexes: Vec<u8>,
}

/// A versioned transaction message (v0).
#[derive(Debug, Clone)]
pub struct MessageV0 {
    /// The legacy message portion.
    pub message: Message,
    /// Address lookup table references.
    pub address_table_lookups: Vec<AddressLookupTable>,
}

impl MessageV0 {
    /// Serialize a v0 message.
    ///
    /// Format: `0x80 || legacy_message_bytes || address_table_lookups`
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(0x80); // Version prefix (v0 = 0x80)
        buf.extend_from_slice(&self.message.serialize());

        // Serialize address table lookups
        buf.extend_from_slice(&encode_compact_u16(self.address_table_lookups.len() as u16));
        for table in &self.address_table_lookups {
            buf.extend_from_slice(&table.account_key);
            buf.extend_from_slice(&encode_compact_u16(table.writable_indexes.len() as u16));
            buf.extend_from_slice(&table.writable_indexes);
            buf.extend_from_slice(&encode_compact_u16(table.readonly_indexes.len() as u16));
            buf.extend_from_slice(&table.readonly_indexes);
        }
        buf
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

    // ─── Compact-u16 Tests (Solana specification vectors) ──────────

    #[test]
    fn test_compact_u16_zero() {
        assert_eq!(encode_compact_u16(0), vec![0]);
        assert_eq!(decode_compact_u16(&[0]).unwrap(), (0, 1));
    }

    #[test]
    fn test_compact_u16_small() {
        assert_eq!(encode_compact_u16(5), vec![5]);
        assert_eq!(decode_compact_u16(&[5]).unwrap(), (5, 1));
    }

    #[test]
    fn test_compact_u16_127_boundary() {
        assert_eq!(encode_compact_u16(0x7F), vec![0x7F]);
        assert_eq!(decode_compact_u16(&[0x7F]).unwrap(), (0x7F, 1));
    }

    #[test]
    fn test_compact_u16_128() {
        let encoded = encode_compact_u16(0x80);
        assert_eq!(encoded.len(), 2);
        assert_eq!(decode_compact_u16(&encoded).unwrap(), (0x80, 2));
    }

    #[test]
    fn test_compact_u16_16383() {
        // Maximum 2-byte value
        let encoded = encode_compact_u16(0x3FFF);
        assert_eq!(encoded.len(), 2);
        assert_eq!(decode_compact_u16(&encoded).unwrap(), (0x3FFF, 2));
    }

    #[test]
    fn test_compact_u16_16384() {
        // First 3-byte value
        let encoded = encode_compact_u16(0x4000);
        assert_eq!(encoded.len(), 3);
        assert_eq!(decode_compact_u16(&encoded).unwrap(), (0x4000, 3));
    }

    #[test]
    fn test_compact_u16_roundtrip_all_boundaries() {
        for val in [0u16, 1, 127, 128, 255, 256, 16383, 16384, 32767, 65535] {
            let encoded = encode_compact_u16(val);
            let (decoded, _) = decode_compact_u16(&encoded).unwrap();
            assert_eq!(decoded, val, "roundtrip failed for {val}");
        }
    }

    // ─── System Program Tests ──────────────────────────────────────

    #[test]
    fn test_system_transfer_instruction() {
        let from = [0xAA; 32];
        let to = [0xBB; 32];
        let ix = system_program::transfer(&from, &to, 1_000_000_000);
        assert_eq!(ix.program_id, system_program::ID);
        assert_eq!(ix.accounts.len(), 2);
        assert_eq!(ix.accounts[0].pubkey, from);
        assert!(ix.accounts[0].is_signer);
        assert!(!ix.accounts[1].is_signer);
        // Data: 4 bytes instruction index + 8 bytes lamports
        assert_eq!(ix.data.len(), 12);
        assert_eq!(&ix.data[..4], &[2, 0, 0, 0]);
        let lamports = u64::from_le_bytes(ix.data[4..12].try_into().unwrap());
        assert_eq!(lamports, 1_000_000_000);
    }

    #[test]
    fn test_system_create_account() {
        let from = [0xAA; 32];
        let new = [0xBB; 32];
        let owner = [0xCC; 32];
        let ix = system_program::create_account(&from, &new, 1_000_000, 165, &owner);
        assert_eq!(ix.program_id, system_program::ID);
        assert_eq!(ix.accounts.len(), 2);
        // Data: 4 index + 8 lamports + 8 space + 32 owner = 52
        assert_eq!(ix.data.len(), 52);
    }

    #[test]
    fn test_system_allocate() {
        let account = [0xAA; 32];
        let ix = system_program::allocate(&account, 1024);
        assert_eq!(ix.data.len(), 12);
    }

    // ─── SPL Token Tests ───────────────────────────────────────────

    #[test]
    fn test_spl_token_transfer() {
        let src = [0x11; 32];
        let dst = [0x22; 32];
        let auth = [0x33; 32];
        let ix = spl_token::transfer(&src, &dst, &auth, 1_000_000);
        assert_eq!(ix.program_id, spl_token::ID);
        assert_eq!(ix.accounts.len(), 3);
        assert!(!ix.accounts[0].is_signer); // source
        assert!(!ix.accounts[1].is_signer); // destination
        assert!(ix.accounts[2].is_signer);  // authority
        assert_eq!(ix.data[0], 3); // Transfer discriminator
        assert_eq!(ix.data.len(), 9);
    }

    #[test]
    fn test_spl_token_approve() {
        let src = [0x11; 32];
        let delegate = [0x22; 32];
        let auth = [0x33; 32];
        let ix = spl_token::approve(&src, &delegate, &auth, 500_000);
        assert_eq!(ix.data[0], 4); // Approve discriminator
    }

    #[test]
    fn test_spl_token_mint_to() {
        let mint = [0x11; 32];
        let dst = [0x22; 32];
        let auth = [0x33; 32];
        let ix = spl_token::mint_to(&mint, &dst, &auth, 1_000);
        assert_eq!(ix.data[0], 7); // MintTo discriminator
    }

    // ─── Compute Budget Tests ──────────────────────────────────────

    #[test]
    fn test_compute_unit_limit() {
        let ix = compute_budget::set_compute_unit_limit(200_000);
        assert_eq!(ix.data[0], 2);
        let units = u32::from_le_bytes(ix.data[1..5].try_into().unwrap());
        assert_eq!(units, 200_000);
        assert!(ix.accounts.is_empty());
    }

    #[test]
    fn test_compute_unit_price() {
        let ix = compute_budget::set_compute_unit_price(50_000);
        assert_eq!(ix.data[0], 3);
        let price = u64::from_le_bytes(ix.data[1..9].try_into().unwrap());
        assert_eq!(price, 50_000);
    }

    // ─── Message Building Tests ────────────────────────────────────

    #[test]
    fn test_message_building() {
        let payer = [0xAA; 32];
        let to = [0xBB; 32];
        let ix = system_program::transfer(&payer, &to, 100);
        let msg = Message::new(&[ix], payer);

        assert_eq!(msg.num_required_signatures, 1);
        assert_eq!(msg.num_readonly_signed_accounts, 0);
        // system program = readonly unsigned
        assert_eq!(msg.num_readonly_unsigned_accounts, 1);
        // payer, to, system_program
        assert_eq!(msg.account_keys.len(), 3);
        assert_eq!(msg.account_keys[0], payer); // fee payer first
    }

    #[test]
    fn test_message_serialization() {
        let payer = [0xAA; 32];
        let to = [0xBB; 32];
        let ix = system_program::transfer(&payer, &to, 100);
        let msg = Message::new(&[ix], payer);
        let bytes = msg.serialize();
        assert!(!bytes.is_empty());
        // Header: 3 bytes
        assert_eq!(bytes[0], 1); // num_required_signatures
        assert_eq!(bytes[1], 0); // num_readonly_signed
        assert_eq!(bytes[2], 1); // num_readonly_unsigned (system program)
    }

    // ─── Transaction Tests ─────────────────────────────────────────

    #[test]
    fn test_transaction_sign_and_serialize() {
        let signer = SolanaSigner::generate().unwrap();
        let payer = signer.public_key_bytes_32();
        let to = [0xBB; 32];
        let ix = system_program::transfer(&payer, &to, 1_000_000);
        let msg = Message::new(&[ix], payer);
        let blockhash = [0xCC; 32];

        let tx = Transaction::sign(&msg, &[&signer], blockhash).unwrap();
        assert_eq!(tx.signatures.len(), 1);
        assert_eq!(tx.signatures[0].len(), 64);

        let raw = tx.serialize();
        assert!(!raw.is_empty());
        // First byte should be compact-u16(1) = 0x01
        assert_eq!(raw[0], 1);
    }

    #[test]
    fn test_transaction_deterministic() {
        let signer = SolanaSigner::from_bytes(&[0x42; 32]).unwrap();
        let payer = signer.public_key_bytes_32();
        let ix = system_program::transfer(&payer, &[0xBB; 32], 100);
        let msg = Message::new(&[ix], payer);

        let tx1 = Transaction::sign(&msg, &[&signer], [0; 32]).unwrap();
        let tx2 = Transaction::sign(&msg, &[&signer], [0; 32]).unwrap();
        assert_eq!(tx1.serialize(), tx2.serialize());
    }

    // ─── Versioned Transaction Tests ───────────────────────────────

    #[test]
    fn test_v0_message_has_version_prefix() {
        let payer = [0xAA; 32];
        let ix = system_program::transfer(&payer, &[0xBB; 32], 100);
        let msg = Message::new(&[ix], payer);
        let v0 = MessageV0 {
            message: msg,
            address_table_lookups: vec![],
        };
        let bytes = v0.serialize();
        assert_eq!(bytes[0], 0x80, "v0 messages start with 0x80");
    }

    #[test]
    fn test_v0_with_lookup_table() {
        let payer = [0xAA; 32];
        let ix = system_program::transfer(&payer, &[0xBB; 32], 100);
        let msg = Message::new(&[ix], payer);
        let v0 = MessageV0 {
            message: msg,
            address_table_lookups: vec![AddressLookupTable {
                account_key: [0xDD; 32],
                writable_indexes: vec![0, 1],
                readonly_indexes: vec![2],
            }],
        };
        let bytes = v0.serialize();
        assert_eq!(bytes[0], 0x80);
        assert!(bytes.len() > 100); // includes lookup table data
    }
}
