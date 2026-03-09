//! Jupiter DCA (Dollar-Cost Averaging) instruction builders.
//!
//! Provides instruction encoding for Jupiter's DCA program on Solana,
//! enabling automated periodic token purchases at market prices.
//!
//! Supports:
//! - DCA account creation with configurable parameters
//! - Position closure and fund withdrawal
//! - DCA execution (keeper-triggered)
//!
//! # Example
//! ```no_run
//! use chains_sdk::solana::jupiter_dca::*;
//!
//! let params = DcaParams {
//!     in_amount_per_cycle: 1_000_000,     // 1 USDC per cycle
//!     cycle_frequency: 86400,              // daily
//!     min_out_amount_per_cycle: 0,
//!     max_out_amount_per_cycle: u64::MAX,
//!     start_at: None,
//!     num_cycles: Some(30),                // 30 days
//! };
//! let ix = open_dca(
//!     &JUPITER_DCA_PROGRAM,
//!     &[1; 32], // dca_account
//!     &[2; 32], // user
//!     &[3; 32], // input_mint
//!     &[4; 32], // output_mint
//!     &[5; 32], // user_ata_in
//!     &[6; 32], // dca_ata_in
//!     &params,
//! );
//! ```

use crate::solana::transaction::{AccountMeta, Instruction};

/// Jupiter DCA program ID: `DCA265Vj8a9CEuX1eb1LWRnDT7uK6q1xMipnNyatn23M`
pub const JUPITER_DCA_PROGRAM: [u8; 32] = [
    0xB5, 0x27, 0xD4, 0x5D, 0x64, 0x0E, 0x3E, 0xC1, 0x5F, 0x61, 0x5D, 0x5B, 0x0E, 0x23, 0xA5, 0x4A,
    0x96, 0xB8, 0x3F, 0x0B, 0x82, 0x0B, 0xF7, 0x06, 0x35, 0xF2, 0x43, 0x4A, 0xC6, 0x40, 0xCC, 0x04,
];

/// System program ID.
const SYSTEM_PROGRAM: [u8; 32] = [0u8; 32];
/// Token program ID: `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`
const TOKEN_PROGRAM: [u8; 32] = [
    0x06, 0xDD, 0xF6, 0xE1, 0xD7, 0x65, 0xA1, 0x93, 0xD9, 0xCB, 0xE1, 0x46, 0xCE, 0xEB, 0x79, 0xAC,
    0x1C, 0xB4, 0x85, 0xED, 0x5F, 0x5B, 0x37, 0x91, 0x3A, 0x8C, 0xF5, 0x85, 0x7E, 0xFF, 0x00, 0xA9,
];
/// Associated token program: `ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL`
const ASSOCIATED_TOKEN_PROGRAM: [u8; 32] = [
    0x8C, 0x97, 0x25, 0x8F, 0x4E, 0x24, 0x89, 0xF1, 0xBB, 0x3D, 0x10, 0x29, 0x14, 0x8E, 0x0D, 0x83,
    0x0B, 0x5A, 0x13, 0x99, 0xDA, 0xFF, 0x10, 0x84, 0x04, 0x8E, 0x7B, 0xD8, 0xDB, 0xE9, 0xF8, 0x59,
];

// ═══════════════════════════════════════════════════════════════════
// Instruction Discriminators (Anchor-style 8-byte hashes)
// ═══════════════════════════════════════════════════════════════════

/// `sha256("global:open_dca")[..8]` — instruction discriminator.
const IX_OPEN_DCA: [u8; 8] = [0xe2, 0x97, 0xa4, 0xb9, 0x01, 0x52, 0x77, 0x08];
/// `sha256("global:close_dca")[..8]` — instruction discriminator.
const IX_CLOSE_DCA: [u8; 8] = [0x81, 0xcb, 0x60, 0x6d, 0x63, 0x46, 0xe0, 0x53];
/// `sha256("global:withdraw")[..8]` — instruction discriminator.
const IX_WITHDRAW: [u8; 8] = [0xb7, 0x12, 0x46, 0x9c, 0x94, 0x6d, 0xa1, 0x22];

// ═══════════════════════════════════════════════════════════════════
// DCA Parameters
// ═══════════════════════════════════════════════════════════════════

/// Parameters for a DCA position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DcaParams {
    /// Amount of input token per DCA cycle (in token base units).
    pub in_amount_per_cycle: u64,
    /// Cycle frequency in seconds (e.g., 86400 for daily).
    pub cycle_frequency: u64,
    /// Minimum output per cycle (slippage protection, 0 = no limit).
    pub min_out_amount_per_cycle: u64,
    /// Maximum output per cycle (u64::MAX = no limit).
    pub max_out_amount_per_cycle: u64,
    /// Optional start timestamp (None = start immediately).
    pub start_at: Option<u64>,
    /// Optional number of cycles (None = unlimited).
    pub num_cycles: Option<u64>,
}

impl DcaParams {
    /// Create daily DCA params.
    #[must_use]
    pub fn daily(amount_per_cycle: u64, num_days: u64) -> Self {
        Self {
            in_amount_per_cycle: amount_per_cycle,
            cycle_frequency: 86_400,
            min_out_amount_per_cycle: 0,
            max_out_amount_per_cycle: u64::MAX,
            start_at: None,
            num_cycles: Some(num_days),
        }
    }

    /// Create hourly DCA params.
    #[must_use]
    pub fn hourly(amount_per_cycle: u64, num_hours: u64) -> Self {
        Self {
            in_amount_per_cycle: amount_per_cycle,
            cycle_frequency: 3_600,
            min_out_amount_per_cycle: 0,
            max_out_amount_per_cycle: u64::MAX,
            start_at: None,
            num_cycles: Some(num_hours),
        }
    }

    /// Create weekly DCA params.
    #[must_use]
    pub fn weekly(amount_per_cycle: u64, num_weeks: u64) -> Self {
        Self {
            in_amount_per_cycle: amount_per_cycle,
            cycle_frequency: 604_800,
            min_out_amount_per_cycle: 0,
            max_out_amount_per_cycle: u64::MAX,
            start_at: None,
            num_cycles: Some(num_weeks),
        }
    }

    /// Set slippage bounds.
    #[must_use]
    pub fn with_bounds(mut self, min_out: u64, max_out: u64) -> Self {
        self.min_out_amount_per_cycle = min_out;
        self.max_out_amount_per_cycle = max_out;
        self
    }

    /// Set a specific start time.
    #[must_use]
    pub fn with_start_at(mut self, timestamp: u64) -> Self {
        self.start_at = Some(timestamp);
        self
    }

    /// Serialize params to instruction data bytes (Borsh-like).
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&self.in_amount_per_cycle.to_le_bytes());
        data.extend_from_slice(&self.cycle_frequency.to_le_bytes());
        data.extend_from_slice(&self.min_out_amount_per_cycle.to_le_bytes());
        data.extend_from_slice(&self.max_out_amount_per_cycle.to_le_bytes());
        // Option<u64> start_at
        match self.start_at {
            Some(ts) => {
                data.push(1);
                data.extend_from_slice(&ts.to_le_bytes());
            }
            None => data.push(0),
        }
        // Option<u64> num_cycles
        match self.num_cycles {
            Some(n) => {
                data.push(1);
                data.extend_from_slice(&n.to_le_bytes());
            }
            None => data.push(0),
        }
        data
    }

    /// Total input amount across all cycles.
    ///
    /// Returns `None` if unlimited cycles or overflow.
    #[must_use]
    pub fn total_input_amount(&self) -> Option<u64> {
        self.num_cycles
            .and_then(|n| self.in_amount_per_cycle.checked_mul(n))
    }
}

// ═══════════════════════════════════════════════════════════════════
// Instructions
// ═══════════════════════════════════════════════════════════════════

/// Open a new DCA position.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn open_dca(
    program_id: &[u8; 32],
    dca_account: &[u8; 32],
    user: &[u8; 32],
    input_mint: &[u8; 32],
    output_mint: &[u8; 32],
    user_ata_in: &[u8; 32],
    dca_ata_in: &[u8; 32],
    params: &DcaParams,
) -> Instruction {
    let mut data = Vec::with_capacity(80);
    data.extend_from_slice(&IX_OPEN_DCA);
    data.extend_from_slice(&params.serialize());

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*dca_account, true),
            AccountMeta::new(*user, true),
            AccountMeta::new_readonly(*input_mint, false),
            AccountMeta::new_readonly(*output_mint, false),
            AccountMeta::new(*user_ata_in, false),
            AccountMeta::new(*dca_ata_in, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            AccountMeta::new_readonly(TOKEN_PROGRAM, false),
            AccountMeta::new_readonly(ASSOCIATED_TOKEN_PROGRAM, false),
        ],
        data,
    }
}

/// Close a DCA position and withdraw remaining funds.
#[must_use]
pub fn close_dca(
    program_id: &[u8; 32],
    dca_account: &[u8; 32],
    user: &[u8; 32],
    user_ata_in: &[u8; 32],
    user_ata_out: &[u8; 32],
    dca_ata_in: &[u8; 32],
    dca_ata_out: &[u8; 32],
) -> Instruction {
    let mut data = Vec::with_capacity(8);
    data.extend_from_slice(&IX_CLOSE_DCA);

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*dca_account, false),
            AccountMeta::new(*user, true),
            AccountMeta::new(*user_ata_in, false),
            AccountMeta::new(*user_ata_out, false),
            AccountMeta::new(*dca_ata_in, false),
            AccountMeta::new(*dca_ata_out, false),
            AccountMeta::new_readonly(TOKEN_PROGRAM, false),
        ],
        data,
    }
}

/// Withdraw accumulated output tokens from a DCA position.
#[must_use]
pub fn withdraw(
    program_id: &[u8; 32],
    dca_account: &[u8; 32],
    user: &[u8; 32],
    user_ata_out: &[u8; 32],
    dca_ata_out: &[u8; 32],
) -> Instruction {
    let mut data = Vec::with_capacity(8);
    data.extend_from_slice(&IX_WITHDRAW);

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*dca_account, false),
            AccountMeta::new(*user, true),
            AccountMeta::new(*user_ata_out, false),
            AccountMeta::new(*dca_ata_out, false),
            AccountMeta::new_readonly(TOKEN_PROGRAM, false),
        ],
        data,
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const DCA: [u8; 32] = [1; 32];
    const USER: [u8; 32] = [2; 32];
    const INPUT_MINT: [u8; 32] = [3; 32];
    const OUTPUT_MINT: [u8; 32] = [4; 32];
    const USER_ATA_IN: [u8; 32] = [5; 32];
    const USER_ATA_OUT: [u8; 32] = [6; 32];
    const DCA_ATA_IN: [u8; 32] = [7; 32];
    const DCA_ATA_OUT: [u8; 32] = [8; 32];

    fn sample_params() -> DcaParams {
        DcaParams::daily(1_000_000, 30)
    }

    // ─── DcaParams ──────────────────────────────────────────────

    #[test]
    fn test_daily_params() {
        let p = DcaParams::daily(1_000_000, 30);
        assert_eq!(p.in_amount_per_cycle, 1_000_000);
        assert_eq!(p.cycle_frequency, 86_400);
        assert_eq!(p.num_cycles, Some(30));
    }

    #[test]
    fn test_hourly_params() {
        let p = DcaParams::hourly(100_000, 24);
        assert_eq!(p.cycle_frequency, 3_600);
        assert_eq!(p.num_cycles, Some(24));
    }

    #[test]
    fn test_weekly_params() {
        let p = DcaParams::weekly(10_000_000, 52);
        assert_eq!(p.cycle_frequency, 604_800);
        assert_eq!(p.num_cycles, Some(52));
    }

    #[test]
    fn test_params_with_bounds() {
        let p = DcaParams::daily(1000, 1).with_bounds(900, 1100);
        assert_eq!(p.min_out_amount_per_cycle, 900);
        assert_eq!(p.max_out_amount_per_cycle, 1100);
    }

    #[test]
    fn test_params_with_start_at() {
        let p = DcaParams::daily(1000, 1).with_start_at(1_700_000_000);
        assert_eq!(p.start_at, Some(1_700_000_000));
    }

    #[test]
    fn test_total_input_amount() {
        let p = DcaParams::daily(1_000_000, 30);
        assert_eq!(p.total_input_amount(), Some(30_000_000));
    }

    #[test]
    fn test_total_input_amount_unlimited() {
        let mut p = DcaParams::daily(1000, 1);
        p.num_cycles = None;
        assert_eq!(p.total_input_amount(), None);
    }

    #[test]
    fn test_serialize_length_daily() {
        let p = DcaParams::daily(1000, 30);
        let serialized = p.serialize();
        // 8 + 8 + 8 + 8 + 1 (None) + 1 + 8 (Some(30)) = 42
        assert_eq!(serialized.len(), 42);
    }

    #[test]
    fn test_serialize_with_start_at() {
        let p = DcaParams::daily(1000, 30).with_start_at(1_700_000_000);
        let serialized = p.serialize();
        // 8 + 8 + 8 + 8 + 1 + 8 (start_at) + 1 + 8 (num_cycles) = 50
        assert_eq!(serialized.len(), 50);
    }

    #[test]
    fn test_serialize_amount_encoding() {
        let p = DcaParams::daily(42, 1);
        let serialized = p.serialize();
        let amount = u64::from_le_bytes(serialized[0..8].try_into().unwrap());
        assert_eq!(amount, 42);
    }

    // ─── open_dca ───────────────────────────────────────────────

    #[test]
    fn test_open_dca_discriminator() {
        let ix = open_dca(
            &JUPITER_DCA_PROGRAM,
            &DCA,
            &USER,
            &INPUT_MINT,
            &OUTPUT_MINT,
            &USER_ATA_IN,
            &DCA_ATA_IN,
            &sample_params(),
        );
        assert_eq!(&ix.data[..8], &IX_OPEN_DCA);
    }

    #[test]
    fn test_open_dca_accounts() {
        let ix = open_dca(
            &JUPITER_DCA_PROGRAM,
            &DCA,
            &USER,
            &INPUT_MINT,
            &OUTPUT_MINT,
            &USER_ATA_IN,
            &DCA_ATA_IN,
            &sample_params(),
        );
        assert_eq!(ix.accounts.len(), 9);
        assert!(ix.accounts[0].is_writable); // dca account
        assert!(ix.accounts[1].is_signer); // user
    }

    #[test]
    fn test_open_dca_program_id() {
        let ix = open_dca(
            &JUPITER_DCA_PROGRAM,
            &DCA,
            &USER,
            &INPUT_MINT,
            &OUTPUT_MINT,
            &USER_ATA_IN,
            &DCA_ATA_IN,
            &sample_params(),
        );
        assert_eq!(ix.program_id, JUPITER_DCA_PROGRAM);
    }

    // ─── close_dca ──────────────────────────────────────────────

    #[test]
    fn test_close_dca_discriminator() {
        let ix = close_dca(
            &JUPITER_DCA_PROGRAM,
            &DCA,
            &USER,
            &USER_ATA_IN,
            &USER_ATA_OUT,
            &DCA_ATA_IN,
            &DCA_ATA_OUT,
        );
        assert_eq!(&ix.data[..8], &IX_CLOSE_DCA);
    }

    #[test]
    fn test_close_dca_accounts() {
        let ix = close_dca(
            &JUPITER_DCA_PROGRAM,
            &DCA,
            &USER,
            &USER_ATA_IN,
            &USER_ATA_OUT,
            &DCA_ATA_IN,
            &DCA_ATA_OUT,
        );
        assert_eq!(ix.accounts.len(), 7);
    }

    // ─── withdraw ───────────────────────────────────────────────

    #[test]
    fn test_withdraw_discriminator() {
        let ix = withdraw(
            &JUPITER_DCA_PROGRAM,
            &DCA,
            &USER,
            &USER_ATA_OUT,
            &DCA_ATA_OUT,
        );
        assert_eq!(&ix.data[..8], &IX_WITHDRAW);
    }

    #[test]
    fn test_withdraw_accounts() {
        let ix = withdraw(
            &JUPITER_DCA_PROGRAM,
            &DCA,
            &USER,
            &USER_ATA_OUT,
            &DCA_ATA_OUT,
        );
        assert_eq!(ix.accounts.len(), 5);
    }

    // ─── Constants ──────────────────────────────────────────────

    #[test]
    fn test_program_id_not_zero() {
        assert_ne!(JUPITER_DCA_PROGRAM, [0u8; 32]);
    }
}
