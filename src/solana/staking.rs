//! Solana staking instruction builders.
//!
//! Provides helpers for Marinade Finance (liquid staking)
//! and native Solana staking operations.
//!
//! # Example
//! ```no_run
//! use chains_sdk::solana::staking::*;
//! use chains_sdk::solana::staking::marinade;
//!
//! let user = [0x01u8; 32];
//! let msol_mint = [0x02u8; 32];
//! let ix = marinade::deposit(&user, &msol_mint, &[0x03; 32], &[0x04; 32], 1_000_000_000);
//! ```

use crate::solana::transaction::{AccountMeta, Instruction};

// ═══════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════

/// Solana native Stake program ID.
const STAKE_PROGRAM_ID: [u8; 32] = {
    let mut id = [0u8; 32];
    // Stake11111111111111111111111111111111111111
    id[0] = 0x06;
    id[1] = 0xa1;
    id[2] = 0xd8;
    id[3] = 0x17;
    id[4] = 0x91;
    id
};

/// System program ID.
const SYSTEM_PROGRAM_ID: [u8; 32] = [0u8; 32];

/// Sysvar Clock.
const SYSVAR_CLOCK_ID: [u8; 32] = {
    let mut id = [0u8; 32];
    id[0] = 0x06;
    id[1] = 0xa7;
    id[2] = 0xd5;
    id[3] = 0x17;
    id[4] = 0x18;
    id
};

/// Sysvar Stake History.
const SYSVAR_STAKE_HISTORY_ID: [u8; 32] = {
    let mut id = [0u8; 32];
    id[0] = 0x06;
    id[1] = 0xa7;
    id[2] = 0xd5;
    id[3] = 0x17;
    id[4] = 0x1b;
    id
};

/// Stake Config.
const STAKE_CONFIG_ID: [u8; 32] = {
    let mut id = [0u8; 32];
    id[0] = 0x06;
    id[1] = 0xa1;
    id[2] = 0xd8;
    id[3] = 0x79;
    id
};

/// Sysvar Rent.
const SYSVAR_RENT_ID: [u8; 32] = {
    let mut id = [0u8; 32];
    id[0] = 0x06;
    id[1] = 0xa7;
    id[2] = 0xd5;
    id[3] = 0x17;
    id[4] = 0x19;
    id
};

// ═══════════════════════════════════════════════════════════════════
// Native Staking Instructions
// ═══════════════════════════════════════════════════════════════════

/// Build a `DelegateStake` instruction.
///
/// Delegates a stake account to a validator vote account.
pub fn delegate_stake(
    stake_account: &[u8; 32],
    authority: &[u8; 32],
    vote_account: &[u8; 32],
) -> Instruction {
    // Instruction index 2 = DelegateStake
    let data = vec![2, 0, 0, 0];

    Instruction {
        program_id: STAKE_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*stake_account, false),
            AccountMeta::new_readonly(*vote_account, false),
            AccountMeta::new_readonly(SYSVAR_CLOCK_ID, false),
            AccountMeta::new_readonly(SYSVAR_STAKE_HISTORY_ID, false),
            AccountMeta::new_readonly(STAKE_CONFIG_ID, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data,
    }
}

/// Build a `Deactivate` instruction.
///
/// Deactivates a delegated stake account. After the cooldown period,
/// the stake can be withdrawn.
pub fn deactivate_stake(
    stake_account: &[u8; 32],
    authority: &[u8; 32],
) -> Instruction {
    // Instruction index 5 = Deactivate
    let data = vec![5, 0, 0, 0];

    Instruction {
        program_id: STAKE_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*stake_account, false),
            AccountMeta::new_readonly(SYSVAR_CLOCK_ID, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data,
    }
}

/// Build a `Withdraw` instruction.
///
/// Withdraws SOL from a deactivated stake account.
pub fn withdraw_stake(
    stake_account: &[u8; 32],
    authority: &[u8; 32],
    to: &[u8; 32],
    lamports: u64,
) -> Instruction {
    // Instruction index 4 = Withdraw
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&4u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());

    Instruction {
        program_id: STAKE_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*stake_account, false),
            AccountMeta::new(*to, false),
            AccountMeta::new_readonly(SYSVAR_CLOCK_ID, false),
            AccountMeta::new_readonly(SYSVAR_STAKE_HISTORY_ID, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data,
    }
}

/// Build an `Initialize` instruction for a stake account.
///
/// Sets the staker and withdrawer authorities.
pub fn initialize_stake(
    stake_account: &[u8; 32],
    staker: &[u8; 32],
    withdrawer: &[u8; 32],
) -> Instruction {
    // Instruction index 0 = Initialize
    let mut data = Vec::with_capacity(100);
    data.extend_from_slice(&0u32.to_le_bytes());
    // Authorized struct: staker (32) + withdrawer (32)
    data.extend_from_slice(staker);
    data.extend_from_slice(withdrawer);
    // Lockup struct: unix_timestamp (i64) + epoch (u64) + custodian (pubkey)
    data.extend_from_slice(&0i64.to_le_bytes()); // no lockup
    data.extend_from_slice(&0u64.to_le_bytes());
    data.extend_from_slice(&[0u8; 32]); // no custodian

    Instruction {
        program_id: STAKE_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*stake_account, false),
            AccountMeta::new_readonly(SYSVAR_RENT_ID, false),
        ],
        data,
    }
}

/// Build a `Merge` instruction to combine two stake accounts.
pub fn merge_stake(
    destination: &[u8; 32],
    source: &[u8; 32],
    authority: &[u8; 32],
) -> Instruction {
    // Instruction index 7 = Merge
    let data = vec![7, 0, 0, 0];

    Instruction {
        program_id: STAKE_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*destination, false),
            AccountMeta::new(*source, false),
            AccountMeta::new_readonly(SYSVAR_CLOCK_ID, false),
            AccountMeta::new_readonly(SYSVAR_STAKE_HISTORY_ID, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data,
    }
}

/// Build a `Split` instruction to split a stake account.
pub fn split_stake(
    source: &[u8; 32],
    destination: &[u8; 32],
    authority: &[u8; 32],
    lamports: u64,
) -> Instruction {
    // Instruction index 3 = Split
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&3u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());

    Instruction {
        program_id: STAKE_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*source, false),
            AccountMeta::new(*destination, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data,
    }
}

// ═══════════════════════════════════════════════════════════════════
// Marinade Finance (Liquid Staking)
// ═══════════════════════════════════════════════════════════════════

/// Marinade Finance instruction builders.
pub mod marinade {
    use super::*;

    /// Marinade Finance program ID.
    /// `MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD`
    pub const MARINADE_PROGRAM_ID: [u8; 32] = [
        0x05, 0x2f, 0x21, 0x68, 0x1b, 0x77, 0xa0, 0x42,
        0x6c, 0x31, 0x73, 0xd2, 0x97, 0x87, 0x62, 0x14,
        0x45, 0x6f, 0x5b, 0x48, 0xc4, 0x92, 0x59, 0x1e,
        0x54, 0x8c, 0x46, 0x7f, 0x2f, 0x3e, 0x14, 0x0a,
    ];

    /// SPL Token program ID.
    const TOKEN_PROGRAM_ID: [u8; 32] = {
        let mut id = [0u8; 32];
        id[0] = 0x06;
        id[1] = 0xDD;
        id[2] = 0xF6;
        id[3] = 0xE1;
        id
    };

    /// Build a Marinade `Deposit` instruction (stake SOL → receive mSOL).
    ///
    /// Anchor discriminator for "deposit": first 8 bytes of SHA-256("global:deposit")
    #[allow(clippy::too_many_arguments)]
    pub fn deposit(
        user: &[u8; 32],
        msol_mint: &[u8; 32],
        user_msol_account: &[u8; 32],
        marinade_state: &[u8; 32],
        lamports: u64,
    ) -> Instruction {
        let discriminator: [u8; 8] = [242, 35, 198, 137, 82, 225, 242, 182];

        let mut data = Vec::with_capacity(16);
        data.extend_from_slice(&discriminator);
        data.extend_from_slice(&lamports.to_le_bytes());

        Instruction {
            program_id: MARINADE_PROGRAM_ID,
            accounts: vec![
                AccountMeta::new_readonly(*marinade_state, false),
                AccountMeta::new(*msol_mint, false),
                AccountMeta::new(*user_msol_account, false),
                AccountMeta::new(*user, true), // payer/signer
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
                AccountMeta::new_readonly(TOKEN_PROGRAM_ID, false),
            ],
            data,
        }
    }

    /// Build a Marinade `LiquidUnstake` instruction (instant mSOL → SOL).
    pub fn liquid_unstake(
        user: &[u8; 32],
        msol_mint: &[u8; 32],
        user_msol_account: &[u8; 32],
        marinade_state: &[u8; 32],
        msol_amount: u64,
    ) -> Instruction {
        let discriminator: [u8; 8] = [30, 148, 247, 99, 14, 86, 105, 11];

        let mut data = Vec::with_capacity(16);
        data.extend_from_slice(&discriminator);
        data.extend_from_slice(&msol_amount.to_le_bytes());

        Instruction {
            program_id: MARINADE_PROGRAM_ID,
            accounts: vec![
                AccountMeta::new_readonly(*marinade_state, false),
                AccountMeta::new(*msol_mint, false),
                AccountMeta::new(*user_msol_account, false),
                AccountMeta::new(*user, true),
                AccountMeta::new_readonly(TOKEN_PROGRAM_ID, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            ],
            data,
        }
    }

    /// Build a Marinade `OrderUnstake` instruction (delayed unstake, lower fee).
    pub fn order_unstake(
        user: &[u8; 32],
        msol_mint: &[u8; 32],
        user_msol_account: &[u8; 32],
        marinade_state: &[u8; 32],
        ticket_account: &[u8; 32],
        msol_amount: u64,
    ) -> Instruction {
        let discriminator: [u8; 8] = [97, 167, 144, 107, 117, 190, 128, 36];

        let mut data = Vec::with_capacity(16);
        data.extend_from_slice(&discriminator);
        data.extend_from_slice(&msol_amount.to_le_bytes());

        Instruction {
            program_id: MARINADE_PROGRAM_ID,
            accounts: vec![
                AccountMeta::new_readonly(*marinade_state, false),
                AccountMeta::new(*msol_mint, false),
                AccountMeta::new(*user_msol_account, false),
                AccountMeta::new(*user, true),
                AccountMeta::new(*ticket_account, false),
                AccountMeta::new_readonly(TOKEN_PROGRAM_ID, false),
                AccountMeta::new_readonly(SYSVAR_CLOCK_ID, false),
                AccountMeta::new_readonly(SYSVAR_RENT_ID, false),
            ],
            data,
        }
    }

    /// Build a Marinade `Claim` instruction (claim delayed unstake ticket).
    pub fn claim(
        user: &[u8; 32],
        marinade_state: &[u8; 32],
        ticket_account: &[u8; 32],
        reserve_sol_account: &[u8; 32],
    ) -> Instruction {
        let discriminator: [u8; 8] = [62, 198, 214, 193, 213, 159, 108, 210];

        let data = discriminator.to_vec();

        Instruction {
            program_id: MARINADE_PROGRAM_ID,
            accounts: vec![
                AccountMeta::new_readonly(*marinade_state, false),
                AccountMeta::new(*ticket_account, false),
                AccountMeta::new(*user, true),
                AccountMeta::new(*reserve_sol_account, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
                AccountMeta::new_readonly(SYSVAR_CLOCK_ID, false),
            ],
            data,
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

    const USER: [u8; 32] = [0x01; 32];
    const STAKE_ACCT: [u8; 32] = [0x02; 32];
    const VOTE: [u8; 32] = [0x03; 32];
    const DEST: [u8; 32] = [0x04; 32];
    const MSOL_MINT: [u8; 32] = [0x05; 32];
    const USER_MSOL: [u8; 32] = [0x06; 32];
    const MARINADE_STATE: [u8; 32] = [0x07; 32];
    const TICKET: [u8; 32] = [0x08; 32];
    const RESERVE: [u8; 32] = [0x09; 32];

    // ─── Native Staking ─────────────────────────────────────────

    #[test]
    fn test_delegate_stake_instruction_index() {
        let ix = delegate_stake(&STAKE_ACCT, &USER, &VOTE);
        assert_eq!(ix.data[0], 2); // DelegateStake
    }

    #[test]
    fn test_delegate_stake_program_id() {
        let ix = delegate_stake(&STAKE_ACCT, &USER, &VOTE);
        assert_eq!(ix.program_id, STAKE_PROGRAM_ID);
    }

    #[test]
    fn test_delegate_stake_accounts() {
        let ix = delegate_stake(&STAKE_ACCT, &USER, &VOTE);
        assert_eq!(ix.accounts.len(), 6);
        assert_eq!(ix.accounts[0].pubkey, STAKE_ACCT);
        assert!(ix.accounts[0].is_writable);
        assert_eq!(ix.accounts[1].pubkey, VOTE);
        assert!(ix.accounts[5].is_signer); // authority
    }

    #[test]
    fn test_deactivate_stake_instruction_index() {
        let ix = deactivate_stake(&STAKE_ACCT, &USER);
        assert_eq!(ix.data[0], 5); // Deactivate
    }

    #[test]
    fn test_deactivate_stake_accounts() {
        let ix = deactivate_stake(&STAKE_ACCT, &USER);
        assert_eq!(ix.accounts.len(), 3);
        assert!(ix.accounts[2].is_signer); // authority
    }

    #[test]
    fn test_withdraw_stake_instruction_index() {
        let ix = withdraw_stake(&STAKE_ACCT, &USER, &DEST, 1_000_000);
        assert_eq!(ix.data[0], 4); // Withdraw
    }

    #[test]
    fn test_withdraw_stake_lamports_encoding() {
        let ix = withdraw_stake(&STAKE_ACCT, &USER, &DEST, 42_000_000);
        let lamports = u64::from_le_bytes(ix.data[4..12].try_into().unwrap());
        assert_eq!(lamports, 42_000_000);
    }

    #[test]
    fn test_withdraw_stake_accounts() {
        let ix = withdraw_stake(&STAKE_ACCT, &USER, &DEST, 100);
        assert_eq!(ix.accounts.len(), 5);
        assert!(ix.accounts[4].is_signer); // authority
        assert!(ix.accounts[1].is_writable); // destination
    }

    #[test]
    fn test_initialize_stake_instruction_index() {
        let ix = initialize_stake(&STAKE_ACCT, &USER, &USER);
        assert_eq!(ix.data[0], 0); // Initialize
    }

    #[test]
    fn test_initialize_stake_data_size() {
        let ix = initialize_stake(&STAKE_ACCT, &USER, &USER);
        // 4 (index) + 32 (staker) + 32 (withdrawer) + 8+8+32 (lockup) = 116
        assert_eq!(ix.data.len(), 116);
    }

    #[test]
    fn test_initialize_stake_accounts() {
        let ix = initialize_stake(&STAKE_ACCT, &USER, &USER);
        assert_eq!(ix.accounts.len(), 2);
    }

    #[test]
    fn test_merge_stake_instruction_index() {
        let ix = merge_stake(&STAKE_ACCT, &DEST, &USER);
        assert_eq!(ix.data[0], 7); // Merge
    }

    #[test]
    fn test_merge_stake_accounts() {
        let ix = merge_stake(&STAKE_ACCT, &DEST, &USER);
        assert_eq!(ix.accounts.len(), 5);
        assert!(ix.accounts[0].is_writable); // destination
        assert!(ix.accounts[1].is_writable); // source
    }

    #[test]
    fn test_split_stake_instruction_index() {
        let ix = split_stake(&STAKE_ACCT, &DEST, &USER, 500_000);
        assert_eq!(ix.data[0], 3); // Split
    }

    #[test]
    fn test_split_stake_lamports() {
        let ix = split_stake(&STAKE_ACCT, &DEST, &USER, 12345);
        let lamports = u64::from_le_bytes(ix.data[4..12].try_into().unwrap());
        assert_eq!(lamports, 12345);
    }

    // ─── Marinade Finance ───────────────────────────────────────

    #[test]
    fn test_marinade_deposit_discriminator() {
        let ix = marinade::deposit(&USER, &MSOL_MINT, &USER_MSOL, &MARINADE_STATE, 1_000_000_000);
        assert_eq!(&ix.data[..8], &[242, 35, 198, 137, 82, 225, 242, 182]);
    }

    #[test]
    fn test_marinade_deposit_amount() {
        let ix = marinade::deposit(&USER, &MSOL_MINT, &USER_MSOL, &MARINADE_STATE, 2_000_000_000);
        let amount = u64::from_le_bytes(ix.data[8..16].try_into().unwrap());
        assert_eq!(amount, 2_000_000_000);
    }

    #[test]
    fn test_marinade_deposit_program_id() {
        let ix = marinade::deposit(&USER, &MSOL_MINT, &USER_MSOL, &MARINADE_STATE, 100);
        assert_eq!(ix.program_id, marinade::MARINADE_PROGRAM_ID);
    }

    #[test]
    fn test_marinade_deposit_accounts() {
        let ix = marinade::deposit(&USER, &MSOL_MINT, &USER_MSOL, &MARINADE_STATE, 100);
        assert_eq!(ix.accounts.len(), 6);
        assert!(ix.accounts[3].is_signer); // user is signer
    }

    #[test]
    fn test_marinade_liquid_unstake_discriminator() {
        let ix = marinade::liquid_unstake(&USER, &MSOL_MINT, &USER_MSOL, &MARINADE_STATE, 500);
        assert_eq!(&ix.data[..8], &[30, 148, 247, 99, 14, 86, 105, 11]);
    }

    #[test]
    fn test_marinade_liquid_unstake_amount() {
        let ix = marinade::liquid_unstake(&USER, &MSOL_MINT, &USER_MSOL, &MARINADE_STATE, 999);
        let amount = u64::from_le_bytes(ix.data[8..16].try_into().unwrap());
        assert_eq!(amount, 999);
    }

    #[test]
    fn test_marinade_order_unstake_discriminator() {
        let ix = marinade::order_unstake(&USER, &MSOL_MINT, &USER_MSOL, &MARINADE_STATE, &TICKET, 100);
        assert_eq!(&ix.data[..8], &[97, 167, 144, 107, 117, 190, 128, 36]);
    }

    #[test]
    fn test_marinade_order_unstake_accounts() {
        let ix = marinade::order_unstake(&USER, &MSOL_MINT, &USER_MSOL, &MARINADE_STATE, &TICKET, 100);
        assert_eq!(ix.accounts.len(), 8);
        assert!(ix.accounts[3].is_signer); // user
        assert!(ix.accounts[4].is_writable); // ticket
    }

    #[test]
    fn test_marinade_claim_discriminator() {
        let ix = marinade::claim(&USER, &MARINADE_STATE, &TICKET, &RESERVE);
        assert_eq!(&ix.data[..8], &[62, 198, 214, 193, 213, 159, 108, 210]);
    }

    #[test]
    fn test_marinade_claim_data_length() {
        let ix = marinade::claim(&USER, &MARINADE_STATE, &TICKET, &RESERVE);
        assert_eq!(ix.data.len(), 8); // discriminator only
    }

    #[test]
    fn test_marinade_claim_accounts() {
        let ix = marinade::claim(&USER, &MARINADE_STATE, &TICKET, &RESERVE);
        assert_eq!(ix.accounts.len(), 6);
        assert!(ix.accounts[2].is_signer); // user
    }

    // ─── Cross-cutting ──────────────────────────────────────────

    #[test]
    fn test_stake_program_id_is_32_bytes() {
        assert_eq!(STAKE_PROGRAM_ID.len(), 32);
    }

    #[test]
    fn test_marinade_program_id_is_32_bytes() {
        assert_eq!(marinade::MARINADE_PROGRAM_ID.len(), 32);
    }

    #[test]
    fn test_different_program_ids() {
        assert_ne!(STAKE_PROGRAM_ID, marinade::MARINADE_PROGRAM_ID);
    }
}
