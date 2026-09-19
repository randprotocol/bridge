//! The program's instruction set and the client-side builders for it.
//!
//! Instructions are Borsh-encoded [`BridgeInstruction`] values; the
//! account list of each one is documented on its builder below and is
//! re-derived and re-checked by [`crate::processor`], so a client that
//! passes the wrong account gets [`crate::error::BridgeError::InvalidPda`]
//! rather than a silent misread.
//!
//! Every PDA in these lists is derived from the seeds in
//! [`crate::state::seeds`]; nothing here is a bare address the caller may
//! choose freely except the payer/signer accounts, the mint, and the two
//! associated token accounts (which are themselves re-derived from the
//! wallet and the mint).

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::instruction::{AccountMeta, Instruction};
use solana_program::pubkey::Pubkey;
use solana_program::sysvar;
use solana_sdk_ids::{bpf_loader_upgradeable, system_program};

use crate::state::{
    authority_pda, config_pda, custody_pda, guardian_pda, msg_pda, spent_pda, token_pda,
};

/// A decoded instruction for the bridge program.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub enum BridgeInstruction {
    /// One-shot deployment: create the config and guardian set 0.
    Initialize {
        /// The privileged account (a multisig, in production).
        admin: Pubkey,
        /// The account allowed to pause but not unpause.
        pauser: Pubkey,
        /// The Rand-side emitter whose burn attestations are honored.
        rand_emitter: [u8; 32],
        /// Guardian set 0: non-empty, no zero key, no duplicates.
        guardians: Vec<[u8; 20]>,
    },
    /// Whitelist a mint and set its release caps (native units, 0 =
    /// unlimited).
    SetToken {
        /// Whether locks and releases of this mint are accepted.
        enabled: bool,
        /// Largest single release, or 0 for unlimited.
        per_transfer_cap: u64,
        /// Largest total release per rolling day, or 0 for unlimited.
        daily_cap: u64,
    },
    /// Move tokens into custody and post an outbound transfer message.
    Lock {
        /// Amount in the mint's own units; the sub-attestable remainder
        /// stays with the caller.
        amount: u64,
        /// The 32-byte Rand-side recipient; must not be all zeroes.
        rand_recipient: [u8; 32],
        /// Relayer fee, quoted in the mint's own units like `amount`.
        relayer_fee: u64,
        /// Caller-chosen nonce, echoed into the message body.
        nonce: u32,
    },
    /// Redeem a guardian-signed Rand burn attestation out of custody.
    Release {
        /// The encoded attestation (envelope + signatures + body).
        attestation: Vec<u8>,
    },
    /// Rotate the guardian set from a governance attestation.
    GuardianSetUpgrade {
        /// The encoded attestation carrying a payload id 2.
        attestation: Vec<u8>,
    },
    /// Halt locks and releases. Pauser or admin.
    Pause,
    /// Resume locks and releases. Admin only.
    Unpause,
    /// Start (or, with `to == Pubkey::default()`, cancel) an admin
    /// handover.
    TransferAdmin {
        /// The account that may then call `AcceptAdmin`.
        to: Pubkey,
    },
    /// Second half of the two-step admin handover.
    AcceptAdmin,
    /// Set the protocol fee rate. Admin only, at most
    /// `MAX_PROTOCOL_FEE_BPS`.
    SetProtocolFee {
        /// Basis points of the bridged amount, taken on lock and release.
        bps: u16,
    },
    /// Pay accrued protocol fees out of the custody token account. Admin
    /// only; bounded by `TokenRegistry::accrued_fees`, never custody.
    WithdrawFees {
        /// Amount in the mint's own units.
        amount: u64,
    },
}

/// `Initialize`.
///
/// The payer must be the program's **upgrade authority**: this is the one
/// instruction with no config to check a role against, so it is bound to
/// the only identity that exists before the bridge does.
///
/// Accounts:
/// 0. `[signer, writable]` payer — the upgrade authority; funds the two
///    accounts created here.
/// 1. `[writable]` config PDA `["config"]` — created; must not exist.
/// 2. `[writable]` guardian set 0 PDA `["guardian", 0u32 LE]` — created.
/// 3. `[]` custody authority PDA `["authority"]` — address checked only.
/// 4. `[]` the program's ProgramData account under the upgradeable
///    loader, `[program_id]` — read for the upgrade authority.
/// 5. `[]` system program.
pub fn initialize(
    program: &Pubkey,
    payer: &Pubkey,
    admin: &Pubkey,
    pauser: &Pubkey,
    rand_emitter: [u8; 32],
    guardians: Vec<[u8; 20]>,
) -> Instruction {
    Instruction::new_with_borsh(
        *program,
        &BridgeInstruction::Initialize {
            admin: *admin,
            pauser: *pauser,
            rand_emitter,
            guardians,
        },
        vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(config_pda(program).0, false),
            AccountMeta::new(guardian_pda(program, 0).0, false),
            AccountMeta::new_readonly(authority_pda(program).0, false),
            AccountMeta::new_readonly(program_data_address(program), false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
    )
}

/// The ProgramData account of an upgradeable program: the PDA
/// `[program_id]` under the upgradeable loader, where the loader stores
/// the upgrade authority.
pub fn program_data_address(program: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[program.as_ref()], &bpf_loader_upgradeable::id()).0
}

/// `SetToken`.
///
/// Accounts:
/// 0. `[signer, writable]` admin — must equal `Config::admin`; funds the
///    registry and custody accounts the first time a mint is configured.
/// 1. `[]` config PDA.
/// 2. `[]` the SPL mint, owned by the token program.
/// 3. `[writable]` token registry PDA `["token", mint]` — created if missing.
/// 4. `[writable]` custody PDA `["custody", mint]` — created as an SPL
///    token account owned by the authority PDA if missing.
/// 5. `[]` custody authority PDA `["authority"]`.
/// 6. `[]` SPL token program.
/// 7. `[]` system program.
/// 8. `[]` rent sysvar — consumed by the token program's
///    `InitializeAccount`.
pub fn set_token(
    program: &Pubkey,
    admin: &Pubkey,
    mint: &Pubkey,
    enabled: bool,
    per_transfer_cap: u64,
    daily_cap: u64,
) -> Instruction {
    Instruction::new_with_borsh(
        *program,
        &BridgeInstruction::SetToken {
            enabled,
            per_transfer_cap,
            daily_cap,
        },
        vec![
            AccountMeta::new(*admin, true),
            AccountMeta::new_readonly(config_pda(program).0, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(token_pda(program, mint).0, false),
            AccountMeta::new(custody_pda(program, mint).0, false),
            AccountMeta::new_readonly(authority_pda(program).0, false),
            AccountMeta::new_readonly(spl_token::id(), false),
            AccountMeta::new_readonly(system_program::id(), false),
            AccountMeta::new_readonly(sysvar::rent::id(), false),
        ],
    )
}

/// `Lock`.
///
/// `sequence` must be the config's current sequence number, since the
/// message PDA is seeded with it; a stale value derives the wrong address
/// and the instruction fails with `InvalidPda`.
///
/// Accounts:
/// 0. `[signer, writable]` owner — the token owner, and the rent payer for
///    the posted message.
/// 1. `[writable]` the owner's token account for `mint`.
/// 2. `[writable]` config PDA — its sequence is bumped.
/// 3. `[]` the SPL mint.
/// 4. `[writable]` token registry PDA.
/// 5. `[writable]` custody PDA.
/// 6. `[writable]` message PDA `["msg", sequence LE]` — created.
/// 7. `[]` SPL token program.
/// 8. `[]` system program.
/// 9. `[]` clock sysvar.
#[allow(clippy::too_many_arguments)]
pub fn lock(
    program: &Pubkey,
    owner: &Pubkey,
    owner_token_account: &Pubkey,
    mint: &Pubkey,
    sequence: u64,
    amount: u64,
    rand_recipient: [u8; 32],
    relayer_fee: u64,
    nonce: u32,
) -> Instruction {
    Instruction::new_with_borsh(
        *program,
        &BridgeInstruction::Lock {
            amount,
            rand_recipient,
            relayer_fee,
            nonce,
        },
        vec![
            AccountMeta::new(*owner, true),
            AccountMeta::new(*owner_token_account, false),
            AccountMeta::new(config_pda(program).0, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(token_pda(program, mint).0, false),
            AccountMeta::new(custody_pda(program, mint).0, false),
            AccountMeta::new(msg_pda(program, sequence).0, false),
            AccountMeta::new_readonly(spl_token::id(), false),
            AccountMeta::new_readonly(system_program::id(), false),
            AccountMeta::new_readonly(sysvar::clock::id(), false),
        ],
    )
}

/// `Release`.
///
/// `guardian_set_index`, `digest` and `recipient` all come out of the
/// attestation being submitted: they only select which PDAs the client
/// passes, and the program re-derives every one of them from the
/// attestation it verifies.
///
/// Accounts:
/// 0. `[signer, writable]` relayer — pays the consumed-marker rent and
///    collects the payload's fee.
/// 1. `[]` config PDA.
/// 2. `[]` guardian set PDA for the attestation's index.
/// 3. `[]` the SPL mint named by the payload's `token_address`.
/// 4. `[writable]` token registry PDA.
/// 5. `[writable]` custody PDA.
/// 6. `[]` custody authority PDA — the CPI signer.
/// 7. `[writable]` the recipient's associated token account.
/// 8. `[writable]` the relayer's associated token account.
/// 9. `[writable]` consumed PDA `["spent", digest]` — created.
/// 10. `[]` SPL token program.
/// 11. `[]` system program.
/// 12. `[]` clock sysvar.
pub fn release(
    program: &Pubkey,
    relayer: &Pubkey,
    mint: &Pubkey,
    guardian_set_index: u32,
    recipient: &Pubkey,
    digest: &[u8; 32],
    attestation: Vec<u8>,
) -> Instruction {
    Instruction::new_with_borsh(
        *program,
        &BridgeInstruction::Release { attestation },
        vec![
            AccountMeta::new(*relayer, true),
            AccountMeta::new_readonly(config_pda(program).0, false),
            AccountMeta::new_readonly(guardian_pda(program, guardian_set_index).0, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(token_pda(program, mint).0, false),
            AccountMeta::new(custody_pda(program, mint).0, false),
            AccountMeta::new_readonly(authority_pda(program).0, false),
            AccountMeta::new(associated_token_address(recipient, mint), false),
            AccountMeta::new(associated_token_address(relayer, mint), false),
            AccountMeta::new(spent_pda(program, digest).0, false),
            AccountMeta::new_readonly(spl_token::id(), false),
            AccountMeta::new_readonly(system_program::id(), false),
            AccountMeta::new_readonly(sysvar::clock::id(), false),
        ],
    )
}

/// `GuardianSetUpgrade`.
///
/// Deliberately submittable while paused: pausing stops value movement,
/// and it must not stand between the guardians and rotating away from a
/// compromised set.
///
/// Accounts:
/// 0. `[signer, writable]` payer — funds the new set and the consumed marker.
/// 1. `[writable]` config PDA — its current set index moves.
/// 2. `[writable]` current guardian set PDA — gains an expiry.
/// 3. `[writable]` new guardian set PDA `["guardian", new_index LE]` — created.
/// 4. `[writable]` consumed PDA `["spent", digest]` — created.
/// 5. `[]` system program.
/// 6. `[]` clock sysvar.
pub fn guardian_set_upgrade(
    program: &Pubkey,
    payer: &Pubkey,
    current_index: u32,
    new_index: u32,
    digest: &[u8; 32],
    attestation: Vec<u8>,
) -> Instruction {
    Instruction::new_with_borsh(
        *program,
        &BridgeInstruction::GuardianSetUpgrade { attestation },
        vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(config_pda(program).0, false),
            AccountMeta::new(guardian_pda(program, current_index).0, false),
            AccountMeta::new(guardian_pda(program, new_index).0, false),
            AccountMeta::new(spent_pda(program, digest).0, false),
            AccountMeta::new_readonly(system_program::id(), false),
            AccountMeta::new_readonly(sysvar::clock::id(), false),
        ],
    )
}

/// `Pause`: `[signer]` pauser or admin, `[writable]` config PDA.
pub fn pause(program: &Pubkey, pauser: &Pubkey) -> Instruction {
    role_instruction(program, pauser, BridgeInstruction::Pause)
}

/// `Unpause`: `[signer]` admin, `[writable]` config PDA.
pub fn unpause(program: &Pubkey, admin: &Pubkey) -> Instruction {
    role_instruction(program, admin, BridgeInstruction::Unpause)
}

/// `TransferAdmin`: `[signer]` admin, `[writable]` config PDA.
pub fn transfer_admin(program: &Pubkey, admin: &Pubkey, to: &Pubkey) -> Instruction {
    role_instruction(program, admin, BridgeInstruction::TransferAdmin { to: *to })
}

/// `AcceptAdmin`: `[signer]` pending admin, `[writable]` config PDA.
pub fn accept_admin(program: &Pubkey, pending_admin: &Pubkey) -> Instruction {
    role_instruction(program, pending_admin, BridgeInstruction::AcceptAdmin)
}

/// `SetProtocolFee`: `[signer]` admin, `[writable]` config PDA.
pub fn set_protocol_fee(program: &Pubkey, admin: &Pubkey, bps: u16) -> Instruction {
    role_instruction(program, admin, BridgeInstruction::SetProtocolFee { bps })
}

/// `WithdrawFees`.
///
/// Accounts:
/// 0. `[signer]` admin — must equal `Config::admin`.
/// 1. `[]` config PDA.
/// 2. `[]` the SPL mint.
/// 3. `[writable]` token registry PDA `["token", mint]`.
/// 4. `[writable]` custody PDA `["custody", mint]`.
/// 5. `[]` custody authority PDA `["authority"]`.
/// 6. `[writable]` destination token account for the mint.
/// 7. `[]` SPL token program.
pub fn withdraw_fees(
    program: &Pubkey,
    admin: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
    amount: u64,
) -> Instruction {
    Instruction::new_with_borsh(
        *program,
        &BridgeInstruction::WithdrawFees { amount },
        vec![
            AccountMeta::new_readonly(*admin, true),
            AccountMeta::new_readonly(config_pda(program).0, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(token_pda(program, mint).0, false),
            AccountMeta::new(custody_pda(program, mint).0, false),
            AccountMeta::new_readonly(authority_pda(program).0, false),
            AccountMeta::new(*destination, false),
            AccountMeta::new_readonly(spl_token::id(), false),
        ],
    )
}

/// The role instructions share one account list: the signer whose
/// authority is being exercised, and the config it mutates.
fn role_instruction(program: &Pubkey, signer: &Pubkey, ix: BridgeInstruction) -> Instruction {
    Instruction::new_with_borsh(
        *program,
        &ix,
        vec![
            AccountMeta::new_readonly(*signer, true),
            AccountMeta::new(config_pda(program).0, false),
        ],
    )
}

/// The associated token account of `wallet` for `mint`, under the classic
/// SPL token program.
///
/// Derived here rather than pulled from
/// `spl_associated_token_account::get_associated_token_address`, whose
/// re-export is deprecated in favor of a separate client crate; the seeds
/// are the associated-token-account program's own and are pinned by
/// `matches_the_spl_helper` in this module's tests.
pub fn associated_token_address(wallet: &Pubkey, mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[wallet.as_ref(), spl_token::id().as_ref(), mint.as_ref()],
        &spl_associated_token_account::id(),
    )
    .0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_spl_helper() {
        let wallet = Pubkey::new_from_array([3u8; 32]);
        let mint = Pubkey::new_from_array([4u8; 32]);
        #[allow(deprecated)]
        let expected = spl_associated_token_account::get_associated_token_address(&wallet, &mint);
        assert_eq!(associated_token_address(&wallet, &mint), expected);
    }

    #[test]
    fn instructions_round_trip_through_borsh() {
        let all = [
            BridgeInstruction::Initialize {
                admin: Pubkey::new_from_array([1u8; 32]),
                pauser: Pubkey::new_from_array([2u8; 32]),
                rand_emitter: [3u8; 32],
                guardians: vec![[4u8; 20]],
            },
            BridgeInstruction::SetToken {
                enabled: true,
                per_transfer_cap: 1,
                daily_cap: 2,
            },
            BridgeInstruction::Lock {
                amount: 3,
                rand_recipient: [5u8; 32],
                relayer_fee: 4,
                nonce: 6,
            },
            BridgeInstruction::Release {
                attestation: vec![7, 8],
            },
            BridgeInstruction::GuardianSetUpgrade {
                attestation: vec![9],
            },
            BridgeInstruction::Pause,
            BridgeInstruction::Unpause,
            BridgeInstruction::TransferAdmin {
                to: Pubkey::new_from_array([6u8; 32]),
            },
            BridgeInstruction::AcceptAdmin,
            BridgeInstruction::SetProtocolFee { bps: 10 },
            BridgeInstruction::WithdrawFees { amount: 11 },
        ];
        for (tag, ix) in all.iter().enumerate() {
            let bytes = borsh::to_vec(ix).expect("serializes");
            assert_eq!(bytes[0], tag as u8, "{ix:?} moved variant index");
            assert_eq!(
                &BridgeInstruction::try_from_slice(&bytes).expect("deserializes"),
                ix
            );
        }
    }

    #[test]
    fn builders_produce_the_documented_account_lists() {
        let program = crate::id();
        let signer = Pubkey::new_from_array([9u8; 32]);
        let mint = Pubkey::new_from_array([8u8; 32]);

        let ix = initialize(
            &program,
            &signer,
            &signer,
            &signer,
            [1u8; 32],
            vec![[2u8; 20]],
        );
        assert_eq!(ix.program_id, program);
        assert_eq!(ix.accounts.len(), 6);
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable);
        assert_eq!(ix.accounts[1].pubkey, config_pda(&program).0);
        assert_eq!(ix.accounts[2].pubkey, guardian_pda(&program, 0).0);
        assert_eq!(ix.accounts[4].pubkey, program_data_address(&program));

        let ix = set_token(&program, &signer, &mint, true, 0, 0);
        assert_eq!(ix.accounts.len(), 9);
        assert_eq!(ix.accounts[3].pubkey, token_pda(&program, &mint).0);
        assert_eq!(ix.accounts[4].pubkey, custody_pda(&program, &mint).0);
        assert_eq!(ix.accounts[8].pubkey, sysvar::rent::id());

        let ix = lock(&program, &signer, &signer, &mint, 7, 1, [1u8; 32], 0, 0);
        assert_eq!(ix.accounts.len(), 10);
        assert_eq!(ix.accounts[6].pubkey, msg_pda(&program, 7).0);

        let ix = release(&program, &signer, &mint, 2, &signer, &[5u8; 32], vec![]);
        assert_eq!(ix.accounts.len(), 13);
        assert_eq!(ix.accounts[2].pubkey, guardian_pda(&program, 2).0);
        assert_eq!(
            ix.accounts[7].pubkey,
            associated_token_address(&signer, &mint)
        );
        assert_eq!(ix.accounts[9].pubkey, spent_pda(&program, &[5u8; 32]).0);

        let ix = guardian_set_upgrade(&program, &signer, 0, 1, &[6u8; 32], vec![]);
        assert_eq!(ix.accounts.len(), 7);
        assert_eq!(ix.accounts[2].pubkey, guardian_pda(&program, 0).0);
        assert_eq!(ix.accounts[3].pubkey, guardian_pda(&program, 1).0);

        for ix in [
            pause(&program, &signer),
            unpause(&program, &signer),
            transfer_admin(&program, &signer, &signer),
            accept_admin(&program, &signer),
        ] {
            assert_eq!(ix.accounts.len(), 2);
            assert!(ix.accounts[0].is_signer);
            assert!(ix.accounts[1].is_writable);
        }
    }
}
