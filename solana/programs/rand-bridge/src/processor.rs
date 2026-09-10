//! Instruction dispatch.
//!
//! A stub until the instruction set lands: every instruction is rejected,
//! so a partially deployed program can never move tokens.

use solana_program::account_info::AccountInfo;
use solana_program::entrypoint::ProgramResult;
use solana_program::program_error::ProgramError;
use solana_program::pubkey::Pubkey;

/// Dispatches an instruction. Rejects everything for now.
pub fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    Err(ProgramError::InvalidInstructionData)
}
