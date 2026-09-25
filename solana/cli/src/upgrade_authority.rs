//! BR-3: handing the program's BPF Upgradeable Loader authority to a new
//! key (a Squads vault, in production), and reading it back.
//!
//! Pure, unit-tested helpers only; `main.rs` does the RPC and confirmation
//! dance around them (`set-upgrade-authority`, and `show`'s extra field).

use anyhow::{anyhow, Result};
use solana_loader_v3_interface::instruction::set_upgrade_authority;
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use solana_sdk::instruction::Instruction;
use solana_sdk::pubkey::Pubkey;

/// The BPF Upgradeable Loader's ProgramData PDA for `program`: `[program]`
/// under `bpf_loader_upgradeable`. Re-exported from `rand_bridge` so the
/// CLI and the program derive the same address from one place.
pub use rand_bridge::instruction::program_data_address;

/// Builds the loader's `SetAuthority` instruction moving `program`'s
/// upgrade authority from `current` (must sign) to `new`. This is the
/// *unchecked* variant: `new` is not required to co-sign, because the
/// intended new authority is a Squads vault PDA, which cannot sign offline.
pub fn build_set_upgrade_authority(
    program: &Pubkey,
    current: &Pubkey,
    new: &Pubkey,
) -> Instruction {
    set_upgrade_authority(program, current, Some(new))
}

/// Decodes a ProgramData account (bincode-encoded
/// `UpgradeableLoaderState::ProgramData`), returning its slot and current
/// upgrade authority (`None` means the program has been made immutable).
pub fn decode_program_data(data: &[u8]) -> Result<(u64, Option<Pubkey>)> {
    match bincode::deserialize::<UpgradeableLoaderState>(data)
        .map_err(|e| anyhow!("undecodable ProgramData account: {e}"))?
    {
        UpgradeableLoaderState::ProgramData {
            slot,
            upgrade_authority_address,
        } => Ok((slot, upgrade_authority_address)),
        other => Err(anyhow!(
            "account is not a ProgramData account (got {other:?}); is the program deployed under the upgradeable loader?"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::signature::Signer;
    use solana_sdk::signer::keypair::Keypair;

    #[test]
    fn set_upgrade_authority_matches_the_loaders_own_encoding() {
        let program = Pubkey::new_unique();
        let current = Pubkey::new_unique();
        let new = Pubkey::new_unique();

        let built = build_set_upgrade_authority(&program, &current, &new);

        // Program id: the BPF Upgradeable Loader, not the bridge program.
        assert_eq!(built.program_id, solana_sdk::bpf_loader_upgradeable::id());

        // Accounts: ProgramData (writable, non-signer), current authority
        // (signer, read-only), new authority (read-only, non-signer).
        assert_eq!(built.accounts.len(), 3);

        assert_eq!(built.accounts[0].pubkey, program_data_address(&program));
        assert!(built.accounts[0].is_writable);
        assert!(!built.accounts[0].is_signer);

        assert_eq!(built.accounts[1].pubkey, current);
        assert!(built.accounts[1].is_signer);
        assert!(!built.accounts[1].is_writable);

        assert_eq!(built.accounts[2].pubkey, new);
        assert!(!built.accounts[2].is_signer);
        assert!(!built.accounts[2].is_writable);

        // Instruction data: exactly the loader's own `SetAuthority` encoding.
        let expected = set_upgrade_authority(&program, &current, Some(&new));
        assert_eq!(built.data, expected.data);
        assert_eq!(built, expected);
    }

    #[test]
    fn program_data_decodes_a_mutable_program() {
        let authority = Keypair::new().pubkey();
        let state = UpgradeableLoaderState::ProgramData {
            slot: 42,
            upgrade_authority_address: Some(authority),
        };
        let bytes = bincode::serialize(&state).unwrap();

        let (slot, decoded) = decode_program_data(&bytes).unwrap();
        assert_eq!(slot, 42);
        assert_eq!(decoded, Some(authority));
    }

    #[test]
    fn program_data_decodes_an_immutable_program() {
        let state = UpgradeableLoaderState::ProgramData {
            slot: 7,
            upgrade_authority_address: None,
        };
        let bytes = bincode::serialize(&state).unwrap();

        let (slot, decoded) = decode_program_data(&bytes).unwrap();
        assert_eq!(slot, 7);
        assert_eq!(decoded, None);
    }

    #[test]
    fn a_program_account_is_not_program_data() {
        let state = UpgradeableLoaderState::Program {
            programdata_address: Pubkey::new_unique(),
        };
        let bytes = bincode::serialize(&state).unwrap();
        assert!(decode_program_data(&bytes).is_err());
    }
}
