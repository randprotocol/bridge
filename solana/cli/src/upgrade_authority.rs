//! BR-3: handing the program's BPF Upgradeable Loader authority to a new
//! key (a Squads vault, in production), and reading it back.
//!
//! Pure, unit-tested helpers only; `main.rs` does the RPC and confirmation
//! dance around them (`set-upgrade-authority`, and `show`'s extra field).

use anyhow::{anyhow, bail, Result};
use solana_loader_v3_interface::instruction::set_upgrade_authority;
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use solana_sdk::instruction::Instruction;
use solana_sdk::pubkey::Pubkey;

/// The BPF Upgradeable Loader's ProgramData PDA for `program`: `[program]`
/// under `bpf_loader_upgradeable`. Re-exported from `rand_bridge` so the
/// CLI and the program derive the same address from one place.
pub use rand_bridge::instruction::program_data_address;

/// The Squads v4 program.
pub const SQUADS_PROGRAM_ID: &str = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf";

/// Derives a Squads v4 multisig's vault PDA: `["multisig", ms, "vault",
/// [index]]` under the Squads program. Vault 0 is the multisig's default
/// spending/voting vault; a multisig may have several.
pub fn squads_vault_pda(multisig: &Pubkey, vault_index: u8) -> Pubkey {
    let squads_program: Pubkey = SQUADS_PROGRAM_ID
        .parse()
        .expect("SQUADS_PROGRAM_ID is a valid base58 pubkey");
    Pubkey::find_program_address(
        &[b"multisig", multisig.as_ref(), b"vault", &[vault_index]],
        &squads_program,
    )
    .0
}

/// Refuses an on-curve `new` upgrade authority. A Squads vault (or any
/// PDA) is never on the Ed25519 curve, so an on-curve key is almost
/// certainly a wallet given by mistake rather than a vault.
pub fn check_not_on_curve(new: &Pubkey) -> Result<()> {
    if new.is_on_curve() {
        bail!(
            "{new} is on the Ed25519 curve; a Squads vault is a PDA and is never on the curve. Pass --allow-on-curve to override."
        );
    }
    Ok(())
}

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

/// The upgrade authority moves last and only to a vault whose multisig is at
/// least this strict: 2 signatures, and the design's 48 h time lock.
pub const MIN_SQUADS_THRESHOLD: u16 = 2;
pub const MIN_SQUADS_TIME_LOCK_SECS: u32 = 172_800;

/// The fields of a Squads v4 `Multisig` account this CLI checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SquadsMultisig {
    pub create_key: Pubkey,
    pub config_authority: Pubkey,
    pub threshold: u16,
    pub time_lock: u32,
    pub members: usize,
}

/// A Squads v4 `Multisig` account (`state/multisig.rs`): the Anchor
/// discriminator `sha256("account:Multisig")[..8]`, then Borsh: create_key,
/// config_authority, threshold u16, time_lock u32, transaction_index u64,
/// stale_transaction_index u64, rent_collector `Option<Pubkey>`, bump u8,
/// members `Vec<{key, permissions u8}>`. The same decoder as
/// `daemons/src/gov_audit.rs` `decode_squads_multisig`.
pub fn decode_squads_multisig(data: &[u8]) -> Result<SquadsMultisig> {
    let mut at = 0usize;
    let mut take = |n: usize| -> Result<&[u8]> {
        let out = data
            .get(at..at + n)
            .ok_or_else(|| anyhow!("Squads multisig account too short at byte {at}"))?;
        at += n;
        Ok(out)
    };
    let discriminator = solana_sdk::hash::hash(b"account:Multisig");
    if take(8)? != &discriminator.as_ref()[..8] {
        bail!("not a Squads v4 Multisig account (discriminator)");
    }
    let key = |b: &[u8]| Pubkey::try_from(b).expect("32 bytes");
    let create_key = key(take(32)?);
    let config_authority = key(take(32)?);
    let threshold = u16::from_le_bytes(take(2)?.try_into().expect("2"));
    let time_lock = u32::from_le_bytes(take(4)?.try_into().expect("4"));
    take(16)?; // transaction_index, stale_transaction_index
    match take(1)?[0] {
        0 => {}
        1 => {
            take(32)?;
        }
        t => bail!("bad Option tag {t} for rent_collector"),
    }
    take(1)?; // bump
    let members = u32::from_le_bytes(take(4)?.try_into().expect("4")) as usize;
    if members > data.len() / 33 {
        bail!("member count {members} does not fit the account");
    }
    take(33 * members)?;
    Ok(SquadsMultisig {
        create_key,
        config_authority,
        threshold,
        time_lock,
        members,
    })
}

/// The multisig behind the vault that will hold the upgrade authority:
/// owned by Squads v4, autonomous (no `config_authority`, which could change
/// members, threshold and time lock without a vote), `threshold >= 2` and no
/// more than its members, `time_lock >= 172800` s.
pub fn check_squads_multisig(owner: &Pubkey, data: &[u8]) -> Result<SquadsMultisig> {
    let squads: Pubkey = SQUADS_PROGRAM_ID.parse().expect("a pubkey");
    if *owner != squads {
        bail!("--squads-multisig is not owned by Squads v4 ({squads}) but by {owner}");
    }
    let ms = decode_squads_multisig(data)?;
    if ms.config_authority != Pubkey::default() {
        bail!(
            "the Squads multisig is controlled: config_authority {} can change it without a vote; create it autonomous",
            ms.config_authority
        );
    }
    if ms.threshold < MIN_SQUADS_THRESHOLD || usize::from(ms.threshold) > ms.members {
        bail!(
            "the Squads multisig threshold is {} of {} members; need at least {MIN_SQUADS_THRESHOLD} and no more than the members",
            ms.threshold,
            ms.members
        );
    }
    if ms.time_lock < MIN_SQUADS_TIME_LOCK_SECS {
        bail!(
            "the Squads multisig time_lock is {} s; need at least {MIN_SQUADS_TIME_LOCK_SECS} s (48 h)",
            ms.time_lock
        );
    }
    Ok(ms)
}

/// The upgrade authority is the last step: the bridge's admin must already be
/// the vault, with no admin transfer in flight. Until then a mistake is still
/// recoverable by the old upgrade authority.
pub fn check_admin_handed_over(config: &rand_bridge::state::Config, new: &Pubkey) -> Result<()> {
    if config.admin != *new {
        bail!(
            "the bridge admin is {}, not {new}: finish the admin handover (transfer-admin, then AcceptAdmin from the vault) first; the upgrade authority moves last",
            config.admin
        );
    }
    if config.pending_admin != Pubkey::default() {
        bail!(
            "pending_admin is {}: an admin transfer is in flight; cancel or finish it first",
            config.pending_admin
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use solana_sdk::signature::Signer;
    use solana_sdk::signer::keypair::Keypair;

    /// Mainnet Squads v4 multisig 5qprF75BYaQvgYq1dVUgAEkUczW5DhiuNn7ahiYu6FR6
    /// (getAccountInfo, 2026-09-25; threshold 2 of 4, time_lock 0, autonomous),
    /// the audit's fixture.
    fn ms_5qpr() -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(
                include_str!(
                    "../../../daemons/tests/fixtures/squads-v4-multisig-5qprF75BYaQvgYq1dVUgAEkUczW5DhiuNn7ahiYu6FR6.b64"
                )
                .trim(),
            )
            .unwrap()
    }

    /// The fixture with threshold 3 (bytes 72..74, after the 8-byte
    /// discriminator, create_key and config_authority) and its time lock
    /// (bytes 74..78) set.
    fn with_time_lock(mut data: Vec<u8>, secs: u32) -> Vec<u8> {
        data[72..74].copy_from_slice(&3u16.to_le_bytes());
        data[74..78].copy_from_slice(&secs.to_le_bytes());
        data
    }

    fn squads() -> Pubkey {
        SQUADS_PROGRAM_ID.parse().unwrap()
    }

    #[test]
    fn decodes_the_mainnet_squads_multisig_fixture() {
        let ms = decode_squads_multisig(&ms_5qpr()).unwrap();
        assert_eq!((ms.threshold, ms.time_lock, ms.members), (2, 0, 4));
        assert_eq!(ms.config_authority, Pubkey::default());
        // It is the multisig PDA of its own create_key.
        let (pda, _) = Pubkey::find_program_address(
            &[b"multisig", b"multisig", ms.create_key.as_ref()],
            &squads(),
        );
        assert_eq!(
            pda,
            "5qprF75BYaQvgYq1dVUgAEkUczW5DhiuNn7ahiYu6FR6"
                .parse::<Pubkey>()
                .unwrap()
        );
        let mut bad = ms_5qpr();
        bad[0] ^= 1;
        assert!(decode_squads_multisig(&bad).is_err(), "discriminator");
        assert!(
            decode_squads_multisig(&ms_5qpr()[..90]).is_err(),
            "truncated"
        );
    }

    #[test]
    fn the_squads_multisig_must_be_autonomous_2_of_n_and_time_locked() {
        let good = with_time_lock(ms_5qpr(), 172_800);
        let ms = check_squads_multisig(&squads(), &good).unwrap();
        assert_eq!((ms.threshold, ms.time_lock), (3, 172_800));

        // The fixture as it is: no time lock.
        let err = check_squads_multisig(&squads(), &ms_5qpr())
            .unwrap_err()
            .to_string();
        assert!(err.contains("time_lock"), "{err}");
        assert!(check_squads_multisig(&squads(), &with_time_lock(ms_5qpr(), 172_799)).is_err());
        // Not owned by Squads v4.
        let err = check_squads_multisig(&Pubkey::new_unique(), &good)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not owned by Squads"), "{err}");
        // A controlled multisig: its config_authority changes members, threshold and time lock alone.
        let mut controlled = good.clone();
        controlled[40..72].copy_from_slice(Pubkey::new_unique().as_ref());
        let err = check_squads_multisig(&squads(), &controlled)
            .unwrap_err()
            .to_string();
        assert!(err.contains("config_authority"), "{err}");
        // Threshold 1 is a key; more than the members is unusable.
        let mut one = good.clone();
        one[72..74].copy_from_slice(&1u16.to_le_bytes());
        let err = check_squads_multisig(&squads(), &one)
            .unwrap_err()
            .to_string();
        assert!(err.contains("threshold"), "{err}");
        let mut five = good;
        five[72..74].copy_from_slice(&5u16.to_le_bytes());
        assert!(check_squads_multisig(&squads(), &five).is_err(), "5 of 4");
    }

    fn config(admin: Pubkey, pending_admin: Pubkey) -> rand_bridge::state::Config {
        rand_bridge::state::Config {
            admin,
            pending_admin,
            pauser: Pubkey::new_unique(),
            paused: false,
            rand_emitter: [7; 32],
            current_guardian_set: 0,
            sequence: 0,
            bump: 255,
            protocol_fee_bps: 10,
        }
    }

    #[test]
    fn the_upgrade_authority_moves_only_after_the_admin_did() {
        let vault = Pubkey::new_unique();
        assert!(check_admin_handed_over(&config(vault, Pubkey::default()), &vault).is_ok());
        let err = check_admin_handed_over(&config(Pubkey::new_unique(), vault), &vault)
            .unwrap_err()
            .to_string();
        assert!(err.contains("admin"), "{err}");
        let err = check_admin_handed_over(&config(vault, Pubkey::new_unique()), &vault)
            .unwrap_err()
            .to_string();
        assert!(err.contains("pending_admin"), "{err}");
    }

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

        // Instruction data: exactly the loader's own `SetAuthority` encoding,
        // pinned independently of the SDK builder: bincode's 4-byte
        // little-endian enum index, 4 (SetAuthority is the 5th variant).
        let expected = set_upgrade_authority(&program, &current, Some(&new));
        assert_eq!(built.data, expected.data);
        assert_eq!(built.data, vec![4u8, 0, 0, 0]);
        assert_eq!(built, expected);
    }

    #[test]
    fn program_data_decodes_a_mutable_program() {
        let authority = Keypair::new().pubkey();
        let state = UpgradeableLoaderState::ProgramData {
            slot: 42,
            upgrade_authority_address: Some(authority),
        };
        // A real ProgramData account is the bincode header followed by the
        // program's own executable bytes; the decoder must ignore them.
        let mut bytes = bincode::serialize(&state).unwrap();
        bytes.extend(std::iter::repeat(0xAB).take(100));

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
        let mut bytes = bincode::serialize(&state).unwrap();
        bytes.extend(std::iter::repeat(0xCD).take(100));

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

    #[test]
    fn squads_vault_pda_matches_a_known_vector_and_differs_from_the_multisig() {
        let multisig = Pubkey::new_unique();
        let squads_program: Pubkey = SQUADS_PROGRAM_ID.parse().unwrap();
        let (expected, _) = Pubkey::find_program_address(
            &[b"multisig", multisig.as_ref(), b"vault", &[0u8]],
            &squads_program,
        );

        let vault = squads_vault_pda(&multisig, 0);
        assert_eq!(vault, expected);
        assert_ne!(vault, multisig);

        // A different index derives a different vault.
        assert_ne!(squads_vault_pda(&multisig, 1), vault);
    }

    #[test]
    fn an_on_curve_key_is_refused_but_a_pda_passes() {
        let on_curve = Keypair::new().pubkey();
        assert!(check_not_on_curve(&on_curve).is_err());

        let (pda, _) = Pubkey::find_program_address(&[b"whatever"], &rand_bridge::id());
        assert!(!pda.is_on_curve());
        assert!(check_not_on_curve(&pda).is_ok());
    }
}
