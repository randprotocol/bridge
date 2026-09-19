//! Account state and program-derived addresses.
//!
//! Every account this program owns is stored as a leading `u8`
//! discriminator followed by the Borsh encoding of the struct below it, so
//! an account's type can be told from its first byte before any
//! deserialization is attempted. The discriminator is a property of the
//! *account*, not a field of the struct: [`BridgeAccount::load`] checks it
//! and [`BridgeAccount::store`] writes it.

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::pubkey::Pubkey;

use crate::error::BridgeError;

/// Solana's chain id in the bridge's chain-id space.
pub const CHAIN_ID: u16 = 5;
/// The consistency level this program stamps on the messages it emits.
pub const CONSISTENCY_LEVEL: u8 = 1;

/// The protocol fee every endpoint launches with: 10 bps of the bridged
/// token, taken on release only (a lock is free). Mirrors `RandBridgeBase`.
pub const DEFAULT_PROTOCOL_FEE_BPS: u16 = 10;
/// The most the admin can ever set it to (1%).
pub const MAX_PROTOCOL_FEE_BPS: u16 = 100;

/// Leading discriminator byte of a [`Config`] account.
pub const DISCRIMINATOR_CONFIG: u8 = 1;
/// Leading discriminator byte of a [`GuardianSetAccount`].
pub const DISCRIMINATOR_GUARDIAN_SET: u8 = 2;
/// Leading discriminator byte of a [`TokenRegistry`] account.
pub const DISCRIMINATOR_TOKEN_REGISTRY: u8 = 3;
/// Leading discriminator byte of a [`Consumed`] account.
pub const DISCRIMINATOR_CONSUMED: u8 = 4;
/// Leading discriminator byte of a [`PostedMessage`] account.
pub const DISCRIMINATOR_POSTED_MESSAGE: u8 = 5;

/// PDA seed prefixes. Kept in one place so the program and its clients
/// derive the same addresses.
pub mod seeds {
    /// Seed of the singleton [`super::Config`] account.
    pub const CONFIG: &[u8] = b"config";
    /// Seed prefix of a [`super::GuardianSetAccount`], followed by the set
    /// index as a little-endian `u32`.
    pub const GUARDIAN: &[u8] = b"guardian";
    /// Seed prefix of a [`super::TokenRegistry`], followed by the mint.
    pub const TOKEN: &[u8] = b"token";
    /// Seed of the custody authority, the signer for custody token
    /// accounts.
    pub const AUTHORITY: &[u8] = b"authority";
    /// Seed prefix of a custody token account, followed by the mint.
    pub const CUSTODY: &[u8] = b"custody";
    /// Seed prefix of a [`super::Consumed`] marker, followed by the
    /// attestation digest.
    pub const SPENT: &[u8] = b"spent";
    /// Seed prefix of a [`super::PostedMessage`], followed by the sequence
    /// number as a little-endian `u64`.
    pub const MSG: &[u8] = b"msg";
}

/// The bridge's singleton configuration account.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct Config {
    /// The account allowed to run privileged instructions.
    pub admin: Pubkey,
    /// An admin transfer in flight; `Pubkey::default()` when none is.
    pub pending_admin: Pubkey,
    /// The account allowed to pause the bridge.
    pub pauser: Pubkey,
    /// Whether redemption and locking are currently halted.
    pub paused: bool,
    /// The Rand-side emitter address whose attestations this program
    /// honors.
    pub rand_emitter: [u8; 32],
    /// The index of the guardian set currently in force.
    pub current_guardian_set: u32,
    /// The next sequence number this program will stamp on an outbound
    /// message.
    pub sequence: u64,
    /// The config PDA's bump seed.
    pub bump: u8,
    /// Protocol fee rate, in basis points of a released amount.
    pub protocol_fee_bps: u16,
}

/// One guardian set: its member keys, indexed `0..n`, and its expiry.
///
/// `expiration_time == 0` means "current, never expires"; a superseded set
/// stays usable until its grace period elapses.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct GuardianSetAccount {
    /// The set's index, matching the `guardian_set_index` of the
    /// attestations it signs.
    pub index: u32,
    /// The guardian addresses, each the last 20 bytes of
    /// `keccak256(uncompressed_pubkey[1..])`.
    pub keys: Vec<[u8; 20]>,
    /// Unix time after which this set is no longer accepted, or 0 for
    /// "never".
    pub expiration_time: u64,
}

/// A registered SPL mint, with its rate limits and custody accounting.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct TokenRegistry {
    /// The SPL mint this entry governs.
    pub mint: Pubkey,
    /// Whether transfers of this token are currently accepted.
    pub enabled: bool,
    /// The mint's decimals, cached to convert to the bridge's 8-decimal
    /// wire amounts.
    pub decimals: u8,
    /// Largest single transfer allowed, in the mint's own units.
    pub per_transfer_cap: u64,
    /// Largest total allowed within one rolling window.
    pub daily_cap: u64,
    /// The rate-limit window this counter belongs to: the *window index*
    /// `unix_timestamp / 86400`, not a unix timestamp. A release resets
    /// `window_used` whenever the current index differs from this one.
    pub window_start: u64,
    /// Amount already moved within the current window.
    pub window_used: u64,
    /// Amount this program currently holds in custody for the mint.
    pub custody: u64,
    /// Protocol fees collected and not yet withdrawn. They sit in the same
    /// token account as custody but are never part of it: `custody` is
    /// exactly what backs the notes on Rand.
    pub accrued_fees: u64,
}

/// Existence of this account marks an attestation digest as redeemed.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct Consumed {
    /// The redeemed attestation's digest.
    pub digest: [u8; 32],
}

/// An outbound message body, stored on chain so guardians read it durably
/// rather than scraping transaction logs.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct PostedMessage {
    /// This message's sequence number.
    pub sequence: u64,
    /// The full encoded attestation body.
    pub body: Vec<u8>,
}

/// An account type this program owns: a discriminator byte plus a Borsh
/// body.
pub trait BridgeAccount: BorshDeserialize + BorshSerialize {
    /// The byte that must lead this account's data.
    const DISCRIMINATOR: u8;

    /// Reads the struct out of raw account data, checking the leading
    /// discriminator byte first.
    fn load(data: &[u8]) -> Result<Self, BridgeError> {
        match data.split_first() {
            Some((&tag, body)) if tag == Self::DISCRIMINATOR => {
                Self::try_from_slice(body).map_err(|_| BridgeError::Truncated)
            }
            _ => Err(BridgeError::InvalidPda),
        }
    }

    /// Writes the discriminator and the Borsh body into raw account data,
    /// which must be large enough to hold both.
    fn store(&self, data: &mut [u8]) -> Result<(), BridgeError> {
        let body = borsh::to_vec(self).map_err(|_| BridgeError::SerializationFailed)?;
        if data.len() < 1 + body.len() {
            return Err(BridgeError::Truncated);
        }
        data[0] = Self::DISCRIMINATOR;
        data[1..1 + body.len()].copy_from_slice(&body);
        Ok(())
    }
}

impl BridgeAccount for Config {
    const DISCRIMINATOR: u8 = DISCRIMINATOR_CONFIG;
}

impl BridgeAccount for GuardianSetAccount {
    const DISCRIMINATOR: u8 = DISCRIMINATOR_GUARDIAN_SET;
}

impl BridgeAccount for TokenRegistry {
    const DISCRIMINATOR: u8 = DISCRIMINATOR_TOKEN_REGISTRY;
}

impl BridgeAccount for Consumed {
    const DISCRIMINATOR: u8 = DISCRIMINATOR_CONSUMED;
}

impl BridgeAccount for PostedMessage {
    const DISCRIMINATOR: u8 = DISCRIMINATOR_POSTED_MESSAGE;
}

/// The singleton config account: seeds `["config"]`.
pub fn config_pda(program: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[seeds::CONFIG], program)
}

/// A guardian set account: seeds `["guardian", index as LE u32]`.
pub fn guardian_pda(program: &Pubkey, index: u32) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[seeds::GUARDIAN, &index.to_le_bytes()], program)
}

/// A token registry entry: seeds `["token", mint]`.
pub fn token_pda(program: &Pubkey, mint: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[seeds::TOKEN, mint.as_ref()], program)
}

/// The custody authority: seeds `["authority"]`.
pub fn authority_pda(program: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[seeds::AUTHORITY], program)
}

/// A custody token account: seeds `["custody", mint]`.
pub fn custody_pda(program: &Pubkey, mint: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[seeds::CUSTODY, mint.as_ref()], program)
}

/// A consumed-digest marker: seeds `["spent", digest]`.
pub fn spent_pda(program: &Pubkey, digest: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[seeds::SPENT, digest], program)
}

/// A posted message: seeds `["msg", sequence as LE u64]`.
pub fn msg_pda(program: &Pubkey, sequence: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[seeds::MSG, &sequence.to_le_bytes()], program)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed, arbitrary program id: PDA derivation only needs *a*
    /// program id, and a constant one keeps the assertions deterministic.
    fn program() -> Pubkey {
        Pubkey::new_from_array([7u8; 32])
    }

    fn sample_config() -> Config {
        Config {
            admin: Pubkey::new_from_array([1u8; 32]),
            pending_admin: Pubkey::default(),
            pauser: Pubkey::new_from_array([2u8; 32]),
            paused: false,
            rand_emitter: [4u8; 32],
            current_guardian_set: 3,
            sequence: 17,
            bump: 254,
            protocol_fee_bps: 10,
        }
    }

    #[test]
    fn pdas_use_the_documented_seeds() {
        let p = program();
        let mint = Pubkey::new_from_array([3u8; 32]);
        let digest = [9u8; 32];

        let expect = |seeds: &[&[u8]]| Pubkey::find_program_address(seeds, &p);
        assert_eq!(config_pda(&p), expect(&[b"config"]));
        assert_eq!(
            guardian_pda(&p, 1),
            expect(&[b"guardian", &1u32.to_le_bytes()])
        );
        assert_eq!(token_pda(&p, &mint), expect(&[b"token", mint.as_ref()]));
        assert_eq!(authority_pda(&p), expect(&[b"authority"]));
        assert_eq!(custody_pda(&p, &mint), expect(&[b"custody", mint.as_ref()]));
        assert_eq!(spent_pda(&p, &digest), expect(&[b"spent", &digest]));
        assert_eq!(msg_pda(&p, 42), expect(&[b"msg", &42u64.to_le_bytes()]));
    }

    #[test]
    fn distinct_inputs_give_distinct_pdas() {
        let p = program();
        assert_ne!(guardian_pda(&p, 0).0, guardian_pda(&p, 1).0);
        assert_ne!(msg_pda(&p, 0).0, msg_pda(&p, 1).0);
        assert_ne!(config_pda(&p).0, authority_pda(&p).0);
        let mint = Pubkey::new_from_array([3u8; 32]);
        assert_ne!(token_pda(&p, &mint).0, custody_pda(&p, &mint).0);
    }

    #[test]
    fn accounts_round_trip_behind_their_discriminator() {
        fn round_trip<T: BridgeAccount + Clone + core::fmt::Debug + PartialEq>(value: T, tag: u8) {
            let mut data = vec![0u8; 1 + borsh::to_vec(&value).expect("serializes").len()];
            value.store(&mut data).expect("stores");
            assert_eq!(data[0], tag);
            assert_eq!(T::load(&data).expect("loads"), value);
            // A body written under someone else's discriminator is
            // refused rather than silently reinterpreted.
            data[0] = tag.wrapping_add(1);
            assert_eq!(T::load(&data).unwrap_err(), BridgeError::InvalidPda);
        }

        round_trip(sample_config(), DISCRIMINATOR_CONFIG);
        round_trip(
            GuardianSetAccount {
                index: 2,
                keys: vec![[1u8; 20], [2u8; 20]],
                expiration_time: 0,
            },
            DISCRIMINATOR_GUARDIAN_SET,
        );
        round_trip(
            TokenRegistry {
                mint: Pubkey::new_from_array([5u8; 32]),
                enabled: true,
                decimals: 6,
                per_transfer_cap: 1_000,
                daily_cap: 10_000,
                window_start: 1,
                window_used: 2,
                custody: 3,
                accrued_fees: 4,
            },
            DISCRIMINATOR_TOKEN_REGISTRY,
        );
        round_trip(Consumed { digest: [8u8; 32] }, DISCRIMINATOR_CONSUMED);
        round_trip(
            PostedMessage {
                sequence: 9,
                body: vec![1, 2, 3],
            },
            DISCRIMINATOR_POSTED_MESSAGE,
        );
    }

    #[test]
    fn store_refuses_an_undersized_account() {
        let config = sample_config();
        let mut too_small = [0u8; 4];
        assert_eq!(
            config.store(&mut too_small).unwrap_err(),
            BridgeError::Truncated
        );
        assert_eq!(Config::load(&[]).unwrap_err(), BridgeError::InvalidPda);
    }

    #[test]
    fn discriminators_and_constants_are_what_the_spec_says() {
        let all = [
            DISCRIMINATOR_CONFIG,
            DISCRIMINATOR_GUARDIAN_SET,
            DISCRIMINATOR_TOKEN_REGISTRY,
            DISCRIMINATOR_CONSUMED,
            DISCRIMINATOR_POSTED_MESSAGE,
        ];
        assert_eq!(all, [1, 2, 3, 4, 5]);
        assert_eq!(CHAIN_ID, bridge_codec::CHAIN_SOLANA);
        assert_eq!(CONSISTENCY_LEVEL, 1);
    }
}
