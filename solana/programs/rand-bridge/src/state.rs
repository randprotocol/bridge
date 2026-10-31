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

/// The largest guardian set this endpoint accepts.
///
/// At `n = 10` the quorum is 7, whose release is 1,231 of the 1,232 bytes a
/// legacy transaction may hold (`tests/sbf_compute.rs`). At `n = 11` it is 8,
/// and the release no longer fits: a set that size would freeze custody until
/// a program upgrade, so it is refused here.
///
/// This differs from the EVM endpoints, whose bound is 255, and `MAX_GUARDIANS`
/// is meant to be a rule of every verifier or none: a knowing exception, pending
/// the owner's decision, because those contracts cannot be upgraded
/// (`docs/architecture.md` §12). `rand-bridge-gov` refuses to build a larger
/// rotation. One built any other way would apply on EVM and be refused here, and
/// releases on this endpoint stop, because burns are attested by a set it does
/// not have, until this program is upgraded and the rotation is applied.
pub const MAX_GUARDIANS: usize = 10;

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

/// Leading discriminator byte of a message page; see [`MESSAGE_PAGE_LEN`].
pub const DISCRIMINATOR_MESSAGE_PAGE: u8 = 6;

/// How many sequences one message page indexes. A lock names the page of the
/// sequence it read, so it fails only if that sequence moves past the end of
/// the page while it is in flight. Part of the on-chain format, repeated in
/// the daemons' Solana source: change both or neither, and never for pages
/// that exist.
pub const MESSAGE_PAGE_SLOTS: u64 = 64;

/// A message page: the discriminator, the page number as a little-endian
/// `u64`, then [`MESSAGE_PAGE_SLOTS`] addresses of 32 bytes each. Slot
/// `sequence % MESSAGE_PAGE_SLOTS` holds the address of the message a
/// `LockKeyed` posted at that sequence; all zeroes means none did.
///
/// It is read and written in place rather than through Borsh: 2 KiB would not
/// survive a trip through the 4 KiB SBF stack frame.
pub const MESSAGE_PAGE_LEN: usize = MESSAGE_PAGE_HEADER + MESSAGE_PAGE_SLOTS as usize * 32;
const MESSAGE_PAGE_HEADER: usize = 1 + 8;

/// The page that indexes `sequence`.
pub const fn message_page(sequence: u64) -> u64 {
    sequence / MESSAGE_PAGE_SLOTS
}

/// Starts page `page` in a newly allocated, zeroed account.
pub fn init_message_page(data: &mut [u8], page: u64) -> Result<(), BridgeError> {
    if data.len() != MESSAGE_PAGE_LEN {
        return Err(BridgeError::Truncated);
    }
    data[0] = DISCRIMINATOR_MESSAGE_PAGE;
    data[1..MESSAGE_PAGE_HEADER].copy_from_slice(&page.to_le_bytes());
    Ok(())
}

/// Records `message` as the account of `sequence`, in the page that indexes it.
/// A sequence is assigned once, so a slot already written is refused.
pub fn set_message_page_slot(
    data: &mut [u8],
    sequence: u64,
    message: &Pubkey,
) -> Result<(), BridgeError> {
    if data.len() != MESSAGE_PAGE_LEN
        || data[0] != DISCRIMINATOR_MESSAGE_PAGE
        || data[1..MESSAGE_PAGE_HEADER] != message_page(sequence).to_le_bytes()
    {
        return Err(BridgeError::InvalidPda);
    }
    let start = MESSAGE_PAGE_HEADER + (sequence % MESSAGE_PAGE_SLOTS) as usize * 32;
    let slot = &mut data[start..start + 32];
    if slot.iter().any(|byte| *byte != 0) {
        return Err(BridgeError::InvalidPda);
    }
    slot.copy_from_slice(message.as_ref());
    Ok(())
}

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
    /// Seed prefix of a [`super::PostedMessage`] posted by `LockKeyed`,
    /// followed by the owner and the nonce as a little-endian `u32`.
    pub const KEYED_MSG: &[u8] = b"keyed-msg";
    /// Seed prefix of a message page, followed by the page number as a
    /// little-endian `u64`.
    pub const MESSAGE_PAGE: &[u8] = b"msg-page";
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

/// A message posted by `LockKeyed`: seeds `["keyed-msg", owner, nonce as LE
/// u32]`. Only `owner` can create it, so nobody can take the address from them.
pub fn keyed_msg_pda(program: &Pubkey, owner: &Pubkey, nonce: u32) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[seeds::KEYED_MSG, owner.as_ref(), &nonce.to_le_bytes()],
        program,
    )
}

/// A message page: seeds `["msg-page", page as LE u64]`.
pub fn message_page_pda(program: &Pubkey, page: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[seeds::MESSAGE_PAGE, &page.to_le_bytes()], program)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed, arbitrary program id: PDA derivation only needs *a*
    /// program id, and a constant one keeps the assertions deterministic.
    fn program() -> Pubkey {
        Pubkey::new_from_array([7u8; 32])
    }

    const LIVE_CONFIG: &str = "AfLAn6N4o937fdUEAAemqQa0qnVwqj5yuP4ixCKe2sFJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABw226UZJIkuPDBH9T4KkKvqnDAIqVVfr9Nu7iqhO+YwwDALfa6cMJFenQGeA2pdJKmrLV9xAdR5iefADpXBVnRXwEAAAAHAAAAAAAAAPwAAA==";
    const LIVE_MESSAGE_6: &str = "BQYAAAAAAAAAuAAAAGq979YAAAAAAAXT5Y8ekxe7w8abY/rf9VjqgrpdAHZfHx5IPXBdIJtBOgAAAAAAAAAGAQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWWgvAM4BDmCv7bInF71jGS9UFFo/llozu4LSxwKess4eIIJkAAUCBtFELeFAp59ZsTfvbrPrpzF7nT8wLOttjN78vAMT4QABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    const LIVE_REGISTRY_USDT: &str = "A84BDmCv7bInF71jGS9UFFo/llozu4LSxwKess4eIIJkAQYA4fUFAAAAAADKmjsAAAAA91AAAAAAAAAAJPQAAAAAAEB4fQEAAAAAqGEAAAAAAAA=";
    const LIVE_REGISTRY_USDC: &str = "A8b6evO+2606PWXzaqvJdDGxu+TC0vbg5HymAgNFL11hAQYA4fUFAAAAAADKmjsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const LIVE_GUARDIAN_SET_0: &str = "AgAAAAAGAAAAW1wAe1Y4tkOh9rPBivsqd4Spoqo/rNr26lm8dc0YtMoYRDRABeZkU4zXR47KcjXopSZdS39jgIbyXMn1doRTR2ebh4wAFkkbGd78Wcg+IPti+j459WY2lV3yKJF+3S6eaPOpV7PxQJrg1bJGcin6dKksUbFfmARFEj23agAAAAA=";
    const LIVE_GUARDIAN_SET_1: &str = "AgEAAAAIAAAAKYUdd7S1sJXNEPha127pF9zw8Ky6VtHOx2tGG3rrBKVZNQliBwtff8Cp/CUM/iro6/tnBHd+a+T74+N0b3GW6ESEFfZnsyzxYuhon5jmqYdNyTJYJmjb/rJMA7InAffpOtUzIG1jlHYnysB7uGPTbgFacUCZpXNZhJ9OniQg4RX6bmcV9TJ5rwpnnDmY//3sdShNd0M0BMHA/J+Qq7WKnAAAAAAAAAAA";

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
        assert_eq!(
            keyed_msg_pda(&p, &mint, 9),
            expect(&[b"keyed-msg", mint.as_ref(), &9u32.to_le_bytes()])
        );
        assert_eq!(
            message_page_pda(&p, 2),
            expect(&[b"msg-page", &2u64.to_le_bytes()])
        );
    }

    /// The addresses on the live program id, which
    /// `the_message_addresses_are_the_programs` in the daemons' tests repeats.
    #[test]
    fn message_addresses_on_the_live_program() {
        let live = Pubkey::from_str_const("FGA3kY3RjfDKjUszJESMYtYXAbsnkFhhoxM3Mb34vycu");
        let owner = Pubkey::new_from_array([7u8; 32]);
        assert_eq!(
            keyed_msg_pda(&live, &owner, 9).0.to_string(),
            "66sKh7F4rtXeHdV1gxeEDG817YVsuVkVSbTajk9yCSFE"
        );
        assert_eq!(
            message_page_pda(&live, 2).0.to_string(),
            "7G8ABWRBDkeEgxTWVoroGLMhKAY4nrXRK9dmq5c6LKxH"
        );
    }

    #[test]
    fn message_pages_index_by_sequence() {
        let message = Pubkey::new_from_array([3u8; 32]);
        let mut data = vec![0u8; MESSAGE_PAGE_LEN];
        assert_eq!(MESSAGE_PAGE_LEN, 2057);
        init_message_page(&mut data, 2).expect("init");
        set_message_page_slot(&mut data, 129, &message).expect("in the page");
        assert_eq!(&data[..9], &[6, 2, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&data[9 + 32..9 + 64], message.as_ref());
        assert!(data[9..9 + 32].iter().all(|b| *b == 0));

        // Once only, and only in its own page.
        let refused = Err(BridgeError::InvalidPda);
        assert_eq!(set_message_page_slot(&mut data, 129, &message), refused);
        assert_eq!(set_message_page_slot(&mut data, 127, &message), refused);
        assert_eq!(set_message_page_slot(&mut data, 192, &message), refused);
        assert_eq!(set_message_page_slot(&mut [0u8; 9], 0, &message), refused);
        assert_eq!(
            init_message_page(&mut [0u8; 9], 0),
            Err(BridgeError::Truncated)
        );
    }

    #[test]
    fn distinct_inputs_give_distinct_pdas() {
        let p = program();
        assert_ne!(guardian_pda(&p, 0).0, guardian_pda(&p, 1).0);
        assert_ne!(msg_pda(&p, 0).0, msg_pda(&p, 1).0);
        let owner = Pubkey::new_from_array([4u8; 32]);
        assert_ne!(
            keyed_msg_pda(&p, &owner, 0).0,
            keyed_msg_pda(&p, &owner, 1).0
        );
        assert_ne!(keyed_msg_pda(&p, &owner, 0).0, keyed_msg_pda(&p, &p, 0).0);
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

    /// Bytes read from mainnet at `finalized` on 2026-10-31: one of every
    /// layout that can be loaded and written back. An upgrade must keep
    /// reading exactly these, and `load` refuses trailing bytes, so no struct
    /// here may grow. `Consumed` is 32 bytes behind its discriminator and
    /// nothing reads one back.
    #[test]
    fn mainnet_accounts_keep_deserialising() {
        use base64::Engine;
        let decode = |text: &str| {
            base64::engine::general_purpose::STANDARD
                .decode(text)
                .expect("base64")
        };
        let data = decode(LIVE_CONFIG);
        assert_eq!(data.len(), 145);
        let config = Config::load(&data).expect("the live config");
        assert_eq!((config.current_guardian_set, config.sequence), (1, 7));
        assert_eq!((config.bump, config.protocol_fee_bps), (252, 0));
        let live = Pubkey::from_str_const("FGA3kY3RjfDKjUszJESMYtYXAbsnkFhhoxM3Mb34vycu");
        assert_eq!(config_pda(&live).1, config.bump);
        let mut stored = vec![0u8; data.len()];
        config.store(&mut stored).expect("stores");
        assert_eq!(stored, data);

        let data = decode(LIVE_MESSAGE_6);
        assert_eq!(data.len(), 197);
        let message = PostedMessage::load(&data).expect("the live message");
        assert_eq!(message.sequence, 6);
        assert_eq!(message.body.len(), 184);

        let usdt = Pubkey::from_str_const("Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB");
        let data = decode(LIVE_REGISTRY_USDT);
        assert_eq!(data.len(), 83);
        let registry = TokenRegistry::load(&data).expect("the live USDT registry");
        assert_eq!(registry.mint, usdt);
        assert!(registry.enabled);
        assert_eq!((registry.decimals, registry.custody), (6, 25_000_000));
        assert_eq!(registry.accrued_fees, 25_000);
        let mut stored = vec![0u8; data.len()];
        registry.store(&mut stored).expect("stores");
        assert_eq!(stored, data);

        let usdc = Pubkey::from_str_const("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
        let registry =
            TokenRegistry::load(&decode(LIVE_REGISTRY_USDC)).expect("the live USDC registry");
        assert_eq!((registry.mint, registry.custody), (usdc, 0));

        // Set 0 was superseded and has an expiry; set 1 is in force and has
        // none. An expiry is written back in place, so both shapes matter.
        for (text, len, index, keys, expiration_time) in [
            (LIVE_GUARDIAN_SET_0, 137, 0, 6, 1_790_393_618),
            (LIVE_GUARDIAN_SET_1, 177, 1, 8, 0),
        ] {
            let data = decode(text);
            assert_eq!(data.len(), len);
            let set = GuardianSetAccount::load(&data).expect("a live guardian set");
            assert_eq!(set.index, index);
            assert_eq!(set.keys.len(), keys);
            assert_eq!(set.expiration_time, expiration_time);
            assert!(set.keys.len() <= MAX_GUARDIANS);
            let mut stored = vec![0u8; data.len()];
            set.store(&mut stored).expect("stores");
            assert_eq!(stored, data);
        }
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
            DISCRIMINATOR_MESSAGE_PAGE,
        ];
        assert_eq!(all, [1, 2, 3, 4, 5, 6]);
        assert_eq!(CHAIN_ID, bridge_codec::CHAIN_SOLANA);
        assert_eq!(CONSISTENCY_LEVEL, 1);
    }
}
