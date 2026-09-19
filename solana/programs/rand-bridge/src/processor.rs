//! Instruction dispatch and the rules of design Section 5.1.
//!
//! This is the Solana half of a multi-chain endpoint: it must accept and
//! reject exactly what `evm/src/RandBridgeBase.sol` does, in the same
//! order, so a relayer sees the same failure whichever chain it submits
//! to. Where the two differ it is because Solana forces it — accounts are
//! passed in rather than looked up, so every one of them is re-derived
//! and compared here, and amounts are `u64` rather than `uint256`, so the
//! denormalisation can overflow.
//!
//! Two invariants hold across every path:
//!
//! - **Effects before interactions.** A release marks the digest consumed
//!   and decrements custody *before* any token CPI, so nothing reachable
//!   from a token program can replay an attestation.
//! - **Custody soundness.** `TokenRegistry::custody` is this program's own
//!   count of what it holds for a mint, and no release may exceed it,
//!   independently of the guardian set (paper `thm:custodysoundness`).

use borsh::BorshDeserialize;
use bridge_codec::{Body, Payload, Transfer, CHAIN_RAND, GOVERNANCE_EMITTER, GUARDIAN_GRACE_SECS};
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use solana_program::account_info::{next_account_info, AccountInfo};
use solana_program::clock::Clock;
use solana_program::entrypoint::ProgramResult;
use solana_program::program::{invoke, invoke_signed};
use solana_program::program_error::ProgramError;
use solana_program::program_pack::Pack;
use solana_program::pubkey::Pubkey;
use solana_program::rent::Rent;
use solana_program::sysvar::Sysvar;
use solana_program::{msg, sysvar};
use solana_sdk_ids::{bpf_loader_upgradeable, system_program};
use solana_system_interface::instruction as system_instruction;

use crate::attestation;
use crate::error::BridgeError;
use crate::instruction::{associated_token_address, program_data_address, BridgeInstruction};
use crate::state::{
    authority_pda, config_pda, custody_pda, guardian_pda, msg_pda, seeds, spent_pda, token_pda,
    BridgeAccount, Config, Consumed, GuardianSetAccount, PostedMessage, TokenRegistry, CHAIN_ID,
    CONSISTENCY_LEVEL, DEFAULT_PROTOCOL_FEE_BPS, MAX_PROTOCOL_FEE_BPS,
};

/// The largest mint `decimals` this program will whitelist.
///
/// Mirrors `RandBridgeBase.MAX_DECIMALS`: `10 ** (decimals - 8)` has to
/// stay inside the `u128` the normalisation runs in, and no real token is
/// anywhere near this. The bound only stops `SetToken` from registering a
/// mint whose every transfer would overflow.
pub const MAX_DECIMALS: u8 = 36;

/// Length of the rolling rate-limit window, in seconds.
pub const SECONDS_PER_DAY: u64 = 86_400;

/// The largest attested (8-decimal) amount a single lock may publish:
/// `u64::MAX`, the width of a Rand note's amount field. Rand rejects
/// anything above it (`BridgeError::AmountTooLarge` there), so the
/// program must too, or the locked tokens could never be minted or
/// released. Mirrors `RandBridgeBase.MAX_ATTESTED_AMOUNT`.
pub const MAX_ATTESTED_AMOUNT: u128 = u64::MAX as u128;

/// Dispatches a Borsh-encoded [`BridgeInstruction`].
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = BridgeInstruction::try_from_slice(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    match instruction {
        BridgeInstruction::Initialize {
            admin,
            pauser,
            rand_emitter,
            guardians,
        } => process_initialize(program_id, accounts, admin, pauser, rand_emitter, guardians),
        BridgeInstruction::SetToken {
            enabled,
            per_transfer_cap,
            daily_cap,
        } => process_set_token(program_id, accounts, enabled, per_transfer_cap, daily_cap),
        BridgeInstruction::Lock {
            amount,
            rand_recipient,
            relayer_fee,
            nonce,
        } => process_lock(
            program_id,
            accounts,
            amount,
            rand_recipient,
            relayer_fee,
            nonce,
        ),
        BridgeInstruction::Release { attestation } => {
            process_release(program_id, accounts, &attestation)
        }
        BridgeInstruction::GuardianSetUpgrade { attestation } => {
            process_guardian_set_upgrade(program_id, accounts, &attestation)
        }
        BridgeInstruction::Pause => process_pause(program_id, accounts),
        BridgeInstruction::Unpause => process_unpause(program_id, accounts),
        BridgeInstruction::TransferAdmin { to } => process_transfer_admin(program_id, accounts, to),
        BridgeInstruction::AcceptAdmin => process_accept_admin(program_id, accounts),
        BridgeInstruction::SetProtocolFee { bps } => {
            process_set_protocol_fee(program_id, accounts, bps)
        }
        BridgeInstruction::WithdrawFees { amount } => {
            process_withdraw_fees(program_id, accounts, amount)
        }
    }
}

// ----------------------------------------------------------------------
// shared helpers
// ----------------------------------------------------------------------

/// Every account this program is handed is re-derived and compared, so a
/// caller cannot substitute one PDA for another (or a look-alike account
/// of its own) and have the program read or write the wrong state.
fn check_key(actual: &Pubkey, expected: &Pubkey) -> Result<(), BridgeError> {
    if actual == expected {
        Ok(())
    } else {
        Err(BridgeError::InvalidPda)
    }
}

/// The two associated token accounts a release pays into get their own
/// error, because a mismatch there means the *caller* named the wrong
/// wallet's account rather than passing the wrong kind of PDA.
fn check_ata(actual: &Pubkey, wallet: &Pubkey, mint: &Pubkey) -> Result<(), BridgeError> {
    if *actual == associated_token_address(wallet, mint) {
        Ok(())
    } else {
        Err(BridgeError::InvalidAta)
    }
}

fn check_signer(account: &AccountInfo) -> Result<(), ProgramError> {
    if account.is_signer {
        Ok(())
    } else {
        Err(ProgramError::MissingRequiredSignature)
    }
}

/// Reads one of this program's accounts, checking that the program owns
/// it before trusting the discriminator inside it.
fn load<T: BridgeAccount>(account: &AccountInfo, program_id: &Pubkey) -> Result<T, BridgeError> {
    if account.owner != program_id {
        return Err(BridgeError::InvalidPda);
    }
    let data = account.data.borrow();
    T::load(&data)
}

/// Writes one of this program's accounts back in place. Only ever called
/// on an account whose encoding cannot grow (`Config`, `TokenRegistry`,
/// and a `GuardianSetAccount` gaining an expiry), so the account is
/// always large enough.
fn store<T: BridgeAccount>(value: &T, account: &AccountInfo) -> Result<(), BridgeError> {
    let mut data = account.data.borrow_mut();
    value.store(&mut data)
}

/// Creates a rent-exempt account at a PDA this program derives.
///
/// `seeds` must end with the bump, since the system program requires the
/// PDA itself to sign its own creation.
///
/// # Griefing
///
/// Every address this program creates is derived from public data — an
/// attestation digest, the next sequence number, the next guardian set
/// index, a mint — so anyone can compute it before the program gets
/// there and send it a lamport. `CreateAccount` refuses to act on an
/// account that already holds lamports, so a single lamport sent to
/// `["spent", digest]` would make a fully signed release permanently
/// unredeemable, one sent to `["msg", sequence]` would brick every
/// subsequent lock, and one sent to `["guardian", current + 1]` would
/// block guardian rotation.
///
/// So the pre-funded case is handled rather than refused: top the
/// account up to rent exemption if it is short, then `Allocate` and
/// `Assign` it with the PDA's own signature, which is exactly what
/// `CreateAccount` does internally and reaches the same end state. Any
/// lamports the griefer donated simply stay in the account.
///
/// The account must still be empty and system-owned, so this can never
/// re-target an account that is already in use.
fn create_pda_account<'a>(
    payer: &AccountInfo<'a>,
    account: &AccountInfo<'a>,
    system_program_account: &AccountInfo<'a>,
    owner: &Pubkey,
    space: usize,
    seeds: &[&[u8]],
) -> ProgramResult {
    if !account.data_is_empty() || account.owner != &system_program::id() {
        return Err(BridgeError::InvalidPda.into());
    }
    let required = Rent::get()?.minimum_balance(space).max(1);
    let held = account.lamports();
    let infos = [
        payer.clone(),
        account.clone(),
        system_program_account.clone(),
    ];

    if held == 0 {
        return invoke_signed(
            &system_instruction::create_account(
                payer.key,
                account.key,
                required,
                space as u64,
                owner,
            ),
            &infos,
            &[seeds],
        );
    }

    if let Some(shortfall) = required.checked_sub(held).filter(|missing| *missing > 0) {
        invoke(
            &system_instruction::transfer(payer.key, account.key, shortfall),
            &infos,
        )?;
    }
    invoke_signed(
        &system_instruction::allocate(account.key, space as u64),
        &infos,
        &[seeds],
    )?;
    invoke_signed(
        &system_instruction::assign(account.key, owner),
        &infos,
        &[seeds],
    )
}

/// Creates a PDA sized exactly for `value` and writes `value` into it.
fn create_state<'a, T: BridgeAccount>(
    value: &T,
    account: &AccountInfo<'a>,
    payer: &AccountInfo<'a>,
    system_program_account: &AccountInfo<'a>,
    program_id: &Pubkey,
    seeds: &[&[u8]],
) -> ProgramResult {
    let body = borsh::to_vec(value).map_err(|_| BridgeError::SerializationFailed)?;
    create_pda_account(
        payer,
        account,
        system_program_account,
        program_id,
        1 + body.len(),
        seeds,
    )?;
    store(value, account)?;
    Ok(())
}

/// `10 ** |decimals - 8|`, the factor between a mint's own units and the
/// attestation's 8 decimals.
fn scale(decimals: u8) -> Result<u128, BridgeError> {
    let exponent = decimals.abs_diff(8);
    10u128
        .checked_pow(u32::from(exponent))
        .ok_or(BridgeError::AmountOverflow)
}

/// Design Section 3.7. `locked` is what the caller actually parts with
/// (the remainder below one attestable unit stays with them); `attested`
/// is the 8-decimal value the guardians sign.
fn normalize(amount: u64, decimals: u8) -> Result<(u64, u128), BridgeError> {
    let factor = scale(decimals)?;
    if decimals > 8 {
        let attested = u128::from(amount) / factor;
        // `attested * factor <= amount`, so this cannot exceed a u64.
        let locked = attested
            .checked_mul(factor)
            .and_then(|l| u64::try_from(l).ok())
            .ok_or(BridgeError::AmountOverflow)?;
        Ok((locked, attested))
    } else {
        let attested = u128::from(amount)
            .checked_mul(factor)
            .ok_or(BridgeError::AmountOverflow)?;
        Ok((amount, attested))
    }
}

/// `bps` basis points of `amount`, rounded down. `bps <= 10_000` always
/// (it is capped at `MAX_PROTOCOL_FEE_BPS`), so the result is `<= amount`.
fn protocol_fee_of(amount: u64, bps: u16) -> u64 {
    (u128::from(amount) * u128::from(bps) / 10_000) as u64
}

/// The inverse of [`normalize`]: an 8-decimal wire amount back into the
/// mint's own units. Unlike EVM's `uint256`, the result has to fit a
/// `u64`.
fn denormalize(attested: u128, decimals: u8) -> Result<u64, BridgeError> {
    let factor = scale(decimals)?;
    let native = if decimals > 8 {
        attested
            .checked_mul(factor)
            .ok_or(BridgeError::AmountOverflow)?
    } else {
        attested / factor
    };
    u64::try_from(native).map_err(|_| BridgeError::AmountOverflow)
}

/// A guardian set must be non-empty, hold no zero key (the address a
/// malformed signature recovers to) and no duplicate (which would let one
/// key count twice towards quorum). Mirrors `RandBridgeBase._checkKeys`.
fn check_guardian_keys(keys: &[[u8; 20]]) -> Result<(), BridgeError> {
    if keys.is_empty() {
        return Err(BridgeError::ZeroAddress);
    }
    for (i, key) in keys.iter().enumerate() {
        if *key == [0u8; 20] {
            return Err(BridgeError::ZeroAddress);
        }
        if keys[i + 1..].contains(key) {
            return Err(BridgeError::DuplicateGuardian);
        }
    }
    Ok(())
}

/// The guardian set index in an attestation's envelope, read without
/// decoding the rest of it: the index selects *which* guardian set
/// account the caller must have passed, so it has to be known before the
/// set can be loaded and the signatures checked.
///
/// Reports the same two errors the full decoder would for these bytes, in
/// the same order.
fn envelope_guardian_set_index(bytes: &[u8]) -> Result<u32, BridgeError> {
    if bytes.is_empty() {
        return Err(BridgeError::Truncated);
    }
    if bytes[0] != bridge_codec::VERSION {
        return Err(BridgeError::BadVersion);
    }
    let index: [u8; 4] = bytes
        .get(1..5)
        .and_then(|s| s.try_into().ok())
        .ok_or(BridgeError::Truncated)?;
    Ok(u32::from_be_bytes(index))
}

/// The current unix time, as the `u64` every expiry and window
/// computation here uses.
fn now_from(clock: &AccountInfo) -> Result<u64, ProgramError> {
    let clock = Clock::from_account_info(clock)?;
    u64::try_from(clock.unix_timestamp).map_err(|_| BridgeError::AmountOverflow.into())
}

/// The custody token account for `mint`, with everything about it
/// re-checked rather than inferred from the PDA derivation alone: the SPL
/// token program owns the account, its SPL authority is this program's
/// custody authority PDA, and it holds the mint the caller named.
///
/// Defence in depth. The address is already derived from
/// `["custody", mint]`, so none of these can differ unless `SetToken`
/// initialized the account wrongly — but custody is the one balance the
/// whole bridge's soundness rests on, so it is verified on every path
/// that reads or moves it.
fn custody_state(
    account: &AccountInfo,
    program_id: &Pubkey,
    mint: &Pubkey,
) -> Result<spl_token::state::Account, ProgramError> {
    if account.owner != &spl_token::id() {
        return Err(BridgeError::InvalidPda.into());
    }
    let data = account.data.borrow();
    let token = spl_token::state::Account::unpack(&data)?;
    if token.owner != authority_pda(program_id).0 || token.mint != *mint {
        return Err(BridgeError::InvalidPda.into());
    }
    Ok(token)
}

/// Requires `payer` to be the signer named as this program's upgrade
/// authority.
///
/// `Initialize` installs the admin, the pauser, the Rand emitter and
/// guardian set 0, so without this anyone watching the mempool could run
/// it first on a freshly deployed program and own the bridge. The upgrade
/// authority is the only identity that exists before the config does, and
/// whoever holds it could replace the program wholesale anyway, so
/// binding deployment to it grants nothing new.
fn check_upgrade_authority(
    program_data: &AccountInfo,
    program_id: &Pubkey,
    payer: &AccountInfo,
) -> ProgramResult {
    check_key(program_data.key, &program_data_address(program_id))?;
    if program_data.owner != &bpf_loader_upgradeable::id() {
        return Err(BridgeError::NotAdmin.into());
    }
    let data = program_data.data.borrow();
    // The ProgramData metadata is followed by the raw ELF; bincode 1's
    // `deserialize` allows the trailing bytes.
    let state: UpgradeableLoaderState =
        bincode::deserialize(&data).map_err(|_| BridgeError::NotAdmin)?;
    match state {
        UpgradeableLoaderState::ProgramData {
            upgrade_authority_address: Some(authority),
            ..
        } if authority == *payer.key => Ok(()),
        // No authority (the program is frozen) or a different one.
        _ => Err(BridgeError::NotAdmin.into()),
    }
}

/// Moves `amount` out of custody, signed by the custody authority PDA.
fn transfer_from_custody<'a>(
    custody: &AccountInfo<'a>,
    destination: &AccountInfo<'a>,
    authority: &AccountInfo<'a>,
    token_program: &AccountInfo<'a>,
    amount: u64,
    authority_bump: u8,
) -> ProgramResult {
    invoke_signed(
        &spl_token::instruction::transfer(
            &spl_token::id(),
            custody.key,
            destination.key,
            authority.key,
            &[],
            amount,
        )?,
        &[
            custody.clone(),
            destination.clone(),
            authority.clone(),
            token_program.clone(),
        ],
        &[&[seeds::AUTHORITY, &[authority_bump]]],
    )
}

/// Loads the config, having first checked that the account really is the
/// config PDA.
fn load_config(account: &AccountInfo, program_id: &Pubkey) -> Result<Config, BridgeError> {
    check_key(account.key, &config_pda(program_id).0)?;
    load(account, program_id)
}

/// Loads a token registry, having checked both the PDA and that the entry
/// is the one for `mint`.
fn load_registry(
    account: &AccountInfo,
    program_id: &Pubkey,
    mint: &Pubkey,
) -> Result<TokenRegistry, BridgeError> {
    check_key(account.key, &token_pda(program_id, mint).0)?;
    let registry: TokenRegistry = load(account, program_id)?;
    check_key(&registry.mint, mint)?;
    Ok(registry)
}

// ----------------------------------------------------------------------
// Initialize
// ----------------------------------------------------------------------

fn process_initialize(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    admin: Pubkey,
    pauser: Pubkey,
    rand_emitter: [u8; 32],
    guardians: Vec<[u8; 20]>,
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let payer = next_account_info(iter)?;
    let config_account = next_account_info(iter)?;
    let set_account = next_account_info(iter)?;
    let authority_account = next_account_info(iter)?;
    let program_data_account = next_account_info(iter)?;
    let system_account = next_account_info(iter)?;

    check_signer(payer)?;
    check_key(system_account.key, &system_program::id())?;
    let (config_key, config_bump) = config_pda(program_id);
    check_key(config_account.key, &config_key)?;
    let (set_key, set_bump) = guardian_pda(program_id, 0);
    check_key(set_account.key, &set_key)?;
    check_key(authority_account.key, &authority_pda(program_id).0)?;

    // Authenticate before doing anything else: `Initialize` is the one
    // instruction with no config to check a role against, so without this
    // anyone could front-run the deployer and take the bridge.
    check_upgrade_authority(program_data_account, program_id, payer)?;

    // Deployment is one-shot: a second `Initialize` would otherwise
    // install a new admin and guardian set over live custody.
    if !config_account.data_is_empty() {
        return Err(BridgeError::InvalidPda.into());
    }

    if admin == Pubkey::default() || rand_emitter == [0u8; 32] {
        return Err(BridgeError::ZeroAddress.into());
    }
    check_guardian_keys(&guardians)?;

    let config = Config {
        admin,
        pending_admin: Pubkey::default(),
        pauser,
        paused: false,
        rand_emitter,
        current_guardian_set: 0,
        sequence: 0,
        bump: config_bump,
        protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
    };
    create_state(
        &config,
        config_account,
        payer,
        system_account,
        program_id,
        &[seeds::CONFIG, &[config_bump]],
    )?;

    let guardian_count = guardians.len();
    let set = GuardianSetAccount {
        index: 0,
        keys: guardians,
        expiration_time: 0,
    };
    let index_seed = 0u32.to_le_bytes();
    create_state(
        &set,
        set_account,
        payer,
        system_account,
        program_id,
        &[seeds::GUARDIAN, &index_seed, &[set_bump]],
    )?;

    msg!(
        "rand-bridge: initialized, guardian set 0 has {} keys",
        guardian_count
    );
    Ok(())
}

// ----------------------------------------------------------------------
// SetToken
// ----------------------------------------------------------------------

fn process_set_token(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    enabled: bool,
    per_transfer_cap: u64,
    daily_cap: u64,
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let admin = next_account_info(iter)?;
    let config_account = next_account_info(iter)?;
    let mint_account = next_account_info(iter)?;
    let registry_account = next_account_info(iter)?;
    let custody_account = next_account_info(iter)?;
    let authority_account = next_account_info(iter)?;
    let token_program = next_account_info(iter)?;
    let system_account = next_account_info(iter)?;
    let rent_account = next_account_info(iter)?;

    check_signer(admin)?;
    let config = load_config(config_account, program_id)?;
    if *admin.key != config.admin {
        return Err(BridgeError::NotAdmin.into());
    }
    if *mint_account.key == Pubkey::default() {
        return Err(BridgeError::ZeroAddress.into());
    }
    check_key(token_program.key, &spl_token::id())?;
    check_key(system_account.key, &system_program::id())?;
    check_key(rent_account.key, &sysvar::rent::id())?;
    check_key(mint_account.owner, &spl_token::id())?;

    let (registry_key, registry_bump) = token_pda(program_id, mint_account.key);
    check_key(registry_account.key, &registry_key)?;
    let (custody_key, custody_bump) = custody_pda(program_id, mint_account.key);
    check_key(custody_account.key, &custody_key)?;
    let (authority_key, _) = authority_pda(program_id);
    check_key(authority_account.key, &authority_key)?;

    let registry_exists = !registry_account.data_is_empty();
    let mut registry = if registry_exists {
        load_registry(registry_account, program_id, mint_account.key)?
    } else {
        TokenRegistry {
            mint: *mint_account.key,
            enabled: false,
            decimals: 0,
            per_transfer_cap: 0,
            daily_cap: 0,
            window_start: 0,
            window_used: 0,
            custody: 0,
            accrued_fees: 0,
        }
    };

    registry.enabled = enabled;
    // Only read the mint when whitelisting. Disabling must always be
    // possible, which is exactly when the admin most needs it; the stored
    // decimals stay as they were, so re-enabling refreshes them.
    if enabled {
        let decimals = spl_token::state::Mint::unpack(&mint_account.data.borrow())?.decimals;
        if decimals > MAX_DECIMALS {
            return Err(BridgeError::AmountOverflow.into());
        }
        registry.decimals = decimals;
    }
    registry.per_transfer_cap = per_transfer_cap;
    registry.daily_cap = daily_cap;
    // The window counters are deliberately untouched, so re-configuring
    // a cap cannot reset the day's usage.

    if registry_exists {
        store(&registry, registry_account)?;
    } else {
        create_state(
            &registry,
            registry_account,
            admin,
            system_account,
            program_id,
            &[seeds::TOKEN, mint_account.key.as_ref(), &[registry_bump]],
        )?;
    }

    if custody_account.data_is_empty() {
        create_pda_account(
            admin,
            custody_account,
            system_account,
            &spl_token::id(),
            spl_token::state::Account::LEN,
            &[seeds::CUSTODY, mint_account.key.as_ref(), &[custody_bump]],
        )?;
        invoke(
            &spl_token::instruction::initialize_account(
                &spl_token::id(),
                custody_account.key,
                mint_account.key,
                authority_account.key,
            )?,
            &[
                custody_account.clone(),
                mint_account.clone(),
                authority_account.clone(),
                rent_account.clone(),
            ],
        )?;
    }

    msg!("rand-bridge: token configured, enabled {}", enabled);
    Ok(())
}

// ----------------------------------------------------------------------
// Lock
// ----------------------------------------------------------------------

fn process_lock(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64,
    rand_recipient: [u8; 32],
    relayer_fee: u64,
    nonce: u32,
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let owner = next_account_info(iter)?;
    let owner_token_account = next_account_info(iter)?;
    let config_account = next_account_info(iter)?;
    let mint_account = next_account_info(iter)?;
    let registry_account = next_account_info(iter)?;
    let custody_account = next_account_info(iter)?;
    let message_account = next_account_info(iter)?;
    let token_program = next_account_info(iter)?;
    let system_account = next_account_info(iter)?;
    let clock_account = next_account_info(iter)?;

    check_signer(owner)?;
    check_key(token_program.key, &spl_token::id())?;
    check_key(system_account.key, &system_program::id())?;
    let now = now_from(clock_account)?;

    let mut config = load_config(config_account, program_id)?;
    if config.paused {
        return Err(BridgeError::IsPaused.into());
    }
    let mut registry = load_registry(registry_account, program_id, mint_account.key)?;
    if !registry.enabled {
        return Err(BridgeError::TokenDisabled.into());
    }
    if rand_recipient == [0u8; 32] {
        return Err(BridgeError::ZeroRecipient.into());
    }
    if relayer_fee > amount {
        return Err(BridgeError::FeeExceedsAmount.into());
    }

    // A lock is free of the protocol fee: that is charged on release only.
    let (locked, attested) = normalize(amount, registry.decimals)?;
    if attested == 0 {
        return Err(BridgeError::ZeroAmount.into());
    }
    // Rand keeps a bridged holding in a note whose amount is a `u64` and
    // refuses a larger attestation at admission; a lock it could never
    // mint would sit in custody with no burn able to release it. Mirrors
    // `RandBridgeBase.lock`'s `AmountTooLarge`.
    if attested > MAX_ATTESTED_AMOUNT {
        return Err(BridgeError::AmountOverflow.into());
    }
    // The fee is quoted in the mint's own units like `amount`, and
    // normalised the same way, so it rounds down with it and stays
    // `<= attested`.
    let (_, attested_fee) = normalize(relayer_fee, registry.decimals)?;
    debug_assert!(attested_fee <= attested, "normalisation is monotonic");

    check_key(mint_account.owner, &spl_token::id())?;
    let (custody_key, _) = custody_pda(program_id, mint_account.key);
    check_key(custody_account.key, &custody_key)?;
    let sequence = config.sequence;
    let (message_key, message_bump) = msg_pda(program_id, sequence);
    check_key(message_account.key, &message_key)?;

    // The balance delta is measured rather than trusted: a mint that
    // credits custody less than the attestation is about to promise is
    // rejected outright rather than mis-accounted.
    let before = custody_state(custody_account, program_id, mint_account.key)?.amount;
    invoke(
        &spl_token::instruction::transfer(
            &spl_token::id(),
            owner_token_account.key,
            custody_account.key,
            owner.key,
            &[],
            locked,
        )?,
        &[
            owner_token_account.clone(),
            custody_account.clone(),
            owner.clone(),
            token_program.clone(),
        ],
    )?;
    let after = custody_state(custody_account, program_id, mint_account.key)?.amount;
    if after.checked_sub(before) != Some(locked) {
        return Err(BridgeError::TransferAmountMismatch.into());
    }

    registry.custody = registry
        .custody
        .checked_add(locked)
        .ok_or(BridgeError::AmountOverflow)?;

    let body = Body {
        // The wire format carries a u32 unix time; truncation is a
        // year-2106 concern shared with every other endpoint.
        timestamp: now as u32,
        nonce,
        emitter_chain: CHAIN_ID,
        emitter_address: program_id.to_bytes(),
        sequence,
        consistency_level: CONSISTENCY_LEVEL,
        payload: Payload::Transfer(Transfer {
            amount: Transfer::u256_from_u128(attested),
            token_address: mint_account.key.to_bytes(),
            token_chain: CHAIN_ID,
            to: rand_recipient,
            to_chain: CHAIN_RAND,
            fee: Transfer::u256_from_u128(attested_fee),
        })
        .encode(),
    };
    let posted = PostedMessage {
        sequence,
        body: body.encode(),
    };
    let sequence_seed = sequence.to_le_bytes();
    create_state(
        &posted,
        message_account,
        owner,
        system_account,
        program_id,
        &[seeds::MSG, &sequence_seed, &[message_bump]],
    )?;

    config.sequence = sequence.checked_add(1).ok_or(BridgeError::AmountOverflow)?;
    store(&config, config_account)?;
    store(&registry, registry_account)?;

    msg!("rand-bridge: locked {} at sequence {}", locked, sequence);
    Ok(())
}

// ----------------------------------------------------------------------
// Release
// ----------------------------------------------------------------------

fn process_release(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    attestation_bytes: &[u8],
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let relayer = next_account_info(iter)?;
    let config_account = next_account_info(iter)?;
    let set_account = next_account_info(iter)?;
    let mint_account = next_account_info(iter)?;
    let registry_account = next_account_info(iter)?;
    let custody_account = next_account_info(iter)?;
    let authority_account = next_account_info(iter)?;
    let recipient_token_account = next_account_info(iter)?;
    let relayer_token_account = next_account_info(iter)?;
    let consumed_account = next_account_info(iter)?;
    let token_program = next_account_info(iter)?;
    let system_account = next_account_info(iter)?;
    let clock_account = next_account_info(iter)?;

    check_signer(relayer)?;
    check_key(token_program.key, &spl_token::id())?;
    check_key(system_account.key, &system_program::id())?;
    check_key(mint_account.owner, &spl_token::id())?;
    let (custody_key, _) = custody_pda(program_id, mint_account.key);
    check_key(custody_account.key, &custody_key)?;
    // Not just the address: the account it names must really be an SPL
    // token account for this mint under this program's custody
    // authority. Checked here, before any effect is written and long
    // before the payout CPIs.
    custody_state(custody_account, program_id, mint_account.key)?;
    let (authority_key, authority_bump) = authority_pda(program_id);
    check_key(authority_account.key, &authority_key)?;
    let now = now_from(clock_account)?;

    let config = load_config(config_account, program_id)?;
    if config.paused {
        return Err(BridgeError::IsPaused.into());
    }

    // 1. resolve the guardian set the attestation names.
    let set_index = envelope_guardian_set_index(attestation_bytes)?;
    check_key(set_account.key, &guardian_pda(program_id, set_index).0)?;
    if set_account.data_is_empty() {
        return Err(BridgeError::UnknownGuardianSet.into());
    }
    let set: GuardianSetAccount = load(set_account, program_id)?;
    if set.index != set_index {
        return Err(BridgeError::UnknownGuardianSet.into());
    }
    // The current set is always usable; a superseded one only inside its
    // grace period.
    let usable = set.index == config.current_guardian_set
        || (set.expiration_time != 0 && now <= set.expiration_time);
    if !usable {
        return Err(BridgeError::GuardianSetExpired.into());
    }

    // 2. envelope, quorum, signatures.
    let (attestation, digest) = attestation::verify(attestation_bytes, &set, now)?;

    // 3. replay.
    let (consumed_key, consumed_bump) = spent_pda(program_id, &digest);
    check_key(consumed_account.key, &consumed_key)?;
    if !consumed_account.data_is_empty() {
        return Err(BridgeError::AlreadyConsumed.into());
    }

    // 4. emitter binding.
    if attestation.body.emitter_chain != CHAIN_RAND
        || attestation.body.emitter_address != config.rand_emitter
    {
        return Err(BridgeError::WrongEmitter.into());
    }

    // 5. payload.
    let transfer = match Payload::decode(&attestation.body.payload).map_err(BridgeError::from)? {
        Payload::Transfer(t) => t,
        Payload::GuardianSetUpgrade(_) => return Err(BridgeError::BadPayloadId.into()),
    };
    if transfer.to_chain != CHAIN_ID {
        return Err(BridgeError::WrongToChain.into());
    }
    if transfer.token_chain != CHAIN_ID {
        return Err(BridgeError::WrongTokenChain.into());
    }
    // `fee <= amount` is Section 3.6's rule on the payload itself, so it
    // is checked on the wire u256s, before anything about this chain's
    // configuration and before the denormalisation that could overflow.
    if transfer.fee > transfer.amount {
        return Err(BridgeError::FeeExceedsAmount.into());
    }

    // 6. the token, and the accounts that belong to it.
    check_key(
        &Pubkey::new_from_array(transfer.token_address),
        mint_account.key,
    )?;
    let mut registry = load_registry(registry_account, program_id, mint_account.key)?;
    if !registry.enabled {
        return Err(BridgeError::TokenDisabled.into());
    }
    if transfer.to == [0u8; 32] {
        return Err(BridgeError::ZeroRecipient.into());
    }
    let recipient = Pubkey::new_from_array(transfer.to);
    check_ata(recipient_token_account.key, &recipient, mint_account.key)?;
    check_ata(relayer_token_account.key, relayer.key, mint_account.key)?;

    // 7. amounts.
    let amount = denormalize(
        transfer.amount_u128().ok_or(BridgeError::AmountOverflow)?,
        registry.decimals,
    )?;
    let fee = denormalize(
        transfer.fee_u128().ok_or(BridgeError::AmountOverflow)?,
        registry.decimals,
    )?;
    // Attested dust below one unit of this mint: paying it out would move
    // nothing while burning the digest, so refuse it and leave the burn
    // re-submittable if the mint is ever re-configured.
    if amount == 0 {
        return Err(BridgeError::ZeroAmount.into());
    }
    // Denormalisation is monotonic, so `fee <= amount` on the wire
    // already implies this — asserted anyway, because `amount - fee`
    // below runs after the effects have been written and must not be
    // able to underflow.
    if fee > amount {
        return Err(BridgeError::FeeExceedsAmount.into());
    }
    // The protocol fee is taken from the gross amount first and the
    // relayer is paid out of what is left: a burn that names its whole
    // amount as the relayer fee can neither dodge the protocol fee nor
    // make the release impossible (the burn on Rand is already final).
    let protocol_fee = protocol_fee_of(amount, config.protocol_fee_bps);
    let fee = fee.min(amount - protocol_fee);

    // 8. custody soundness, then the caps.
    if registry.custody < amount {
        return Err(BridgeError::InsufficientCustody.into());
    }
    if registry.per_transfer_cap != 0 && amount > registry.per_transfer_cap {
        return Err(BridgeError::PerTransferCap.into());
    }
    let window = now / SECONDS_PER_DAY;
    let used = if registry.window_start == window {
        registry.window_used
    } else {
        0
    };
    let window_used = used
        .checked_add(amount)
        .ok_or(BridgeError::AmountOverflow)?;
    if registry.daily_cap != 0 && window_used > registry.daily_cap {
        return Err(BridgeError::DailyCap.into());
    }

    // 9. effects, all of them, before any token CPI: the digest can never
    // be replayed, not even from inside a token program's own transfer.
    create_state(
        &Consumed { digest },
        consumed_account,
        relayer,
        system_account,
        program_id,
        &[seeds::SPENT, &digest, &[consumed_bump]],
    )?;
    registry.custody = registry
        .custody
        .checked_sub(amount)
        .ok_or(BridgeError::InsufficientCustody)?;
    // Leaves custody, stays in the token account.
    registry.accrued_fees = registry
        .accrued_fees
        .checked_add(protocol_fee)
        .ok_or(BridgeError::AmountOverflow)?;
    registry.window_start = window;
    registry.window_used = window_used;
    store(&registry, registry_account)?;

    // 10. interactions.
    if fee != 0 {
        transfer_from_custody(
            custody_account,
            relayer_token_account,
            authority_account,
            token_program,
            fee,
            authority_bump,
        )?;
    }
    let payout = amount - protocol_fee - fee;
    if payout != 0 {
        transfer_from_custody(
            custody_account,
            recipient_token_account,
            authority_account,
            token_program,
            payout,
            authority_bump,
        )?;
    }

    msg!(
        "rand-bridge: released {} (fee {}, protocol fee {})",
        amount,
        fee,
        protocol_fee
    );
    Ok(())
}

// ----------------------------------------------------------------------
// GuardianSetUpgrade
// ----------------------------------------------------------------------

fn process_guardian_set_upgrade(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    attestation_bytes: &[u8],
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let payer = next_account_info(iter)?;
    let config_account = next_account_info(iter)?;
    let current_set_account = next_account_info(iter)?;
    let new_set_account = next_account_info(iter)?;
    let consumed_account = next_account_info(iter)?;
    let system_account = next_account_info(iter)?;
    let clock_account = next_account_info(iter)?;

    check_signer(payer)?;
    check_key(system_account.key, &system_program::id())?;
    let now = now_from(clock_account)?;

    // Deliberately not gated on `paused`: pausing stops value movement,
    // and must not stand between the guardians and rotating away from a
    // compromised set.
    let mut config = load_config(config_account, program_id)?;
    let current = config.current_guardian_set;

    // A rotation is signed by the set currently in force, so that a
    // superseded set cannot rotate itself back in during its grace
    // period.
    let set_index = envelope_guardian_set_index(attestation_bytes)?;
    if set_index != current {
        return Err(BridgeError::GuardianSetExpired.into());
    }
    check_key(
        current_set_account.key,
        &guardian_pda(program_id, current).0,
    )?;
    if current_set_account.data_is_empty() {
        return Err(BridgeError::UnknownGuardianSet.into());
    }
    let mut current_set: GuardianSetAccount = load(current_set_account, program_id)?;

    let (attestation, digest) = attestation::verify(attestation_bytes, &current_set, now)?;

    let (consumed_key, consumed_bump) = spent_pda(program_id, &digest);
    check_key(consumed_account.key, &consumed_key)?;
    if !consumed_account.data_is_empty() {
        return Err(BridgeError::AlreadyConsumed.into());
    }

    // Governance messages come from their own emitter on chain 1, so a
    // burn message can never be mistaken for a rotation.
    if attestation.body.emitter_chain != CHAIN_RAND
        || attestation.body.emitter_address != GOVERNANCE_EMITTER
    {
        return Err(BridgeError::WrongEmitter.into());
    }

    let upgrade = match Payload::decode(&attestation.body.payload).map_err(BridgeError::from)? {
        Payload::GuardianSetUpgrade(g) => g,
        Payload::Transfer(_) => return Err(BridgeError::BadPayloadId.into()),
    };
    let new_index = current.checked_add(1).ok_or(BridgeError::BadUpgradeIndex)?;
    if upgrade.new_index != new_index {
        return Err(BridgeError::BadUpgradeIndex.into());
    }
    check_guardian_keys(&upgrade.keys)?;

    let (new_set_key, new_set_bump) = guardian_pda(program_id, new_index);
    check_key(new_set_account.key, &new_set_key)?;
    if !new_set_account.data_is_empty() {
        return Err(BridgeError::InvalidPda.into());
    }

    let key_count = upgrade.keys.len();
    let new_set = GuardianSetAccount {
        index: new_index,
        keys: upgrade.keys,
        expiration_time: 0,
    };
    let index_seed = new_index.to_le_bytes();
    create_state(
        &new_set,
        new_set_account,
        payer,
        system_account,
        program_id,
        &[seeds::GUARDIAN, &index_seed, &[new_set_bump]],
    )?;

    // The superseded set stays usable for one grace period, so
    // in-flight attestations are not stranded.
    current_set.expiration_time = now
        .checked_add(GUARDIAN_GRACE_SECS)
        .ok_or(BridgeError::AmountOverflow)?;
    store(&current_set, current_set_account)?;

    config.current_guardian_set = new_index;
    store(&config, config_account)?;

    create_state(
        &Consumed { digest },
        consumed_account,
        payer,
        system_account,
        program_id,
        &[seeds::SPENT, &digest, &[consumed_bump]],
    )?;

    msg!(
        "rand-bridge: guardian set {} installed with {} keys",
        new_index,
        key_count
    );
    Ok(())
}

// ----------------------------------------------------------------------
// roles
// ----------------------------------------------------------------------

/// The four role instructions share one account list: the signer and the
/// config it mutates.
fn role_accounts<'a, 'b>(
    accounts: &'a [AccountInfo<'b>],
    program_id: &Pubkey,
) -> Result<(&'a AccountInfo<'b>, &'a AccountInfo<'b>, Config), ProgramError> {
    let iter = &mut accounts.iter();
    let signer = next_account_info(iter)?;
    let config_account = next_account_info(iter)?;
    check_signer(signer)?;
    let config = load_config(config_account, program_id)?;
    Ok((signer, config_account, config))
}

fn process_pause(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let (signer, config_account, mut config) = role_accounts(accounts, program_id)?;
    // The pause quorum, or the admin.
    if *signer.key != config.pauser && *signer.key != config.admin {
        return Err(BridgeError::NotPauser.into());
    }
    if config.paused {
        return Err(BridgeError::IsPaused.into());
    }
    config.paused = true;
    store(&config, config_account)?;
    msg!("rand-bridge: paused");
    Ok(())
}

fn process_unpause(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let (signer, config_account, mut config) = role_accounts(accounts, program_id)?;
    // Admin only: the pauser can stop the bridge but not restart it.
    if *signer.key != config.admin {
        return Err(BridgeError::NotAdmin.into());
    }
    if !config.paused {
        return Err(BridgeError::NotPaused.into());
    }
    config.paused = false;
    store(&config, config_account)?;
    msg!("rand-bridge: unpaused");
    Ok(())
}

fn process_transfer_admin(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    to: Pubkey,
) -> ProgramResult {
    let (signer, config_account, mut config) = role_accounts(accounts, program_id)?;
    if *signer.key != config.admin {
        return Err(BridgeError::NotAdmin.into());
    }
    // `to == default` cancels the transfer in flight.
    config.pending_admin = to;
    store(&config, config_account)?;
    msg!("rand-bridge: admin transfer pending");
    Ok(())
}

fn process_accept_admin(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let (signer, config_account, mut config) = role_accounts(accounts, program_id)?;
    // The zero check matters here rather than in `TransferAdmin`: with no
    // transfer in flight there is nothing to accept.
    if config.pending_admin == Pubkey::default() || *signer.key != config.pending_admin {
        return Err(BridgeError::NotAdmin.into());
    }
    config.admin = *signer.key;
    config.pending_admin = Pubkey::default();
    store(&config, config_account)?;
    msg!("rand-bridge: admin transferred");
    Ok(())
}

fn process_set_protocol_fee(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    bps: u16,
) -> ProgramResult {
    let (signer, config_account, mut config) = role_accounts(accounts, program_id)?;
    if *signer.key != config.admin {
        return Err(BridgeError::NotAdmin.into());
    }
    if bps > MAX_PROTOCOL_FEE_BPS {
        return Err(BridgeError::ProtocolFeeTooHigh.into());
    }
    config.protocol_fee_bps = bps;
    store(&config, config_account)?;
    msg!("rand-bridge: protocol fee {} bps", bps);
    Ok(())
}

// ----------------------------------------------------------------------
// WithdrawFees
// ----------------------------------------------------------------------

/// Pays accrued protocol fees out. Bounded by `accrued_fees`, so it can
/// never reach custody; not gated by the pause, which protects custody
/// and has no bearing on fees already earned.
fn process_withdraw_fees(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let admin = next_account_info(iter)?;
    let config_account = next_account_info(iter)?;
    let mint_account = next_account_info(iter)?;
    let registry_account = next_account_info(iter)?;
    let custody_account = next_account_info(iter)?;
    let authority_account = next_account_info(iter)?;
    let destination_account = next_account_info(iter)?;
    let token_program = next_account_info(iter)?;

    check_signer(admin)?;
    check_key(token_program.key, &spl_token::id())?;
    let config = load_config(config_account, program_id)?;
    if *admin.key != config.admin {
        return Err(BridgeError::NotAdmin.into());
    }
    let mut registry = load_registry(registry_account, program_id, mint_account.key)?;
    let (custody_key, _) = custody_pda(program_id, mint_account.key);
    check_key(custody_account.key, &custody_key)?;
    let (authority_key, authority_bump) = authority_pda(program_id);
    check_key(authority_account.key, &authority_key)?;
    // A transfer onto itself succeeds and moves nothing: the fees would
    // leave the counter and stay in the account, outside both counters.
    if destination_account.key == custody_account.key {
        return Err(BridgeError::BadRecipient.into());
    }

    registry.accrued_fees = registry
        .accrued_fees
        .checked_sub(amount)
        .ok_or(BridgeError::InsufficientFees)?;
    store(&registry, registry_account)?;

    transfer_from_custody(
        custody_account,
        destination_account,
        authority_account,
        token_program,
        amount,
        authority_bump,
    )?;
    msg!("rand-bridge: withdrew {} in fees", amount);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalisation_matches_spec_3_7() {
        // 6 decimals: scale up by 100, nothing is ever truncated.
        assert_eq!(normalize(1_234_567, 6), Ok((1_234_567, 123_456_700)));
        // 9 decimals: one unit below the attestable step is left behind.
        assert_eq!(
            normalize(1_000_000_001, 9),
            Ok((1_000_000_000, 100_000_000))
        );
        // Exactly 8 decimals is the identity.
        assert_eq!(normalize(42, 8), Ok((42, 42)));
        // Dust below one attestable unit normalises to zero and locks
        // nothing, which `Lock` then refuses as `ZeroAmount`.
        assert_eq!(normalize(9, 9), Ok((0, 0)));

        assert_eq!(denormalize(123_456_700, 6), Ok(1_234_567));
        assert_eq!(denormalize(100_000_000, 9), Ok(1_000_000_000));
        assert_eq!(denormalize(42, 8), Ok(42));
        // Dust below one unit of an 18-decimal mint... which is the other
        // direction: 8 -> 18 scales up, so overflow is the risk.
        assert_eq!(denormalize(u128::MAX, 18), Err(BridgeError::AmountOverflow));
        assert_eq!(
            denormalize(u128::from(u64::MAX) + 1, 8),
            Err(BridgeError::AmountOverflow)
        );
    }

    #[test]
    fn round_trip_is_lossless_above_the_attestable_step() {
        for decimals in [0u8, 6, 8, 9, 18] {
            let (locked, attested) = normalize(1_000_000_000_000, decimals).expect("normalizes");
            assert_eq!(denormalize(attested, decimals), Ok(locked), "{decimals}");
        }
    }

    #[test]
    fn scale_refuses_an_absurd_decimals() {
        assert_eq!(scale(MAX_DECIMALS).unwrap(), 10u128.pow(28));
        assert_eq!(scale(255), Err(BridgeError::AmountOverflow));
    }

    #[test]
    fn guardian_key_rules() {
        assert_eq!(check_guardian_keys(&[]), Err(BridgeError::ZeroAddress));
        assert_eq!(
            check_guardian_keys(&[[1u8; 20], [0u8; 20]]),
            Err(BridgeError::ZeroAddress)
        );
        assert_eq!(
            check_guardian_keys(&[[1u8; 20], [2u8; 20], [1u8; 20]]),
            Err(BridgeError::DuplicateGuardian)
        );
        assert_eq!(check_guardian_keys(&[[1u8; 20], [2u8; 20]]), Ok(()));
    }

    #[test]
    fn envelope_index_is_read_without_decoding() {
        let mut bytes = vec![1u8, 0, 0, 0, 7, 0];
        assert_eq!(envelope_guardian_set_index(&bytes), Ok(7));
        bytes[0] = 2;
        assert_eq!(
            envelope_guardian_set_index(&bytes),
            Err(BridgeError::BadVersion)
        );
        assert_eq!(
            envelope_guardian_set_index(&[1, 0, 0]),
            Err(BridgeError::Truncated)
        );
        assert_eq!(
            envelope_guardian_set_index(&[]),
            Err(BridgeError::Truncated)
        );
    }
}
