//! Compute and size of the live paths on the real SBF binary, at the largest
//! guardian set the program accepts.
//!
//! `solana-program-test` links the program natively in `tests/bridge.rs`, and
//! native code is not metered, so nothing there can see a compute or a
//! transaction-size failure. These tests load `rand_bridge.so` and are ignored
//! in a plain `cargo test`, because the binary has to be built first:
//!
//! ```text
//! cargo build-sbf --manifest-path programs/rand-bridge/Cargo.toml --sbf-out-dir "$OUT"
//! SBF_OUT_DIR="$OUT" cargo test -p rand-bridge --test sbf_compute -- --ignored --nocapture
//! ```
//!
//! Accounts are seeded directly, in the layouts mainnet holds, so a test starts
//! from the state an upgraded program finds. Each test sends the same legacy
//! transaction the CLI does: a compute-unit limit, then the instruction.

use bridge_codec::{
    Attestation, Body, GuardianSetUpgrade, Payload, Signature, Transfer, CHAIN_RAND,
    GOVERNANCE_EMITTER,
};
use k256::ecdsa::{RecoveryId, SigningKey, VerifyingKey};
use rand_bridge::attestation::digest as attestation_digest;
use rand_bridge::instruction as bridge_ix;
use rand_bridge::state::{
    authority_pda, config_pda, custody_pda, guardian_pda, token_pda, BridgeAccount, Config,
    GuardianSetAccount, TokenRegistry, CHAIN_ID,
};
use sha3::{Digest as _, Keccak256};
use solana_program_test::{ProgramTest, ProgramTestContext};
use solana_sdk::account::Account;
use solana_sdk::compute_budget::ComputeBudgetInstruction;
use solana_sdk::instruction::Instruction;
use solana_sdk::program_option::COption;
use solana_sdk::program_pack::Pack;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};
use solana_sdk::transaction::Transaction;

/// The Solana packet limit a transaction has to serialize into.
const PACKET: usize = 1232;
/// What the CLI asks for by default.
const COMPUTE_LIMIT: u32 = 400_000;
/// The largest set under test.
const N: usize = 10;
/// `n * 2 / 3 + 1` at `n = 10`.
const QUORUM: usize = 7;
const RAND_EMITTER: [u8; 32] = [0x11; 32];
const FUNDED: u64 = 100_000_000_000;

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn secret(index: u8) -> [u8; 32] {
    let mut secret = [0u8; 32];
    secret[31] = index + 1;
    secret
}

fn guardian_address(index: u8) -> [u8; 20] {
    let key = SigningKey::from_bytes(&secret(index).into()).expect("valid secret");
    let encoded = VerifyingKey::from(&key).to_sec1_point(false);
    let hash = keccak256(&encoded.as_bytes()[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..]);
    out
}

fn sign(index: u8, digest: &[u8; 32]) -> Signature {
    let key = SigningKey::from_bytes(&secret(index).into()).expect("valid secret");
    let (sig, recid) = key.sign_prehash_recoverable(digest);
    let normalized = sig.normalize_s();
    let (sig, recid) = if normalized != sig {
        (
            normalized,
            RecoveryId::from_byte(recid.to_byte() ^ 1).expect("valid recovery id"),
        )
    } else {
        (sig, recid)
    };
    let (r, s) = sig.split_bytes();
    Signature {
        index,
        r: r.into(),
        s: s.into(),
        v: recid.to_byte(),
    }
}

fn signed(set_index: u32, body: Body) -> (Vec<u8>, [u8; 32]) {
    let digest = attestation_digest(&body.encode());
    let signatures = (0..QUORUM as u8).map(|i| sign(i, &digest)).collect();
    (
        Attestation {
            guardian_set_index: set_index,
            signatures,
            body,
        }
        .encode(),
        digest,
    )
}

fn body(emitter: [u8; 32], payload: Vec<u8>) -> Body {
    Body {
        timestamp: 1_700_000_000,
        nonce: 7,
        emitter_chain: CHAIN_RAND,
        emitter_address: emitter,
        sequence: 3,
        consistency_level: 1,
        payload,
    }
}

fn program_owned<T: BridgeAccount>(value: &T) -> Account {
    let mut data = vec![0u8; 1 + borsh::to_vec(value).expect("serializes").len()];
    value.store(&mut data).expect("stores");
    Account {
        lamports: FUNDED,
        data,
        owner: rand_bridge::id(),
        executable: false,
        rent_epoch: 0,
    }
}

fn wallet() -> Account {
    Account {
        lamports: FUNDED,
        data: Vec::new(),
        owner: solana_sdk_ids::system_program::id(),
        executable: false,
        rent_epoch: 0,
    }
}

fn token_account(mint: &Pubkey, owner: &Pubkey, amount: u64) -> Account {
    let mut data = vec![0u8; spl_token::state::Account::LEN];
    spl_token::state::Account {
        mint: *mint,
        owner: *owner,
        amount,
        delegate: COption::None,
        state: spl_token::state::AccountState::Initialized,
        is_native: COption::None,
        delegated_amount: 0,
        close_authority: COption::None,
    }
    .pack_into_slice(&mut data);
    Account {
        lamports: FUNDED,
        data,
        owner: spl_token::id(),
        executable: false,
        rent_epoch: 0,
    }
}

fn mint_account() -> Account {
    let mut data = vec![0u8; spl_token::state::Mint::LEN];
    spl_token::state::Mint {
        mint_authority: COption::None,
        supply: u64::MAX / 2,
        decimals: 6,
        is_initialized: true,
        freeze_authority: COption::None,
    }
    .pack_into_slice(&mut data);
    Account {
        lamports: FUNDED,
        data,
        owner: spl_token::id(),
        executable: false,
        rent_epoch: 0,
    }
}

/// A bank running the SBF binary with a ten-key set 0, one enabled mint with
/// 1,000 tokens in custody, a funded user and the protocol fee on, so a release
/// takes its longest path: two token transfers and a new consumed marker.
struct Rig {
    ctx: ProgramTestContext,
    program: Pubkey,
    mint: Pubkey,
    user: Keypair,
}

async fn rig() -> Rig {
    let program = rand_bridge::id();
    let mint = Pubkey::new_unique();
    let user = Keypair::new();

    let mut test = ProgramTest::new("rand_bridge", program, None);
    test.prefer_bpf(true);
    test.set_compute_max_units(u64::from(COMPUTE_LIMIT));
    test.add_account(mint, mint_account());
    test.add_account(user.pubkey(), wallet());
    test.add_account(
        config_pda(&program).0,
        program_owned(&Config {
            admin: Pubkey::new_unique(),
            pending_admin: Pubkey::default(),
            pauser: Pubkey::new_unique(),
            paused: false,
            rand_emitter: RAND_EMITTER,
            current_guardian_set: 0,
            sequence: 0,
            bump: config_pda(&program).1,
            protocol_fee_bps: 10,
        }),
    );
    test.add_account(
        guardian_pda(&program, 0).0,
        program_owned(&GuardianSetAccount {
            index: 0,
            keys: (0..N as u8).map(guardian_address).collect(),
            expiration_time: 0,
        }),
    );
    test.add_account(
        token_pda(&program, &mint).0,
        program_owned(&TokenRegistry {
            mint,
            enabled: true,
            decimals: 6,
            per_transfer_cap: 0,
            daily_cap: 0,
            window_start: 0,
            window_used: 0,
            custody: 1_000_000_000,
            accrued_fees: 0,
        }),
    );
    test.add_account(
        custody_pda(&program, &mint).0,
        token_account(&mint, &authority_pda(&program).0, 1_000_000_000),
    );
    test.add_account(
        bridge_ix::associated_token_address(&user.pubkey(), &mint),
        token_account(&mint, &user.pubkey(), 1_000_000_000),
    );

    Rig {
        ctx: test.start_with_context().await,
        program,
        mint,
        user,
    }
}

impl Rig {
    /// Signs `ix` behind a compute-unit limit as a legacy transaction, checks
    /// that it fits a packet, sends it, and returns (bytes, units consumed).
    async fn run(&mut self, label: &str, ix: Instruction) -> (usize, u64) {
        let blockhash = self
            .ctx
            .banks_client
            .get_latest_blockhash()
            .await
            .expect("blockhash");
        let tx = Transaction::new_signed_with_payer(
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(COMPUTE_LIMIT),
                ix,
            ],
            Some(&self.user.pubkey()),
            &[&self.user],
            blockhash,
        );
        let bytes = bincode::serialize(&tx).expect("serializes").len();
        let result = self
            .ctx
            .banks_client
            .process_transaction_with_metadata(tx)
            .await
            .expect("transport");
        let meta = result.metadata.expect("metadata");
        println!(
            "{label}: {bytes} of {PACKET} bytes, {} compute units",
            meta.compute_units_consumed
        );
        result.result.expect(label);
        assert!(bytes <= PACKET, "{label} is {bytes} bytes, over {PACKET}");
        (bytes, meta.compute_units_consumed)
    }
}

#[tokio::test]
#[ignore = "needs the SBF binary: see the module docs"]
async fn release_at_n_10_fits_a_packet_and_the_compute_limit() {
    let mut r = rig().await;
    let recipient = Pubkey::new_unique();
    let ata = bridge_ix::associated_token_address(&recipient, &r.mint);
    r.ctx
        .set_account(&ata, &token_account(&r.mint, &recipient, 0).into());
    let (bytes, digest) = signed(
        0,
        body(
            RAND_EMITTER,
            Payload::Transfer(Transfer {
                amount: Transfer::u256_from_u128(100_000_000),
                token_address: r.mint.to_bytes(),
                token_chain: CHAIN_ID,
                to: recipient.to_bytes(),
                to_chain: CHAIN_ID,
                fee: Transfer::u256_from_u128(1_000_000),
            })
            .encode(),
        ),
    );
    let ix = bridge_ix::release(
        &r.program,
        &r.user.pubkey(),
        &r.mint,
        0,
        &recipient,
        &digest,
        bytes,
    );
    let (_, units) = r.run("release n=10 q=7", ix).await;
    assert!(units < u64::from(COMPUTE_LIMIT));
}

#[tokio::test]
#[ignore = "needs the SBF binary: see the module docs"]
async fn rotation_from_n_10_to_n_10_fits_a_packet_and_the_compute_limit() {
    let mut r = rig().await;
    let upgrade = Payload::GuardianSetUpgrade(GuardianSetUpgrade {
        new_index: 1,
        keys: (20..20 + N as u8).map(guardian_address).collect(),
    })
    .encode();
    let (bytes, digest) = signed(0, body(GOVERNANCE_EMITTER, upgrade));
    let ix = bridge_ix::guardian_set_upgrade(&r.program, &r.user.pubkey(), 0, 1, &digest, bytes);
    let (_, units) = r.run("rotation n=10 q=7", ix).await;
    assert!(units < u64::from(COMPUTE_LIMIT));
}

#[tokio::test]
#[ignore = "needs the SBF binary: see the module docs"]
async fn lock_fits_the_default_compute_limit() {
    let mut r = rig().await;
    let ix = bridge_ix::lock(
        &r.program,
        &r.user.pubkey(),
        &bridge_ix::associated_token_address(&r.user.pubkey(), &r.mint),
        &r.mint,
        0,
        1_000_000,
        [0x44; 32],
        0,
        1,
    );
    let (_, units) = r.run("lock", ix).await;
    assert!(units < 200_000);
}
