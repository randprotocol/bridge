//! End-to-end tests for the `rand_bridge` processor under
//! `solana-program-test`, which links the program natively and runs it
//! against a real bank, the real SPL token program, and real sysvars — so
//! the CPIs, the PDA signatures and the rent are all genuine without the
//! SBF toolchain.
//!
//! Every rejection is asserted by its `BridgeError` code rather than by
//! "the transaction failed", because the codes are the bridge's ABI and
//! must mean the same thing here as on the EVM endpoints.

use bridge_codec::{
    Attestation, Body, GuardianSetUpgrade, Payload, Signature, Transfer, CHAIN_RAND,
    GOVERNANCE_EMITTER, GUARDIAN_GRACE_SECS,
};
use k256::ecdsa::{RecoveryId, SigningKey, VerifyingKey};
use rand_bridge::attestation::digest as attestation_digest;
use rand_bridge::error::BridgeError;
use rand_bridge::instruction as bridge_ix;
use rand_bridge::processor::process_instruction;
use rand_bridge::state::{
    authority_pda, config_pda, custody_pda, guardian_pda, msg_pda, spent_pda, token_pda,
    BridgeAccount, Config, GuardianSetAccount, PostedMessage, TokenRegistry,
};
use serde_json::Value;
use sha3::{Digest as _, Keccak256};
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use solana_program_test::{processor, BanksClientError, ProgramTest, ProgramTestContext};
use solana_sdk::account::{Account, AccountSharedData};
use solana_sdk::clock::Clock;
use solana_sdk::instruction::{Instruction, InstructionError};
use solana_sdk::program_option::COption;
use solana_sdk::program_pack::Pack;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signature as TxSignature, Signer};
use solana_sdk::transaction::{Transaction, TransactionError};
use std::collections::HashSet;

/// The shared vectors, baked in so the test needs no working-directory
/// assumptions.
const VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../vectors/attestations.json"
));

/// The Rand-side burn emitter these tests configure, where no vector
/// pins one.
const RAND_EMITTER: [u8; 32] = [0x11; 32];

/// Enough lamports to be rent-exempt for anything these tests create.
const FUNDED: u64 = 100_000_000_000;

/// A quorum of the six-key guardian set: `6 * 2 / 3 + 1 == 5`.
const QUORUM: &[u8] = &[0, 1, 2, 3, 4];

// ----------------------------------------------------------------------
// guardian secp256k1 helpers
//
// `sign_digest` and `guardian_address` mirror `shrugg-core::bridge`; they
// are copied rather than imported so this crate does not depend on the
// fullnode workspace.
// ----------------------------------------------------------------------

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// The last 20 bytes of `keccak256(uncompressed_pubkey[1..])`.
fn address_from_verifying_key(key: &VerifyingKey) -> [u8; 20] {
    let encoded = key.to_encoded_point(false);
    let hash = keccak256(&encoded.as_bytes()[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..]);
    out
}

/// Signs `digest` with the secp256k1 secret key `secret`, returning a
/// low-s [`Signature`] tagged with guardian `index` and recovery id 0 or 1.
fn sign_digest(secret: &[u8; 32], index: u8, digest: &[u8; 32]) -> Signature {
    let signing_key = SigningKey::from_bytes(secret.into()).expect("valid secp256k1 secret key");
    let (sig, recid) = signing_key
        .sign_prehash_recoverable(digest)
        .expect("prehash signing cannot fail for a valid key and 32-byte digest");
    let (sig, recid) = match sig.normalize_s() {
        Some(normalized) => {
            let flipped = RecoveryId::from_byte(recid.to_byte() ^ 1)
                .expect("flipping bit 0 of a valid recovery id stays valid");
            (normalized, flipped)
        }
        None => (sig, recid),
    };
    let (r, s) = sig.split_bytes();
    Signature {
        index,
        r: r.into(),
        s: s.into(),
        v: recid.to_byte(),
    }
}

/// The shared vectors' guardian secrets: `[0; 31] || (index + 1)`.
fn guardian_secret(index: u8) -> [u8; 32] {
    let mut secret = [0u8; 32];
    secret[31] = index + 1;
    secret
}

fn guardian_address(index: u8) -> [u8; 20] {
    let signing_key =
        SigningKey::from_bytes(&guardian_secret(index).into()).expect("valid secret key");
    address_from_verifying_key(&VerifyingKey::from(&signing_key))
}

/// Guardian set 0 as the shared vectors define it: secrets 1..=6.
fn vector_guardians() -> Vec<[u8; 20]> {
    (0..6u8).map(guardian_address).collect()
}

// ----------------------------------------------------------------------
// attestation construction
// ----------------------------------------------------------------------

fn transfer_payload(
    amount: u128,
    token: &Pubkey,
    token_chain: u16,
    to: &Pubkey,
    to_chain: u16,
    fee: u128,
) -> Vec<u8> {
    Payload::Transfer(Transfer {
        amount: Transfer::u256_from_u128(amount),
        token_address: token.to_bytes(),
        token_chain,
        to: to.to_bytes(),
        to_chain,
        fee: Transfer::u256_from_u128(fee),
    })
    .encode()
}

fn body(emitter_chain: u16, emitter_address: [u8; 32], sequence: u64, payload: Vec<u8>) -> Body {
    Body {
        timestamp: 1_700_000_000,
        nonce: 7,
        emitter_chain,
        emitter_address,
        sequence,
        consistency_level: 1,
        payload,
    }
}

/// Signs `body` with `signers` (guardian indices into the *secrets*, not
/// necessarily into the on-chain set) and returns the encoded attestation
/// plus its digest.
fn signed(set_index: u32, body: Body, signers: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let digest = attestation_digest(&body.encode());
    let signatures = signers
        .iter()
        .enumerate()
        .map(|(position, &secret_index)| {
            let mut sig = sign_digest(&guardian_secret(secret_index), secret_index, &digest);
            // The signature's own index is its slot in the guardian set,
            // which for a rotated set is not the secret's number.
            sig.index = position as u8;
            sig
        })
        .collect();
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

// ----------------------------------------------------------------------
// account fixtures
// ----------------------------------------------------------------------

fn mint_account(decimals: u8) -> Account {
    let mut data = vec![0u8; spl_token::state::Mint::LEN];
    spl_token::state::Mint {
        mint_authority: COption::None,
        supply: u64::MAX / 2,
        decimals,
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

/// A synthetic ProgramData account naming `authority` as the program's
/// upgrade authority. `solana-program-test` registers the program as a
/// builtin rather than through the upgradeable loader, so the account
/// `Initialize` authenticates against is seeded by hand.
fn program_data_account(authority: &Pubkey) -> Account {
    let state = UpgradeableLoaderState::ProgramData {
        slot: 0,
        upgrade_authority_address: Some(*authority),
    };
    Account {
        lamports: FUNDED,
        data: bincode::serialize(&state).expect("serializes"),
        owner: solana_sdk_ids::bpf_loader_upgradeable::id(),
        executable: false,
        rent_epoch: 0,
    }
}

fn wallet_account() -> Account {
    Account {
        lamports: FUNDED,
        data: Vec::new(),
        owner: solana_sdk_ids::system_program::id(),
        executable: false,
        rent_epoch: 0,
    }
}

#[track_caller]
fn assert_bridge_error(result: Result<(), BanksClientError>, expected: BridgeError) {
    let err = result
        .err()
        .unwrap_or_else(|| panic!("expected {expected:?}, but the transaction succeeded"));
    match err.unwrap() {
        TransactionError::InstructionError(_, InstructionError::Custom(code)) => {
            assert_eq!(
                BridgeError::from_code(code),
                Some(expected),
                "expected {expected:?} (code {}), got code {code}",
                expected.code()
            );
        }
        other => panic!("expected {expected:?}, got {other:?}"),
    }
}

// ----------------------------------------------------------------------
// the harness
// ----------------------------------------------------------------------

struct Bridge {
    ctx: ProgramTestContext,
    program: Pubkey,
    admin: Keypair,
    pauser: Keypair,
    /// The program's upgrade authority, the only account `Initialize`
    /// accepts.
    deployer: Keypair,
    mint: Pubkey,
    /// Signatures already submitted, so a repeat is not served from
    /// the bank's status cache.
    sent: HashSet<TxSignature>,
}

impl Bridge {
    /// Boots a bank with the program, a mint, a funded admin and pauser,
    /// and any extra pre-seeded accounts, then runs `Initialize`.
    async fn start(
        mint: Pubkey,
        decimals: u8,
        rand_emitter: [u8; 32],
        guardians: Vec<[u8; 20]>,
        extra: Vec<(Pubkey, Account)>,
    ) -> Bridge {
        let program = rand_bridge::id();
        let admin = Keypair::new();
        let pauser = Keypair::new();
        let deployer = Keypair::new();

        let mut test = ProgramTest::new("rand_bridge", program, processor!(process_instruction));
        test.add_account(mint, mint_account(decimals));
        test.add_account(admin.pubkey(), wallet_account());
        test.add_account(pauser.pubkey(), wallet_account());
        test.add_account(deployer.pubkey(), wallet_account());
        test.add_account(
            bridge_ix::program_data_address(&program),
            program_data_account(&deployer.pubkey()),
        );
        for (key, account) in extra {
            test.add_account(key, account);
        }
        let ctx = test.start_with_context().await;

        let mut bridge = Bridge {
            ctx,
            program,
            admin,
            pauser,
            deployer,
            mint,
            sent: HashSet::new(),
        };
        let ix = bridge_ix::initialize(
            &program,
            &bridge.deployer.pubkey(),
            &bridge.admin.pubkey(),
            &bridge.pauser.pubkey(),
            rand_emitter,
            guardians,
        );
        let deployer = bridge.deployer.insecure_clone();
        bridge.send(ix, &[&deployer]).await.expect("initialize");
        bridge
    }

    /// The common case: a fresh 6-decimal mint and the vectors' guardian
    /// set 0.
    async fn simple(decimals: u8) -> Bridge {
        Bridge::start(
            Pubkey::new_unique(),
            decimals,
            RAND_EMITTER,
            vector_guardians(),
            Vec::new(),
        )
        .await
    }

    /// Signs `instruction` with the bank's payer plus `extra_signers` and
    /// submits it.
    ///
    /// A byte-identical transaction would be answered out of the bank's
    /// status cache rather than executed — which would silently turn "the
    /// second `Pause` must fail" into a pass — so a repeat is re-signed
    /// against a fresh blockhash until its signature is one this harness
    /// has not sent before.
    async fn send(
        &mut self,
        instruction: Instruction,
        extra_signers: &[&Keypair],
    ) -> Result<(), BanksClientError> {
        let payer = self.ctx.payer.pubkey();
        loop {
            let blockhash = self
                .ctx
                .banks_client
                .get_latest_blockhash()
                .await
                .expect("blockhash");
            let tx = {
                let mut signers: Vec<&Keypair> = vec![&self.ctx.payer];
                signers.extend_from_slice(extra_signers);
                Transaction::new_signed_with_payer(
                    std::slice::from_ref(&instruction),
                    Some(&payer),
                    &signers,
                    blockhash,
                )
            };
            if self.sent.insert(tx.signatures[0]) {
                return self.ctx.banks_client.process_transaction(tx).await;
            }
            self.ctx
                .get_new_latest_blockhash()
                .await
                .expect("a fresh blockhash");
        }
    }

    async fn admin_send(&mut self, instruction: Instruction) -> Result<(), BanksClientError> {
        let admin = self.admin.insecure_clone();
        self.send(instruction, &[&admin]).await
    }

    async fn pauser_send(&mut self, instruction: Instruction) -> Result<(), BanksClientError> {
        let pauser = self.pauser.insecure_clone();
        self.send(instruction, &[&pauser]).await
    }

    async fn account(&mut self, key: Pubkey) -> Option<Account> {
        self.ctx.banks_client.get_account(key).await.expect("rpc")
    }

    async fn state<T: BridgeAccount>(&mut self, key: Pubkey) -> T {
        let account = self
            .account(key)
            .await
            .unwrap_or_else(|| panic!("account {key} does not exist"));
        T::load(&account.data).expect("decodes")
    }

    async fn token(&mut self, key: Pubkey) -> spl_token::state::Account {
        let account = self
            .account(key)
            .await
            .unwrap_or_else(|| panic!("token account {key} does not exist"));
        spl_token::state::Account::unpack(&account.data).expect("unpacks")
    }

    async fn config(&mut self) -> Config {
        self.state(config_pda(&self.program).0).await
    }

    async fn registry(&mut self) -> TokenRegistry {
        self.state(token_pda(&self.program, &self.mint).0).await
    }

    async fn custody_balance(&mut self) -> u64 {
        self.token(custody_pda(&self.program, &self.mint).0)
            .await
            .amount
    }

    /// Sends a lamport to an address the program is about to create an
    /// account at, the way a griefer would.
    fn grief(&mut self, address: &Pubkey) {
        let account = Account {
            lamports: 1,
            data: Vec::new(),
            owner: solana_sdk_ids::system_program::id(),
            executable: false,
            rent_epoch: 0,
        };
        self.ctx
            .set_account(address, &AccountSharedData::from(account));
    }

    /// Gives `wallet` lamports so it can sign and pay rent.
    fn fund(&mut self, wallet: &Pubkey) {
        self.ctx
            .set_account(wallet, &AccountSharedData::from(wallet_account()));
    }

    /// Creates `wallet`'s associated token account for the bridge's mint,
    /// holding `amount`.
    fn put_ata(&mut self, wallet: &Pubkey, amount: u64) -> Pubkey {
        let ata = bridge_ix::associated_token_address(wallet, &self.mint);
        let account = token_account(&self.mint, wallet, amount);
        self.ctx
            .set_account(&ata, &AccountSharedData::from(account));
        ata
    }

    async fn set_token(
        &mut self,
        enabled: bool,
        per_transfer_cap: u64,
        daily_cap: u64,
    ) -> Result<(), BanksClientError> {
        let ix = bridge_ix::set_token(
            &self.program,
            &self.admin.pubkey(),
            &self.mint,
            enabled,
            per_transfer_cap,
            daily_cap,
        );
        self.admin_send(ix).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn lock(
        &mut self,
        owner: &Keypair,
        owner_ata: Pubkey,
        amount: u64,
        rand_recipient: [u8; 32],
        relayer_fee: u64,
        nonce: u32,
    ) -> Result<(), BanksClientError> {
        let sequence = self.config().await.sequence;
        let ix = bridge_ix::lock(
            &self.program,
            &owner.pubkey(),
            &owner_ata,
            &self.mint,
            sequence,
            amount,
            rand_recipient,
            relayer_fee,
            nonce,
        );
        self.send(ix, &[owner]).await
    }

    async fn release(
        &mut self,
        relayer: &Keypair,
        set_index: u32,
        recipient: &Pubkey,
        digest: &[u8; 32],
        attestation: Vec<u8>,
    ) -> Result<(), BanksClientError> {
        let ix = self.release_ix(relayer, set_index, recipient, digest, attestation);
        self.send(ix, &[relayer]).await
    }

    fn release_ix(
        &self,
        relayer: &Keypair,
        set_index: u32,
        recipient: &Pubkey,
        digest: &[u8; 32],
        attestation: Vec<u8>,
    ) -> Instruction {
        bridge_ix::release(
            &self.program,
            &relayer.pubkey(),
            &self.mint,
            set_index,
            recipient,
            digest,
            attestation,
        )
    }

    /// Fills custody by locking `amount` from a throwaway holder, so a
    /// release has something to pay out of.
    async fn fill_custody(&mut self, amount: u64) {
        let holder = Keypair::new();
        self.fund(&holder.pubkey());
        let ata = self.put_ata(&holder.pubkey(), amount);
        self.lock(&holder, ata, amount, [0x44; 32], 0, 0)
            .await
            .expect("custody-filling lock");
    }

    async fn now(&mut self) -> i64 {
        let clock: Clock = self.ctx.banks_client.get_sysvar().await.expect("clock");
        clock.unix_timestamp
    }

    /// Pins the clock's wall time, so grace periods and rate-limit
    /// windows are testable.
    ///
    /// Overriding the sysvar is the whole mechanism: `warp_to_slot` would
    /// be the more realistic way to move time, but it re-verifies the
    /// bank's capitalization against its accounts hash, which the
    /// `set_account` calls that seed these fixtures deliberately break.
    /// Nothing here depends on the slot itself, only on `unix_timestamp`.
    async fn set_time(&mut self, unix_timestamp: i64) {
        let mut clock: Clock = self.ctx.banks_client.get_sysvar().await.expect("clock");
        clock.unix_timestamp = unix_timestamp;
        self.ctx.set_sysvar(&clock);
    }
}

// ----------------------------------------------------------------------
// tests
// ----------------------------------------------------------------------

#[tokio::test]
async fn initialize_and_set_token() {
    let mut b = Bridge::simple(6).await;
    let program = b.program;
    let mint = b.mint;
    let admin = b.admin.pubkey();
    let pauser = b.pauser.pubkey();

    let config = b.config().await;
    assert_eq!(config.admin, admin);
    assert_eq!(config.pending_admin, Pubkey::default());
    assert_eq!(config.pauser, pauser);
    assert!(!config.paused);
    assert_eq!(config.rand_emitter, RAND_EMITTER);
    assert_eq!(config.current_guardian_set, 0);
    assert_eq!(config.sequence, 0);
    assert_eq!(config.bump, config_pda(&program).1);

    let set: GuardianSetAccount = b.state(guardian_pda(&program, 0).0).await;
    assert_eq!(set.index, 0);
    assert_eq!(set.keys, vector_guardians());
    assert_eq!(set.expiration_time, 0, "the current set never expires");

    // Only the upgrade authority may initialize, and authentication
    // comes before the one-shot check.
    let stranger = Keypair::new();
    b.fund(&stranger.pubkey());
    let front_run = bridge_ix::initialize(
        &program,
        &stranger.pubkey(),
        &stranger.pubkey(),
        &stranger.pubkey(),
        RAND_EMITTER,
        vector_guardians(),
    );
    assert_bridge_error(b.send(front_run, &[&stranger]).await, BridgeError::NotAdmin);

    // Deployment is one-shot, even for the authority.
    let deployer = b.deployer.insecure_clone();
    let again = bridge_ix::initialize(
        &program,
        &deployer.pubkey(),
        &admin,
        &pauser,
        RAND_EMITTER,
        vector_guardians(),
    );
    assert_bridge_error(b.send(again, &[&deployer]).await, BridgeError::InvalidPda);

    // Only the admin configures tokens.
    let ix = bridge_ix::set_token(&program, &stranger.pubkey(), &mint, true, 0, 0);
    assert_bridge_error(b.send(ix, &[&stranger]).await, BridgeError::NotAdmin);

    b.set_token(true, 1_000, 2_000).await.expect("set token");
    let registry = b.registry().await;
    assert_eq!(registry.mint, mint);
    assert!(registry.enabled);
    assert_eq!(registry.decimals, 6);
    assert_eq!(registry.per_transfer_cap, 1_000);
    assert_eq!(registry.daily_cap, 2_000);
    assert_eq!(registry.custody, 0);

    let custody = b.token(custody_pda(&program, &mint).0).await;
    assert_eq!(custody.mint, mint);
    assert_eq!(
        custody.owner,
        authority_pda(&program).0,
        "custody must be owned by the authority PDA, not by anyone else"
    );
    assert_eq!(custody.amount, 0);

    // Disabling keeps the cached decimals (the mint may have stopped
    // answering, which is exactly when disabling matters); re-enabling
    // refreshes them.
    b.set_token(false, 0, 0).await.expect("disable");
    let registry = b.registry().await;
    assert!(!registry.enabled);
    assert_eq!(registry.decimals, 6);
    assert_eq!(registry.per_transfer_cap, 0);

    b.set_token(true, 5, 6).await.expect("re-enable");
    let registry = b.registry().await;
    assert!(registry.enabled);
    assert_eq!(registry.decimals, 6);
    assert_eq!(registry.per_transfer_cap, 5);
    assert_eq!(registry.daily_cap, 6);
    // Reconfiguring did not recreate custody.
    assert_eq!(b.custody_balance().await, 0);
}

#[tokio::test]
async fn lock_transfers_and_posts_message() {
    let mut b = Bridge::simple(6).await;
    let program = b.program;
    let mint = b.mint;
    b.set_token(true, 0, 0).await.expect("set token");

    let owner = Keypair::new();
    b.fund(&owner.pubkey());
    let owner_ata = b.put_ata(&owner.pubkey(), 10_000_000);

    let recipient = [0x33u8; 32];
    b.lock(&owner, owner_ata, 1_234_567, recipient, 0, 9)
        .await
        .expect("lock");

    assert_eq!(b.token(owner_ata).await.amount, 10_000_000 - 1_234_567);
    assert_eq!(b.custody_balance().await, 1_234_567);
    assert_eq!(b.registry().await.custody, 1_234_567);
    assert_eq!(b.config().await.sequence, 1);

    let posted: PostedMessage = b.state(msg_pda(&program, 0).0).await;
    assert_eq!(posted.sequence, 0);
    let decoded = Body::decode(&posted.body).expect("body decodes");
    assert_eq!(decoded.emitter_chain, 5);
    assert_eq!(decoded.emitter_address, program.to_bytes());
    assert_eq!(decoded.sequence, 0);
    assert_eq!(decoded.consistency_level, 1);
    assert_eq!(decoded.nonce, 9);
    assert!(decoded.timestamp > 0, "the clock was read");
    match Payload::decode(&decoded.payload).expect("payload decodes") {
        Payload::Transfer(t) => {
            assert_eq!(t.amount_u128(), Some(123_456_700), "6dp scales up by 100");
            assert_eq!(t.token_address, mint.to_bytes());
            assert_eq!(t.token_chain, 5);
            assert_eq!(t.to, recipient);
            assert_eq!(t.to_chain, CHAIN_RAND);
            assert_eq!(t.fee_u128(), Some(0));
        }
        other => panic!("expected a transfer payload, got {other:?}"),
    }

    // The fee is normalised the same way as the amount.
    b.lock(&owner, owner_ata, 1_000_000, recipient, 100_000, 0)
        .await
        .expect("second lock");
    let posted: PostedMessage = b.state(msg_pda(&program, 1).0).await;
    let decoded = Body::decode(&posted.body).expect("body decodes");
    assert_eq!(decoded.sequence, 1);
    match Payload::decode(&decoded.payload).expect("payload decodes") {
        Payload::Transfer(t) => {
            assert_eq!(t.amount_u128(), Some(100_000_000));
            assert_eq!(t.fee_u128(), Some(10_000_000));
        }
        other => panic!("expected a transfer payload, got {other:?}"),
    }
    assert_eq!(b.config().await.sequence, 2);
    assert_eq!(b.registry().await.custody, 2_234_567);

    // Rejections, in the order `RandBridgeBase.lock` checks them.
    assert_bridge_error(
        b.lock(&owner, owner_ata, 1_000, [0u8; 32], 0, 0).await,
        BridgeError::ZeroRecipient,
    );
    assert_bridge_error(
        b.lock(&owner, owner_ata, 1_000, recipient, 2_000, 0).await,
        BridgeError::FeeExceedsAmount,
    );
    assert_bridge_error(
        b.lock(&owner, owner_ata, 0, recipient, 0, 0).await,
        BridgeError::ZeroAmount,
    );

    b.set_token(false, 0, 0).await.expect("disable");
    assert_bridge_error(
        b.lock(&owner, owner_ata, 1_000, recipient, 0, 0).await,
        BridgeError::TokenDisabled,
    );
    b.set_token(true, 0, 0).await.expect("re-enable");

    let ix = bridge_ix::pause(&program, &b.pauser.pubkey());
    b.pauser_send(ix).await.expect("pause");
    assert_bridge_error(
        b.lock(&owner, owner_ata, 1_000, recipient, 0, 0).await,
        BridgeError::IsPaused,
    );

    // Nothing above moved a token or a sequence number.
    assert_eq!(b.config().await.sequence, 2);
    assert_eq!(b.custody_balance().await, 2_234_567);
}

#[tokio::test]
async fn lock_truncates_9dp_mint() {
    let mut b = Bridge::simple(9).await;
    b.set_token(true, 0, 0).await.expect("set token");

    let owner = Keypair::new();
    b.fund(&owner.pubkey());
    let owner_ata = b.put_ata(&owner.pubkey(), 2_000_000_000);

    b.lock(&owner, owner_ata, 1_000_000_001, [0x33; 32], 0, 0)
        .await
        .expect("lock");

    // The odd unit is below one attestable step and stays with the owner.
    assert_eq!(b.custody_balance().await, 1_000_000_000);
    assert_eq!(
        b.token(owner_ata).await.amount,
        2_000_000_000 - 1_000_000_000
    );
    assert_eq!(b.registry().await.custody, 1_000_000_000);

    let posted: PostedMessage = b.state(msg_pda(&b.program, 0).0).await;
    let decoded = Body::decode(&posted.body).expect("body decodes");
    match Payload::decode(&decoded.payload).expect("payload decodes") {
        Payload::Transfer(t) => assert_eq!(t.amount_u128(), Some(100_000_000)),
        other => panic!("expected a transfer payload, got {other:?}"),
    }

    // Dust below one attestable unit locks nothing at all.
    assert_bridge_error(
        b.lock(&owner, owner_ata, 9, [0x33; 32], 0, 0).await,
        BridgeError::ZeroAmount,
    );
}

#[tokio::test]
async fn release_pays_recipient_and_relayer() {
    let mut b = Bridge::simple(6).await;
    let mint = b.mint;
    b.set_token(true, 0, 0).await.expect("set token");
    b.fill_custody(2_000_000).await;

    let relayer = Keypair::new();
    b.fund(&relayer.pubkey());
    let relayer_ata = b.put_ata(&relayer.pubkey(), 0);
    let recipient = Pubkey::new_unique();
    let recipient_ata = b.put_ata(&recipient, 0);

    let (attestation, digest) = signed(
        0,
        body(
            CHAIN_RAND,
            RAND_EMITTER,
            1,
            transfer_payload(100_000_000, &mint, 5, &recipient, 5, 5_000_000),
        ),
        QUORUM,
    );
    b.release(&relayer, 0, &recipient, &digest, attestation)
        .await
        .expect("release");

    // 100_000_000 at 8dp is 1_000_000 units of a 6dp mint; the fee is
    // 50_000 of those.
    assert_eq!(b.token(relayer_ata).await.amount, 50_000);
    assert_eq!(b.token(recipient_ata).await.amount, 950_000);
    assert_eq!(b.custody_balance().await, 1_000_000);

    let registry = b.registry().await;
    assert_eq!(registry.custody, 1_000_000);
    assert_eq!(registry.window_used, 1_000_000);
    let now = b.now().await as u64;
    assert_eq!(registry.window_start, now / 86_400);

    // The digest is marked spent, by an account only this program owns.
    let consumed = b
        .account(spent_pda(&b.program, &digest).0)
        .await
        .expect("consumed marker exists");
    assert_eq!(consumed.owner, b.program);
}

#[tokio::test]
async fn release_rejects_replay_wrong_emitter_caps_paused_and_insufficient_custody() {
    let mut b = Bridge::simple(6).await;
    let program = b.program;
    let mint = b.mint;
    b.set_token(true, 0, 0).await.expect("set token");
    b.fill_custody(2_000_000).await;

    let relayer = Keypair::new();
    b.fund(&relayer.pubkey());
    b.put_ata(&relayer.pubkey(), 0);
    let recipient = Pubkey::new_unique();
    b.put_ata(&recipient, 0);

    // A good release first, so the replay has something to replay.
    let good = transfer_payload(100_000_000, &mint, 5, &recipient, 5, 0);
    let (bytes, digest) = signed(0, body(CHAIN_RAND, RAND_EMITTER, 1, good.clone()), QUORUM);
    b.release(&relayer, 0, &recipient, &digest, bytes.clone())
        .await
        .expect("release");
    assert_bridge_error(
        b.release(&relayer, 0, &recipient, &digest, bytes).await,
        BridgeError::AlreadyConsumed,
    );

    // Each case below gets its own sequence, so its digest is distinct
    // and none of them can be confused with a replay.
    let mut sequence = 10u64;
    let mut submit = |payload: Vec<u8>, emitter_chain: u16, emitter: [u8; 32], signers: &[u8]| {
        sequence += 1;
        signed(0, body(emitter_chain, emitter, sequence, payload), signers)
    };

    let cases: Vec<(BridgeError, Vec<u8>, [u8; 32])> = vec![
        (
            BridgeError::WrongEmitter,
            good.clone(),
            [0x99; 32], // not the configured Rand emitter
        ),
        (
            BridgeError::WrongToChain,
            transfer_payload(100_000_000, &mint, 5, &recipient, CHAIN_RAND, 0),
            RAND_EMITTER,
        ),
        (
            BridgeError::WrongTokenChain,
            transfer_payload(100_000_000, &mint, 2, &recipient, 5, 0),
            RAND_EMITTER,
        ),
        (
            BridgeError::FeeExceedsAmount,
            transfer_payload(100_000_000, &mint, 5, &recipient, 5, 200_000_000),
            RAND_EMITTER,
        ),
        (
            BridgeError::ZeroRecipient,
            transfer_payload(100_000_000, &mint, 5, &Pubkey::default(), 5, 0),
            RAND_EMITTER,
        ),
        (
            // 99 at 8dp is below one unit of a 6dp mint.
            BridgeError::ZeroAmount,
            transfer_payload(99, &mint, 5, &recipient, 5, 0),
            RAND_EMITTER,
        ),
        (
            BridgeError::InsufficientCustody,
            transfer_payload(900_000_000, &mint, 5, &recipient, 5, 0),
            RAND_EMITTER,
        ),
    ];
    for (expected, payload, emitter) in cases {
        let recipient_for_case = match Payload::decode(&payload).expect("payload") {
            Payload::Transfer(t) => Pubkey::new_from_array(t.to),
            other => panic!("expected a transfer, got {other:?}"),
        };
        let (bytes, digest) = submit(payload, CHAIN_RAND, emitter, QUORUM);
        assert_bridge_error(
            b.release(&relayer, 0, &recipient_for_case, &digest, bytes)
                .await,
            expected,
        );
    }

    // A payload amount that does not fit a u128 — let alone the mint's
    // u64 — is refused rather than truncated.
    let huge = Payload::Transfer(Transfer {
        amount: [0xff; 32],
        token_address: mint.to_bytes(),
        token_chain: 5,
        to: recipient.to_bytes(),
        to_chain: 5,
        fee: [0u8; 32],
    })
    .encode();
    let (bytes, digest) = submit(huge, CHAIN_RAND, RAND_EMITTER, QUORUM);
    assert_bridge_error(
        b.release(&relayer, 0, &recipient, &digest, bytes).await,
        BridgeError::AmountOverflow,
    );

    // Guardian set 1 does not exist yet, so its (empty) PDA is not a set.
    let (bytes, digest) = signed(1, body(CHAIN_RAND, RAND_EMITTER, 99, good.clone()), QUORUM);
    assert_bridge_error(
        b.release(&relayer, 1, &recipient, &digest, bytes).await,
        BridgeError::UnknownGuardianSet,
    );

    // The emitter chain is bound as tightly as the address.
    let (bytes, digest) = submit(good.clone(), 2, RAND_EMITTER, QUORUM);
    assert_bridge_error(
        b.release(&relayer, 0, &recipient, &digest, bytes).await,
        BridgeError::WrongEmitter,
    );

    // A governance payload is not a transfer.
    let upgrade = Payload::GuardianSetUpgrade(GuardianSetUpgrade {
        new_index: 1,
        keys: vector_guardians(),
    })
    .encode();
    let (bytes, digest) = submit(upgrade, CHAIN_RAND, RAND_EMITTER, QUORUM);
    assert_bridge_error(
        b.release(&relayer, 0, &recipient, &digest, bytes).await,
        BridgeError::BadPayloadId,
    );

    // Four signatures is under the six-key set's quorum of five.
    let (bytes, digest) = submit(good.clone(), CHAIN_RAND, RAND_EMITTER, &[0, 1, 2, 3]);
    assert_bridge_error(
        b.release(&relayer, 0, &recipient, &digest, bytes).await,
        BridgeError::NoQuorum,
    );

    // Caps: per-transfer, then the rolling day.
    b.set_token(true, 500_000, 0).await.expect("cap");
    let (bytes, digest) = submit(good.clone(), CHAIN_RAND, RAND_EMITTER, QUORUM);
    assert_bridge_error(
        b.release(&relayer, 0, &recipient, &digest, bytes).await,
        BridgeError::PerTransferCap,
    );

    // The first release already used 1_000_000 of the window, so a cap of
    // 1_500_000 leaves no room for another 1_000_000.
    b.set_token(true, 0, 1_500_000).await.expect("daily cap");
    let (bytes, digest) = submit(good.clone(), CHAIN_RAND, RAND_EMITTER, QUORUM);
    assert_bridge_error(
        b.release(&relayer, 0, &recipient, &digest, bytes).await,
        BridgeError::DailyCap,
    );

    // Disabled, then paused.
    b.set_token(false, 0, 0).await.expect("disable");
    let (bytes, digest) = submit(good.clone(), CHAIN_RAND, RAND_EMITTER, QUORUM);
    assert_bridge_error(
        b.release(&relayer, 0, &recipient, &digest, bytes).await,
        BridgeError::TokenDisabled,
    );
    b.set_token(true, 0, 0).await.expect("re-enable");

    let ix = bridge_ix::pause(&program, &b.pauser.pubkey());
    b.pauser_send(ix).await.expect("pause");
    let (bytes, digest) = submit(good, CHAIN_RAND, RAND_EMITTER, QUORUM);
    assert_bridge_error(
        b.release(&relayer, 0, &recipient, &digest, bytes).await,
        BridgeError::IsPaused,
    );

    // Custody is exactly where the one successful release left it.
    assert_eq!(b.custody_balance().await, 1_000_000);
    assert_eq!(b.registry().await.custody, 1_000_000);
}

#[tokio::test]
async fn release_rejects_bad_ata_and_wrong_pda() {
    let mut b = Bridge::simple(6).await;
    let program = b.program;
    let mint = b.mint;
    b.set_token(true, 0, 0).await.expect("set token");
    b.fill_custody(2_000_000).await;

    let relayer = Keypair::new();
    b.fund(&relayer.pubkey());
    let relayer_ata = b.put_ata(&relayer.pubkey(), 0);
    let recipient = Pubkey::new_unique();
    b.put_ata(&recipient, 0);

    let (bytes, digest) = signed(
        0,
        body(
            CHAIN_RAND,
            RAND_EMITTER,
            1,
            transfer_payload(100_000_000, &mint, 5, &recipient, 5, 0),
        ),
        QUORUM,
    );

    // Every one of these is a well-formed, fully signed attestation; only
    // the account list is wrong.
    let base = b.release_ix(&relayer, 0, &recipient, &digest, bytes.clone());

    // 7: recipient ATA — pointed at the relayer's account instead.
    let mut ix = base.clone();
    ix.accounts[7].pubkey = relayer_ata;
    assert_bridge_error(b.send(ix, &[&relayer]).await, BridgeError::InvalidAta);

    // 8: relayer ATA — pointed at a stranger's.
    let stranger = Pubkey::new_unique();
    let mut ix = base.clone();
    ix.accounts[8].pubkey = bridge_ix::associated_token_address(&stranger, &mint);
    assert_bridge_error(b.send(ix, &[&relayer]).await, BridgeError::InvalidAta);

    // 2: guardian set PDA — the set the attestation does not name.
    let mut ix = base.clone();
    ix.accounts[2].pubkey = guardian_pda(&program, 1).0;
    assert_bridge_error(b.send(ix, &[&relayer]).await, BridgeError::InvalidPda);

    // 5: custody PDA — another mint's.
    let other_mint = Pubkey::new_unique();
    let mut ix = base.clone();
    ix.accounts[5].pubkey = custody_pda(&program, &other_mint).0;
    assert_bridge_error(b.send(ix, &[&relayer]).await, BridgeError::InvalidPda);

    // 6: authority PDA — the config, which is a PDA of this program but
    // not this one.
    let mut ix = base.clone();
    ix.accounts[6].pubkey = config_pda(&program).0;
    assert_bridge_error(b.send(ix, &[&relayer]).await, BridgeError::InvalidPda);

    // 9: consumed PDA — seeded with a different digest, which would leave
    // this attestation replayable.
    let mut ix = base.clone();
    ix.accounts[9].pubkey = spent_pda(&program, &[0xab; 32]).0;
    assert_bridge_error(b.send(ix, &[&relayer]).await, BridgeError::InvalidPda);

    // 1: config PDA — a look-alike account.
    let mut ix = base.clone();
    ix.accounts[1].pubkey = token_pda(&program, &mint).0;
    assert_bridge_error(b.send(ix, &[&relayer]).await, BridgeError::InvalidPda);

    // 10: the token program — a fake one.
    let mut ix = base.clone();
    ix.accounts[10].pubkey = Pubkey::new_unique();
    assert_bridge_error(b.send(ix, &[&relayer]).await, BridgeError::InvalidPda);

    // Nothing moved, and the untouched instruction still works.
    assert_eq!(b.custody_balance().await, 2_000_000);
    b.send(base, &[&relayer]).await.expect("release");
    assert_eq!(b.custody_balance().await, 1_000_000);
}

#[tokio::test]
async fn guardian_upgrade_then_old_set_grace() {
    let mut b = Bridge::simple(6).await;
    let program = b.program;
    let mint = b.mint;
    b.set_token(true, 0, 0).await.expect("set token");
    b.fill_custody(5_000_000).await;

    let relayer = Keypair::new();
    b.fund(&relayer.pubkey());
    b.put_ata(&relayer.pubkey(), 0);
    let recipient = Pubkey::new_unique();
    let recipient_ata = b.put_ata(&recipient, 0);

    let start = 1_700_000_000i64;
    b.set_time(start).await;

    // Set 1 is six fresh keys, secrets 7..=12.
    let new_keys: Vec<[u8; 20]> = (6..12u8).map(guardian_address).collect();
    let upgrade = Payload::GuardianSetUpgrade(GuardianSetUpgrade {
        new_index: 1,
        keys: new_keys.clone(),
    })
    .encode();

    // A rotation must come from the governance emitter.
    let (bytes, digest) = signed(
        0,
        body(CHAIN_RAND, RAND_EMITTER, 1, upgrade.clone()),
        QUORUM,
    );
    let ix = bridge_ix::guardian_set_upgrade(&program, &relayer.pubkey(), 0, 1, &digest, bytes);
    assert_bridge_error(b.send(ix, &[&relayer]).await, BridgeError::WrongEmitter);

    // ... and must not skip an index.
    let skip = Payload::GuardianSetUpgrade(GuardianSetUpgrade {
        new_index: 2,
        keys: new_keys.clone(),
    })
    .encode();
    let (bytes, digest) = signed(0, body(CHAIN_RAND, GOVERNANCE_EMITTER, 2, skip), QUORUM);
    let ix = bridge_ix::guardian_set_upgrade(&program, &relayer.pubkey(), 0, 2, &digest, bytes);
    assert_bridge_error(b.send(ix, &[&relayer]).await, BridgeError::BadUpgradeIndex);

    // ... and must not list a key twice.
    let mut dup = new_keys.clone();
    dup[5] = dup[0];
    let duplicate = Payload::GuardianSetUpgrade(GuardianSetUpgrade {
        new_index: 1,
        keys: dup,
    })
    .encode();
    let (bytes, digest) = signed(
        0,
        body(CHAIN_RAND, GOVERNANCE_EMITTER, 3, duplicate),
        QUORUM,
    );
    let ix = bridge_ix::guardian_set_upgrade(&program, &relayer.pubkey(), 0, 1, &digest, bytes);
    assert_bridge_error(
        b.send(ix, &[&relayer]).await,
        BridgeError::DuplicateGuardian,
    );

    // The real thing. Rotations are allowed while paused.
    let pause_ix = bridge_ix::pause(&program, &b.pauser.pubkey());
    b.pauser_send(pause_ix).await.expect("pause");
    let (bytes, digest) = signed(0, body(CHAIN_RAND, GOVERNANCE_EMITTER, 4, upgrade), QUORUM);
    let ix = bridge_ix::guardian_set_upgrade(&program, &relayer.pubkey(), 0, 1, &digest, bytes);
    b.send(ix, &[&relayer]).await.expect("upgrade");
    let unpause_ix = bridge_ix::unpause(&program, &b.admin.pubkey());
    b.admin_send(unpause_ix).await.expect("unpause");

    assert_eq!(b.config().await.current_guardian_set, 1);
    let set0: GuardianSetAccount = b.state(guardian_pda(&program, 0).0).await;
    assert_eq!(
        set0.expiration_time,
        start as u64 + GUARDIAN_GRACE_SECS,
        "the superseded set expires one grace period out"
    );
    let set1: GuardianSetAccount = b.state(guardian_pda(&program, 1).0).await;
    assert_eq!(set1.index, 1);
    assert_eq!(set1.keys, new_keys);
    assert_eq!(set1.expiration_time, 0);

    // The superseded set still works inside its grace period.
    let transfer = transfer_payload(50_000_000, &mint, 5, &recipient, 5, 0);
    let (bytes, digest) = signed(
        0,
        body(CHAIN_RAND, RAND_EMITTER, 5, transfer.clone()),
        QUORUM,
    );
    b.release(&relayer, 0, &recipient, &digest, bytes)
        .await
        .expect("old set in grace");
    assert_eq!(b.token(recipient_ata).await.amount, 500_000);

    // The new set works too, signed by its own secrets.
    let (bytes, digest) = signed(
        1,
        body(CHAIN_RAND, RAND_EMITTER, 6, transfer.clone()),
        &[6, 7, 8, 9, 10],
    );
    b.release(&relayer, 1, &recipient, &digest, bytes)
        .await
        .expect("new set");
    assert_eq!(b.token(recipient_ata).await.amount, 1_000_000);

    // Past the grace period the old set is refused, and the new one is
    // not.
    b.set_time(start + GUARDIAN_GRACE_SECS as i64 + 1).await;
    let (bytes, digest) = signed(
        0,
        body(CHAIN_RAND, RAND_EMITTER, 7, transfer.clone()),
        QUORUM,
    );
    assert_bridge_error(
        b.release(&relayer, 0, &recipient, &digest, bytes).await,
        BridgeError::GuardianSetExpired,
    );
    let (bytes, digest) = signed(
        1,
        body(CHAIN_RAND, RAND_EMITTER, 8, transfer),
        &[6, 7, 8, 9, 10],
    );
    b.release(&relayer, 1, &recipient, &digest, bytes)
        .await
        .expect("new set after grace");
    assert_eq!(b.token(recipient_ata).await.amount, 1_500_000);

    // A rotation signed by the superseded set is refused outright, even
    // before its grace period runs out — it may not rotate itself back in.
    let stale = Payload::GuardianSetUpgrade(GuardianSetUpgrade {
        new_index: 2,
        keys: vector_guardians(),
    })
    .encode();
    let (bytes, digest) = signed(0, body(CHAIN_RAND, GOVERNANCE_EMITTER, 9, stale), QUORUM);
    let ix = bridge_ix::guardian_set_upgrade(&program, &relayer.pubkey(), 1, 2, &digest, bytes);
    assert_bridge_error(
        b.send(ix, &[&relayer]).await,
        BridgeError::GuardianSetExpired,
    );

    // The new window opened, so the day's usage restarted.
    let registry = b.registry().await;
    assert_eq!(registry.custody, 5_000_000 - 1_500_000);
    assert_eq!(registry.window_used, 500_000);
}

#[tokio::test]
async fn admin_two_step_and_pause_roles() {
    let mut b = Bridge::simple(6).await;
    let program = b.program;
    let mint = b.mint;
    let admin = b.admin.pubkey();
    let pauser = b.pauser.pubkey();

    let stranger = Keypair::new();
    b.fund(&stranger.pubkey());

    // Pausing: the pauser or the admin, and never twice.
    assert_bridge_error(
        b.send(bridge_ix::pause(&program, &stranger.pubkey()), &[&stranger])
            .await,
        BridgeError::NotPauser,
    );
    let ix = bridge_ix::pause(&program, &pauser);
    b.pauser_send(ix).await.expect("pauser pauses");
    let ix = bridge_ix::pause(&program, &pauser);
    assert_bridge_error(b.pauser_send(ix).await, BridgeError::IsPaused);

    // Unpausing: admin only. The pause quorum can stop the bridge but not
    // restart it.
    let ix = bridge_ix::unpause(&program, &pauser);
    assert_bridge_error(b.pauser_send(ix).await, BridgeError::NotAdmin);
    let ix = bridge_ix::unpause(&program, &admin);
    b.admin_send(ix).await.expect("admin unpauses");
    let ix = bridge_ix::unpause(&program, &admin);
    assert_bridge_error(b.admin_send(ix).await, BridgeError::NotPaused);

    // The admin can also pause.
    let ix = bridge_ix::pause(&program, &admin);
    b.admin_send(ix).await.expect("admin pauses");
    let ix = bridge_ix::unpause(&program, &admin);
    b.admin_send(ix).await.expect("admin unpauses");

    // With nothing in flight there is nothing to accept.
    assert_bridge_error(
        b.send(
            bridge_ix::accept_admin(&program, &stranger.pubkey()),
            &[&stranger],
        )
        .await,
        BridgeError::NotAdmin,
    );
    assert_bridge_error(
        b.send(
            bridge_ix::transfer_admin(&program, &stranger.pubkey(), &stranger.pubkey()),
            &[&stranger],
        )
        .await,
        BridgeError::NotAdmin,
    );

    // Start a transfer, then cancel it with the zero address.
    let next = Keypair::new();
    b.fund(&next.pubkey());
    let ix = bridge_ix::transfer_admin(&program, &admin, &next.pubkey());
    b.admin_send(ix).await.expect("transfer admin");
    assert_eq!(b.config().await.pending_admin, next.pubkey());

    let ix = bridge_ix::transfer_admin(&program, &admin, &Pubkey::default());
    b.admin_send(ix).await.expect("cancel");
    assert_eq!(b.config().await.pending_admin, Pubkey::default());
    assert_bridge_error(
        b.send(bridge_ix::accept_admin(&program, &next.pubkey()), &[&next])
            .await,
        BridgeError::NotAdmin,
    );

    // Start it again and hand over for real.
    let ix = bridge_ix::transfer_admin(&program, &admin, &next.pubkey());
    b.admin_send(ix).await.expect("transfer admin");
    assert_bridge_error(
        b.send(
            bridge_ix::accept_admin(&program, &stranger.pubkey()),
            &[&stranger],
        )
        .await,
        BridgeError::NotAdmin,
    );
    b.send(bridge_ix::accept_admin(&program, &next.pubkey()), &[&next])
        .await
        .expect("accept");

    let config = b.config().await;
    assert_eq!(config.admin, next.pubkey());
    assert_eq!(config.pending_admin, Pubkey::default());

    // The old admin has lost its powers; the new one has them.
    let ix = bridge_ix::set_token(&program, &admin, &mint, true, 0, 0);
    assert_bridge_error(b.admin_send(ix).await, BridgeError::NotAdmin);
    b.send(
        bridge_ix::set_token(&program, &next.pubkey(), &mint, true, 0, 0),
        &[&next],
    )
    .await
    .expect("new admin configures the token");

    // The pauser is unchanged by an admin handover.
    let ix = bridge_ix::pause(&program, &pauser);
    b.pauser_send(ix).await.expect("pauser still pauses");
}

/// Every account this program creates sits at an address anyone can
/// compute in advance. A lamport sent there first must not be able to
/// strand a signed release, brick the lock sequence, or block a guardian
/// rotation.
#[tokio::test]
async fn prefunded_pdas_do_not_brick_release_lock_or_upgrade() {
    let mut b = Bridge::simple(6).await;
    let program = b.program;
    let mint = b.mint;
    b.set_token(true, 0, 0).await.expect("set token");

    // --- Lock: someone owns the next message PDA's address. ---
    let owner = Keypair::new();
    b.fund(&owner.pubkey());
    let owner_ata = b.put_ata(&owner.pubkey(), 5_000_000);
    let next_sequence = b.config().await.sequence;
    b.grief(&msg_pda(&program, next_sequence).0);
    b.lock(&owner, owner_ata, 3_000_000, [0x44; 32], 0, 0)
        .await
        .expect("a pre-funded message PDA must not brick locking");
    assert_eq!(b.custody_balance().await, 3_000_000);
    let posted: PostedMessage = b.state(msg_pda(&program, next_sequence).0).await;
    assert_eq!(posted.sequence, next_sequence);
    assert_eq!(b.config().await.sequence, next_sequence + 1);

    // --- Release: someone owns the consumed marker's address. ---
    let relayer = Keypair::new();
    b.fund(&relayer.pubkey());
    let relayer_ata = b.put_ata(&relayer.pubkey(), 0);
    let recipient = Pubkey::new_unique();
    let recipient_ata = b.put_ata(&recipient, 0);

    let (bytes, digest) = signed(
        0,
        body(
            CHAIN_RAND,
            RAND_EMITTER,
            1,
            transfer_payload(100_000_000, &mint, 5, &recipient, 5, 5_000_000),
        ),
        QUORUM,
    );
    b.grief(&spent_pda(&program, &digest).0);
    b.release(&relayer, 0, &recipient, &digest, bytes)
        .await
        .expect("a pre-funded consumed PDA must not strand a signed release");
    assert_eq!(b.token(recipient_ata).await.amount, 950_000);
    assert_eq!(b.token(relayer_ata).await.amount, 50_000);
    let consumed = b
        .account(spent_pda(&program, &digest).0)
        .await
        .expect("consumed marker exists");
    assert_eq!(consumed.owner, program);

    // --- GuardianSetUpgrade: someone owns the next set's address. ---
    let new_keys: Vec<[u8; 20]> = (6..12u8).map(guardian_address).collect();
    let upgrade = Payload::GuardianSetUpgrade(GuardianSetUpgrade {
        new_index: 1,
        keys: new_keys.clone(),
    })
    .encode();
    let (bytes, digest) = signed(0, body(CHAIN_RAND, GOVERNANCE_EMITTER, 2, upgrade), QUORUM);
    b.grief(&guardian_pda(&program, 1).0);
    let ix = bridge_ix::guardian_set_upgrade(&program, &relayer.pubkey(), 0, 1, &digest, bytes);
    b.send(ix, &[&relayer])
        .await
        .expect("a pre-funded guardian set PDA must not block rotation");
    assert_eq!(b.config().await.current_guardian_set, 1);
    let set: GuardianSetAccount = b.state(guardian_pda(&program, 1).0).await;
    assert_eq!(set.keys, new_keys);
    assert_eq!(set.expiration_time, 0);
}

/// Every shared vector whose verifier is Solana, replayed against a bank
/// configured exactly as the vector describes.
#[tokio::test]
async fn vectors_release_to_solana() {
    let file: Value = serde_json::from_str(VECTORS).expect("vectors.json parses");
    let rand_emitter = unhex32(file["rand_emitter"].as_str().expect("rand_emitter"));

    // The vectors' guardian addresses must be the ones our secrets
    // produce, or nothing below proves anything.
    let listed: Vec<[u8; 20]> = file["guardians"]
        .as_array()
        .expect("guardians")
        .iter()
        .map(|g| {
            let bytes = hex::decode(g["address"].as_str().expect("address")).expect("hex");
            <[u8; 20]>::try_from(&bytes[..]).expect("20 bytes")
        })
        .collect();
    assert_eq!(listed, vector_guardians(), "guardian secrets drifted");

    let mut checked = 0usize;
    for vector in file["vectors"].as_array().expect("vectors") {
        if vector["verifier_chain"].as_u64() != Some(5) {
            continue;
        }
        checked += 1;
        let name = vector["name"].as_str().expect("name");
        let expect = vector["expect"].as_str().expect("expect");
        let set_index = vector["guardian_set_index"].as_u64().expect("index") as u32;

        let payload = &vector["payload"];
        let mint = Pubkey::new_from_array(unhex32(
            payload["token_address"].as_str().expect("token_address"),
        ));
        let recipient = Pubkey::new_from_array(unhex32(payload["to"].as_str().expect("to")));

        let keys: Vec<[u8; 20]> = vector["sets"]
            .as_array()
            .expect("sets")
            .iter()
            .find(|s| s["index"].as_u64() == Some(u64::from(set_index)))
            .expect("the vector's own guardian set")["keys"]
            .as_array()
            .expect("keys")
            .iter()
            .map(|k| {
                let bytes = hex::decode(k.as_str().expect("key")).expect("hex");
                <[u8; 20]>::try_from(&bytes[..]).expect("20 bytes")
            })
            .collect();

        // 6 decimals: the vectors' Solana asset is a USDC-shaped mint.
        let mut b = Bridge::start(mint, 6, rand_emitter, keys, Vec::new()).await;
        b.set_token(true, 0, 0).await.expect("set token");
        b.fill_custody(10_000_000).await;

        let relayer = Keypair::new();
        b.fund(&relayer.pubkey());
        let relayer_ata = b.put_ata(&relayer.pubkey(), 0);
        let recipient_ata = b.put_ata(&recipient, 0);

        let bytes = hex::decode(
            vector["attestation"]
                .as_str()
                .expect("attestation")
                .trim_start_matches("0x"),
        )
        .expect("hex");
        let digest = unhex32(vector["digest"].as_str().expect("digest"));

        let result = b
            .release(&relayer, set_index, &recipient, &digest, bytes)
            .await;

        match expect {
            "ok" => {
                result.unwrap_or_else(|e| panic!("{name}: expected ok, got {e:?}"));
                let amount: u128 = payload["amount"]
                    .as_str()
                    .expect("amount")
                    .parse()
                    .expect("amount parses");
                let fee: u128 = payload["fee"]
                    .as_str()
                    .expect("fee")
                    .parse()
                    .expect("fee parses");
                // 8dp on the wire, 6dp in the mint.
                let native = (amount / 100) as u64;
                let native_fee = (fee / 100) as u64;
                assert_eq!(
                    b.token(recipient_ata).await.amount,
                    native - native_fee,
                    "{name}: recipient"
                );
                assert_eq!(b.token(relayer_ata).await.amount, native_fee, "{name}: fee");
                assert_eq!(b.registry().await.custody, 10_000_000 - native, "{name}");
            }
            "wrong_emitter" => assert_bridge_error(result, BridgeError::WrongEmitter),
            "wrong_to_chain" => assert_bridge_error(result, BridgeError::WrongToChain),
            "wrong_token_chain" => assert_bridge_error(result, BridgeError::WrongTokenChain),
            "fee_exceeds_amount" => assert_bridge_error(result, BridgeError::FeeExceedsAmount),
            "amount_overflow" => assert_bridge_error(result, BridgeError::AmountOverflow),
            "replay" => assert_bridge_error(result, BridgeError::AlreadyConsumed),
            "no_quorum" => assert_bridge_error(result, BridgeError::NoQuorum),
            "set_expired" => assert_bridge_error(result, BridgeError::GuardianSetExpired),
            "unknown_set" => assert_bridge_error(result, BridgeError::UnknownGuardianSet),
            "bad_version" => assert_bridge_error(result, BridgeError::BadVersion),
            "bad_payload" => assert_bridge_error(result, BridgeError::BadPayloadLength),
            other => panic!("{name}: unhandled expect {other}"),
        }
    }

    // Exact, not a lower bound: if the shared generator gains or loses a
    // Solana vector, this test must be looked at rather than quietly
    // covering less than it did.
    assert_eq!(checked, 1, "expected 1 Solana vector, checked {checked}");
}

fn unhex32(s: &str) -> [u8; 32] {
    let bytes = hex::decode(s.trim_start_matches("0x")).expect("valid hex");
    <[u8; 32]>::try_from(&bytes[..]).expect("32 bytes")
}
