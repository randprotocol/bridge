//! End to end against the real `EthereumRandBridge` on a local anvil node:
//! a lock is observed and signed by six guardian daemons' worth of logic, and
//! a Rand burn is assembled by the relayer and released on-chain through its
//! own EIP-1559 signing. Skipped when Foundry is not installed.

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use bridge_codec::{Body, Payload, Transfer};
use bridge_daemons::api::{self, GuardianClient};
use bridge_daemons::config::{EvmConfig, EvmKind, Finality};
use bridge_daemons::crypto::GuardianKey;
use bridge_daemons::guardian;
use bridge_daemons::message::{Emitters, Observed};
use bridge_daemons::relayer::{self, Destinations, EndpointSubmitter, GuardianSet, Progress};
use bridge_daemons::sources::evm::EvmSource;
use bridge_daemons::store::Store;
use bridge_daemons::submit::evm::EvmSubmitter;
use bridge_daemons::submit::Outcome;

// anvil's published development keys; they guard nothing.
const DEPLOYER_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const DEPLOYER: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const RELAYER_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const RELAYER: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const RECIPIENT: &str = "0x000000000000000000000000000000000000cafe";
const RAND_EMITTER: [u8; 32] = [0xAA; 32];

struct Anvil(Child);
impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn have(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn run(cmd: &mut Command) -> String {
    let out = cmd.output().expect("spawn");
    assert!(
        out.status.success(),
        "{:?} failed: {}",
        cmd,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn deploy(rpc: &str, contract: &str, args: &[&str]) -> String {
    let evm_root = concat!(env!("CARGO_MANIFEST_DIR"), "/../evm");
    let mut cmd = Command::new("forge");
    cmd.args([
        "create",
        "--root",
        evm_root,
        "--rpc-url",
        rpc,
        "--private-key",
        DEPLOYER_KEY,
        "--broadcast",
        contract,
        "--constructor-args",
    ])
    .args(args);
    let out = run(&mut cmd);
    out.lines()
        .find_map(|l| l.strip_prefix("Deployed to: "))
        .expect("deployed address")
        .trim()
        .to_string()
}

fn send(rpc: &str, to: &str, sig: &str, args: &[&str]) {
    run(Command::new("cast")
        .args([
            "send",
            "--rpc-url",
            rpc,
            "--private-key",
            DEPLOYER_KEY,
            to,
            sig,
        ])
        .args(args));
}

fn call_u256(rpc: &str, to: &str, sig: &str, args: &[&str]) -> u128 {
    let out = run(Command::new("cast")
        .args(["call", "--rpc-url", rpc, to, sig])
        .args(args));
    out.split_whitespace().next().unwrap().parse().unwrap()
}

fn word(addr: &str) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(&hex::decode(addr.trim_start_matches("0x")).unwrap());
    w
}

#[tokio::test(flavor = "multi_thread")]
async fn lock_is_signed_and_a_burn_is_released_on_anvil() {
    if !(have("anvil") && have("forge") && have("cast")) {
        eprintln!("skipped: Foundry is not installed");
        return;
    }
    let port = free_port();
    let rpc = format!("http://127.0.0.1:{port}");
    let _anvil = Anvil(
        Command::new("anvil")
            .args(["--port", &port.to_string(), "--silent"])
            .spawn()
            .expect("anvil"),
    );
    for _ in 0..50 {
        if Command::new("cast")
            .args(["chain-id", "--rpc-url", &rpc])
            .stderr(Stdio::null())
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // Six guardians, as at launch.
    let keys: Vec<GuardianKey> = (1..=6u8)
        .map(|i| GuardianKey::from_hex(&format!("{:064x}", i)).unwrap())
        .collect();
    let guardian_list = format!(
        "[{}]",
        keys.iter()
            .map(|k| format!("0x{}", hex::encode(k.address())))
            .collect::<Vec<_>>()
            .join(",")
    );

    let token = deploy(
        &rpc,
        "test/mocks/MockERC20.sol:MockERC20",
        &["USD Tether", "USDT", "6"],
    );
    let bridge = deploy(
        &rpc,
        "src/EthereumRandBridge.sol:EthereumRandBridge",
        &[
            DEPLOYER,
            DEPLOYER,
            &format!("0x{}", hex::encode(RAND_EMITTER)),
            &guardian_list,
        ],
    );
    send(
        &rpc,
        &bridge,
        "setToken(address,bool,uint256,uint256)",
        &[&token, "true", "0", "0"],
    );
    send(
        &rpc,
        &token,
        "mint(address,uint256)",
        &[DEPLOYER, "5000000"],
    );
    send(
        &rpc,
        &token,
        "approve(address,uint256)",
        &[&bridge, "5000000"],
    );
    let rand_recipient = format!("0x{}", "77".repeat(32));
    send(
        &rpc,
        &bridge,
        "lock(address,uint256,bytes32,uint256,uint32)",
        &[&token, "1000000", &rand_recipient, "0", "9"],
    );

    let cfg = EvmConfig {
        name: "anvil".into(),
        chain: 2,
        kind: EvmKind::Evm,
        rpc: rpc.clone(),
        contract: bridge.clone(),
        finality: Finality::Tag("latest".into()),
        start_block: 0,
        max_log_range: 2_000,
    };
    let emitters = Emitters {
        rand: RAND_EMITTER,
        endpoints: vec![(2, word(&bridge))],
    };

    // Each guardian: its own store, its own poll of the chain, its own API.
    let tmp = tempfile::tempdir().unwrap();
    let mut clients = Vec::new();
    let mut stores = Vec::new();
    for (i, key) in keys.iter().enumerate() {
        let store = Store::open(&tmp.path().join(format!("guardian-{i}"))).unwrap();
        let signed = guardian::step(&EvmSource::new(&cfg).unwrap(), &store, key, None, &emitters)
            .await
            .unwrap();
        assert_eq!(signed, 1, "guardian {i} signs the lock");
        // A second poll finds nothing new and signs nothing twice.
        assert_eq!(
            guardian::step(&EvmSource::new(&cfg).unwrap(), &store, key, None, &emitters)
                .await
                .unwrap(),
            0
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        clients.push(GuardianClient::new(&format!(
            "http://{}",
            listener.local_addr().unwrap()
        )));
        let router = api::router(store.clone(), key.address());
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        stores.push(store);
    }

    // The lock, as the guardians rebuilt it from the event: a deposit is
    // free, so the whole 1 USDT is attested (8 decimals).
    let lock: api::SignedMessage = stores[0]
        .read_message(api::SIGNED, 2, 0)
        .unwrap()
        .expect("lock signed");
    let body = lock.message.decoded();
    assert_eq!(
        (
            body.emitter_chain,
            body.sequence,
            body.nonce,
            body.emitter_address
        ),
        (2, 0, 9, word(&bridge))
    );
    let Payload::Transfer(t) = Payload::decode(&body.payload).unwrap() else {
        panic!("not a transfer")
    };
    assert_eq!(t.amount_u128(), Some(100_000_000));
    assert_eq!(
        (t.to_chain, t.token_chain, t.token_address),
        (1, 2, word(&token))
    );

    // A burn on Rand: 0.5 USDT back to Ethereum, 0.01 of it to the relayer.
    let burn = Observed::new(
        Body {
            timestamp: 1_800_000_000,
            nonce: 0,
            emitter_chain: 1,
            emitter_address: RAND_EMITTER,
            sequence: 0,
            consistency_level: 1,
            payload: Payload::Transfer(Transfer {
                amount: Transfer::u256_from_u128(50_000_000),
                token_address: word(&token),
                token_chain: 2,
                to: word(RECIPIENT),
                to_chain: 2,
                fee: Transfer::u256_from_u128(1_000_000),
            })
            .encode(),
        }
        .encode(),
    )
    .unwrap();
    // Only five of the six sign: exactly a quorum.
    for (store, key) in stores.iter().zip(&keys).skip(1) {
        assert!(guardian::sign_one(store, key, None, &emitters, &burn).unwrap());
    }

    let relayer_store = Store::open(&tmp.path().join("relayer")).unwrap();
    let set = GuardianSet {
        index: 0,
        keys: keys.iter().map(|k| k.address()).collect(),
        pq_keys: Vec::new(),
        rand_chain_id: None,
    };
    let mut endpoints = std::collections::BTreeMap::new();
    endpoints.insert(
        2u16,
        EndpointSubmitter::Evm(EvmSubmitter::new(&cfg, RELAYER_KEY).unwrap()),
    );
    let destinations = Destinations {
        endpoints,
        solana: None,
        rand: None,
        min_relayer_fee: 0,
    };

    // With one guardian short of a quorum, nothing is submitted.
    let short = relayer::relay_one(&burn, &relayer_store, &clients[..5], &set, &destinations)
        .await
        .unwrap();
    assert_eq!(short, Progress::AwaitingQuorum { have: 4, need: 5 });

    let progress = relayer::relay_one(&burn, &relayer_store, &clients, &set, &destinations)
        .await
        .unwrap();
    assert!(
        matches!(progress, Progress::Done(Outcome::Submitted(_))),
        "{progress:?}"
    );

    // 500_000 released: 10 bps (500) to the protocol, 10_000 to the relayer.
    assert_eq!(
        call_u256(&rpc, &token, "balanceOf(address)(uint256)", &[RECIPIENT]),
        489_500
    );
    assert_eq!(
        call_u256(&rpc, &token, "balanceOf(address)(uint256)", &[RELAYER]),
        10_000
    );
    assert_eq!(
        call_u256(&rpc, &bridge, "accruedFees(address)(uint256)", &[&token]),
        500
    );
    assert_eq!(
        call_u256(&rpc, &bridge, "custody(address)(uint256)", &[&token]),
        500_000
    );

    // Another relayer arriving late finds the digest consumed and moves on.
    let late_store = Store::open(&tmp.path().join("late-relayer")).unwrap();
    let late = relayer::relay_one(&burn, &late_store, &clients, &set, &destinations)
        .await
        .unwrap();
    assert_eq!(late, Progress::Done(Outcome::AlreadyDone));

    // A guardian shown a different body under a signed sequence stops dead.
    let mut forged = burn.decoded();
    forged.nonce = 1;
    let forged = Observed::new(forged.encode()).unwrap();
    let err = guardian::sign_one(&stores[1], &keys[1], None, &emitters, &forged).unwrap_err();
    assert!(err.downcast_ref::<guardian::Equivocation>().is_some());
}
