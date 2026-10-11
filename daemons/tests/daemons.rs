//! `rand-guardian` and `rand-relayer` run as the operator runs them: a TOML
//! file, keys in the environment, loopback fakes for every chain, SIGINT to
//! stop. Startup errors are checked without any fake at all.

mod common;

use std::path::Path;
use std::process::Command;

use bridge_daemons::api::{self, SignedMessage};
use bridge_daemons::crypto::{recover, GuardianKey};
use bridge_daemons::guardian;
use bridge_daemons::message::Observed;
use bridge_daemons::pq::PqKey;
use bridge_daemons::store::Store;
use common::*;
use serde_json::{json, Value};

const CONTRACT: &str = "0x1111111111111111111111111111111111111111";
const REAL_ADDRESS: &str = include_str!("fixtures/rand-address.txt");
const REAL_HASH: &str = "58bbaf413a0a303a1740c286673f0ce74199c7b64d035a7a6772468bac66b972";

fn guardian_cmd() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_rand-guardian"));
    c.env_remove("GUARDIAN_KEY").env_remove("GUARDIAN_PQ_SEED").env_remove("RAND_BRIDGE_CONFIG");
    c
}

fn relayer_cmd() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_rand-relayer"));
    c.env_remove("RELAYER_EVM_KEY").env_remove("RELAYER_TRON_KEY").env_remove("RAND_BRIDGE_CONFIG");
    c
}

fn write_config(dir: &Path, text: &str) -> std::path::PathBuf {
    let path = dir.join("config.toml");
    std::fs::write(&path, text).unwrap();
    path
}

fn run_failing(c: &mut Command, config: &Path) -> String {
    let o = c.arg("--config").arg(config).output().unwrap();
    assert!(!o.status.success(), "expected a failure");
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

fn base(dir: &Path, rand_rpc: &str, extra: &str) -> String {
    format!(
        "data_dir = {data:?}\npoll_secs = 1\n[rand]\nrpc = {rand_rpc:?}\nemitter = {emitter:?}\n{extra}\n",
        data = dir.join("data"),
        emitter = hex::encode(RAND_EMITTER),
    )
}

// ---- startup errors ------------------------------------------------------------

#[test]
fn both_daemons_refuse_a_missing_or_wrong_config() {
    let dir = tempfile::tempdir().unwrap();
    for cmd in [guardian_cmd as fn() -> Command, relayer_cmd] {
        let o = cmd().output().unwrap();
        assert_eq!(o.status.code(), Some(2), "--config is required");
        let text = run_failing(&mut cmd(), &dir.path().join("nope.toml"));
        assert!(text.contains("reading") && text.contains("nope.toml"), "{text}");
        let bad = write_config(dir.path(), "data_dir = 3");
        assert!(run_failing(&mut cmd(), &bad).contains("parsing"));
        let unknown = write_config(dir.path(), &base(dir.path(), "http://127.0.0.1:1", "bogus = 1"));
        assert!(run_failing(&mut cmd(), &unknown).contains("parsing"));
    }
}

#[test]
fn each_daemon_needs_its_own_section() {
    let dir = tempfile::tempdir().unwrap();
    let only_relayer = write_config(dir.path(), &base(dir.path(), "http://127.0.0.1:1", "[relayer]\nguardians = []"));
    assert!(run_failing(&mut guardian_cmd(), &only_relayer).contains("no [guardian] section"));
    let only_guardian = write_config(dir.path(), &base(dir.path(), "http://127.0.0.1:1", "[guardian]\nlisten = \"127.0.0.1:0\""));
    assert!(run_failing(&mut relayer_cmd(), &only_guardian).contains("no [relayer] section"));
}

#[test]
fn the_config_env_var_names_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "data_dir = 3");
    let o = guardian_cmd().env("RAND_BRIDGE_CONFIG", &config).output().unwrap();
    assert!(String::from_utf8_lossy(&o.stderr).contains("parsing"), "{}", String::from_utf8_lossy(&o.stderr));
}

#[test]
fn a_guardian_needs_a_valid_key_chain_id_and_listen_address() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), &base(dir.path(), "http://127.0.0.1:1", "[guardian]\nlisten = \"127.0.0.1:0\""));
    assert!(run_failing(&mut guardian_cmd(), &config).contains("GUARDIAN_KEY is not set"));
    assert!(run_failing(&mut guardian_cmd().env("GUARDIAN_KEY", "zz"), &config).contains("not hex"));
    assert!(run_failing(&mut guardian_cmd().env("GUARDIAN_KEY", "00".repeat(32)), &config).contains("not a valid scalar"));

    // A PQ seed without rand.chain_id cannot co-sign.
    let key = format!("{:064x}", 1);
    let seed = "07".repeat(32);
    let text = run_failing(&mut guardian_cmd().env("GUARDIAN_KEY", &key).env("GUARDIAN_PQ_SEED", &seed), &config);
    assert!(text.contains("rand.chain_id is required to co-sign"), "{text}");
    // A bad seed.
    let with_id = write_config(dir.path(), &base(dir.path(), "http://127.0.0.1:1", "chain_id = 14\n[guardian]\nlisten = \"127.0.0.1:0\""));
    assert!(run_failing(&mut guardian_cmd().env("GUARDIAN_KEY", &key).env("GUARDIAN_PQ_SEED", "0102"), &with_id).contains("PQ seed must be 32 bytes"));
    // An address that cannot be bound.
    let bad_listen = write_config(dir.path(), &base(dir.path(), "http://127.0.0.1:1", "[guardian]\nlisten = \"999.1.1.1:1\""));
    assert!(run_failing(&mut guardian_cmd().env("GUARDIAN_KEY", &key), &bad_listen).contains("binding 999.1.1.1:1"));
}

#[test]
fn a_guardian_refuses_a_chain_id_the_node_contradicts() {
    let dir = tempfile::tempdir().unwrap();
    let node = rpc(|m, _| (m == "rand_chainId").then(|| Ok(json!(15))));
    let config = write_config(dir.path(), &base(dir.path(), &node.url, "chain_id = 14\n[guardian]\nlisten = \"127.0.0.1:0\""));
    let text = run_failing(&mut guardian_cmd().env("GUARDIAN_KEY", format!("{:064x}", 1)).env("GUARDIAN_PQ_SEED", "07".repeat(32)), &config);
    assert!(text.contains("rand.chain_id is 14 but the node at rand.rpc serves chain 15"), "{text}");
}

#[test]
fn a_relayer_refuses_a_recipients_file_whose_hash_does_not_match() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("recipients.json");
    let config = write_config(
        dir.path(),
        &base(dir.path(), "http://127.0.0.1:1", &format!("[relayer]\nguardians = []\nrecipients_file = {file:?}")),
    );
    assert!(run_failing(&mut relayer_cmd(), &config).contains("reading"), "a missing file");
    std::fs::write(&file, "nope").unwrap();
    assert!(run_failing(&mut relayer_cmd(), &config).contains("parsing"));
    std::fs::write(&file, json!({ "00".repeat(32): REAL_ADDRESS.trim() }).to_string()).unwrap();
    assert!(run_failing(&mut relayer_cmd(), &config).contains("is not the hash of its address"));
    std::fs::write(&file, json!({ "zz": REAL_ADDRESS.trim() }).to_string()).unwrap();
    assert!(!run_failing(&mut relayer_cmd(), &config).is_empty());
    std::fs::write(&file, json!({ REAL_HASH: "rand1nonsense" }).to_string()).unwrap();
    assert!(run_failing(&mut relayer_cmd(), &config).contains("decodes to"));
}

#[test]
fn a_relayer_cannot_bind_a_taken_registration_port() {
    let dir = tempfile::tempdir().unwrap();
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listen = taken.local_addr().unwrap();
    let config = write_config(
        dir.path(),
        &base(dir.path(), "http://127.0.0.1:1", &format!("[relayer]\nguardians = []\nlisten = \"{listen}\"")),
    );
    assert!(run_failing(&mut relayer_cmd(), &config).contains(&format!("binding {listen}")));
}

// ---- a guardian that runs ------------------------------------------------------

fn rand_node(burns: Vec<Observed>, chain_id: u64, guardians: &[GuardianKey]) -> Fake {
    let addresses: Vec<String> = guardians.iter().map(|g| format!("0x{}", hex::encode(g.address()))).collect();
    rpc(move |m, p| match m {
        "rand_chainId" => Some(Ok(json!(chain_id))),
        "rand_getBridgeState" => Some(Ok(json!({
            "enabled": true, "guardian_set_index": 0, "guardians": addresses,
            "burn_sequence": burns.len(), "pq_guardians": [],
        }))),
        "rand_getBridgeBurn" => {
            let b = &burns[p[0].as_u64().unwrap() as usize];
            Some(Ok(json!({ "body_hex": hex::encode(&b.body), "digest": hex::encode(b.digest) })))
        }
        _ => None,
    })
}

fn evm_node(logs: Vec<Value>, consumed: bool) -> Fake {
    rpc(move |m, p| {
        Some(Ok(match m {
            "eth_blockNumber" => json!("0x64"),
            "eth_getBlockByNumber" => json!({ "number": "0x64", "timestamp": format!("0x{:x}", 1_800_000_000u64) }),
            "eth_getLogs" => Value::Array(logs.clone()),
            "eth_call" => {
                let _ = p;
                json!(format!("0x{:064x}", u8::from(consumed)))
            }
            _ => return None,
        }))
    })
}

fn eth_lock(sequence: u64, to: [u8; 32]) -> Observed {
    lock(2, word(CONTRACT), sequence, to)
}

fn status_of(url: &str) -> Option<u16> {
    get_json(url).map(|(s, _)| s)
}

fn json_of<T: serde::de::DeserializeOwned>(url: &str) -> T {
    serde_json::from_value(get_json(url).unwrap().1).unwrap()
}

#[test]
fn a_guardian_signs_what_it_watches_and_serves_it_until_interrupted() {
    let dir = tempfile::tempdir().unwrap();
    let deposit = eth_lock(0, [9; 32]);
    let burn = burn(0, 2, 50_000_000, 0);
    let key = GuardianKey::from_hex(&format!("{:064x}", 1)).unwrap();
    let eth = evm_node(vec![evm_log(CONTRACT, &deposit, 50)], false);
    let rand = rand_node(vec![burn.clone()], 14, &[]);
    // A Solana endpoint with no bridge account: warned about, never fatal.
    let sol = rpc(|m, _| (m == "getAccountInfo").then(|| Ok(json!({ "value": null }))));
    let port = free_port();
    let config = write_config(
        dir.path(),
        &base(
            dir.path(),
            &rand.url,
            &format!(
                "chain_id = 14\n\n[[evm]]\nname = \"eth\"\nchain = 2\nkind = \"evm\"\nrpc = {:?}\ncontract = {CONTRACT:?}\nfinality = 0\n\n\
                 [solana]\nrpc = {:?}\nprogram = \"11111111111111111111111111111111\"\n\n[guardian]\nlisten = \"127.0.0.1:{port}\"\n",
                eth.url, sol.url
            ),
        ),
    );
    // The Rand burn is only signed if the emitter matches: base() puts RAND_EMITTER in the config.
    let mut cmd = guardian_cmd();
    cmd.arg("--config").arg(&config).env("GUARDIAN_KEY", format!("{:064x}", 1)).env("GUARDIAN_PQ_SEED", "07".repeat(32));
    let mut daemon = Daemon::spawn(cmd, dir.path());

    let origin = format!("http://127.0.0.1:{port}");
    wait_until("both messages signed", || {
        daemon.exited().is_none()
            && status_of(&format!("{origin}/v1/signature/2/0")) == Some(200)
            && status_of(&format!("{origin}/v1/signature/1/0")) == Some(200)
    });

    let health: api::Health = json_of(&format!("{origin}/v1/health"));
    assert_eq!(health.guardian, hex::encode(key.address()));

    // The lock was signed, ECDSA and (it is addressed to Rand) Dilithium2.
    let lock_sig: SignedMessage = json_of(&format!("{origin}/v1/signature/2/0"));
    assert_eq!(lock_sig.message, deposit);
    assert_eq!(recover(&deposit.digest, &lock_sig.signature).unwrap(), key.address());
    let pq = PqKey::from_seed_hex(&"07".repeat(32)).unwrap();
    let co = hex::decode(lock_sig.pq_signature.expect("co-signed")).unwrap();
    assert!(bridge_daemons::pq::verify(&pq.public_key(), 14, &deposit.digest, &co));
    // The burn is released on Ethereum: classical only.
    let burn_sig: SignedMessage = json_of(&format!("{origin}/v1/signature/1/0"));
    assert!(burn_sig.pq_signature.is_none());

    // The cursors survived on disk, and the log says why Solana was skipped.
    let store = Store::open(&dir.path().join("data")).unwrap();
    assert_eq!(store.cursor("eth").unwrap().unwrap().next_sequence, 1);
    assert_eq!(store.cursor("rand").unwrap().unwrap().next_sequence, 1);
    wait_until("the Solana warning", || daemon.log().contains("not initialized"));
    let log = daemon.log();
    assert!(log.contains("co-signing for Rand chain 14"), "{log}");
    assert!(!log.contains(&format!("{:064x}", 1)) && !log.contains(&"07".repeat(32)), "keys are never logged");

    let status = daemon.stop();
    assert!(status.success(), "a clean exit on SIGINT");
}

#[test]
fn a_guardian_with_no_pq_seed_warns_and_signs_classically() {
    let dir = tempfile::tempdir().unwrap();
    let deposit = eth_lock(0, [9; 32]);
    let eth = evm_node(vec![evm_log(CONTRACT, &deposit, 50)], false);
    let rand = rpc(|_, _| None); // a Rand node that serves no bridge: the source just fails and is retried
    let port = free_port();
    let config = write_config(
        dir.path(),
        &base(
            dir.path(),
            &rand.url,
            &format!("[[evm]]\nname = \"eth\"\nchain = 2\nkind = \"evm\"\nrpc = {:?}\ncontract = {CONTRACT:?}\nfinality = \"latest\"\n\n[guardian]\nlisten = \"127.0.0.1:{port}\"\n", eth.url),
        ),
    );
    let mut cmd = guardian_cmd();
    cmd.arg("--config").arg(&config).env("GUARDIAN_KEY", format!("0x{:064x}", 1));
    let mut daemon = Daemon::spawn(cmd, dir.path());
    let url = format!("http://127.0.0.1:{port}/v1/signature/2/0");
    wait_until("the lock signed", || daemon.exited().is_none() && status_of(&url) == Some(200));
    let signed: SignedMessage = json_of(&url);
    assert!(signed.pq_signature.is_none());
    wait_until("the warning", || daemon.log().contains("GUARDIAN_PQ_SEED is not set"));
    assert!(daemon.stop().success());
}

// ---- a relayer that runs -------------------------------------------------------

/// Three guardian APIs (quorum of 3) with `messages` signed, served from this process.
struct Guardians {
    urls: Vec<String>,
    keys: Vec<GuardianKey>,
    _dirs: Vec<tempfile::TempDir>,
    _rt: tokio::runtime::Runtime,
}

fn guardians(messages: &[&Observed]) -> Guardians {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let keys = guardian_keys(3);
    let emitters = bridge_daemons::message::Emitters { rand: RAND_EMITTER, endpoints: vec![(2, word(CONTRACT))] };
    let (mut urls, mut dirs) = (vec![], vec![]);
    for key in &keys {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        for m in messages {
            guardian::sign_one(&store, key, None, &emitters, m).unwrap();
        }
        let router = api::router(store, key.address());
        let listener = rt.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
        urls.push(format!("http://{}", listener.local_addr().unwrap()));
        rt.spawn(async move { axum::serve(listener, router).await.unwrap() });
        dirs.push(dir);
    }
    Guardians { urls, keys, _dirs: dirs, _rt: rt }
}

fn done_exists(dir: &Path, chain: u16, seq: u64) -> bool {
    dir.join(format!("data/done/{chain}/{seq:020}.json")).exists()
}

#[test]
fn a_relayer_observes_collects_a_quorum_and_records_the_release() {
    let dir = tempfile::tempdir().unwrap();
    let burn = burn(0, 2, 50_000_000, 1_000_000);
    let g = guardians(&[&burn]);
    let rand = rand_node(vec![burn.clone()], 14, &g.keys);
    // The Ethereum endpoint says the digest is already consumed.
    let eth = evm_node(vec![], true);
    let config = write_config(
        dir.path(),
        &base(
            dir.path(),
            &rand.url,
            &format!(
                "[[evm]]\nname = \"eth\"\nchain = 2\nkind = \"evm\"\nrpc = {:?}\ncontract = {CONTRACT:?}\nfinality = 0\n\n\
                 [relayer]\nguardians = {:?}\nmin_relayer_fee = 1\n",
                eth.url, g.urls
            ),
        ),
    );
    let mut cmd = relayer_cmd();
    cmd.arg("--config").arg(&config).env("RELAYER_EVM_KEY", format!("{:064x}", 2));
    let mut daemon = Daemon::spawn(cmd, dir.path());
    wait_until("the release recorded", || daemon.exited().is_none() && done_exists(dir.path(), 1, 0));

    let done: Value = serde_json::from_slice(&std::fs::read(dir.path().join(format!("data/done/1/{:020}.json", 0))).unwrap()).unwrap();
    assert_eq!(done["to_chain"], 2);
    assert_eq!(done["outcome"], "AlreadyDone");
    assert_eq!(done["digest"], hex::encode(burn.digest));
    assert!(dir.path().join(format!("data/observed/1/{:020}.json", 0)).exists());
    assert!(daemon.log().contains("relayed: AlreadyDone") || daemon.log().contains("Done"), "{}", daemon.log());
    assert!(daemon.stop().success());
}

#[test]
fn a_relayer_mints_a_deposit_for_a_registered_recipient_through_the_wallet() {
    let dir = tempfile::tempdir().unwrap();
    let recipient = bridge_daemons::config::hex32(REAL_HASH).unwrap();
    let deposit = eth_lock(0, recipient);
    let g = guardians(&[&deposit]);
    let eth = evm_node(vec![evm_log(CONTRACT, &deposit, 50)], false);
    // Rand serves no bridge state: the guardian set comes from the config.
    let rand = rpc(|_, _| None);
    let wallet = dir.path().join("wallet.sh");
    std::fs::write(&wallet, format!("#!/bin/sh\necho \"$@\" > {:?}\necho minted-note\n", dir.path().join("wallet.args"))).unwrap();
    std::fs::set_permissions(&wallet, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let recipients = dir.path().join("recipients.json");
    std::fs::write(&recipients, json!({ REAL_HASH: REAL_ADDRESS.trim() }).to_string()).unwrap();
    let port = free_port();
    let addresses: Vec<String> = g.keys.iter().map(|k| format!("0x{}", hex::encode(k.address()))).collect();
    let config = write_config(
        dir.path(),
        &base(
            dir.path(),
            &rand.url,
            &format!(
                "[[evm]]\nname = \"eth\"\nchain = 2\nkind = \"evm\"\nrpc = {:?}\ncontract = {CONTRACT:?}\nfinality = 0\n\n\
                 [relayer]\nguardians = {:?}\nguardian_set_index = 0\nguardian_addresses = {addresses:?}\n\
                 rand_cli = {wallet:?}\nrand_cli_args = [\"--wallet\", \"w.json\"]\nrecipients_file = {recipients:?}\nlisten = \"127.0.0.1:{port}\"\n",
                eth.url, g.urls
            ),
        ),
    );
    let mut cmd = relayer_cmd();
    cmd.arg("--config").arg(&config);
    let mut daemon = Daemon::spawn(cmd, dir.path());
    wait_until("the mint recorded", || daemon.exited().is_none() && done_exists(dir.path(), 2, 0));

    let done: Value = serde_json::from_slice(&std::fs::read(dir.path().join(format!("data/done/2/{:020}.json", 0))).unwrap()).unwrap();
    assert_eq!(done["outcome"], json!({ "Submitted": "minted-note" }));
    let args = std::fs::read_to_string(dir.path().join("wallet.args")).unwrap();
    assert!(args.starts_with("--wallet w.json bridge-mint @"), "{args}");
    assert!(args.contains(&format!("--to {}", REAL_ADDRESS.trim())), "the registered address is the mint's recipient");

    // The registration API: the same address is accepted again, a wrong preimage is a 400,
    // an overwrite of an operator entry cannot happen, junk is refused.
    let url = format!("http://127.0.0.1:{port}/v1/recipients");
    let post = |hash: &str, address: &str| {
        request("POST", &url, "application/json", &json!({ "recipient_hash": hash, "address": address }).to_string()).unwrap().0
    };
    assert_eq!(post(REAL_HASH, REAL_ADDRESS.trim()), 204);
    assert_eq!(post(&"00".repeat(32), REAL_ADDRESS.trim()), 400, "the address does not hash to it");
    assert_eq!(post("zz", REAL_ADDRESS.trim()), 400);
    let other = format!("rand1{}", bs58::encode(vec![7u8; 32 + 1184]).into_string());
    let other_hash = hex::encode(bridge_daemons::relayer::recipient_hash(&other).unwrap());
    assert_eq!(post(&other_hash, &other), 204, "a new, honest registration");
    assert_eq!(request("POST", &url, "application/json", "not json").unwrap().0, 400);
    assert_eq!(request("GET", &url, "application/json", "").unwrap().0, 405);
    assert!(daemon.stop().success());
}
