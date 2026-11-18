//! BR-4: the providers a chain is read through must be different parties on
//! the same chain — checked from the config, and by asking them.

mod common;

use std::process::Command;

use bridge_daemons::config::Config;
use bridge_daemons::providers::{self, independence_gap, operator_of};
use common::*;
use serde_json::json;

const GENESIS: &str = "ca76c2766ed6090ac6ba5dad86b724dd5d2b80c0edfaed287cd8b129e663ca9a";

#[test]
fn the_operator_of_a_url_is_its_site_or_its_local_endpoint() {
    for (url, operator) in [
        ("https://ethereum-rpc.publicnode.com", "publicnode.com"),
        ("https://bsc-rpc.publicnode.com/", "publicnode.com"),
        ("https://eth-mainnet.g.alchemy.com/v2/SECRETKEY", "alchemy.com"),
        ("https://user:pass@RPC.Example.ORG:8443/path?x=1", "example.org"),
        ("https://api.trongrid.io", "trongrid.io"),
        ("http://127.0.0.1:8545", "127.0.0.1:8545"),
        ("http://127.0.0.1:8546/", "127.0.0.1:8546"),
        ("http://localhost:8545", "localhost:8545"),
        ("http://[::1]:8545", "[::1]:8545"),
        ("http://node-a:8545/rpc", "node-a:8545"),
    ] {
        assert_eq!(operator_of(url), operator, "{url}");
    }
    assert!(!operator_of("https://eth-mainnet.g.alchemy.com/v2/SECRETKEY").contains("SECRET"));
}

fn urls(list: &[&str]) -> Vec<String> {
    list.iter().map(|u| u.to_string()).collect()
}

#[test]
fn a_quorum_one_operator_can_meet_alone_is_a_gap() {
    let same = urls(&["https://ethereum-rpc.publicnode.com", "https://ethereum.publicnode.com"]);
    let gap = independence_gap("evm.eth", &same, 2).expect("two URLs of one operator");
    assert!(gap.contains("publicnode.com") && gap.contains("BR-4"), "{gap}");
    // Two of three from one operator still meet a quorum of two; three are needed.
    let mixed = urls(&["https://a.publicnode.com", "https://b.publicnode.com", "https://rpc.mevblocker.io"]);
    assert!(independence_gap("evm.eth", &mixed, 2).is_some());
    assert!(independence_gap("evm.eth", &mixed, 3).is_none());
    // Different operators; local endpoints on different ports are different.
    assert!(independence_gap("evm.eth", &urls(&["https://a.publicnode.com", "https://rpc.mevblocker.io"]), 2).is_none());
    assert!(independence_gap("rand", &urls(&["http://127.0.0.1:8545", "http://127.0.0.1:8546"]), 2).is_none());
    // A quorum of one claims nothing, so it is not judged here.
    assert!(independence_gap("evm.eth", &same, 1).is_none());
}

fn config_text(dir: &std::path::Path, rand: &[&str], eth: &[&str], quorum: usize) -> std::path::PathBuf {
    let list = |u: &[&str]| u[1..].iter().map(|x| format!("{x:?}")).collect::<Vec<_>>().join(", ");
    let path = dir.join("config.toml");
    std::fs::write(
        &path,
        format!(
            "data_dir = {:?}\n[rand]\nrpc = {:?}\nrpcs = [{}]\nrpc_quorum = {quorum}\nchain_id = 21\ngenesis_hash = {GENESIS:?}\nemitter = {:?}\n\
             [[evm]]\nname = \"ethereum\"\nchain = 2\nkind = \"evm\"\nrpc = {:?}\nrpcs = [{}]\nrpc_quorum = {quorum}\ncontract = \"0x1111111111111111111111111111111111111111\"\nfinality = 0\n\
             [guardian]\nlisten = \"127.0.0.1:0\"\n",
            dir.join("data"),
            rand[0],
            list(rand),
            hex::encode(RAND_EMITTER),
            eth[0],
            list(eth),
        ),
    )
    .unwrap();
    path
}

#[test]
fn a_config_whose_quorum_one_operator_meets_does_not_load() {
    let dir = tempfile::tempdir().unwrap();
    let rand = ["http://127.0.0.1:1", "http://127.0.0.1:2"];
    let bad = config_text(dir.path(), &rand, &["https://ethereum-rpc.publicnode.com", "https://ethereum.publicnode.com"], 2);
    let err = format!("{:#}", Config::load(&bad).unwrap_err());
    assert!(err.contains("evm.ethereum") && err.contains("publicnode.com") && err.contains("BR-4"), "{err}");
    let good = config_text(dir.path(), &rand, &["https://ethereum-rpc.publicnode.com", "https://rpc.mevblocker.io"], 2);
    Config::load(&good).unwrap();
    // The same two URLs at a quorum of one load as before: nothing running today changes.
    let dir = tempfile::tempdir().unwrap();
    let one = config_text(dir.path(), &rand, &["https://ethereum-rpc.publicnode.com", "https://ethereum.publicnode.com"], 1);
    Config::load(&one).unwrap();
}

#[test]
fn the_repository_mainnet_configs_still_load() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("mainnet");
    for i in 1..=8 {
        Config::load(&dir.join(format!("guardian-{i}.toml"))).unwrap_or_else(|e| panic!("guardian-{i}: {e:#}"));
    }
    Config::load(&dir.join("relayer.toml")).unwrap();
}

fn rand_node(chain_id: u64, genesis: &'static str) -> Fake {
    rpc(move |m, _| match m {
        "rand_chainId" => Some(Ok(json!(chain_id))),
        "rand_getGenesisHash" => Some(Ok(json!(genesis))),
        _ => None,
    })
}

fn eth_node(chain_id: u64) -> Fake {
    rpc(move |m, _| match m {
        "eth_chainId" => Some(Ok(json!(format!("0x{chain_id:x}")))),
        _ => None,
    })
}

fn guardian() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_rand-guardian"));
    c.env_remove("RAND_BRIDGE_CONFIG");
    c
}

fn check(config: &std::path::Path) -> (bool, String, String) {
    let o = guardian().arg("--config").arg(config).arg("--check-providers").output().unwrap();
    (o.status.success(), String::from_utf8_lossy(&o.stdout).into(), String::from_utf8_lossy(&o.stderr).into())
}

#[test]
fn check_providers_passes_when_a_quorum_of_operators_name_the_configured_chain() {
    let (r1, r2, e1, e2) = (rand_node(21, GENESIS), rand_node(21, GENESIS), eth_node(1), eth_node(1));
    let dir = tempfile::tempdir().unwrap();
    let cfg = config_text(dir.path(), &[&r1.url, &r2.url], &[&e1.url, &e2.url], 2);
    let (ok, out, err) = check(&cfg);
    assert!(ok, "{out}\n{err}");
    assert_eq!(out.matches("PASS").count(), 2, "{out}");
    assert!(out.contains("eip155:1 (Ethereum mainnet)") && out.contains(&format!("rand:21:{GENESIS}")), "{out}");
    // One identity call per provider, and nothing else: no logs, no state, no key asked for.
    assert_eq!(e1.rpc_methods(), vec!["eth_chainId"]);
    assert_eq!(r1.rpc_methods(), vec!["rand_chainId", "rand_getGenesisHash"]);
    assert!(!dir.path().join("data").exists(), "the check opens no data directory");
}

#[test]
fn check_providers_fails_when_providers_name_different_chains_or_too_few_answer() {
    // One Ethereum provider serves another network.
    let (r1, r2, e1, e2) = (rand_node(21, GENESIS), rand_node(21, GENESIS), eth_node(1), eth_node(11155111));
    let dir = tempfile::tempdir().unwrap();
    let (ok, out, err) = check(&config_text(dir.path(), &[&r1.url, &r2.url], &[&e1.url, &e2.url], 2));
    assert!(!ok && err.contains("BR-4"), "{out}\n{err}");
    assert!(out.contains("FAIL: 1 of 2 providers name chain") && out.contains("different chains"), "{out}");
    // One Ethereum provider is down: a quorum of two cannot be met.
    let down = rpc(|_, _| None);
    let dir = tempfile::tempdir().unwrap();
    let (ok, out, _) = check(&config_text(dir.path(), &[&r1.url, &r2.url], &[&e1.url, &down.url], 2));
    assert!(!ok && out.contains("no answer") && out.contains("FAIL: 1 of 2"), "{out}");
}

#[test]
fn check_providers_fails_when_the_rand_nodes_agree_on_a_chain_the_config_does_not_name() {
    const OTHER: &str = "6210cf07000000000000000000000000000000000000000000000000000051350";
    let other: &'static str = &OTHER[..64];
    let (r1, r2, e1, e2) = (rand_node(20, other), rand_node(20, other), eth_node(1), eth_node(1));
    let dir = tempfile::tempdir().unwrap();
    let (ok, out, _) = check(&config_text(dir.path(), &[&r1.url, &r2.url], &[&e1.url, &e2.url], 2));
    assert!(!ok, "{out}");
    assert!(out.contains("the config names rand:21:"), "{out}");
}

#[test]
fn a_quorum_of_one_passes_the_check_and_is_called_what_it_is() {
    let (r1, e1) = (rand_node(21, GENESIS), eth_node(1));
    let dir = tempfile::tempdir().unwrap();
    let (ok, out, err) = check(&config_text(dir.path(), &[&r1.url], &[&e1.url], 1));
    assert!(ok, "{out}\n{err}");
    assert_eq!(out.matches("a single provider can get a message signed").count(), 2, "{out}");
}

#[tokio::test]
async fn agreeing_providers_of_one_operator_do_not_pass() {
    // Built by hand: the config check refuses this shape, so a report is the only way to see
    // the rule.
    let a = |shown: &str, op: &str, id: &str| providers::Answer { shown: shown.into(), operator: op.into(), identity: Ok(id.into()) };
    let r = providers::ChainReport {
        name: "ethereum".into(),
        quorum: 2,
        answers: vec![a("a.example.com", "example.com", "eip155:1"), a("b.example.com", "example.com", "eip155:1")],
        expected: None,
    };
    assert!(r.verdict().unwrap_err().contains("one operator"));
}
