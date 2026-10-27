//! BR-4: a guardian reads each chain through several providers and signs
//! nothing that one provider alone reports — the lock's body (amount,
//! recipient, token), its block and its finality must agree across a quorum.

mod common;

use bridge_codec::{Payload, CHAIN_RAND, CHAIN_SOLANA};
use bridge_daemons::config::{Config, EvmConfig, EvmKind, Finality, RandConfig, SolanaConfig};
use bridge_daemons::guardian;
use bridge_daemons::message::Emitters;
use bridge_daemons::sources::{self, Cursor, Source};
use bridge_daemons::store::Store;
use common::*;
use serde_json::{json, Value};

const CONTRACT: &str = "0x1111111111111111111111111111111111111111";

fn evm_cfg(urls: &[&str], quorum: Option<usize>) -> EvmConfig {
    EvmConfig {
        name: "eth".into(),
        chain: 2,
        kind: EvmKind::Evm,
        rpc: urls[0].into(),
        rpcs: urls[1..].iter().map(|u| u.to_string()).collect(),
        rpc_quorum: quorum,
        contract: CONTRACT.into(),
        finality: Finality::Confirmations(10),
        start_block: 7,
        max_log_range: 2000,
    }
}

fn payload(amount: u128) -> Vec<u8> {
    Payload::Transfer(transfer(amount, 0, 2, CHAIN_RAND, [7; 32])).encode()
}

/// A `MessagePublished` log for `sequence` in `block`.
fn log(sequence: u64, payload: &[u8], block: u64) -> Value {
    let mut data = Vec::new();
    data.extend_from_slice(&word("9"));
    data.extend_from_slice(&word("f"));
    data.extend_from_slice(&word("60"));
    data.extend_from_slice(&word(&format!("{:x}", payload.len())));
    data.extend_from_slice(&pad32(payload));
    json!({
        "address": CONTRACT,
        "topics": ["0xabcd", format!("0x{}", hex::encode(word(&format!("{sequence:x}"))))],
        "data": format!("0x{}", hex::encode(data)),
        "blockNumber": format!("0x{block:x}"),
        "removed": false,
    })
}

/// An EVM provider at `head`: `logs` within the range asked for, one block
/// timestamp, and `counter` as `sequence()` (`None`: the call fails).
fn evm_node(head: u64, logs: Vec<Value>, counter: Option<u64>) -> Fake {
    rpc(move |m, p| match m {
        "eth_blockNumber" => Some(Ok(json!(format!("0x{head:x}")))),
        "eth_getBlockByNumber" => Some(Ok(json!({ "number": "0x1", "timestamp": "0x6553f100" }))),
        "eth_getLogs" => {
            let n = |v: &Value| u64::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
            let (from, to) = (n(&p[0]["fromBlock"]), n(&p[0]["toBlock"]));
            Some(Ok(Value::Array(
                logs.iter().filter(|l| (from..=to).contains(&n(&l["blockNumber"]))).cloned().collect(),
            )))
        }
        "eth_call" => counter.map(|n| Ok(json!(format!("0x{}", hex::encode(word(&format!("{n:x}"))))))),
        _ => None,
    })
}

fn honest() -> Vec<Value> {
    vec![log(0, &payload(100_000_000), 50), log(1, &payload(200_000_000), 51)]
}

#[tokio::test]
async fn two_providers_that_agree_get_both_locks_read() {
    let (a, b) = (evm_node(100, honest(), Some(2)), evm_node(100, honest(), Some(2)));
    let source = sources::evm_quorum(&evm_cfg(&[&a.url, &b.url], None)).unwrap();
    assert_eq!(source.quorum(), 2, "a majority of two is both");
    let (messages, next) = source.poll(&source.start()).await.unwrap();
    assert_eq!(messages.len(), 2);
    assert_eq!(next, Cursor { next_block: 91, next_sequence: 2 });
    assert!(b.count("eth_getLogs") >= 1, "the second provider scanned the range too");
}

#[tokio::test]
async fn a_lock_one_provider_alone_reports_is_not_read() {
    // A reports a lock of 1,000,000 tokens where B saw 1.
    let a = evm_node(100, vec![log(0, &payload(100_000_000_000_000), 50)], Some(1));
    let b = evm_node(100, vec![log(0, &payload(100_000_000), 50)], Some(1));
    let source = sources::evm_quorum(&evm_cfg(&[&a.url, &b.url], None)).unwrap();
    let (messages, next) = source.poll(&source.start()).await.unwrap();
    assert!(messages.is_empty(), "neither body has a quorum of two");
    assert_eq!(next, Cursor { next_block: 7, next_sequence: 0 }, "the cursor does not move");

    // And through the guardian: nothing signed.
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let emitters = Emitters { rand: RAND_EMITTER, endpoints: vec![(2, word(CONTRACT))] };
    let key = &guardian_keys(1)[0];
    assert_eq!(guardian::step(&source, &store, key, None, &emitters).await.unwrap(), 0);
    assert!(store.sequences(bridge_daemons::api::SIGNED, 2).unwrap().is_empty());
}

#[tokio::test]
async fn two_of_three_agree_and_the_odd_one_out_is_outvoted() {
    let liar = evm_node(100, vec![log(0, &payload(9_999_999_999), 50)], Some(1));
    let (b, c) = (
        evm_node(100, vec![log(0, &payload(100_000_000), 50)], Some(1)),
        evm_node(100, vec![log(0, &payload(100_000_000), 50)], Some(1)),
    );
    // The liar scans first: its lock is not confirmed, so the next provider scans.
    let source = sources::evm_quorum(&evm_cfg(&[&liar.url, &b.url, &c.url], None)).unwrap();
    assert_eq!(source.quorum(), 2);
    let (messages, _) = source.poll(&source.start()).await.unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].body, {
        let honest = evm_node(100, vec![log(0, &payload(100_000_000), 50)], None);
        let one = sources::evm_quorum(&evm_cfg(&[&honest.url], None)).unwrap();
        one.poll(&one.start()).await.unwrap().0[0].body.clone()
    });
}

#[tokio::test]
async fn a_lock_not_yet_final_at_the_other_provider_waits() {
    // B's head is 55: its safe head (45) caps the range, which ends before block 50.
    let (a, b) = (evm_node(100, honest(), Some(2)), evm_node(55, honest(), Some(2)));
    let source = sources::evm_quorum(&evm_cfg(&[&a.url, &b.url], None)).unwrap();
    let (messages, next) = source.poll(&source.start()).await.unwrap();
    assert!(messages.is_empty());
    assert_eq!(next, Cursor { next_block: 46, next_sequence: 0 }, "only as far as both call safe");
}

#[tokio::test]
async fn a_scan_that_leaves_a_lock_out_does_not_move_the_cursor_past_it() {
    // A omits lock 1; B has both. Only lock 0 has a quorum, and the cursor stops after it.
    let a = evm_node(100, vec![log(0, &payload(100_000_000), 50)], Some(1));
    let b = evm_node(100, honest(), Some(2));
    let source = sources::evm_quorum(&evm_cfg(&[&a.url, &b.url], None)).unwrap();
    let (messages, next) = source.poll(&source.start()).await.unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].sequence, 0);
    assert_eq!(next, Cursor { next_block: 50, next_sequence: 1 }, "lock 1 is read again");
}

#[tokio::test]
async fn an_inflated_head_over_an_empty_range_cannot_advance_the_cursor() {
    // The liar calls block 10 000 safe and serves no logs; the honest provider's head is 100
    // and it holds the locks. Two providers, quorum two, either order: nothing advances.
    let liar = evm_node(10_010, vec![], Some(0));
    let honest_node = evm_node(100, honest(), Some(2));
    for order in [[&liar, &honest_node], [&honest_node, &liar]] {
        let source = sources::evm_quorum(&evm_cfg(&[&order[0].url, &order[1].url], None)).unwrap();
        let (messages, next) = source.poll(&source.start()).await.unwrap();
        assert!(messages.is_empty());
        assert_eq!(next, Cursor { next_block: 7, next_sequence: 0 });
    }
    // With no locks at all an empty range still stops at the quorum's head, not the liar's.
    let quiet = evm_node(100, vec![], Some(0));
    let source = sources::evm_quorum(&evm_cfg(&[&liar.url, &quiet.url], None)).unwrap();
    let (_, next) = source.poll(&source.start()).await.unwrap();
    assert_eq!(next.next_block, 91);
}

#[tokio::test]
async fn three_providers_with_one_down_need_both_others() {
    let port = |_: ()| std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let down = format!("http://127.0.0.1:{}", port(()));
    let down2 = format!("http://127.0.0.1:{}", port(()));
    let (a, b) = (evm_node(100, honest(), Some(2)), evm_node(100, honest(), Some(2)));
    let source = sources::evm_quorum(&evm_cfg(&[&down, &a.url, &b.url], None)).unwrap();
    let (messages, next) = source.poll(&source.start()).await.unwrap();
    assert_eq!(messages.len(), 2);
    assert_eq!(next, Cursor { next_block: 91, next_sequence: 2 });
    // One down and one lying: no quorum, no movement.
    let liar = evm_node(100, vec![log(0, &payload(5), 50)], Some(1));
    let source = sources::evm_quorum(&evm_cfg(&[&down, &liar.url, &b.url], None)).unwrap();
    let (messages, next) = source.poll(&source.start()).await.unwrap();
    assert!(messages.is_empty());
    assert_eq!(next, Cursor { next_block: 7, next_sequence: 0 });
    // Two down: fewer than a quorum report a head, so the poll is an error.
    let source = sources::evm_quorum(&evm_cfg(&[&down, &down2, &b.url], None)).unwrap();
    assert!(source.poll(&source.start()).await.is_err());
}

#[tokio::test]
async fn one_rpc_still_works_with_a_quorum_of_one() {
    let a = evm_node(100, honest(), None);
    let cfg = evm_cfg(&[&a.url], None);
    assert_eq!(cfg.providers(), (vec![a.url.clone()], 1));
    let source = sources::evm_quorum(&cfg).unwrap();
    let (messages, _) = source.poll(&source.start()).await.unwrap();
    assert_eq!(messages.len(), 2);
}

#[tokio::test]
async fn rand_burns_need_the_same_body_from_a_quorum_of_nodes() {
    let row = |amount: u128| {
        move |_seq: u64| {
            let b = burn(0, 2, amount, 0);
            json!({ "body_hex": hex::encode(&b.body), "digest": hex::encode(b.digest) })
        }
    };
    let node = |amount: u128| {
        let r = row(amount);
        rpc(move |m, p| match m {
            "rand_getBridgeState" => Some(Ok(json!({
                "enabled": true, "guardian_set_index": 1, "guardians": [CONTRACT],
                "burn_sequence": 1, "pq_guardians": [],
            }))),
            "rand_getBridgeBurn" => Some(Ok(r(p[0].as_u64().unwrap()))),
            _ => None,
        })
    };
    let cfg = |urls: &[&str]| RandConfig {
        rpc: urls[0].into(),
        rpcs: urls[1..].iter().map(|u| u.to_string()).collect(),
        rpc_quorum: None,
        emitter: hex::encode(RAND_EMITTER),
        start_sequence: 0,
        chain_id: Some(21),
    };
    let (a, b, liar) = (node(50_000_000), node(50_000_000), node(90_000_000_000));
    let agree = sources::rand_quorum(&cfg(&[&a.url, &b.url])).unwrap();
    assert_eq!(agree.poll(&agree.start()).await.unwrap().0.len(), 1);
    let split = sources::rand_quorum(&cfg(&[&liar.url, &b.url])).unwrap();
    assert!(split.poll(&split.start()).await.unwrap().0.is_empty());
}

#[tokio::test]
async fn solana_messages_need_the_same_account_from_a_quorum_of_rpcs() {
    use base64::Engine;
    let program_b58 = "FGA3kY3RjfDKjUszJESMYtYXAbsnkFhhoxM3Mb34vycu";
    let program = bridge_daemons::config::pubkey32(program_b58).unwrap();
    let pda = |seeds: &[&[u8]]| sources::solana::find_program_address(seeds, &program).unwrap().0;
    let node = |amount: u128| {
        let body = transfer_body(CHAIN_SOLANA, program, 0, transfer(amount, 0, CHAIN_SOLANA, CHAIN_RAND, [9; 32]));
        let mut msg = vec![5u8];
        msg.extend_from_slice(&0u64.to_le_bytes());
        msg.extend_from_slice(&(body.len() as u32).to_le_bytes());
        msg.extend_from_slice(&body);
        let offset = 1 + 32 * 3 + 1 + 32 + 4;
        let mut config = vec![0u8; offset + 24];
        config[0] = 1;
        config[offset..offset + 8].copy_from_slice(&1u64.to_le_bytes());
        let accounts = [(pda(&[b"config"]), config), (pda(&[b"msg", &0u64.to_le_bytes()]), msg)];
        rpc(move |m, p| {
            (m == "getAccountInfo").then(|| {
                let key = p[0].as_str().unwrap();
                Ok(accounts
                    .iter()
                    .find(|(k, _)| bs58::encode(k).into_string() == key)
                    .map(|(_, d)| json!({ "context": { "slot": 1 }, "value": {
                        "owner": program_b58,
                        "data": [base64::engine::general_purpose::STANDARD.encode(d), "base64"] } }))
                    .unwrap_or(json!({ "context": { "slot": 1 }, "value": null })))
            })
        })
    };
    let cfg = |urls: &[&str]| SolanaConfig {
        name: "solana".into(),
        rpc: urls[0].into(),
        rpcs: urls[1..].iter().map(|u| u.to_string()).collect(),
        rpc_quorum: None,
        program: program_b58.into(),
        start_sequence: 0,
    };
    let (a, b, liar) = (node(100_000_000), node(100_000_000), node(7_000_000_000_000));
    let agree = sources::solana_quorum(&cfg(&[&a.url, &b.url])).unwrap();
    assert_eq!(agree.poll(&agree.start()).await.unwrap().0.len(), 1);
    let split = sources::solana_quorum(&cfg(&[&liar.url, &b.url])).unwrap();
    assert!(split.poll(&split.start()).await.unwrap().0.is_empty());
}

#[test]
fn the_config_takes_more_rpcs_and_a_quorum_and_one_rpc_still_parses() {
    let base = |extra: &str| {
        format!(
            r#"
data_dir = "/tmp/x"
[rand]
rpc = "http://127.0.0.1:8545"
emitter = "{}"
[[evm]]
name = "ethereum"
chain = 2
kind = "evm"
rpc = "https://one.example"
{extra}
contract = "{CONTRACT}"
finality = "finalized"
"#,
            "aa".repeat(32)
        )
    };
    let load = |text: String| {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        std::fs::write(&path, text).unwrap();
        Config::load(&path)
    };
    let one = load(base("")).unwrap();
    assert_eq!(one.evm[0].providers().1, 1);
    let three = load(base(r#"rpcs = ["https://two.example", "https://three.example", "https://one.example"]"#)).unwrap();
    assert_eq!(three.evm[0].providers().0.len(), 3, "a repeated URL counts once");
    assert_eq!(three.evm[0].providers().1, 2);
    let all = load(base("rpcs = [\"https://two.example\"]\nrpc_quorum = 2")).unwrap();
    assert_eq!(all.evm[0].providers().1, 2);
    let err = load(base("rpcs = [\"https://two.example\"]\nrpc_quorum = 3")).unwrap_err();
    assert!(format!("{err:#}").contains("rpc_quorum 3"), "{err:#}");
    assert!(load(base("rpc_quorum = 0")).is_err());
}
