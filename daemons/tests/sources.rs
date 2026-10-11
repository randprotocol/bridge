//! The sources and the JSON-RPC client against loopback fakes: what a node
//! says is parsed, and what a node should never say is refused.

mod common;

use base64::Engine;
use bridge_codec::{Body, Payload, CHAIN_RAND, CHAIN_SOLANA};
use bridge_daemons::config::{EvmConfig, EvmKind, Finality, RandConfig, SolanaConfig};
use bridge_daemons::rpc::{hex_data, quantity, quantity_u128, JsonRpc};
use bridge_daemons::sources::evm::EvmSource;
use bridge_daemons::sources::rand::{self, RandSource};
use bridge_daemons::sources::solana::{find_program_address, SolanaSource};
use bridge_daemons::sources::{Cursor, Source};
use common::*;
use serde_json::{json, Value};

// ---- rpc.rs -----------------------------------------------------------------

#[test]
fn only_the_origin_of_an_rpc_url_is_ever_shown() {
    for (url, shown) in [
        ("https://eth.example.com/v2/SECRETKEY", "eth.example.com"),
        ("https://user:pass@node.example.com:8545/x?key=1", "node.example.com:8545"),
        ("http://127.0.0.1:8545", "127.0.0.1:8545"),
        ("node.example.com/path", "node.example.com"),
        ("https://host?apikey=SECRET", "host"),
    ] {
        assert_eq!(JsonRpc::new(url).shown(), shown, "{url}");
    }
}

#[test]
fn quantities_and_data_parse_or_say_what_was_wrong() {
    assert_eq!(quantity(&json!("0x1f")).unwrap(), 31);
    assert_eq!(quantity(&json!("1f")).unwrap(), 31, "the prefix is optional");
    assert_eq!(quantity_u128(&json!("0xffffffffffffffffffff")).unwrap(), (1u128 << 80) - 1);
    assert!(quantity(&json!(31)).unwrap_err().to_string().contains("expected a hex quantity"));
    assert!(quantity(&json!("0xzz")).unwrap_err().to_string().contains("bad hex quantity"));
    assert!(quantity(&json!("0x1ffffffffffffffff")).is_err(), "above u64");
    assert!(quantity_u128(&json!(null)).is_err());
    assert!(quantity_u128(&json!("0xg")).unwrap_err().to_string().contains("bad hex quantity"));
    assert_eq!(hex_data(&json!("0x0aff")).unwrap(), vec![0x0a, 0xff]);
    assert_eq!(hex_data(&json!("0x")).unwrap(), Vec::<u8>::new());
    assert!(hex_data(&json!("0xabc")).is_err(), "odd length");
    assert!(hex_data(&json!(1)).unwrap_err().to_string().contains("expected hex data"));
}

#[tokio::test]
async fn a_call_returns_the_result_and_sends_a_well_formed_request() {
    let node = rpc(|m, p| (m == "echo").then(|| Ok(json!({ "params": p }))));
    let client = JsonRpc::new(&node.url);
    let result = client.call("echo", json!([1, "two"])).await.unwrap();
    assert_eq!(result, json!({ "params": [1, "two"] }));
    let seen = node.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].http_method, "POST");
    assert_eq!(seen[0].body["jsonrpc"], "2.0");
    assert_eq!(seen[0].body["method"], "echo");
}

#[tokio::test]
async fn a_jsonrpc_error_is_an_error_that_names_the_method() {
    let node = rpc(|_, _| Some(Err(json!({ "code": -32000, "message": "execution reverted" }))));
    let err = JsonRpc::new(&node.url).call("eth_call", json!([])).await.unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("eth_call") && text.contains("execution reverted"), "{text}");
}

#[tokio::test]
async fn a_null_error_field_is_not_an_error() {
    let node = http(|_| (200, r#"{"jsonrpc":"2.0","id":1,"error":null,"result":"0x1"}"#.into()));
    assert_eq!(JsonRpc::new(&node.url).call("m", json!([])).await.unwrap(), json!("0x1"));
}

#[tokio::test]
async fn a_reply_without_a_result_or_a_json_body_or_with_http_failure_is_refused() {
    let none = http(|_| (200, r#"{"jsonrpc":"2.0","id":1}"#.into()));
    let err = JsonRpc::new(&none.url).call("m", json!([])).await.unwrap_err();
    assert!(err.to_string().contains("no result"), "{err:#}");

    let html = http(|_| (200, "<html>not json</html>".into()));
    let err = JsonRpc::new(&html.url).call("m", json!([])).await.unwrap_err();
    assert!(format!("{err:#}").contains("response is not JSON"), "{err:#}");

    let down = http(|_| (503, "busy".into()));
    let err = JsonRpc::new(&down.url).call("m", json!([])).await.unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("503"), "{text}");
}

#[tokio::test]
async fn a_refused_connection_names_the_host_but_not_the_key() {
    // Bind then drop: nothing listens on the port any more.
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}/v2/SECRETKEY");
    let err = JsonRpc::new(&url).call("eth_blockNumber", json!([])).await.unwrap_err();
    let text = err.to_string();
    assert!(text.contains("eth_blockNumber") && text.contains(&format!("127.0.0.1:{port}")), "{text}");
    assert!(!text.contains("SECRETKEY"), "{text}");
}

// ---- sources/evm.rs ---------------------------------------------------------

const CONTRACT: &str = "0x1111111111111111111111111111111111111111";

fn evm_cfg(url: &str, kind: EvmKind, finality: Finality, range: u64) -> EvmConfig {
    EvmConfig {
        name: "testnet".into(),
        chain: 2,
        kind,
        rpc: url.into(),
        contract: CONTRACT.into(),
        finality,
        start_block: 7,
        max_log_range: range,
    }
}

fn pad32(bytes: &[u8]) -> Vec<u8> {
    let mut v = bytes.to_vec();
    v.resize(v.len().div_ceil(32) * 32, 0);
    v
}

/// A `MessagePublished(uint64 indexed sequence, uint32 nonce, uint8 level, bytes payload)` log.
fn log(sequence: u64, nonce: u32, level: u8, payload: &[u8], block: u64) -> Value {
    let mut data = Vec::new();
    data.extend_from_slice(&word(&format!("{nonce:x}")));
    data.extend_from_slice(&word(&format!("{level:x}")));
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

fn payload() -> Vec<u8> {
    Payload::Transfer(transfer(
        100_000_000,
        0,
        2,
        CHAIN_RAND,
        word("0x7777777777777777777777777777777777777777777777777777777777777777"),
    ))
    .encode()
}

/// A node at `head` serving `logs` for any range, block timestamp `ts`.
fn evm_node(head: u64, logs: Vec<Value>, ts: Value) -> Fake {
    rpc(move |m, p| match m {
        "eth_blockNumber" => Some(Ok(json!(format!("0x{head:x}")))),
        "eth_getBlockByNumber" => {
            let tag = p[0].as_str().unwrap();
            Some(Ok(if tag == "finalized" {
                json!({ "number": format!("0x{head:x}"), "timestamp": ts })
            } else if tag == "safe" {
                Value::Null
            } else {
                json!({ "number": tag, "timestamp": ts })
            }))
        }
        "eth_getLogs" => Some(Ok(Value::Array(logs.clone()))),
        _ => None,
    })
}

#[tokio::test]
async fn an_evm_poll_rebuilds_the_body_the_contract_published() {
    let node = evm_node(100, vec![log(0, 9, 15, &payload(), 50), log(1, 10, 15, &payload(), 51)], json!("0x6553f100"));
    let source = EvmSource::new(&evm_cfg(&node.url, EvmKind::Evm, Finality::Confirmations(10), 2000)).unwrap();
    assert_eq!(source.name(), "testnet");
    assert_eq!(source.start(), Cursor { next_block: 7, next_sequence: 0 });

    let (messages, next) = source.poll(&source.start()).await.unwrap();
    assert_eq!(next, Cursor { next_block: 91, next_sequence: 2 }, "safe head is 100 - 10");
    assert_eq!(messages.len(), 2);
    let body = messages[1].decoded();
    assert_eq!(
        (body.timestamp, body.nonce, body.emitter_chain, body.sequence, body.consistency_level),
        (0x6553f100, 10, 2, 1, 15)
    );
    assert_eq!(body.emitter_address, word(CONTRACT));
    assert_eq!(body.payload, payload());

    // The filter names the contract, the event topic and the range from the cursor to the safe head.
    let logs_req = node.requests().into_iter().find(|s| s.rpc_method() == Some("eth_getLogs")).unwrap();
    let filter = &logs_req.body["params"][0];
    assert_eq!(filter["address"], CONTRACT);
    assert_eq!((filter["fromBlock"].as_str(), filter["toBlock"].as_str()), (Some("0x7"), Some("0x5a")));
    assert_eq!(
        filter["topics"][0],
        format!("0x{}", hex::encode(bridge_daemons::crypto::keccak256(b"MessagePublished(uint64,uint32,uint8,bytes)")))
    );
}

#[tokio::test]
async fn a_poll_asks_for_at_most_max_log_range_blocks_and_resumes_after_them() {
    let node = evm_node(1000, vec![], json!("0x1"));
    let source = EvmSource::new(&evm_cfg(&node.url, EvmKind::Evm, Finality::Confirmations(0), 100)).unwrap();
    let (messages, next) = source.poll(&Cursor { next_block: 200, next_sequence: 4 }).await.unwrap();
    assert!(messages.is_empty());
    assert_eq!(next, Cursor { next_block: 300, next_sequence: 4 }, "[200, 299]");
    let req = node.requests().into_iter().find(|s| s.rpc_method() == Some("eth_getLogs")).unwrap();
    assert_eq!(req.body["params"][0]["toBlock"], "0x12b");

    // A zero range is read as one block.
    let source = EvmSource::new(&evm_cfg(&node.url, EvmKind::Evm, Finality::Confirmations(0), 0)).unwrap();
    let (_, next) = source.poll(&Cursor { next_block: 5, next_sequence: 0 }).await.unwrap();
    assert_eq!(next.next_block, 6);
}

#[tokio::test]
async fn a_cursor_past_the_safe_head_polls_nothing() {
    let node = evm_node(100, vec![log(0, 0, 1, &payload(), 1)], json!("0x1"));
    let source = EvmSource::new(&evm_cfg(&node.url, EvmKind::Evm, Finality::Confirmations(10), 2000)).unwrap();
    let cursor = Cursor { next_block: 91, next_sequence: 0 };
    let (messages, next) = source.poll(&cursor).await.unwrap();
    assert!(messages.is_empty());
    assert_eq!(next, cursor);
    assert_eq!(node.count("eth_getLogs"), 0, "no logs were asked for");
}

#[tokio::test]
async fn a_finality_tag_asks_the_node_for_that_block() {
    let node = evm_node(100, vec![], json!("0x1"));
    let source = EvmSource::new(&evm_cfg(&node.url, EvmKind::Evm, Finality::Tag("finalized".into()), 2000)).unwrap();
    let (_, next) = source.poll(&Cursor { next_block: 90, next_sequence: 0 }).await.unwrap();
    assert_eq!(next.next_block, 101);
    assert_eq!(node.requests()[0].body["params"], json!(["finalized", false]));

    // A chain with no such block yet is an error, not an empty poll.
    let source = EvmSource::new(&evm_cfg(&node.url, EvmKind::Evm, Finality::Tag("safe".into()), 2000)).unwrap();
    let err = source.poll(&source.start()).await.unwrap_err();
    assert!(err.to_string().contains("no safe block yet"), "{err:#}");
}

#[tokio::test]
async fn tron_logs_come_from_the_jsonrpc_facade_and_millisecond_timestamps_are_normalised() {
    let node = http(|seen| {
        assert_eq!(seen.path, "/jsonrpc", "the Tron origin gets /jsonrpc appended");
        let m = seen.body["method"].as_str().unwrap();
        let result = match m {
            "eth_blockNumber" => json!("0x64"),
            "eth_getBlockByNumber" => json!({ "number": "0x32", "timestamp": format!("0x{:x}", 1_700_000_000_000u64) }), // milliseconds
            "eth_getLogs" => json!([log(0, 0, 19, &payload(), 50)]),
            _ => unreachable!(),
        };
        (200, json!({ "jsonrpc": "2.0", "id": 1, "result": result }).to_string())
    });
    let mut cfg = evm_cfg(&format!("{}/", node.url), EvmKind::Tron, Finality::Confirmations(0), 2000);
    cfg.chain = 4;
    let source = EvmSource::new(&cfg).unwrap();
    let (messages, _) = source.poll(&source.start()).await.unwrap();
    assert_eq!(messages[0].decoded().timestamp, 1_700_000_000);
    assert_eq!(messages[0].emitter_chain, 4);
}

#[tokio::test]
async fn a_timestamp_that_does_not_fit_u32_is_refused() {
    let node = evm_node(100, vec![log(0, 0, 1, &payload(), 50)], json!("0x200000000")); // 8_589_934_592 s: seconds by magnitude, above u32
    let source = EvmSource::new(&evm_cfg(&node.url, EvmKind::Evm, Finality::Confirmations(0), 2000)).unwrap();
    let err = source.poll(&source.start()).await.unwrap_err();
    assert!(err.to_string().contains("timestamp out of range"), "{err:#}");
}

#[tokio::test]
async fn logs_a_guardian_must_not_sign_on_are_refused() {
    let poll = |logs: Vec<Value>| async move {
        let node = evm_node(100, logs, json!("0x6553f100"));
        let source = EvmSource::new(&evm_cfg(&node.url, EvmKind::Evm, Finality::Confirmations(0), 2000)).unwrap();
        format!("{:#}", source.poll(&Cursor { next_block: 7, next_sequence: 5 }).await.unwrap_err())
    };
    let ok = |seq| log(seq, 0, 1, &payload(), 50);

    let mut removed = ok(5);
    removed["removed"] = json!(true);
    assert!(poll(vec![removed]).await.contains("was removed"));

    let mut other = ok(5);
    other["address"] = json!("0x2222222222222222222222222222222222222222");
    assert!(poll(vec![other]).await.contains("another address"));

    assert!(poll(vec![ok(7)]).await.contains("expected sequence 5, saw 7"));

    let mut topics = ok(5);
    topics["topics"] = json!(["0xabcd"]);
    assert!(poll(vec![topics]).await.contains("one indexed field, got 1 topics"));
    let mut no_topics = ok(5);
    no_topics["topics"] = Value::Null;
    assert!(poll(vec![no_topics]).await.contains("log without topics"));

    let mut wide = ok(5);
    wide["topics"][1] = json!(format!("0x01{}", "00".repeat(31)));
    assert!(poll(vec![wide]).await.contains("not a uint64"));

    let mut short = ok(5);
    short["data"] = json!(format!("0x{}", "00".repeat(40)));
    assert!(poll(vec![short]).await.contains("log data too short"));

    // nonce word wider than uint32
    let mut data = hex::decode(ok(5)["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
    data[0] = 1;
    let mut fat = ok(5);
    fat["data"] = json!(format!("0x{}", hex::encode(&data)));
    assert!(poll(vec![fat]).await.contains("wider than its type"));

    // payload offset pointing past the data
    let mut data = hex::decode(ok(5)["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
    data[64..96].copy_from_slice(&word("ffff"));
    let mut far = ok(5);
    far["data"] = json!(format!("0x{}", hex::encode(&data)));
    assert!(poll(vec![far]).await.contains("payload offset out of range"));

    // payload length longer than the data
    let mut data = hex::decode(ok(5)["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
    data[96..128].copy_from_slice(&word("ffff"));
    let mut long = ok(5);
    long["data"] = json!(format!("0x{}", hex::encode(&data)));
    assert!(poll(vec![long]).await.contains("payload length out of range"));

}

#[tokio::test]
async fn a_rescan_after_a_restart_skips_what_was_already_seen() {
    let node = evm_node(100, vec![log(3, 0, 1, &payload(), 40), log(4, 0, 1, &payload(), 41), log(5, 0, 1, &payload(), 42)], json!("0x6553f100"));
    let source = EvmSource::new(&evm_cfg(&node.url, EvmKind::Evm, Finality::Confirmations(0), 2000)).unwrap();
    let (messages, next) = source.poll(&Cursor { next_block: 7, next_sequence: 5 }).await.unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].sequence, 5);
    assert_eq!(next.next_sequence, 6);
}

#[test]
fn an_evm_source_needs_a_valid_contract() {
    let mut cfg = evm_cfg("http://127.0.0.1:1", EvmKind::Evm, Finality::Confirmations(0), 1);
    cfg.contract = "0x1234".into();
    assert!(EvmSource::new(&cfg).is_err());
}

// ---- sources/rand.rs --------------------------------------------------------

fn rand_cfg(url: &str, start: u64) -> RandConfig {
    RandConfig {
        rpc: url.into(),
        emitter: hex::encode(RAND_EMITTER),
        start_sequence: start,
        chain_id: Some(14),
    }
}

fn burn_row(sequence: u64) -> Value {
    let b = burn(sequence, 2, 50_000_000, 1_000_000);
    json!({ "body_hex": hex::encode(&b.body), "digest": hex::encode(b.digest) })
}

fn rand_node(burn_sequence: u64, row: impl Fn(u64) -> Value + Send + Sync + 'static) -> Fake {
    rpc(move |m, p| match m {
        "rand_getBridgeState" => Some(Ok(json!({
            "enabled": true,
            "guardian_set_index": 1,
            "guardians": [CONTRACT, "0x2222222222222222222222222222222222222222"],
            "burn_sequence": burn_sequence,
            "pq_guardians": ["0a0b", "zz", "0c"],
        }))),
        "rand_getBridgeBurn" => Some(Ok(row(p[0].as_u64().unwrap()))),
        "rand_chainId" => Some(Ok(json!(14))),
        _ => None,
    })
}

#[tokio::test]
async fn the_bridge_state_and_chain_id_are_read_from_the_node() {
    let node = rand_node(3, burn_row);
    let client = JsonRpc::new(&node.url);
    let state = rand::bridge_state(&client).await.unwrap().expect("enabled");
    assert_eq!(state.guardian_set_index, 1);
    assert_eq!(state.burn_sequence, 3);
    assert_eq!(state.guardians, vec![[0x11; 20], [0x22; 20]]);
    assert_eq!(state.pq_guardians, vec![vec![0x0a, 0x0b], vec![0x0c]], "an undecodable key is dropped");
    assert_eq!(rand::chain_id(&client).await.unwrap(), 14);
}

#[tokio::test]
async fn bridge_state_is_none_when_disabled_and_an_error_when_malformed() {
    let off = rpc(|m, _| (m == "rand_getBridgeState").then(|| Ok(json!({ "enabled": false }))));
    assert!(rand::bridge_state(&JsonRpc::new(&off.url)).await.unwrap().is_none());

    for (state, why) in [
        (json!({ "enabled": true }), "no guardians"),
        (json!({ "enabled": true, "guardians": [] }), "no guardian_set_index"),
        (json!({ "enabled": true, "guardians": [], "guardian_set_index": 0 }), "no burn_sequence"),
        (json!({ "enabled": true, "guardians": ["0x12"], "guardian_set_index": 0, "burn_sequence": 0 }), "expected 20 bytes"),
    ] {
        let node = rpc(move |_, _| Some(Ok(state.clone())));
        let err = rand::bridge_state(&JsonRpc::new(&node.url)).await.err().expect(why);
        assert!(format!("{err:#}").contains(why), "{why}: {err:#}");
    }
    // No pq_guardians at all is an empty list.
    let bare = rpc(|_, _| Some(Ok(json!({ "enabled": true, "guardians": [], "guardian_set_index": 0, "burn_sequence": 0 }))));
    assert!(rand::bridge_state(&JsonRpc::new(&bare.url)).await.unwrap().unwrap().pq_guardians.is_empty());

    let bad_id = rpc(|_, _| Some(Ok(json!("0xe"))));
    assert!(rand::chain_id(&JsonRpc::new(&bad_id.url)).await.is_err());
}

#[tokio::test]
async fn burns_are_read_in_sequence_from_the_cursor() {
    let node = rand_node(3, burn_row);
    let source = RandSource::new(&rand_cfg(&node.url, 1));
    assert_eq!(source.name(), "rand");
    assert_eq!(source.start(), Cursor { next_block: 0, next_sequence: 1 });
    let (messages, next) = source.poll(&source.start()).await.unwrap();
    assert_eq!(messages.iter().map(|m| m.sequence).collect::<Vec<_>>(), vec![1, 2]);
    assert_eq!(next, Cursor { next_block: 0, next_sequence: 3 });
    assert_eq!(messages[0], burn(1, 2, 50_000_000, 1_000_000));

    // Caught up: nothing to fetch.
    let (none, same) = source.poll(&next).await.unwrap();
    assert!(none.is_empty());
    assert_eq!(same, next);
}

#[tokio::test]
async fn a_poll_takes_at_most_a_batch_of_64() {
    let node = rand_node(1000, burn_row);
    let source = RandSource::new(&rand_cfg(&node.url, 0));
    let (messages, next) = source.poll(&source.start()).await.unwrap();
    assert_eq!(messages.len(), 64);
    assert_eq!(next.next_sequence, 64);
}

#[tokio::test]
async fn a_node_with_no_bridge_or_a_missing_burn_yields_nothing() {
    let off = rpc(|m, _| (m == "rand_getBridgeState").then(|| Ok(json!({ "enabled": false }))));
    let source = RandSource::new(&rand_cfg(&off.url, 0));
    let (messages, next) = source.poll(&Cursor { next_block: 0, next_sequence: 9 }).await.unwrap();
    assert!(messages.is_empty());
    assert_eq!(next.next_sequence, 9);

    // The state counts a burn the row lookup does not have yet: stop, no error.
    let lagging = rand_node(5, |seq| if seq < 2 { burn_row(seq) } else { Value::Null });
    let (messages, next) = RandSource::new(&rand_cfg(&lagging.url, 0)).poll(&Cursor::default()).await.unwrap();
    assert_eq!((messages.len(), next.next_sequence), (2, 2));
}

#[tokio::test]
async fn a_burn_that_disagrees_with_its_slot_or_its_digest_is_refused() {
    let poll = |row: Value| async move {
        let node = rand_node(1, move |_| row.clone());
        format!("{:#}", RandSource::new(&rand_cfg(&node.url, 0)).poll(&Cursor::default()).await.unwrap_err())
    };
    // The row for sequence 0 carries sequence 4.
    let wrong_seq = burn(4, 2, 1, 0);
    let err = poll(json!({ "body_hex": hex::encode(&wrong_seq.body) })).await;
    assert!(err.contains("carries sequence 4 from chain 1"), "{err}");

    // Right sequence, but emitted on Ethereum.
    let wrong_chain = transfer_body(2, [1; 32], 0, transfer(1, 0, 2, 1, [9; 32]));
    let err = poll(json!({ "body_hex": hex::encode(wrong_chain) })).await;
    assert!(err.contains("from chain 2"), "{err}");

    // The node's digest is not the body's.
    let good = burn(0, 2, 50_000_000, 0);
    let err = poll(json!({ "body_hex": hex::encode(&good.body), "digest": "00".repeat(32) })).await;
    assert!(err.contains("node reports digest"), "{err}");

    // No body at all, or one that is not canonical.
    assert!(poll(json!({ "digest": "00" })).await.contains("expected hex data"));
    assert!(poll(json!({ "body_hex": hex::encode(&good.body[..40]) })).await.contains("undecodable"));
}

// ---- sources/solana.rs ------------------------------------------------------

const PROGRAM_B58: &str = "11111111111111111111111111111111";

fn program_key() -> [u8; 32] {
    bridge_daemons::config::pubkey32(PROGRAM_B58).unwrap()
}

fn account(owner: &str, data: &[u8]) -> Value {
    json!({ "context": { "slot": 1 }, "value": {
        "owner": owner,
        "data": [base64::engine::general_purpose::STANDARD.encode(data), "base64"],
    }})
}

const CONFIG_SEQUENCE_OFFSET: usize = 1 + 32 * 3 + 1 + 32 + 4;

fn config_data(sequence: u64) -> Vec<u8> {
    let mut d = vec![0u8; CONFIG_SEQUENCE_OFFSET + 8 + 16];
    d[0] = 1;
    d[CONFIG_SEQUENCE_OFFSET..CONFIG_SEQUENCE_OFFSET + 8].copy_from_slice(&sequence.to_le_bytes());
    d
}

fn posted(sequence: u64, body: &[u8]) -> Vec<u8> {
    let mut d = vec![5u8];
    d.extend_from_slice(&sequence.to_le_bytes());
    d.extend_from_slice(&(body.len() as u32).to_le_bytes());
    d.extend_from_slice(body);
    d
}

fn solana_body(sequence: u64) -> Vec<u8> {
    transfer_body(CHAIN_SOLANA, program_key(), sequence, transfer(100_000_000, 0, CHAIN_SOLANA, CHAIN_RAND, [9; 32]))
}

/// A Solana RPC holding `accounts`: base58 key -> (owner, data).
fn solana_node(accounts: Vec<([u8; 32], &'static str, Vec<u8>)>) -> Fake {
    rpc(move |m, p| {
        if m != "getAccountInfo" {
            return None;
        }
        let key = p[0].as_str().unwrap();
        Some(Ok(accounts
            .iter()
            .find(|(k, _, _)| bs58::encode(k).into_string() == key)
            .map(|(_, owner, data)| account(owner, data))
            .unwrap_or_else(|| json!({ "context": { "slot": 1 }, "value": null }))))
    })
}

fn sol_cfg(url: &str, start: u64) -> SolanaConfig {
    SolanaConfig { name: "sol".into(), rpc: url.into(), program: PROGRAM_B58.into(), start_sequence: start }
}

fn config_key() -> [u8; 32] {
    find_program_address(&[b"config"], &program_key()).unwrap().0
}

fn msg_key(seq: u64) -> [u8; 32] {
    find_program_address(&[b"msg", &seq.to_le_bytes()], &program_key()).unwrap().0
}

#[test]
fn program_addresses_are_off_curve_and_depend_on_the_seeds() {
    let program = program_key();
    let (a, bump_a) = find_program_address(&[b"config"], &program).unwrap();
    let (b, _) = find_program_address(&[b"msg", &0u64.to_le_bytes()], &program).unwrap();
    let (again, bump_again) = find_program_address(&[b"config"], &program).unwrap();
    assert_eq!((a, bump_a), (again, bump_again), "deterministic");
    assert_ne!(a, b);
    for key in [a, b] {
        assert!(curve25519_dalek::edwards::CompressedEdwardsY(key).decompress().is_none(), "a PDA is off the curve");
    }
}

#[tokio::test]
async fn solana_messages_are_walked_by_sequence() {
    let node = solana_node(vec![
        (config_key(), PROGRAM_B58, config_data(3)),
        (msg_key(1), PROGRAM_B58, posted(1, &solana_body(1))),
        (msg_key(2), PROGRAM_B58, posted(2, &solana_body(2))),
    ]);
    let source = SolanaSource::new(&sol_cfg(&node.url, 1)).unwrap();
    assert_eq!(source.name(), "sol");
    assert_eq!(source.start(), Cursor { next_block: 0, next_sequence: 1 });
    let (messages, next) = source.poll(&source.start()).await.unwrap();
    assert_eq!(messages.iter().map(|m| m.sequence).collect::<Vec<_>>(), vec![1, 2]);
    assert!(messages.iter().all(|m| m.emitter_chain == CHAIN_SOLANA));
    assert_eq!(next, Cursor { next_block: 0, next_sequence: 3 });
    // Every read is at finalized commitment.
    assert!(node.requests().iter().all(|s| s.body["params"][1]["commitment"] == "finalized"));

    let (none, same) = source.poll(&next).await.unwrap();
    assert!(none.is_empty());
    assert_eq!(same, next);
}

#[tokio::test]
async fn a_message_not_yet_visible_stops_the_walk_without_error() {
    let node = solana_node(vec![
        (config_key(), PROGRAM_B58, config_data(3)),
        (msg_key(0), PROGRAM_B58, posted(0, &solana_body(0))),
    ]);
    let source = SolanaSource::new(&sol_cfg(&node.url, 0)).unwrap();
    let (messages, next) = source.poll(&source.start()).await.unwrap();
    assert_eq!((messages.len(), next.next_sequence), (1, 1));
}

#[tokio::test]
async fn solana_accounts_that_are_not_what_they_claim_are_refused() {
    let poll = |accounts: Vec<([u8; 32], &'static str, Vec<u8>)>| async move {
        let node = solana_node(accounts);
        let source = SolanaSource::new(&sol_cfg(&node.url, 0)).unwrap();
        format!("{:#}", source.poll(&Cursor::default()).await.unwrap_err())
    };
    assert!(poll(vec![]).await.contains("not initialized"));
    assert!(poll(vec![(config_key(), "Stake11111111111111111111111111111111111111", config_data(1))])
        .await
        .contains("not owned by the bridge program"));
    let mut wrong = config_data(1);
    wrong[0] = 2;
    assert!(poll(vec![(config_key(), PROGRAM_B58, wrong)]).await.contains("wrong discriminator"));
    assert!(poll(vec![(config_key(), PROGRAM_B58, vec![1; 20])]).await.contains("too short"));

    let cfg = (config_key(), PROGRAM_B58, config_data(1));
    // message account: bad discriminator, wrong sequence, truncated header, truncated body, wrong emitter chain
    let mut bad = posted(0, &solana_body(0));
    bad[0] = 9;
    assert!(poll(vec![cfg.clone(), (msg_key(0), PROGRAM_B58, bad)]).await.contains("wrong discriminator"));
    assert!(poll(vec![cfg.clone(), (msg_key(0), PROGRAM_B58, posted(7, &solana_body(0)))])
        .await
        .contains("holds sequence 7, expected 0"));
    assert!(poll(vec![cfg.clone(), (msg_key(0), PROGRAM_B58, vec![5, 0, 0])]).await.contains("too short"));
    let mut cut = posted(0, &solana_body(0));
    cut.truncate(20);
    assert!(poll(vec![cfg.clone(), (msg_key(0), PROGRAM_B58, cut)]).await.contains("truncated"));
    let eth = transfer_body(2, [1; 32], 0, transfer(1, 0, 2, 1, [9; 32]));
    assert!(poll(vec![cfg.clone(), (msg_key(0), PROGRAM_B58, posted(0, &eth))])
        .await
        .contains("from chain 2"));
}

#[test]
fn a_solana_source_needs_a_valid_program_id() {
    let mut cfg = sol_cfg("http://127.0.0.1:1", 0);
    cfg.program = "not-a-key".into();
    assert!(SolanaSource::new(&cfg).is_err());
    let _ = Body::decode(&solana_body(0)).unwrap();
    let _ = CHAIN_RAND;
}
