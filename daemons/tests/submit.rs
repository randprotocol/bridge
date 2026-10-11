//! The destination submitters against loopback fakes and fake command-line
//! tools: what they send, and what they do with each answer.

mod common;

use std::os::unix::fs::PermissionsExt;

use bridge_codec::Attestation;
use bridge_daemons::config::{EvmConfig, EvmKind, Finality};
use bridge_daemons::crypto::{self, recover, GuardianKey, RawSignature};
use bridge_daemons::pq::PqSignature;
use bridge_daemons::submit::evm::{sign_eip1559, EvmSubmitter};
use bridge_daemons::submit::process::{RandSubmitter, SolanaSubmitter};
use bridge_daemons::submit::tron::TronSubmitter;
use bridge_daemons::submit::{consumed_calldata, release_calldata, selector, Outcome};
use common::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const CONTRACT: &str = "0x1111111111111111111111111111111111111111";
/// secp256k1 secret 1 and the address it controls.
const KEY: &str = "0x0000000000000000000000000000000000000000000000000000000000000001";
const KEY_ADDRESS: &str = "7e5f4552091a69125d5dfcb7b8c2659029395bdf";

fn cfg(url: &str, kind: EvmKind) -> EvmConfig {
    EvmConfig {
        name: "dest".into(),
        chain: 2,
        kind,
        rpc: url.into(),
        contract: CONTRACT.into(),
        finality: Finality::Tag("latest".into()),
        start_block: 0,
        max_log_range: 1,
    }
}

/// A burn released on Ethereum, with two guardians' signatures.
fn attestation() -> (Attestation, [u8; 32]) {
    let message = burn(0, 2, 50_000_000, 1_000_000);
    let signatures = guardian_keys(2)
        .iter()
        .enumerate()
        .map(|(i, k)| k.sign(&message.digest).unwrap().indexed(i as u8))
        .collect();
    (
        Attestation {
            guardian_set_index: 0,
            signatures,
            body: message.decoded(),
        },
        message.digest,
    )
}

fn hex_param(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

// ---- submit/evm.rs ----------------------------------------------------------

#[test]
fn the_submitter_key_must_be_a_valid_scalar() {
    let c = cfg("http://127.0.0.1:1", EvmKind::Evm);
    assert_eq!(
        hex::encode(EvmSubmitter::new(&c, KEY).unwrap().address()),
        KEY_ADDRESS
    );
    assert_eq!(
        hex::encode(
            EvmSubmitter::new(&c, &format!(" {} \n", &KEY[2..]))
                .unwrap()
                .address()
        ),
        KEY_ADDRESS
    );
    for bad in ["zz", &"00".repeat(32), "0102"] {
        assert!(EvmSubmitter::new(&c, bad).is_err(), "{bad}");
    }
    let mut c = cfg("http://127.0.0.1:1", EvmKind::Evm);
    c.contract = "0x12".into();
    assert!(EvmSubmitter::new(&c, KEY).is_err());
}

#[test]
fn an_eip1559_transaction_is_type_2_rlp_signed_by_the_key() {
    let key = k256::ecdsa::SigningKey::from_slice(&hex::decode(&KEY[2..]).unwrap()).unwrap();
    let to = [0x11u8; 20];
    let data = vec![0xde, 0xad, 0xbe, 0xef];
    let raw = sign_eip1559(
        &key,
        31337,
        5,
        1_000_000_000,
        3_000_000_000,
        21_000,
        &to,
        &data,
    )
    .unwrap();
    assert_eq!(raw[0], 0x02);
    let rlp = rlp::Rlp::new(&raw[1..]);
    assert_eq!(rlp.item_count().unwrap(), 12);
    assert_eq!(rlp.val_at::<u64>(0).unwrap(), 31337);
    assert_eq!(rlp.val_at::<u64>(1).unwrap(), 5);
    assert_eq!(rlp.val_at::<u128>(2).unwrap(), 1_000_000_000);
    assert_eq!(rlp.val_at::<u128>(3).unwrap(), 3_000_000_000);
    assert_eq!(rlp.val_at::<u64>(4).unwrap(), 21_000);
    assert_eq!(rlp.val_at::<Vec<u8>>(5).unwrap(), to);
    assert_eq!(rlp.val_at::<u64>(6).unwrap(), 0, "value");
    assert_eq!(rlp.val_at::<Vec<u8>>(7).unwrap(), data);
    assert_eq!(rlp.at(8).unwrap().item_count().unwrap(), 0, "access list");

    // The signature is over keccak(0x02 || rlp of the first nine fields) and recovers to the key.
    let mut unsigned = rlp::RlpStream::new_list(9);
    for i in 0..9 {
        unsigned.append_raw(rlp.at(i).unwrap().as_raw(), 1);
    }
    let mut preimage = vec![0x02];
    preimage.extend_from_slice(&unsigned.out());
    let hash = crypto::keccak256(&preimage);
    let pad = |v: Vec<u8>| {
        let mut w = [0u8; 32];
        w[32 - v.len()..].copy_from_slice(&v);
        w
    };
    let sig = RawSignature {
        r: pad(rlp.val_at::<Vec<u8>>(10).unwrap()),
        s: pad(rlp.val_at::<Vec<u8>>(11).unwrap()),
        v: rlp.val_at::<u8>(9).unwrap(),
    };
    assert_eq!(hex::encode(recover(&hash, &sig).unwrap()), KEY_ADDRESS);
}

struct Chain {
    consumed: std::sync::atomic::AtomicBool,
    receipt_status: &'static str,
}

/// A node that accepts a release. `consumed_after_send`: `consumed()` reads true once a
/// transaction was sent (another relayer won the race).
fn evm_node(
    consumed_before: bool,
    consumed_after_send: bool,
    status: &'static str,
    extra: impl Fn(&str) -> Option<Result<Value, Value>> + Send + Sync + 'static,
) -> Fake {
    let state = std::sync::Arc::new(Chain {
        consumed: std::sync::atomic::AtomicBool::new(consumed_before),
        receipt_status: status,
    });
    rpc(move |m, p| {
        if let Some(r) = extra(m) {
            return Some(r);
        }
        use std::sync::atomic::Ordering::SeqCst;
        Some(Ok(match m {
            "eth_call" => {
                let data = hex_param(&p[0]["data"]);
                assert_eq!(data[..4], selector("consumed(bytes32)"));
                json!(format!("0x{:064x}", u8::from(state.consumed.load(SeqCst))))
            }
            "eth_estimateGas" => json!("0x186a0"),
            "eth_chainId" => json!("0x7a69"),
            "eth_getTransactionCount" => json!("0x9"),
            "eth_maxPriorityFeePerGas" => json!("0x3b9aca00"),
            "eth_getBlockByNumber" => json!({ "baseFeePerGas": "0x64" }),
            "eth_sendRawTransaction" => {
                if consumed_after_send {
                    state.consumed.store(true, SeqCst);
                }
                json!("0xabc123")
            }
            "eth_getTransactionReceipt" => json!({ "status": state.receipt_status }),
            _ => return None,
        }))
    })
}

#[tokio::test]
async fn a_release_is_estimated_signed_sent_and_confirmed() {
    let node = evm_node(false, false, "0x1", |_| None);
    let submitter = EvmSubmitter::new(&cfg(&node.url, EvmKind::Evm), KEY).unwrap();
    let (attestation, digest) = attestation();
    let outcome = submitter.release(&attestation, &digest).await.unwrap();
    assert_eq!(outcome, Outcome::Submitted("0xabc123".into()));

    let requests = node.requests();
    let call = |m: &str| {
        requests
            .iter()
            .find(|s| s.rpc_method() == Some(m))
            .unwrap()
            .body["params"]
            .clone()
    };
    // consumed(digest) was asked of the contract first.
    let consumed = call("eth_call");
    assert_eq!(consumed[0]["to"], CONTRACT);
    assert_eq!(hex_param(&consumed[0]["data"]), consumed_calldata(&digest));
    // The estimate is of the release itself, from the relayer's address.
    let estimate = call("eth_estimateGas");
    assert_eq!(
        hex_param(&estimate[0]["data"]),
        release_calldata(&attestation)
    );
    assert_eq!(estimate[0]["from"], format!("0x{KEY_ADDRESS}"));
    assert_eq!(call("eth_getTransactionCount")[1], "pending");
    // The sent transaction: chain 31337, nonce 9, gas 100000 + 20 %, tip 1 gwei, max fee 2*100 + tip.
    let raw = hex_param(&call("eth_sendRawTransaction")[0]);
    assert_eq!(raw[0], 0x02);
    let rlp = rlp::Rlp::new(&raw[1..]);
    assert_eq!(rlp.val_at::<u64>(0).unwrap(), 0x7a69);
    assert_eq!(rlp.val_at::<u64>(1).unwrap(), 9);
    assert_eq!(rlp.val_at::<u128>(2).unwrap(), 1_000_000_000);
    assert_eq!(rlp.val_at::<u128>(3).unwrap(), 200 + 1_000_000_000);
    assert_eq!(rlp.val_at::<u64>(4).unwrap(), 120_000);
    assert_eq!(
        rlp.val_at::<Vec<u8>>(7).unwrap(),
        release_calldata(&attestation)
    );
    // Order: check, estimate, then send, then the receipt.
    let methods = node.rpc_methods();
    let at = |m: &str| methods.iter().position(|x| x == m).unwrap();
    assert!(
        at("eth_call") < at("eth_estimateGas")
            && at("eth_estimateGas") < at("eth_sendRawTransaction")
    );
    assert!(at("eth_sendRawTransaction") < at("eth_getTransactionReceipt"));
}

#[tokio::test]
async fn a_digest_already_consumed_is_not_sent_again() {
    let node = evm_node(true, false, "0x1", |_| None);
    let submitter = EvmSubmitter::new(&cfg(&node.url, EvmKind::Evm), KEY).unwrap();
    let (attestation, digest) = attestation();
    assert_eq!(
        submitter.release(&attestation, &digest).await.unwrap(),
        Outcome::AlreadyDone
    );
    assert!(submitter.is_consumed(&digest).await.unwrap());
    assert_eq!(node.count("eth_sendRawTransaction"), 0);
    assert_eq!(node.count("eth_estimateGas"), 0);
}

#[tokio::test]
async fn a_release_that_would_revert_is_found_out_before_it_is_sent() {
    let node = evm_node(false, false, "0x1", |m| {
        (m == "eth_estimateGas")
            .then(|| Err(json!({ "code": 3, "message": "execution reverted: bad signature" })))
    });
    let submitter = EvmSubmitter::new(&cfg(&node.url, EvmKind::Evm), KEY).unwrap();
    let (attestation, digest) = attestation();
    let err = format!(
        "{:#}",
        submitter.release(&attestation, &digest).await.unwrap_err()
    );
    assert!(
        err.contains("release would revert") && err.contains("bad signature"),
        "{err}"
    );
    assert_eq!(node.count("eth_sendRawTransaction"), 0);
}

#[tokio::test]
async fn a_node_without_fee_data_gets_the_defaults() {
    // No eth_maxPriorityFeePerGas, no baseFeePerGas (a chain before London): tip 1 gwei, max fee = tip.
    let node = evm_node(false, false, "0x1", |m| match m {
        "eth_maxPriorityFeePerGas" => Some(Err(json!({ "code": -32601, "message": "no" }))),
        "eth_getBlockByNumber" => Some(Ok(json!({ "number": "0x1", "baseFeePerGas": null }))),
        _ => None,
    });
    let submitter = EvmSubmitter::new(&cfg(&node.url, EvmKind::Evm), KEY).unwrap();
    let (attestation, digest) = attestation();
    submitter.release(&attestation, &digest).await.unwrap();
    let sent = node
        .requests()
        .into_iter()
        .find(|s| s.rpc_method() == Some("eth_sendRawTransaction"))
        .unwrap();
    let raw = hex_param(&sent.body["params"][0]);
    let rlp = rlp::Rlp::new(&raw[1..]);
    assert_eq!(rlp.val_at::<u128>(2).unwrap(), 1_000_000_000);
    assert_eq!(rlp.val_at::<u128>(3).unwrap(), 1_000_000_000);
}

#[tokio::test]
async fn a_reverted_receipt_is_a_lost_race_or_a_failure() {
    let (attestation, digest) = attestation();
    // Someone else's release landed first: the digest reads consumed afterwards.
    let raced = evm_node(false, true, "0x0", |_| None);
    let submitter = EvmSubmitter::new(&cfg(&raced.url, EvmKind::Evm), KEY).unwrap();
    assert_eq!(
        submitter.release(&attestation, &digest).await.unwrap(),
        Outcome::AlreadyDone
    );

    let failed = evm_node(false, false, "0x0", |_| None);
    let submitter = EvmSubmitter::new(&cfg(&failed.url, EvmKind::Evm), KEY).unwrap();
    let err = submitter
        .release(&attestation, &digest)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("reverted") && err.contains("0xabc123"),
        "{err}"
    );
}

#[tokio::test]
async fn a_node_that_returns_no_transaction_hash_is_an_error() {
    let node = evm_node(false, false, "0x1", |m| {
        (m == "eth_sendRawTransaction").then_some(Ok(Value::Null))
    });
    let submitter = EvmSubmitter::new(&cfg(&node.url, EvmKind::Evm), KEY).unwrap();
    let (attestation, digest) = attestation();
    let err = submitter
        .release(&attestation, &digest)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("no transaction hash"), "{err}");
}

#[tokio::test]
async fn a_guardian_set_upgrade_goes_to_submit_guardian_set_upgrade() {
    let node = evm_node(false, false, "0x1", |_| None);
    let submitter = EvmSubmitter::new(&cfg(&node.url, EvmKind::Evm), KEY).unwrap();
    let (attestation, digest) = attestation();
    let encoded = attestation.encode();
    let outcome = submitter
        .guardian_set_upgrade(&encoded, &digest)
        .await
        .unwrap();
    assert_eq!(outcome, Outcome::Submitted("0xabc123".into()));
    let estimate = node
        .requests()
        .into_iter()
        .find(|s| s.rpc_method() == Some("eth_estimateGas"))
        .unwrap();
    let data = hex_param(&estimate.body["params"][0]["data"]);
    assert_eq!(data[..4], selector("submitGuardianSetUpgrade(bytes)"));
    assert_eq!(data, bridge_daemons::governance::upgrade_calldata(&encoded));
}

// ---- submit/tron.rs ---------------------------------------------------------

struct TronOpts {
    consumed: bool,
    build_ok: bool,
    forge_txid: bool,
    omit_calldata: bool,
    broadcast_ok: bool,
    final_result: &'static str,
    consumed_after: bool,
}

impl Default for TronOpts {
    fn default() -> Self {
        TronOpts {
            consumed: false,
            build_ok: true,
            forge_txid: false,
            omit_calldata: false,
            broadcast_ok: true,
            final_result: "SUCCESS",
            consumed_after: false,
        }
    }
}

fn tron_node(o: TronOpts) -> Fake {
    let broadcast = std::sync::atomic::AtomicBool::new(false);
    http(move |seen| {
        use std::sync::atomic::Ordering::SeqCst;
        let reply = |v: Value| (200, v.to_string());
        match seen.path.as_str() {
            "/wallet/triggerconstantcontract" => {
                assert_eq!(seen.body["function_selector"], "consumed(bytes32)");
                let on = o.consumed || (o.consumed_after && broadcast.load(SeqCst));
                reply(json!({ "constant_result": [format!("{:064x}", u8::from(on))] }))
            }
            "/wallet/triggersmartcontract" => {
                let argument = hex::decode(seen.body["parameter"].as_str().unwrap()).unwrap();
                let mut raw = vec![0x0a, 0x02, 0x00, 0x01, 0x41];
                raw.extend_from_slice(&[0x11; 20]);
                if !o.omit_calldata {
                    raw.extend_from_slice(&selector(
                        seen.body["function_selector"].as_str().unwrap(),
                    ));
                    raw.extend_from_slice(&argument);
                }
                let mut txid = hex::encode(Sha256::digest(&raw));
                if o.forge_txid {
                    txid = "00".repeat(32);
                }
                reply(json!({
                    "result": { "result": o.build_ok },
                    "transaction": { "txID": txid, "raw_data_hex": hex::encode(&raw), "raw_data": {} },
                }))
            }
            "/wallet/broadcasttransaction" => {
                broadcast.store(true, SeqCst);
                reply(json!({ "result": o.broadcast_ok }))
            }
            "/wallet/gettransactioninfobyid" => {
                reply(json!({ "receipt": { "result": o.final_result } }))
            }
            other => panic!("unexpected path {other}"),
        }
    })
}

fn tron(node: &Fake) -> TronSubmitter {
    TronSubmitter::new(
        &cfg(&format!("{}/", node.url), EvmKind::Tron),
        KEY,
        150_000_000,
    )
    .unwrap()
}

#[test]
fn the_tron_submitter_validates_its_key_and_contract() {
    let c = cfg("http://127.0.0.1:1", EvmKind::Tron);
    assert!(TronSubmitter::new(&c, KEY, 1).is_ok());
    assert!(TronSubmitter::new(&c, "xyz", 1).is_err());
    assert!(TronSubmitter::new(&c, &"00".repeat(32), 1).is_err());
    let mut c = c;
    c.contract = "T123".into();
    assert!(TronSubmitter::new(&c, KEY, 1).is_err());
}

#[tokio::test]
async fn a_tron_release_is_built_by_the_node_checked_signed_and_broadcast() {
    let node = tron_node(TronOpts::default());
    let (attestation, digest) = attestation();
    let outcome = tron(&node).release(&attestation, &digest).await.unwrap();

    let requests = node.requests();
    let by_path = |p: &str| requests.iter().find(|s| s.path == p).unwrap().body.clone();
    let built = by_path("/wallet/triggersmartcontract");
    assert_eq!(built["function_selector"], "release(bytes)");
    assert_eq!(built["owner_address"], format!("41{KEY_ADDRESS}"));
    assert_eq!(built["contract_address"], format!("41{}", &CONTRACT[2..]));
    assert_eq!(built["fee_limit"], 150_000_000);
    assert_eq!(built["call_value"], 0);
    assert_eq!(
        hex::decode(built["parameter"].as_str().unwrap()).unwrap(),
        bridge_daemons::submit::abi_encode_bytes(&attestation.encode())
    );

    // What was broadcast carries a signature over the txID that recovers to the relayer.
    let tx = by_path("/wallet/broadcasttransaction");
    let txid = tx["txID"].as_str().unwrap();
    assert_eq!(outcome, Outcome::Submitted(txid.to_string()));
    let sig = hex::decode(tx["signature"][0].as_str().unwrap()).unwrap();
    assert_eq!(sig.len(), 65);
    assert!(sig[64] == 27 || sig[64] == 28);
    let raw = RawSignature {
        r: sig[..32].try_into().unwrap(),
        s: sig[32..64].try_into().unwrap(),
        v: sig[64] - 27,
    };
    assert_eq!(
        hex::encode(recover(&hex::decode(txid).unwrap().try_into().unwrap(), &raw).unwrap()),
        KEY_ADDRESS
    );
}

#[tokio::test]
async fn a_tron_release_already_consumed_builds_nothing() {
    let node = tron_node(TronOpts {
        consumed: true,
        ..Default::default()
    });
    let (attestation, digest) = attestation();
    assert_eq!(
        tron(&node).release(&attestation, &digest).await.unwrap(),
        Outcome::AlreadyDone
    );
    assert!(node
        .requests()
        .iter()
        .all(|s| s.path == "/wallet/triggerconstantcontract"));
}

#[tokio::test]
async fn a_tron_node_is_not_trusted_with_the_signature() {
    let (attestation, digest) = attestation();
    for (opts, why) in [
        (
            TronOpts {
                build_ok: false,
                ..Default::default()
            },
            "refused to build",
        ),
        (
            TronOpts {
                forge_txid: true,
                ..Default::default()
            },
            "txID is not the hash",
        ),
        (
            TronOpts {
                omit_calldata: true,
                ..Default::default()
            },
            "not our call",
        ),
        (
            TronOpts {
                broadcast_ok: false,
                ..Default::default()
            },
            "broadcast refused",
        ),
    ] {
        let node = tron_node(opts);
        let err = tron(&node)
            .release(&attestation, &digest)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains(why), "{why}: {err}");
        let signed = node
            .requests()
            .iter()
            .any(|s| s.path == "/wallet/broadcasttransaction");
        assert_eq!(
            signed,
            why == "broadcast refused",
            "nothing is broadcast unless every check passed ({why})"
        );
    }
}

#[tokio::test]
async fn tron_confirmation_outcomes() {
    // The three polls each wait 3 s before asking; run them together.
    let (attestation, digest) = attestation();
    let (ok, raced, failed) = tokio::join!(
        async {
            let node = tron_node(TronOpts::default());
            tron(&node).release(&attestation, &digest).await
        },
        async {
            let node = tron_node(TronOpts {
                final_result: "REVERT",
                consumed_after: true,
                ..Default::default()
            });
            tron(&node).release(&attestation, &digest).await
        },
        async {
            let node = tron_node(TronOpts {
                final_result: "OUT_OF_ENERGY",
                ..Default::default()
            });
            tron(&node).release(&attestation, &digest).await
        },
    );
    assert!(matches!(ok.unwrap(), Outcome::Submitted(_)));
    assert_eq!(raced.unwrap(), Outcome::AlreadyDone);
    let err = failed.unwrap_err().to_string();
    assert!(err.contains("ended OUT_OF_ENERGY"), "{err}");
}

#[tokio::test]
async fn a_tron_guardian_set_upgrade_names_its_function() {
    let node = tron_node(TronOpts {
        consumed: true,
        ..Default::default()
    });
    let (attestation, digest) = attestation();
    // Consumed: only the read happens, but the submitter still answers.
    assert_eq!(
        tron(&node)
            .guardian_set_upgrade(&attestation.encode(), &digest)
            .await
            .unwrap(),
        Outcome::AlreadyDone
    );

    let node = tron_node(TronOpts {
        build_ok: false,
        ..Default::default()
    });
    tron(&node)
        .guardian_set_upgrade(&attestation.encode(), &digest)
        .await
        .unwrap_err();
    let built = node
        .requests()
        .into_iter()
        .find(|s| s.path == "/wallet/triggersmartcontract")
        .unwrap();
    assert_eq!(
        built.body["function_selector"],
        "submitGuardianSetUpgrade(bytes)"
    );
}

#[tokio::test]
async fn tron_reads_that_return_nonsense_are_errors() {
    let (_, digest) = attestation();
    let none = http(|_| (200, r#"{"constant_result":[]}"#.into()));
    let err = tron(&none)
        .is_consumed(&digest)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("consumed() gave no result"), "{err}");
    let html = http(|_| (200, "oops".into()));
    assert!(tron(&html).is_consumed(&digest).await.is_err());
    let down = http(|_| (500, "".into()));
    assert!(tron(&down).is_consumed(&digest).await.is_err());
}

// ---- submit/process.rs ------------------------------------------------------

/// A fake tool: logs its argv, `SOL_RPC_URL`, and the contents of any `@file`
/// or `--attestation-file` argument to `<dir>/log`, then runs `tail`.
fn fake_tool(dir: &std::path::Path, tail: &str) -> std::path::PathBuf {
    let path = dir.join("tool.sh");
    std::fs::write(
        &path,
        format!(
            r#"#!/bin/sh
{{
  echo "ARGS $*"
  echo "RPC ${{SOL_RPC_URL:-}}"
  prev=""
  for a in "$@"; do
    case "$a" in @*) echo "FILE ${{a#@}}: $(cat "${{a#@}}")";; esac
    [ "$prev" = "--attestation-file" ] && echo "FILE $a: $(cat "$a")"
    prev="$a"
  done
}} >> "{dir}/log"
{tail}
"#,
            dir = dir.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn solana(dir: &std::path::Path, cli: std::path::PathBuf) -> SolanaSubmitter {
    SolanaSubmitter {
        cli,
        rpc: "http://sol.example:8899".into(),
        program: "ProgramId1111".into(),
        scratch: dir.join("scratch"),
    }
}

#[tokio::test]
async fn solana_releases_run_the_cli_with_the_attestation_in_a_file() {
    let dir = tempfile::tempdir().unwrap();
    let tool = fake_tool(dir.path(), "echo 'sending'; echo '5Zq...signature'");
    let (attestation, digest) = attestation();
    let outcome = solana(dir.path(), tool)
        .release(&attestation, &digest)
        .await
        .unwrap();
    assert_eq!(
        outcome,
        Outcome::Submitted("5Zq...signature".into()),
        "the last line of stdout"
    );

    let log = std::fs::read_to_string(dir.path().join("log")).unwrap();
    let file = dir
        .path()
        .join("scratch")
        .join(format!("{}.hex", hex::encode(digest)));
    assert!(
        log.contains(&format!(
            "ARGS release --program ProgramId1111 --attestation-file {}",
            file.display()
        )),
        "{log}"
    );
    assert!(log.contains("RPC http://sol.example:8899"));
    assert!(
        log.contains(&format!(
            "FILE {}: {}",
            file.display(),
            hex::encode(attestation.encode())
        )),
        "{log}"
    );
    assert!(!file.exists(), "the attestation file is removed afterwards");
}

#[tokio::test]
async fn a_tool_that_says_someone_got_there_first_is_already_done() {
    let (attestation, digest) = attestation();
    for said in [
        "echo 'Error: already consumed' >&2",
        "echo AlreadyConsumed >&2",
        "echo 'custom program error: 0x14' >&2",
        "echo 'already consumed'",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let tool = fake_tool(dir.path(), &format!("{said}; exit 1"));
        let outcome = solana(dir.path(), tool)
            .release(&attestation, &digest)
            .await
            .unwrap();
        assert_eq!(outcome, Outcome::AlreadyDone, "{said}");
    }
}

#[tokio::test]
async fn a_failing_tool_reports_the_last_line_of_stderr() {
    let (attestation, digest) = attestation();
    let dir = tempfile::tempdir().unwrap();
    let tool = fake_tool(
        dir.path(),
        "echo 'noise' >&2; echo 'insufficient funds' >&2; exit 2",
    );
    let err = solana(dir.path(), tool)
        .release(&attestation, &digest)
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(err, "rand-bridge-cli release failed: insufficient funds");
    let silent = fake_tool(dir.path(), "exit 3");
    let err = solana(dir.path(), silent)
        .release(&attestation, &digest)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.ends_with("failed: no output"), "{err}");
    let missing = dir.path().join("no-such-tool");
    let err = solana(dir.path(), missing)
        .release(&attestation, &digest)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("starting rand-bridge-cli release"), "{err}");
}

fn rand_submitter(dir: &std::path::Path, cli: std::path::PathBuf) -> RandSubmitter {
    RandSubmitter {
        cli,
        extra_args: vec!["--wallet".into(), "w.json".into()],
        scratch: dir.join("scratch"),
    }
}

#[tokio::test]
async fn a_rand_mint_runs_the_wallet_with_the_recipient_and_the_pq_quorum() {
    let dir = tempfile::tempdir().unwrap();
    let tool = fake_tool(dir.path(), "echo 'minted: note 7'");
    let (attestation, digest) = attestation();
    let pq = vec![PqSignature {
        index: 2,
        signature: "abcd".into(),
    }];
    let outcome = rand_submitter(dir.path(), tool.clone())
        .mint(&attestation, &digest, "rand1xyz", Some(&pq))
        .await
        .unwrap();
    assert_eq!(outcome, Outcome::Submitted("minted: note 7".into()));

    let scratch = dir.path().join("scratch");
    let att = scratch.join(format!("{}.hex", hex::encode(digest)));
    let pqf = scratch.join(format!("{}.pq.json", hex::encode(digest)));
    let log = std::fs::read_to_string(dir.path().join("log")).unwrap();
    assert!(
        log.contains(&format!(
            "ARGS --wallet w.json bridge-mint @{} --to rand1xyz --pq @{}",
            att.display(),
            pqf.display()
        )),
        "{log}"
    );
    assert!(
        log.contains(&format!(
            "FILE {}: {}",
            pqf.display(),
            r#"[{"index":2,"signature":"abcd"}]"#
        )),
        "{log}"
    );
    assert!(
        !att.exists() && !pqf.exists(),
        "both temp files are removed"
    );

    // Without a PQ quorum there is no --pq.
    std::fs::remove_file(dir.path().join("log")).unwrap();
    rand_submitter(dir.path(), tool)
        .mint(&attestation, &digest, "rand1xyz", None)
        .await
        .unwrap();
    let log = std::fs::read_to_string(dir.path().join("log")).unwrap();
    assert!(
        log.contains("--to rand1xyz") && !log.contains("--pq"),
        "{log}"
    );
}

#[tokio::test]
async fn a_rand_mint_that_the_wallet_refuses_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let tool = fake_tool(dir.path(), "echo 'recipient hash mismatch' >&2; exit 1");
    let (attestation, digest) = attestation();
    let err = rand_submitter(dir.path(), tool)
        .mint(&attestation, &digest, "rand1xyz", None)
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "rand bridge-mint failed: recipient hash mismatch"
    );
    let _ = GuardianKey::from_hex(KEY).unwrap();
}
