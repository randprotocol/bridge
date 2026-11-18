//! BR-3: `rand-bridge-audit --handover` says which step of the governance
//! handover each endpoint is at, from chain reads alone.

mod common;

use std::process::Command;

use bridge_daemons::handover::{self, evm_stage, operation, operation_id, solana_stage, EvmHandover, Operation, SolanaHandover, Stage};
use bridge_daemons::submit::selector;
use common::*;
use serde_json::{json, Value};

const BRIDGE: &str = "0x6410797df959987a5baf65b5fab97edeb34d5163";

fn a20(hex40: &str) -> [u8; 20] {
    hex::decode(hex40.trim_start_matches("0x")).unwrap().try_into().unwrap()
}

/// The id recorded in docs/mainnet-deployment.md for the Tron endpoint's acceptAdmin()
/// (bridge TK6JJ… = 0x6410797d…, salt 0), as the live timelock's hashOperation gave it.
#[test]
fn the_operation_id_is_the_timelocks_own() {
    let id = operation_id(&a20(BRIDGE), &handover::ACCEPT_ADMIN, &[0u8; 32]);
    assert_eq!(hex::encode(id), "816a8de4fcd4e876409596609f9021a4771b20f6c0ec745a885f6fa281672d88");
    assert_eq!(handover::ACCEPT_ADMIN, selector("acceptAdmin()"));
    // Another salt is another operation.
    assert_ne!(operation_id(&a20(BRIDGE), &handover::ACCEPT_ADMIN, &[1u8; 32]), id);
}

#[test]
fn a_timelock_timestamp_reads_as_unset_done_waiting_or_ready() {
    assert_eq!(operation(0, 100), Operation::Unset);
    assert_eq!(operation(1, 100), Operation::Done);
    assert_eq!(operation(101, 100), Operation::Waiting { ready_at: 101 });
    assert_eq!(operation(100, 100), Operation::Ready { ready_at: 100 });
    assert_eq!(operation(50, 100), Operation::Ready { ready_at: 50 });
}

fn evm(admin_code: bool, pending: bool, pending_code: bool, accept: Option<Operation>) -> EvmHandover {
    EvmHandover {
        admin: [1; 20],
        admin_has_code: admin_code,
        pending_admin: if pending { [2; 20] } else { [0; 20] },
        pending_has_code: pending_code,
        accept,
    }
}

#[test]
fn each_step_of_the_evm_handover_is_told_apart() {
    let stage = |r: EvmHandover| evm_stage(&r, false);
    assert_eq!(stage(evm(false, false, false, None)).0, Stage::NotStarted);
    assert_eq!(stage(evm(false, true, true, Some(Operation::Unset))).0, Stage::Transferred);
    let (s, next) = stage(evm(false, true, true, Some(Operation::Waiting { ready_at: 1_759_465_440 })));
    assert_eq!(s, Stage::Scheduled);
    assert!(next.contains("1759465440") && next.contains("still admin"), "{next}");
    let (s, next) = stage(evm(false, true, true, Some(Operation::Ready { ready_at: 5 })));
    assert_eq!(s, Stage::Executable);
    assert!(next.contains("execute-accept.json") && next.contains("single key is still admin"), "{next}");
    assert_eq!(stage(evm(true, false, false, None)).0, Stage::Complete);
    // States the handover never passes through are not called progress.
    for odd in [
        evm(false, true, false, None),                  // a key is pending admin
        evm(false, true, true, None),                   // a contract that is no timelock
        evm(false, true, true, Some(Operation::Done)),  // "done" but still pending
        evm(true, true, true, Some(Operation::Unset)),  // a further transfer
    ] {
        assert_eq!(stage(odd.clone()).0, Stage::Unexpected, "{odd:?}");
    }
    // Tron names its own commands.
    let (_, next) = evm_stage(&evm(false, true, true, Some(Operation::Ready { ready_at: 5 })), true);
    assert!(next.contains("tron-ops.js timelock-execute-accept"), "{next}");
}

#[test]
fn each_step_of_the_solana_handover_is_told_apart() {
    let (key, vault, other) = ([1u8; 32], [2u8; 32], [3u8; 32]);
    let s = |admin, pending, authority: Option<[u8; 32]>, v: Option<[u8; 32]>| {
        solana_stage(&SolanaHandover { admin, pending_admin: pending, upgrade_authority: authority, vault: v }).0
    };
    assert_eq!(s(key, [0; 32], Some(other), None), Stage::NotStarted, "no multisig configured");
    assert_eq!(s(key, [0; 32], Some(other), Some(vault)), Stage::NotStarted);
    assert_eq!(s(key, vault, Some(other), Some(vault)), Stage::Scheduled);
    assert_eq!(s(key, other, Some(other), Some(vault)), Stage::Unexpected, "pending is not the vault");
    assert_eq!(s(vault, [0; 32], Some(other), Some(vault)), Stage::Transferred, "the authority is last");
    assert_eq!(s(vault, [0; 32], Some(vault), Some(vault)), Stage::Complete);
    assert_eq!(s(vault, [0; 32], None, Some(vault)), Stage::Complete, "not upgradeable");
    assert_eq!(s(key, [0; 32], Some(vault), Some(vault)), Stage::Unexpected, "authority before admin");
}

// ---- the binary against a loopback node -----------------------------------------

const KEY: &str = "e49bd2571a549e8797be649229f62891fe300d0e";
const TIMELOCK: &str = "6b81056c29c2f131f823f04107747b47d4f22fea";

fn word20(hex40: &str) -> Value {
    json!(format!("0x{}{hex40}", "00".repeat(12)))
}

/// A bridge whose admin is `admin`, with `pending` as pendingAdmin; `TIMELOCK` has code and
/// answers getTimestamp with `timestamp`. The chain's clock reads 1_000.
fn node(admin: &'static str, pending: Option<&'static str>, timestamp: u128) -> Fake {
    let id = hex::encode(operation_id(&a20(BRIDGE), &handover::ACCEPT_ADMIN, &[0u8; 32]));
    rpc(move |m, p| match m {
        "eth_call" => {
            let data = p[0]["data"].as_str().unwrap().trim_start_matches("0x").to_string();
            let sel = |s: &str| data.starts_with(&hex::encode(selector(s)));
            Some(Ok(if sel("admin()") {
                word20(admin)
            } else if sel("pendingAdmin()") {
                word20(pending.unwrap_or(&"0".repeat(40)))
            } else if sel("pauser()") {
                word20(&"9".repeat(40))
            } else if sel("getTimestamp(bytes32)") {
                assert!(data.ends_with(&id), "asked for another operation: {data}");
                json!(format!("0x{timestamp:064x}"))
            } else if sel("getMinDelay()") {
                json!(format!("0x{:064x}", 172_800))
            } else {
                return Some(Err(json!({ "code": 3, "message": "reverted" })));
            }))
        }
        "eth_getCode" => {
            let who = p[0].as_str().unwrap().trim_start_matches("0x").to_lowercase();
            Some(Ok(json!(if who == TIMELOCK { "0x6080" } else { "0x" })))
        }
        "eth_getBlockByNumber" => Some(Ok(json!({ "timestamp": "0x3e8" }))),
        _ => None,
    })
}

fn run(node: &Fake, kind: &str, extra: &[&str]) -> (bool, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        format!(
            "data_dir = {:?}\n[rand]\nrpc = \"http://127.0.0.1:1\"\nemitter = {:?}\n[[evm]]\nname = \"endpoint\"\nchain = {}\nkind = {kind:?}\nrpc = {:?}\ncontract = {BRIDGE:?}\nfinality = 0\n",
            dir.path().join("data"),
            hex::encode(RAND_EMITTER),
            if kind == "tron" { 4 } else { 2 },
            node.url
        ),
    )
    .unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_rand-bridge-audit"))
        .env_remove("RAND_BRIDGE_CONFIG")
        .arg("--config")
        .arg(&path)
        .arg("--handover")
        .args(extra)
        .output()
        .unwrap();
    (o.status.success(), String::from_utf8_lossy(&o.stdout).into(), String::from_utf8_lossy(&o.stderr).into())
}

#[test]
fn the_report_walks_the_handover_and_fails_until_the_admin_has_moved() {
    for (n, stage) in [
        (node(KEY, None, 0), "stage: NOT STARTED"),
        (node(KEY, Some(TIMELOCK), 0), "stage: TRANSFERRED, ACCEPT NOT SCHEDULED"),
        (node(KEY, Some(TIMELOCK), 2_000), "stage: ACCEPT SCHEDULED, WAITING"),
        (node(KEY, Some(TIMELOCK), 900), "stage: ACCEPT EXECUTABLE NOW"),
        (node(KEY, Some(KEY), 0), "stage: UNEXPECTED"),
    ] {
        let (ok, out, err) = run(&n, "evm", &[]);
        assert!(!ok && err.contains("BR-3"), "{stage}: {out}\n{err}");
        assert!(out.contains(stage), "{stage}: {out}");
        assert!(out.contains("nothing was signed or sent"), "{out}");
        // Reads only.
        for m in n.rpc_methods() {
            assert!(["eth_call", "eth_getCode", "eth_getBlockByNumber"].contains(&m.as_str()), "{m}");
        }
    }
    let (ok, out, err) = run(&node(TIMELOCK, None, 1), "evm", &[]);
    assert!(ok, "{out}\n{err}");
    assert!(out.contains("stage: ADMIN MOVED") && out.contains("--governance"), "{out}");
}

#[test]
fn a_tron_endpoint_is_shown_in_tron_form_and_the_salt_selects_the_operation() {
    let n = node(KEY, Some(TIMELOCK), 900);
    let (_, out, _) = run(&n, "tron", &[]);
    assert!(out.contains("TKmds8i5UPQDaV3YghCVJUMomHeQzJzV7k"), "pendingAdmin as T…: {out}");
    assert!(out.contains("0x816a8de4fcd4e876409596609f9021a4771b20f6c0ec745a885f6fa281672d88"), "{out}");
    assert!(out.contains("tron-ops.js timelock-execute-accept") && out.contains("delay 172800 s"), "{out}");
    assert!(n.requests().iter().all(|r| r.path.ends_with("/jsonrpc")), "Tron is read through /jsonrpc");
    // A malformed salt is refused before anything is read.
    let (ok, _, err) = run(&n, "tron", &["--salt", "0x12"]);
    assert!(!ok && err.contains("--salt"), "{err}");
}

#[test]
fn an_endpoint_that_cannot_be_read_is_unknown() {
    let (ok, out, _) = run(&rpc(|_, _| None), "evm", &[]);
    assert!(!ok && out.contains("stage: UNKNOWN"), "{out}");
}
