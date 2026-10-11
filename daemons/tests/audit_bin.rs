//! `rand-bridge-audit` as a subprocess against loopback nodes: the custody
//! reconciliation and the governance check, their tables and their exit codes.

mod common;

use std::path::Path;
use std::process::{Command, Output};

use base64::Engine;
use bridge_daemons::sources::solana::find_program_address;
use bridge_daemons::submit::selector;
use common::*;
use serde_json::{json, Value};

const BRIDGE: &str = "0x1111111111111111111111111111111111111111";
const USDT: &str = "dac17f958d2ee523a2206206994597c13d831ec7";
const USDC: &str = "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";

fn audit() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_rand-bridge-audit"));
    c.env_remove("RAND_BRIDGE_CONFIG");
    c
}

fn text(o: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&o.stdout).to_string(),
        String::from_utf8_lossy(&o.stderr).to_string(),
    )
}

fn config(dir: &Path, rand_rpc: &str, body: &str) -> std::path::PathBuf {
    let path = dir.join("config.toml");
    std::fs::write(
        &path,
        format!(
            "data_dir = {:?}\n[rand]\nrpc = {rand_rpc:?}\nemitter = {:?}\n{body}\n",
            dir.join("data"),
            hex::encode(RAND_EMITTER)
        ),
    )
    .unwrap();
    path
}

fn evm_section(name: &str, chain: u16, kind: &str, rpc: &str) -> String {
    format!("[[evm]]\nname = {name:?}\nchain = {chain}\nkind = {kind:?}\nrpc = {rpc:?}\ncontract = {BRIDGE:?}\nfinality = 0\nmax_log_range = 500\n")
}

fn u256(v: u128) -> Value {
    json!(format!("0x{v:064x}"))
}

/// A chain holding `custody` of each Ethereum coin, with `fees` accrued and `balance` held.
fn custody_node(custody: u128, fees: u128, balance: u128, rand: Option<Value>) -> Fake {
    rpc(move |m, p| match m {
        "eth_call" => {
            let data =
                hex::decode(p[0]["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
            let sel: [u8; 4] = data[..4].try_into().unwrap();
            Some(Ok(if sel == selector("custody(address)") {
                u256(custody)
            } else if sel == selector("accruedFees(address)") {
                u256(fees)
            } else if sel == selector("balanceOf(address)") {
                u256(balance)
            } else if sel == selector("tokenConfig(address)") {
                u256(1)
            } else {
                return Some(Err(json!({ "code": 3, "message": "reverted" })));
            }))
        }
        "rand_getTokenSupply" => rand.clone().map(Ok),
        _ => None,
    })
}

fn supply(total: &str, locked: &str) -> Value {
    let row = |token: &str| json!({ "chain": 2, "token": format!("{}{token}", "00".repeat(12)), "decimals": 6, "locked": locked });
    json!({ "total_supply": total, "backings": [row(USDT), row(USDC)] })
}

fn run_custody(node: &Fake, extra: &[&str]) -> Output {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(
        dir.path(),
        &node.url,
        &evm_section("eth", 2, "evm", &node.url),
    );
    audit()
        .arg("--config")
        .arg(&cfg)
        .args(extra)
        .output()
        .unwrap()
}

#[test]
fn a_solvent_endpoint_matching_rand_is_reported_per_coin() {
    // 1 USDT / 1 USDC in custody (6 decimals) = 100_000_000 in Rand's 8-decimal units.
    let node = custody_node(
        1_000_000,
        0,
        1_000_000,
        Some(supply("200000000", "100000000")),
    );
    let o = run_custody(&node, &[]);
    let (out, err) = text(&o);
    assert!(o.status.success(), "{err}\n{out}");
    assert_eq!(
        out.matches("solvent; custody == locked").count(),
        2,
        "{out}"
    );
    assert!(out.contains("USDT") && out.contains("USDC"));
    assert!(
        out.contains("Rand: total supply 200000000 == sum of locked (8dp)"),
        "{out}"
    );
    assert!(
        out.contains("Endpoints: total custody 200000000 (8dp); custody - locked = 0"),
        "{out}"
    );
    // The default token is registry index 1, sent as a number.
    let req = node
        .requests()
        .into_iter()
        .find(|s| s.rpc_method() == Some("rand_getTokenSupply"))
        .unwrap();
    assert_eq!(req.body["params"], json!([1]));
}

#[test]
fn a_token_given_as_text_is_passed_through() {
    let node = custody_node(
        1_000_000,
        0,
        1_000_000,
        Some(supply("200000000", "100000000")),
    );
    let o = run_custody(&node, &["--token", "rpl1abc"]);
    assert!(o.status.success());
    let req = node
        .requests()
        .into_iter()
        .find(|s| s.rpc_method() == Some("rand_getTokenSupply"))
        .unwrap();
    assert_eq!(req.body["params"], json!(["rpl1abc"]));
}

#[test]
fn an_endpoint_holding_less_than_it_owes_fails_the_audit() {
    // balance 1_000_000 < custody 1_000_000 + fees 10.
    let node = custody_node(
        1_000_000,
        10,
        1_000_000,
        Some(supply("200000000", "100000000")),
    );
    let o = run_custody(&node, &[]);
    let (out, err) = text(&o);
    assert!(!o.status.success());
    assert!(out.contains("INSOLVENT: balance < custody + fees"), "{out}");
    assert!(
        err.contains("at least one endpoint holds less than it owes"),
        "{err}"
    );
}

#[test]
fn messages_in_flight_show_up_as_a_difference() {
    let node = custody_node(
        1_000_000,
        0,
        1_000_000,
        Some(supply("198000000", "99000000")),
    );
    let o = run_custody(&node, &[]);
    let (out, _) = text(&o);
    assert!(o.status.success());
    assert!(
        out.contains("solvent; custody - locked = 1000000 (8dp; in-flight messages?)"),
        "{out}"
    );
    assert!(out.contains("custody - locked = 2000000"), "{out}");
}

#[test]
fn a_ledger_whose_supply_is_not_the_sum_of_its_backings_fails_the_audit() {
    let node = custody_node(1_000_000, 0, 1_000_000, Some(supply("5", "100000000")));
    let o = run_custody(&node, &[]);
    let (out, _) = text(&o);
    assert!(!o.status.success());
    assert!(
        out.contains("TOTAL SUPPLY 5 != SUM OF LOCKED 200000000"),
        "{out}"
    );
}

#[test]
fn without_a_rand_side_only_solvency_is_checked() {
    let node = custody_node(1_000_000, 0, 1_000_000, None);
    let o = run_custody(&node, &[]);
    let (out, _) = text(&o);
    assert!(o.status.success());
    assert!(
        out.contains("solvent; Rand side not available") && out.contains("n/a"),
        "{out}"
    );
    assert!(!out.contains("Rand: "), "{out}");
}

#[test]
fn a_node_that_predates_token_supply_is_read_from_the_bridge_state() {
    let node = rpc(|m, p| match m {
        "eth_call" => {
            let data =
                hex::decode(p[0]["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
            Some(Ok(if data[..4] == selector("tokenConfig(address)") {
                u256(1)
            } else if data[..4] == selector("accruedFees(address)") {
                u256(0)
            } else {
                u256(1_000_000)
            }))
        }
        "rand_getBridgeState" => Some(Ok(json!({ "assets": [
            { "chain": 2, "token": format!("{}{USDT}", "00".repeat(12)), "locked": 100_000_000u64 },
            { "chain": 2, "token": format!("{}{USDC}", "00".repeat(12)), "locked": "100000000" },
        ] }))),
        _ => None,
    });
    let (out, _) = text(&run_custody(&node, &[]));
    assert!(
        out.contains("Rand: sum of locked 200000000 (8dp); total supply not served by this node"),
        "{out}"
    );
    assert_eq!(out.matches("custody == locked").count(), 2, "{out}");
}

#[test]
fn rows_that_cannot_be_read_are_errors_not_zeros() {
    // Every eth_call reverts.
    let reverting = custody_node(0, 0, 0, None);
    let broken = rpc(|_, _| Some(Err(json!({ "code": 3, "message": "reverted" }))));
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(
        dir.path(),
        &reverting.url,
        &evm_section("eth", 2, "evm", &broken.url),
    );
    let o = audit().arg("--config").arg(&cfg).output().unwrap();
    assert!(!o.status.success());
    assert!(text(&o).1.contains("reverted"), "{}", text(&o).1);

    // A custody counter wider than u128.
    let wide = rpc(|_, _| Some(Ok(json!(format!("0x{}", "ff".repeat(32))))));
    let cfg = config(
        dir.path(),
        &wide.url,
        &evm_section("eth", 2, "evm", &wide.url),
    );
    let o = audit().arg("--config").arg(&cfg).output().unwrap();
    assert!(text(&o).1.contains("does not fit a u128"), "{}", text(&o).1);
}

#[test]
fn a_tron_endpoint_is_read_through_its_jsonrpc_facade() {
    let node = http(|seen| {
        assert_eq!(seen.path, "/jsonrpc");
        let sel = seen.body["params"][0]["data"]
            .as_str()
            .map(|d| d[2..10].to_string());
        let v = match sel {
            Some(s) if s == hex::encode(selector("tokenConfig(address)")) => 1,
            Some(s) if s == hex::encode(selector("accruedFees(address)")) => 0,
            _ => 5_000_000,
        };
        (
            200,
            json!({ "jsonrpc": "2.0", "id": 1, "result": format!("0x{v:064x}") }).to_string(),
        )
    });
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(
        dir.path(),
        "http://127.0.0.1:1",
        &evm_section("tron", 4, "tron", &format!("{}/", node.url)),
    );
    let o = audit().arg("--config").arg(&cfg).output().unwrap();
    let (out, err) = text(&o);
    assert!(o.status.success(), "{err}");
    assert!(out.contains("USDT") && out.contains("5000000"), "{out}");
}

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

#[test]
fn solana_custody_is_read_from_the_registry_and_the_custody_account() {
    let program = bridge_daemons::config::pubkey32("11111111111111111111111111111111").unwrap();
    let mint =
        bridge_daemons::config::pubkey32("Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB").unwrap();
    let registry = bs58::encode(
        find_program_address(&[b"token", &mint], &program)
            .unwrap()
            .0,
    )
    .into_string();
    let custody = bs58::encode(
        find_program_address(&[b"custody", &mint], &program)
            .unwrap()
            .0,
    )
    .into_string();
    let mut registry_data = vec![0u8; 83];
    registry_data[33] = 1;
    registry_data[67..75].copy_from_slice(&7_000_000u64.to_le_bytes());
    registry_data[75..83].copy_from_slice(&250u64.to_le_bytes());
    let mut account_data = vec![0u8; 72];
    account_data[64..72].copy_from_slice(&8_000_000u64.to_le_bytes());
    let node = rpc(move |m, p| {
        if m != "getAccountInfo" {
            return None;
        }
        let key = p[0].as_str().unwrap();
        let data = if key == registry {
            Some(&registry_data)
        } else if key == custody {
            Some(&account_data)
        } else {
            None
        };
        Some(Ok(match data {
            Some(d) => json!({ "value": { "data": [b64(d), "base64"], "owner": "x" } }),
            None => json!({ "value": null }),
        }))
    });
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(
        dir.path(),
        &node.url,
        &format!(
            "[solana]\nrpc = {:?}\nprogram = \"11111111111111111111111111111111\"\n",
            node.url
        ),
    );
    let o = audit().arg("--config").arg(&cfg).output().unwrap();
    let (out, err) = text(&o);
    assert!(o.status.success(), "{err}\n{out}");
    let usdt = out.lines().find(|l| l.contains("USDT")).unwrap();
    for needle in ["true", "7000000", "250", "8000000"] {
        assert!(usdt.contains(needle), "{usdt}");
    }
    let usdc = out.lines().find(|l| l.contains("USDC")).unwrap();
    assert!(
        usdc.contains("false"),
        "an unregistered coin reads as disabled with nothing in custody: {usdc}"
    );
}

#[test]
fn the_audit_needs_a_readable_config() {
    let dir = tempfile::tempdir().unwrap();
    let o = audit()
        .arg("--config")
        .arg(dir.path().join("none.toml"))
        .output()
        .unwrap();
    assert!(text(&o).1.contains("reading"));
    assert_eq!(audit().output().unwrap().status.code(), Some(2));
}

// ---- --governance -----------------------------------------------------------

fn addr_word(a: &str) -> Value {
    json!(format!("0x{}{}", "00".repeat(12), a))
}

const ADMIN: &str = "2222222222222222222222222222222222222222";
const PAUSER: &str = "3333333333333333333333333333333333333333";
const MULTISIG: &str = "4444444444444444444444444444444444444444";

fn run_governance(cfg: &Path) -> (bool, String, String) {
    let o = audit()
        .arg("--config")
        .arg(cfg)
        .arg("--governance")
        .output()
        .unwrap();
    let (out, err) = text(&o);
    (o.status.success(), out, err)
}

const CAVEAT: &str = "caveat: custody is still authorised by the guardian quorum";

#[test]
fn a_governance_audit_of_nothing_fails_every_coverage_rule() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path(), "http://127.0.0.1:1", "");
    let (ok, out, err) = run_governance(&cfg);
    assert!(!ok);
    assert!(out.contains("governance policy: min_delay_secs = 172800, min_threshold = 2, solana_multisig = (unset)"), "{out}");
    for chain in [
        "chain 2 not configured",
        "chain 3 not configured",
        "chain 4 not configured",
        "chain 5 not configured",
    ] {
        assert!(out.contains(chain), "{out}");
    }
    assert!(out.contains(CAVEAT), "the caveat follows every run");
    assert!(
        err.contains("governance: 4 rule(s) not passed on 0 endpoint(s)"),
        "{err}"
    );
}

#[test]
fn an_unreachable_endpoint_is_a_failed_rule_not_a_crash() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let cfg = config(
        dir.path(),
        "http://127.0.0.1:1",
        &evm_section("eth", 2, "evm", &format!("http://127.0.0.1:{port}")),
    );
    let (ok, out, err) = run_governance(&cfg);
    assert!(!ok);
    assert!(
        out.contains("endpoint readable") && out.contains("FAIL") && out.contains("admin()"),
        "{out}"
    );
    assert!(out.contains(CAVEAT));
    assert!(err.contains("on 1 endpoint(s)"), "{err}");
}

/// An Ethereum node whose admin is a contract (`admin_has_code`), with a Safe-less multisig.
fn evm_governance_node(admin_has_code: bool, multisig_has_code: bool) -> Fake {
    rpc(move |m, p| {
        Some(Ok(match m {
            "eth_call" => {
                let to = p[0]["to"].as_str().unwrap().to_lowercase();
                let data =
                    hex::decode(p[0]["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
                let sel: [u8; 4] = data[..4].try_into().unwrap();
                if sel == selector("admin()") {
                    addr_word(ADMIN)
                } else if sel == selector("pauser()") {
                    addr_word(PAUSER)
                } else if sel == selector("pendingAdmin()") {
                    addr_word("00".repeat(20).as_str())
                } else if sel == selector("getMinDelay()") && to.ends_with(ADMIN) {
                    u256(172_800)
                } else if sel == selector("getThreshold()") {
                    u256(2)
                } else {
                    return Some(Err(json!({ "code": 3, "message": "execution reverted" })));
                }
            }
            "eth_getCode" => {
                let who = p[0].as_str().unwrap().to_lowercase();
                let has = (who.ends_with(ADMIN) && admin_has_code)
                    || (who.ends_with(MULTISIG) && multisig_has_code);
                json!(if has { "0x6080604052" } else { "0x" })
            }
            "eth_getStorageAt" => json!(format!("0x{}", "00".repeat(32))),
            "eth_blockNumber" => json!("0x3e8"),
            "eth_getLogs" => json!([]),
            _ => return None,
        }))
    })
}

#[test]
fn an_admin_that_is_a_key_or_an_unproven_contract_fails_the_governance_audit() {
    let dir = tempfile::tempdir().unwrap();
    // An EOA admin: no code, no timelock.
    let eoa = evm_governance_node(false, false);
    let cfg = config(
        dir.path(),
        "http://127.0.0.1:1",
        &evm_section("eth", 2, "evm", &eoa.url),
    );
    let (ok, out, err) = run_governance(&cfg);
    assert!(!ok);
    assert!(
        out.contains("== eth (chain 2) 0x1111111111111111111111111111111111111111 =="),
        "{out}"
    );
    assert!(out.contains("FAIL"), "{out}");
    assert!(
        out.contains(CAVEAT) && err.contains("rule(s) not passed"),
        "{out}{err}"
    );
    assert_eq!(
        eoa.count("eth_getLogs"),
        0,
        "an account without code has no logs to read"
    );

    // A contract admin with the role logs configured: the history is read in max_log_range chunks.
    let node = evm_governance_node(true, true);
    let policy = format!(
        "\n[governance]\ntimelock_deploy_block = {{ 2 = 0 }}\nadmin_multisig = {{ 2 = \"0x{MULTISIG}\" }}\n"
    );
    let cfg = config(
        dir.path(),
        "http://127.0.0.1:1",
        &format!("{}{policy}", evm_section("eth", 2, "evm", &node.url)),
    );
    let (ok, out, _) = run_governance(&cfg);
    assert!(!ok);
    assert!(out.contains("timelock_deploy_block = {\"2\": 0}"), "{out}");
    assert!(
        node.count("eth_getLogs") >= 2,
        "1001 blocks in chunks of 500: {}",
        node.count("eth_getLogs")
    );
    let logs: Vec<Value> = node
        .requests()
        .into_iter()
        .filter(|s| s.rpc_method() == Some("eth_getLogs"))
        .map(|s| s.body["params"][0].clone())
        .collect();
    assert_eq!(
        (logs[0]["fromBlock"].as_str(), logs[0]["toBlock"].as_str()),
        (Some("0x0"), Some("0x1f3"))
    );
    assert!(out.contains("FAIL"), "{out}");
    // Safe reads were asked of the multisig and the pauser has no code.
    assert!(node
        .requests()
        .iter()
        .any(|s| s.rpc_method() == Some("eth_call")
            && s.body["params"][0]["to"]
                .as_str()
                .unwrap()
                .ends_with(MULTISIG)));
}

#[test]
fn a_node_that_refuses_log_ranges_makes_the_role_rules_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let refusing = rpc(move |m, p| {
        Some(Ok(match m {
            "eth_call" => {
                let data =
                    hex::decode(p[0]["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
                let sel: [u8; 4] = data[..4].try_into().unwrap();
                if sel == selector("admin()") {
                    addr_word(ADMIN)
                } else if sel == selector("pauser()") {
                    addr_word(PAUSER)
                } else if sel == selector("pendingAdmin()") {
                    addr_word("00".repeat(20).as_str())
                } else {
                    u256(172_800)
                }
            }
            "eth_getCode" => json!("0x6080"),
            "eth_getStorageAt" => json!(format!("0x{}", "00".repeat(32))),
            "eth_blockNumber" => json!("0x10"),
            "eth_getLogs" => {
                return Some(Err(
                    json!({ "code": -32005, "message": "query returned more than 10000 results" }),
                ))
            }
            _ => return None,
        }))
    });
    let cfg = config(
        dir.path(),
        "http://127.0.0.1:1",
        &format!(
            "{}\n[governance]\ntimelock_deploy_block = {{ 2 = 0 }}\n",
            evm_section("eth", 2, "evm", &refusing.url)
        ),
    );
    let (ok, out, _) = run_governance(&cfg);
    assert!(!ok);
    assert!(out.contains("use an archive-capable RPC"), "{out}");
}

#[test]
fn a_tron_endpoint_asks_the_wallet_api_how_many_keys_its_accounts_need() {
    let dir = tempfile::tempdir().unwrap();
    let node = http(|seen| {
        if seen.path == "/wallet/getaccount" {
            return (200, json!({ "address": "41abc", "owner_permission": { "threshold": 2, "keys": [{ "weight": 1 }, { "weight": 1 }] } }).to_string());
        }
        let reply = |v: Value| {
            (
                200,
                json!({ "jsonrpc": "2.0", "id": 1, "result": v }).to_string(),
            )
        };
        match seen.body["method"].as_str().unwrap() {
            "eth_call" => {
                let data = seen.body["params"][0]["data"].as_str().unwrap();
                if data[2..10] == hex::encode(selector("admin()")) {
                    reply(addr_word(ADMIN))
                } else if data[2..10] == hex::encode(selector("pauser()")) {
                    reply(addr_word(PAUSER))
                } else {
                    reply(addr_word("00".repeat(20).as_str()))
                }
            }
            "eth_getCode" => reply(json!("0x")),
            _ => reply(json!(null)),
        }
    });
    let cfg = config(
        dir.path(),
        "http://127.0.0.1:1",
        &format!(
            "{}\n[governance]\nadmin_multisig = {{ 4 = \"0x{MULTISIG}\" }}\n",
            evm_section("tron", 4, "tron", &format!("{}/", node.url))
        ),
    );
    let (ok, out, _) = run_governance(&cfg);
    assert!(!ok);
    assert!(
        out.contains("(chain 4) T"),
        "a Tron contract is titled in base58: {out}"
    );
    let asked: Vec<String> = node
        .requests()
        .into_iter()
        .filter(|s| s.path == "/wallet/getaccount")
        .map(|s| s.body["address"].as_str().unwrap().to_string())
        .collect();
    assert!(
        asked.contains(&format!("41{MULTISIG}")) && asked.contains(&format!("41{PAUSER}")),
        "{asked:?}"
    );
}

// ---- Solana governance ------------------------------------------------------

fn solana_account(owner: &str, data: &[u8]) -> Value {
    json!({ "value": { "owner": owner, "data": [b64(data), "base64"] } })
}

const PROGRAM: &str = "11111111111111111111111111111111";

fn solana_node(accounts: Vec<([u8; 32], String, Vec<u8>)>) -> Fake {
    rpc(move |m, p| {
        if m != "getAccountInfo" {
            return None;
        }
        let key = p[0].as_str().unwrap();
        Some(Ok(accounts
            .iter()
            .find(|(k, _, _)| bs58::encode(k).into_string() == key)
            .map(|(_, owner, data)| solana_account(owner, data))
            .unwrap_or_else(|| json!({ "value": null }))))
    })
}

fn run_solana(node: &Fake, policy: &str) -> (bool, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(
        dir.path(),
        "http://127.0.0.1:1",
        &format!(
            "[solana]\nrpc = {:?}\nprogram = {PROGRAM:?}\n{policy}",
            node.url
        ),
    );
    run_governance(&cfg)
}

#[test]
fn solana_governance_reports_what_is_missing_or_misowned() {
    let program = bridge_daemons::config::pubkey32(PROGRAM).unwrap();
    let config_key = find_program_address(&[b"config"], &program).unwrap().0;

    // No config PDA at all.
    let (ok, out, _) = run_solana(&solana_node(vec![]), "");
    assert!(!ok);
    assert!(
        out.contains("endpoint readable") && out.contains("not found"),
        "{out}"
    );

    // Config PDA owned by someone else.
    let mut config_data = vec![1u8];
    config_data.extend_from_slice(&[5u8; 96]);
    let (_, out, _) = run_solana(
        &solana_node(vec![(
            config_key,
            "Stake11111111111111111111111111111111111111".into(),
            config_data.clone(),
        )]),
        "",
    );
    assert!(
        out.contains("is owned by Stake") && out.contains("not the bridge program"),
        "{out}"
    );

    // A well-formed config but no program account.
    let (_, out, _) = run_solana(
        &solana_node(vec![(config_key, PROGRAM.into(), config_data.clone())]),
        "",
    );
    assert!(out.contains("program account not found"), "{out}");

    // Program under the upgradeable loader, ProgramData with an authority, multisig not found.
    let loader = bridge_daemons::gov_audit::BPF_LOADER_UPGRADEABLE;
    let programdata = [8u8; 32];
    let mut program_data = 2u32.to_le_bytes().to_vec();
    program_data.extend_from_slice(&programdata);
    let mut pd = 3u32.to_le_bytes().to_vec();
    pd.extend_from_slice(&0u64.to_le_bytes());
    pd.push(1);
    pd.extend_from_slice(&[5u8; 32]);
    let accounts = vec![
        (config_key, PROGRAM.to_string(), config_data.clone()),
        (program, loader.to_string(), program_data.clone()),
        (programdata, loader.to_string(), pd),
    ];
    let multisig = "5qprF75BYaQvgYq1dVUgAEkUczW5DhiuNn7ahiYu6FR6";
    let (ok, out, _) = run_solana(
        &solana_node(accounts.clone()),
        &format!("\n[governance]\nsolana_multisig = {multisig:?}\n"),
    );
    assert!(!ok);
    assert!(
        out.contains(&format!("multisig {multisig} not found")),
        "{out}"
    );
    assert!(
        out.contains("== solana (chain 5) 11111111111111111111111111111111 =="),
        "{out}"
    );

    // Without a configured multisig the Solana rules say so.
    let (_, out, _) = run_solana(&solana_node(accounts.clone()), "");
    assert!(
        out.contains("no [governance].solana_multisig configured"),
        "{out}"
    );

    // The multisig exists but is not a Squads account.
    let mut with_ms = accounts.clone();
    with_ms.push((
        bridge_daemons::config::pubkey32(multisig).unwrap(),
        "Stake11111111111111111111111111111111111111".into(),
        vec![0; 10],
    ));
    let (_, out, _) = run_solana(
        &solana_node(with_ms),
        &format!("\n[governance]\nsolana_multisig = {multisig:?}\n"),
    );
    assert!(out.contains("not Squads v4"), "{out}");

    // A program not under the upgradeable loader cannot be upgraded; a ProgramData with another owner is an error.
    let mut immutable = accounts.clone();
    immutable[1].1 = "Stake11111111111111111111111111111111111111".into();
    let (_, out, _) = run_solana(&solana_node(immutable), "");
    assert!(
        out.contains("upgrade authority is the vault")
            && out.contains("immutable (no upgrade authority)"),
        "{out}"
    );
    let mut wrong_pd = accounts;
    wrong_pd[2].1 = "Stake11111111111111111111111111111111111111".into();
    let (_, out, _) = run_solana(&solana_node(wrong_pd), "");
    assert!(out.contains("ProgramData is owned by"), "{out}");
}
