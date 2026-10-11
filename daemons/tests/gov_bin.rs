//! `rand-bridge-gov` as an operator runs it: arguments, environment-held
//! keys, files in and out. Run as a subprocess; no network but loopback.

mod common;

use std::path::Path;
use std::process::{Command, Output};

use bridge_daemons::crypto::GuardianKey;
use bridge_daemons::governance::{rotation_body, sign_rotation, verify_rotation};
use bridge_daemons::pq::{self, PqKey, PqSignature};
use bridge_daemons::pq_gov;
use common::*;
use serde_json::json;

fn gov() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_rand-bridge-gov"));
    for k in [
        "GK1", "GK2", "GK3", "GK4", "PQ1", "PQ2", "PQ3", "PQ4", "PAUSE", "RELAYER",
    ] {
        c.env_remove(k);
    }
    c
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}
fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

fn key(i: u8) -> GuardianKey {
    GuardianKey::from_hex(&format!("{i:064x}")).unwrap()
}
fn addr(i: u8) -> String {
    format!("0x{}", hex::encode(key(i).address()))
}
fn current() -> String {
    format!("{},{},{}", addr(1), addr(2), addr(3))
}
fn seed(i: u8) -> String {
    format!("{:064x}", 0x100 + u64::from(i))
}

/// `rotate` with the three current guardians' keys in GK1..GK3.
fn rotate(dir: &Path, extra: &[&str]) -> Output {
    gov()
        .args([
            "rotate",
            "--current-index",
            "0",
            "--current-guardians",
            &current(),
        ])
        .args(["--new-guardians", &format!("{},{}", addr(7), addr(8))])
        .args([
            "--signer-envs",
            "GK1,GK2,GK3",
            "--timestamp",
            "1800000000",
            "--out",
        ])
        .arg(dir.join("rotation.hex"))
        .args(extra)
        .env("GK1", format!("{:064x}", 1))
        .env("GK2", format!("0x{:064x}", 2))
        .env("GK3", format!("{:064x}", 3))
        .output()
        .unwrap()
}

#[test]
fn a_rotation_is_built_signed_verified_and_written() {
    let dir = tempfile::tempdir().unwrap();
    let o = rotate(dir.path(), &[]);
    assert!(o.status.success(), "{}", err(&o));
    let text = out(&o);

    // Byte for byte what the library builds for the same inputs.
    let set = [key(1).address(), key(2).address(), key(3).address()];
    let body = rotation_body(
        0,
        &[key(7).address(), key(8).address()],
        1_800_000_000,
        0,
        1,
    )
    .unwrap();
    let expected = sign_rotation(&body, 0, &set, &[key(1), key(2), key(3)])
        .unwrap()
        .encode();
    let written = std::fs::read_to_string(dir.path().join("rotation.hex")).unwrap();
    assert_eq!(written, hex::encode(&expected));

    let checked = verify_rotation(&expected, 0, &set).unwrap();
    assert!(text.contains("rotation   set 0 -> set 1"), "{text}");
    assert!(
        text.contains("signed by  guardians [0, 1, 2] of the current set"),
        "{text}"
    );
    assert!(
        text.contains(&format!("new [0]    {}", addr(7)))
            && text.contains(&format!("new [1]    {}", addr(8))),
        "{text}"
    );
    assert!(
        text.contains(&format!("digest     0x{}", hex::encode(checked.digest))),
        "{text}"
    );
    assert!(
        text.contains("pass --timestamp 1800000000 to reproduce"),
        "{text}"
    );
    assert!(
        text.contains(&format!("bytes      {}", expected.len())),
        "{text}"
    );
    assert!(
        text.contains("rand-bridge-gov submit-tron") && text.contains("guardian-set-upgrade"),
        "{text}"
    );
    // Keys were consumed from the environment, never printed.
    assert!(!text.contains(&format!("{:064x}", 1)));
}

#[test]
fn a_rotation_without_a_timestamp_uses_the_clock_and_the_set_index_as_sequence() {
    let dir = tempfile::tempdir().unwrap();
    let o = gov()
        .args([
            "rotate",
            "--current-index",
            "4",
            "--current-guardians",
            &current(),
        ])
        .args([
            "--new-guardians",
            &addr(7),
            "--signer-envs",
            "GK1,GK2,GK3",
            "--out",
        ])
        .arg(dir.path().join("r.hex"))
        .env("GK1", format!("{:064x}", 1))
        .env("GK2", format!("{:064x}", 2))
        .env("GK3", format!("{:064x}", 3))
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", err(&o));
    assert!(out(&o).contains("rotation   set 4 -> set 5"));
    let attestation =
        hex::decode(std::fs::read_to_string(dir.path().join("r.hex")).unwrap()).unwrap();
    let decoded = bridge_codec::Attestation::decode(&attestation).unwrap();
    assert_eq!(decoded.body.sequence, 5, "the new index by convention");
    assert!(decoded.body.timestamp > 1_700_000_000);
}

#[test]
fn a_rotation_the_current_set_could_not_have_signed_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    // A key that is not in the set.
    let o = gov()
        .args([
            "rotate",
            "--current-index",
            "0",
            "--current-guardians",
            &current(),
        ])
        .args([
            "--new-guardians",
            &addr(7),
            "--signer-envs",
            "GK1,GK4,GK3",
            "--out",
        ])
        .arg(dir.path().join("r.hex"))
        .env("GK1", format!("{:064x}", 1))
        .env("GK3", format!("{:064x}", 3))
        .env("GK4", format!("{:064x}", 4))
        .output()
        .unwrap();
    assert!(!o.status.success());
    assert!(
        err(&o).contains("is not in the current guardian set"),
        "{}",
        err(&o)
    );
    assert!(!dir.path().join("r.hex").exists());

    // Below quorum.
    let o = gov()
        .args([
            "rotate",
            "--current-index",
            "0",
            "--current-guardians",
            &current(),
        ])
        .args(["--new-guardians", &addr(7), "--signer-envs", "GK1", "--out"])
        .arg(dir.path().join("r.hex"))
        .env("GK1", format!("{:064x}", 1))
        .output()
        .unwrap();
    assert!(
        err(&o).contains("1 signers, but the current set of 3 needs 3"),
        "{}",
        err(&o)
    );

    // A signer variable that is not set, no signer at all, a bad address, a duplicate new key.
    let o = rotate_with(dir.path(), "GK1,NOPE", &addr(7));
    assert!(err(&o).contains("NOPE is not set"), "{}", err(&o));
    let o = rotate_with(dir.path(), "", &addr(7));
    assert!(
        err(&o).contains("names no key") || !o.status.success(),
        "{}",
        err(&o)
    );
    let o = rotate_with(dir.path(), "GK1,GK2,GK3", "0x1234");
    assert!(err(&o).contains("address 0x1234"), "{}", err(&o));
    let o = rotate_with(
        dir.path(),
        "GK1,GK2,GK3",
        &format!("{},{}", addr(7), addr(7)),
    );
    assert!(err(&o).contains("repeats an earlier key"), "{}", err(&o));
    let o = rotate_with(
        dir.path(),
        "GK1,GK2,GK3",
        "0x0000000000000000000000000000000000000000",
    );
    assert!(err(&o).contains("zero address"), "{}", err(&o));
}

fn rotate_with(dir: &Path, signers: &str, new: &str) -> Output {
    let mut c = gov();
    c.args([
        "rotate",
        "--current-index",
        "0",
        "--current-guardians",
        &current(),
    ])
    .args(["--new-guardians", new, "--out"])
    .arg(dir.join("x.hex"))
    .env("GK1", format!("{:064x}", 1))
    .env("GK2", format!("{:064x}", 2))
    .env("GK3", format!("{:064x}", 3));
    if !signers.is_empty() {
        c.args(["--signer-envs", signers]);
    } else {
        c.arg("--signer-envs=");
    }
    c.output().unwrap()
}

#[test]
fn verify_accepts_the_tools_own_output_and_refuses_anything_else() {
    let dir = tempfile::tempdir().unwrap();
    assert!(rotate(dir.path(), &[]).status.success());
    let file = dir.path().join("rotation.hex");
    let verify = |index: &str, set: &str, file: &Path| {
        gov()
            .args([
                "verify",
                "--current-index",
                index,
                "--current-guardians",
                set,
                "--attestation-file",
            ])
            .arg(file)
            .output()
            .unwrap()
    };
    let o = verify("0", &current(), &file);
    assert!(o.status.success(), "{}", err(&o));
    assert!(
        out(&o).contains("valid: set 0 -> set 1, signed by [0, 1, 2]"),
        "{}",
        out(&o)
    );
    assert!(out(&o).contains(&format!("new [0]  {}", addr(7))));

    // A prefixed file with whitespace is read the same.
    let padded = dir.path().join("padded.hex");
    std::fs::write(
        &padded,
        format!("0x{}\n", std::fs::read_to_string(&file).unwrap()),
    )
    .unwrap();
    assert!(verify("0", &current(), &padded).status.success());

    // The wrong current index, a different set, not hex, a missing file.
    assert!(err(&verify("1", &current(), &file)).contains("must be signed by the current set 1"));
    let other = format!("{},{},{}", addr(1), addr(2), addr(9));
    assert!(err(&verify("0", &other, &file)).contains("does not recover to guardian 2"));
    let junk = dir.path().join("junk.hex");
    std::fs::write(&junk, "not hex").unwrap();
    assert!(err(&verify("0", &current(), &junk)).contains("attestation is not hex"));
    assert!(err(&verify("0", &current(), &dir.path().join("missing"))).contains("reading"));
}

fn pq_set(dir: &Path, seeds: &[u8]) -> std::path::PathBuf {
    let keys: Vec<String> = seeds
        .iter()
        .map(|i| hex::encode(PqKey::from_seed_hex(&seed(*i)).unwrap().public_key()))
        .collect();
    let path = dir.join("pq.json");
    std::fs::write(&path, json!({ "pq_guardians": keys }).to_string()).unwrap();
    path
}

fn with_seeds(c: &mut Command, seeds: &[u8]) {
    for i in seeds {
        c.env(format!("PQ{i}"), seed(*i));
    }
}

#[test]
fn cosign_writes_a_pq_quorum_that_the_ledger_rules_accept() {
    let dir = tempfile::tempdir().unwrap();
    assert!(rotate(dir.path(), &[]).status.success());
    let attestation_file = dir.path().join("rotation.hex");
    let pq_file = pq_set(dir.path(), &[1, 2, 3]);
    let outfile = dir.path().join("pq-sigs.json");
    let mut c = gov();
    c.args([
        "cosign",
        "--rand-chain-id",
        "14",
        "--seed-envs",
        "PQ1,PQ2,PQ3",
        "--attestation-file",
    ])
    .arg(&attestation_file)
    .arg("--pq-guardians-file")
    .arg(&pq_file)
    .arg("--out")
    .arg(&outfile);
    with_seeds(&mut c, &[1, 2, 3]);
    let o = c.output().unwrap();
    assert!(o.status.success(), "{}", err(&o));
    assert!(
        out(&o).contains("for Rand chain 14 by PQ guardians [0, 1, 2]"),
        "{}",
        out(&o)
    );

    let list: Vec<PqSignature> = serde_json::from_slice(&std::fs::read(&outfile).unwrap()).unwrap();
    let attestation = hex::decode(std::fs::read_to_string(&attestation_file).unwrap()).unwrap();
    let mu = bridge_daemons::crypto::digest(
        bridge_codec::Attestation::body_bytes(&attestation).unwrap(),
    );
    let guardians: Vec<Vec<u8>> = (1..=3)
        .map(|i| PqKey::from_seed_hex(&seed(i)).unwrap().public_key())
        .collect();
    pq::check(&list, &guardians, 14, &mu).unwrap();
}

#[test]
fn cosign_refuses_a_seed_that_is_not_a_guardian_and_a_short_quorum() {
    let dir = tempfile::tempdir().unwrap();
    assert!(rotate(dir.path(), &[]).status.success());
    let attestation_file = dir.path().join("rotation.hex");
    let pq_file = pq_set(dir.path(), &[1, 2, 3]);
    let run = |envs: &str, seeds: &[u8]| {
        let mut c = gov();
        c.args([
            "cosign",
            "--rand-chain-id",
            "14",
            "--seed-envs",
            envs,
            "--attestation-file",
        ])
        .arg(&attestation_file)
        .arg("--pq-guardians-file")
        .arg(&pq_file)
        .arg("--out")
        .arg(dir.path().join("o.json"));
        with_seeds(&mut c, seeds);
        c.output().unwrap()
    };
    assert!(
        err(&run("PQ1,PQ4", &[1, 4])).contains("PQ4 is not the seed of any key in pq_guardians")
    );
    assert!(err(&run("PQ1,PQ2", &[1, 2])).contains("2 co-signers, but 3 keys need 3"));
    assert!(err(&run("PQ9", &[])).contains("PQ9 is not set"));
    let o = gov()
        .args([
            "cosign",
            "--rand-chain-id",
            "14",
            "--seed-envs",
            "PQ1",
            "--attestation-file",
        ])
        .arg(dir.path().join("nope"))
        .arg("--pq-guardians-file")
        .arg(&pq_file)
        .arg("--out")
        .arg(dir.path().join("o"))
        .output()
        .unwrap();
    assert!(!o.status.success());
}

#[test]
fn the_pq_governance_messages_are_signed_by_a_quorum_and_described() {
    let dir = tempfile::tempdir().unwrap();
    let pq_file = pq_set(dir.path(), &[1, 2, 3, 4]); // quorum of 4 is 3
    let token = "ab".repeat(32);
    let guardians: Vec<Vec<u8>> = (1..=4)
        .map(|i| PqKey::from_seed_hex(&seed(i)).unwrap().public_key())
        .collect();
    let backing = pq_gov::Backing {
        chain: 2,
        token: [0xab; 32],
        decimals: 6,
    };

    let run = |sub: &[&str], name: &str| -> (Output, Vec<PqSignature>) {
        let outfile = dir.path().join(name);
        let mut c = gov();
        c.args(sub)
            .args([
                "--rand-chain-id",
                "14",
                "--nonce",
                "7",
                "--seed-envs",
                "PQ1,PQ2,PQ3,PQ4",
                "--pq-guardians-file",
            ])
            .arg(&pq_file)
            .arg("--out")
            .arg(&outfile);
        with_seeds(&mut c, &[1, 2, 3, 4]);
        let o = c.output().unwrap();
        let list = std::fs::read(&outfile)
            .ok()
            .map(|b| serde_json::from_slice(&b).unwrap())
            .unwrap_or_default();
        (o, list)
    };

    let (o, list) = run(
        &[
            "pq-list",
            "--token-index",
            "5",
            "--chain",
            "2",
            "--token",
            &token,
            "--decimals",
            "6",
        ],
        "list.json",
    );
    assert!(o.status.success(), "{}", err(&o));
    let message = pq_gov::list_message(14, 7, 5, &backing);
    pq::check_raw(&list, &guardians, &message).unwrap();
    assert_eq!(list.len(), 3, "exactly a quorum");
    assert!(
        out(&o).contains("ListBacking: token 5 += chain 2 coin 0xabab"),
        "{}",
        out(&o)
    );
    assert!(out(&o).contains(&format!(
        "message    0x{}  ({} bytes)",
        hex::encode(&message),
        message.len()
    )));
    assert!(out(&o).contains("signed by  PQ guardians [0, 1, 2]"));

    let salt = "01".repeat(32);
    let (o, list) = run(
        &[
            "pq-register",
            "--name",
            "Tether USD",
            "--symbol",
            "USDT",
            "--salt",
            &salt,
            "--chain",
            "2",
            "--token",
            &token,
            "--decimals",
            "6",
        ],
        "reg.json",
    );
    assert!(o.status.success(), "{}", err(&o));
    let message =
        pq_gov::register_message(14, 7, "Tether USD", "USDT", &[1; 32], &backing).unwrap();
    pq::check_raw(&list, &guardians, &message).unwrap();
    assert!(out(&o).contains("RegisterBridgedToken: Tether USD (USDT)"));

    // pq-unpause takes only the quorum arguments.
    let (o, list) = run(&["pq-unpause"], "unpause.json");
    assert!(o.status.success(), "{}", err(&o));
    pq::check_raw(&list, &guardians, &pq_gov::unpause_message(14, 7)).unwrap();
    assert!(out(&o).contains("UNPAUSE minting on Rand chain 14, pause_nonce 7"));
}

#[test]
fn pq_governance_refuses_bad_backings_and_foreign_signers() {
    let dir = tempfile::tempdir().unwrap();
    let pq_file = pq_set(dir.path(), &[1, 2, 3]);
    let token = "ab".repeat(32);
    let base = |sub: &[&str], envs: &str, seeds: &[u8]| {
        let mut c = gov();
        c.args(sub)
            .args([
                "--rand-chain-id",
                "14",
                "--nonce",
                "0",
                "--seed-envs",
                envs,
                "--pq-guardians-file",
            ])
            .arg(&pq_file)
            .arg("--out")
            .arg(dir.path().join("o.json"));
        with_seeds(&mut c, seeds);
        c.output().unwrap()
    };
    let list = |chain: &str, tok: &str| {
        [
            "pq-list",
            "--token-index",
            "1",
            "--chain",
            chain,
            "--token",
            tok,
            "--decimals",
            "6",
        ]
        .map(String::from)
    };
    let run_list = |chain: &str, tok: &str, envs: &str, seeds: &[u8]| {
        let args = list(chain, tok);
        base(
            &args.iter().map(String::as_str).collect::<Vec<_>>(),
            envs,
            seeds,
        )
    };
    assert!(err(&run_list("1", &token, "PQ1,PQ2,PQ3", &[1, 2, 3]))
        .contains("--chain must be 2, 3, 4 or 5"));
    assert!(err(&run_list("2", "abcd", "PQ1,PQ2,PQ3", &[1, 2, 3])).contains("expected 32 bytes"));
    assert!(err(&run_list("2", &token, "PQ1,PQ4,PQ3", &[1, 4, 3])).contains("not in pq_guardians"));
    assert!(
        err(&run_list("2", &token, "PQ1,PQ2", &[1, 2])).contains("2 signers, but 3 keys need 3")
    );
    assert!(err(&run_list("2", &token, "PQ1,PQ2,PQ3", &[1, 2])).contains("PQ3 is not set"));
    let empty_name = base(
        &[
            "pq-register",
            "--name",
            "",
            "--symbol",
            "X",
            "--salt",
            &"01".repeat(32),
            "--chain",
            "2",
            "--token",
            &token,
            "--decimals",
            "6",
        ],
        "PQ1,PQ2,PQ3",
        &[1, 2, 3],
    );
    assert!(err(&empty_name).contains("1..=255 bytes"));

    // A pq_guardians file that is not what it says.
    std::fs::write(&pq_file, r#"{"other": []}"#).unwrap();
    assert!(
        err(&run_list("2", &token, "PQ1,PQ2,PQ3", &[1, 2, 3])).contains("no pq_guardians array")
    );
    std::fs::write(&pq_file, "nope").unwrap();
    assert!(!run_list("2", &token, "PQ1,PQ2,PQ3", &[1, 2, 3])
        .status
        .success());
}

#[test]
fn pause_signs_with_the_single_pause_key_and_pq_public_key_prints_the_key_not_the_seed() {
    let dir = tempfile::tempdir().unwrap();
    let outfile = dir.path().join("pause.sig");
    let o = gov()
        .args(["pause", "--rand-chain-id", "14", "--nonce", "3", "--out"])
        .arg(&outfile)
        .env("RAND_BRIDGE_PAUSE_KEY_SEED", seed(9))
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", err(&o));
    let key = PqKey::from_seed_hex(&seed(9)).unwrap();
    let message = pq_gov::pause_message(14, 3);
    let sig = hex::decode(std::fs::read_to_string(&outfile).unwrap()).unwrap();
    assert!(pq::verify_raw(&key.public_key(), &message, &sig));
    assert!(out(&o).contains("PAUSE minting on Rand chain 14, pause_nonce 3"));
    assert!(out(&o).contains(&format!("message    0x{}", hex::encode(&message))));
    assert!(!out(&o).contains(&seed(9)) && !err(&o).contains(&seed(9)));

    // The default variable is unset here: a named error.
    let o = gov()
        .args(["pause", "--rand-chain-id", "1", "--nonce", "0", "--out"])
        .arg(&outfile)
        .env_remove("RAND_BRIDGE_PAUSE_KEY_SEED")
        .output()
        .unwrap();
    assert!(err(&o).contains("RAND_BRIDGE_PAUSE_KEY_SEED is not set"));
    // A seed that is not 32 bytes.
    let o = gov()
        .args([
            "pause",
            "--rand-chain-id",
            "1",
            "--nonce",
            "0",
            "--seed-env",
            "PAUSE",
            "--out",
        ])
        .arg(&outfile)
        .env("PAUSE", "0102")
        .output()
        .unwrap();
    assert!(err(&o).contains("PQ seed must be 32 bytes"));

    let o = gov()
        .args(["pq-public-key", "--seed-env", "PQ1"])
        .env("PQ1", seed(1))
        .output()
        .unwrap();
    assert!(o.status.success());
    let public = PqKey::from_seed_hex(&seed(1)).unwrap().public_key();
    assert_eq!(out(&o).trim(), hex::encode(&public));
    assert!(err(&o).contains("sha256 prefix"));
    assert!(!out(&o).contains(&seed(1)));
}

#[test]
fn the_cli_refuses_missing_arguments_and_unknown_subcommands() {
    for args in [
        &[][..],
        &["rotate"],
        &["frobnicate"],
        &["verify", "--current-index", "x"],
    ] {
        let o = gov().args(args).output().unwrap();
        assert_eq!(o.status.code(), Some(2), "{args:?}: {}", err(&o));
    }
    let o = gov().arg("--help").output().unwrap();
    assert!(o.status.success() && out(&o).contains("submit-evm") && out(&o).contains("pq-unpause"));
}

// ---- submit-evm / submit-tron -----------------------------------------------

fn rotation_file(dir: &Path) -> (std::path::PathBuf, [u8; 32]) {
    assert!(rotate(dir, &[]).status.success());
    let file = dir.join("rotation.hex");
    let bytes = hex::decode(std::fs::read_to_string(&file).unwrap()).unwrap();
    (
        file,
        bridge_daemons::crypto::digest(bridge_codec::Attestation::body_bytes(&bytes).unwrap()),
    )
}

const CONTRACT: &str = "0x1111111111111111111111111111111111111111";

#[test]
fn submit_evm_sends_the_rotation_unless_it_is_already_consumed() {
    let dir = tempfile::tempdir().unwrap();
    let (file, digest) = rotation_file(dir.path());
    let consumed = rpc(|m, _| (m == "eth_call").then(|| Ok(json!(format!("0x{:064x}", 1)))));
    let o = gov()
        .args([
            "submit-evm",
            "--rpc",
            &consumed.url,
            "--contract",
            CONTRACT,
            "--attestation-file",
        ])
        .arg(&file)
        .env("RELAYER_EVM_KEY", format!("{:064x}", 1))
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(out(&o).trim(), "AlreadyDone");
    let call = consumed.requests().remove(0);
    let data = hex::decode(
        call.body["params"][0]["data"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
    )
    .unwrap();
    assert_eq!(
        &data[4..],
        &digest,
        "asks about the digest of the rotation's body"
    );

    // Not consumed: the full flow, ending in Submitted.
    let node = rpc(|m, _| {
        Some(Ok(match m {
            "eth_call" => json!(format!("0x{:064x}", 0)),
            "eth_estimateGas" => json!("0x5208"),
            "eth_chainId" => json!("0x1"),
            "eth_getTransactionCount" => json!("0x0"),
            "eth_maxPriorityFeePerGas" => json!("0x1"),
            "eth_getBlockByNumber" => json!({ "baseFeePerGas": "0x1" }),
            "eth_sendRawTransaction" => json!("0xfeed"),
            "eth_getTransactionReceipt" => json!({ "status": "0x1" }),
            _ => return None,
        }))
    });
    let o = gov()
        .args([
            "submit-evm",
            "--rpc",
            &node.url,
            "--contract",
            CONTRACT,
            "--key-env",
            "MYKEY",
            "--attestation-file",
        ])
        .arg(&file)
        .env("MYKEY", format!("{:064x}", 1))
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(out(&o).lines().last().unwrap(), r#"Submitted("0xfeed")"#);
    assert_eq!(node.count("eth_sendRawTransaction"), 1);
}

#[test]
fn submit_evm_and_tron_fail_cleanly_without_a_key_or_a_valid_file() {
    let dir = tempfile::tempdir().unwrap();
    let (file, _) = rotation_file(dir.path());
    let o = gov()
        .args([
            "submit-evm",
            "--rpc",
            "http://127.0.0.1:1",
            "--contract",
            CONTRACT,
            "--attestation-file",
        ])
        .arg(&file)
        .output()
        .unwrap();
    assert!(
        err(&o).contains("RELAYER_EVM_KEY is not set"),
        "{}",
        err(&o)
    );
    let o = gov()
        .args([
            "submit-tron",
            "--api",
            "http://127.0.0.1:1",
            "--contract",
            CONTRACT,
            "--attestation-file",
        ])
        .arg(&file)
        .output()
        .unwrap();
    assert!(
        err(&o).contains("RELAYER_TRON_KEY is not set"),
        "{}",
        err(&o)
    );

    let junk = dir.path().join("junk");
    std::fs::write(&junk, "00").unwrap();
    let o = gov()
        .args([
            "submit-evm",
            "--rpc",
            "http://127.0.0.1:1",
            "--contract",
            CONTRACT,
            "--attestation-file",
        ])
        .arg(&junk)
        .env("RELAYER_EVM_KEY", format!("{:064x}", 1))
        .output()
        .unwrap();
    assert!(!o.status.success());
    let o = gov()
        .args([
            "submit-evm",
            "--rpc",
            "http://127.0.0.1:1",
            "--contract",
            "0x12",
            "--attestation-file",
        ])
        .arg(&file)
        .env("RELAYER_EVM_KEY", format!("{:064x}", 1))
        .output()
        .unwrap();
    assert!(!o.status.success());
    // An unreachable node: the error names the host.
    let o = gov()
        .args([
            "submit-evm",
            "--rpc",
            "http://127.0.0.1:1",
            "--contract",
            CONTRACT,
            "--attestation-file",
        ])
        .arg(&file)
        .env("RELAYER_EVM_KEY", format!("{:064x}", 1))
        .output()
        .unwrap();
    assert!(err(&o).contains("127.0.0.1:1"), "{}", err(&o));
}

#[test]
fn submit_tron_reads_consumed_from_the_node() {
    let dir = tempfile::tempdir().unwrap();
    let (file, _) = rotation_file(dir.path());
    let node = http(|seen| {
        assert_eq!(seen.path, "/wallet/triggerconstantcontract");
        (
            200,
            json!({ "constant_result": [format!("{:064x}", 1)] }).to_string(),
        )
    });
    let o = gov()
        .args([
            "submit-tron",
            "--api",
            &node.url,
            "--contract",
            CONTRACT,
            "--fee-limit",
            "1000",
            "--attestation-file",
        ])
        .arg(&file)
        .env("RELAYER_TRON_KEY", format!("{:064x}", 1))
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(out(&o).trim(), "AlreadyDone");
}
