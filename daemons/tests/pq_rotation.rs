//! BRG-14: `rand-bridge-gov` rotates the post-quantum guardian set and the
//! pause key on Rand — the genesis-bound messages the fullnode verifies
//! (`bridge/gov.rs`, `docs/bridge.md` §21), signed by a PQ quorum of the
//! current set and each new key, checked, and handed to `rand-node` to send.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use bridge_daemons::pq::{self, PqKey};
use bridge_daemons::pq_gov::{self, BindingDomain, RotationKind};
use common::*;
use serde_json::json;

const CHAIN21_GENESIS: &str = "ca76c2766ed6090ac6ba5dad86b724dd5d2b80c0edfaed287cd8b129e663ca9a";

fn genesis() -> [u8; 32] {
    hex::decode(CHAIN21_GENESIS).unwrap().try_into().unwrap()
}

fn seed(i: u8) -> String {
    format!("{:064x}", 0x200 + u64::from(i))
}

fn pk(i: u8) -> Vec<u8> {
    PqKey::from_seed_hex(&seed(i)).unwrap().public_key()
}

fn set_file(dir: &Path, name: &str, seeds: &[u8]) -> PathBuf {
    let keys: Vec<String> = seeds.iter().map(|i| hex::encode(pk(*i))).collect();
    let path = dir.join(name);
    std::fs::write(&path, json!({ "pq_guardians": keys }).to_string()).unwrap();
    path
}

fn gov() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rand-bridge-gov"))
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}

// ---- the layouts --------------------------------------------------------------

#[test]
fn the_rotation_messages_are_the_fullnodes_fixed_layouts() {
    let keys = vec![pk(1), pk(2)];
    let m = pq_gov::rotate_pq_message(0x0102_0304_0506_0708, 5, &keys).unwrap();
    assert_eq!(&m[..26], b"rand-bridge-pq-rotate-pq-1");
    assert_eq!(&m[26..34], &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(&m[34..42], &5u64.to_be_bytes());
    assert_eq!(&m[42..46], &2u32.to_be_bytes(), "a count of keys, not of bytes");
    assert_eq!(&m[46..46 + 1312], &keys[0][..]);
    assert_eq!(m.len(), 46 + 1312 * 2);

    let p = pq_gov::rotate_pause_message(7, 9, &keys[1]).unwrap();
    assert_eq!(&p[..29], b"rand-bridge-pq-rotate-pause-1");
    assert_eq!(p.len(), 1357);
    assert_eq!(&p[45..], &keys[1][..]);

    let c = pq_gov::cancel_rotation_message(7, 9, RotationKind::PauseKey);
    assert_eq!(&c[..29], b"rand-bridge-cancel-rotation-1");
    assert_eq!(c.len(), 46);
    assert_eq!(c[45], 1);
    assert_eq!(pq_gov::cancel_rotation_message(7, 9, RotationKind::PqGuardians)[45], 0);

    // Genesis-bound (chain 20 onward): the `-2` tag, the genesis hash, then the v1 bytes.
    let d = BindingDomain::Genesis(genesis());
    for (v1, v2, tag) in [
        (m.clone(), pq_gov::rotate_pq_message_in(&d, 0x0102_0304_0506_0708, 5, &keys).unwrap(), 26),
        (p.clone(), pq_gov::rotate_pause_message_in(&d, 7, 9, &keys[1]).unwrap(), 29),
        (c.clone(), pq_gov::cancel_rotation_message_in(&d, 7, 9, RotationKind::PauseKey), 29),
    ] {
        assert_eq!(&v2[..tag - 1], &v1[..tag - 1]);
        assert_eq!(v2[tag - 1], b'2');
        assert_eq!(&v2[tag..tag + 32], &genesis());
        assert_eq!(&v2[tag + 32..], &v1[tag..]);
    }
    assert_eq!(pq_gov::rotate_pq_message_in(&BindingDomain::ChainId, 7, 9, &keys).unwrap(), pq_gov::rotate_pq_message(7, 9, &keys).unwrap());

    // Shapes the ledger refuses are refused here.
    assert!(pq_gov::rotate_pq_message(7, 9, &[]).is_err());
    assert!(pq_gov::rotate_pq_message(7, 9, &[pk(1), pk(1)]).is_err());
    assert!(pq_gov::rotate_pq_message(7, 9, &[vec![0; 1311]]).is_err());
    assert!(pq_gov::rotate_pause_message(7, 9, &[0; 32]).is_err());
}

// ---- sign and submit ----------------------------------------------------------

/// A chain-21 node with the current PQ set `current` (seeds) at `nonce`.
fn node(current: &[u8], nonce: u64, needs_possession: bool) -> Fake {
    let pq: Vec<String> = current.iter().map(|i| hex::encode(pk(*i))).collect();
    let guardians: Vec<String> = current.iter().map(|i| format!("0x{:040x}", i)).collect();
    rpc(move |m, _| match m {
        "rand_chainId" => Some(Ok(json!(21))),
        "rand_getGenesisHash" => Some(Ok(json!(CHAIN21_GENESIS))),
        "rand_getBridgeState" => Some(Ok(json!({
            "enabled": true,
            "guardian_set_index": 1,
            "guardians": guardians,
            "burn_sequence": 0,
            "pq_guardians": pq,
            "pause_key": hex::encode(pk(50)),
            "rotation_nonce": nonce,
            "rules_v2": { "cap_window_secs": 86400 },
            "rotation_rules": { "delay_secs": 86400, "needs_possession": needs_possession },
        }))),
        _ => None,
    })
}

fn sign_pq(dir: &Path, node: &Fake, current: &PathBuf, new: &PathBuf, seeds: &[u8], new_seeds: &[u8], nonce: &str) -> Output {
    let mut c = gov();
    c.args(["pq-rotate-pq", "--rand-chain-id", "21", "--rand-rpc", &node.url, "--nonce", nonce])
        .arg("--pq-guardians-file")
        .arg(current)
        .arg("--new-pq-guardians-file")
        .arg(new)
        .arg("--out")
        .arg(dir.join("quorum.txt"))
        .arg("--possession-out")
        .arg(dir.join("possession.txt"));
    let names: Vec<String> = seeds.iter().map(|i| format!("PQ{i}")).collect();
    if !names.is_empty() {
        c.args(["--seed-envs", &names.join(",")]);
    }
    let new_names: Vec<String> = new_seeds.iter().map(|i| format!("NEW{i}")).collect();
    if !new_names.is_empty() {
        c.args(["--possession-seed-envs", &new_names.join(",")]);
    }
    for i in seeds {
        c.env(format!("PQ{i}"), seed(*i));
    }
    for i in new_seeds {
        c.env(format!("NEW{i}"), seed(*i));
    }
    c.output().unwrap()
}

/// A stand-in `rand-node` that records its arguments.
fn fake_rand_node(dir: &Path) -> PathBuf {
    let path = dir.join("rand-node");
    write_script(&path, &format!("echo \"$@\" > {}", dir.join("args.txt").display()));
    path
}

#[test]
fn a_pq_set_rotation_is_signed_on_separate_machines_checked_and_submitted() {
    let dir = tempfile::tempdir().unwrap();
    let rand = node(&[1, 2, 3, 4], 2, true);
    let current = set_file(dir.path(), "current.json", &[1, 2, 3, 4]);
    let new = set_file(dir.path(), "new.json", &[11, 12, 13, 14]);

    // Two current guardians sign on one machine, a third and the new keys elsewhere.
    let o = sign_pq(dir.path(), &rand, &current, &new, &[1, 2], &[], "2");
    assert!(o.status.success(), "{}", err(&o));
    assert!(out(&o).contains("quorum     2 line(s)") && out(&o).contains("needs 3"), "{}", out(&o));
    let o = sign_pq(dir.path(), &rand, &current, &new, &[4], &[11, 12, 13, 14], "2");
    assert!(o.status.success(), "{}", err(&o));

    let message = pq_gov::rotate_pq_message_in(
        &BindingDomain::Genesis(genesis()),
        21,
        2,
        &[pk(11), pk(12), pk(13), pk(14)],
    )
    .unwrap();
    let lines = pq_gov::parse_signature_lines(&std::fs::read_to_string(dir.path().join("quorum.txt")).unwrap()).unwrap();
    assert_eq!(lines.iter().map(|l| l.0).collect::<Vec<_>>(), vec![0, 1, 3]);
    pq_gov::check_quorum_lines(&lines, &[pk(1), pk(2), pk(3), pk(4)], &message).unwrap();

    let rand_node = fake_rand_node(dir.path());
    let submit = |extra: &[&str]| {
        let mut c = gov();
        c.args(["pq-rotate-submit", "--kind", "pq", "--rand-rpc", &rand.url])
            .arg("--new-pq-guardians-file")
            .arg(&new)
            .arg("--quorum")
            .arg(dir.path().join("quorum.txt"))
            .arg("--rand-node")
            .arg(&rand_node)
            .args(extra);
        c.output().unwrap()
    };
    // Possession is required on this chain.
    let o = submit(&[]);
    assert!(!o.status.success() && err(&o).contains("requires a proof of possession"), "{}", err(&o));
    let possession = dir.path().join("possession.txt");
    let o = submit(&["--possession", possession.to_str().unwrap()]);
    assert!(o.status.success(), "{}", err(&o));
    let args = std::fs::read_to_string(dir.path().join("args.txt")).unwrap();
    assert!(args.starts_with("bridge-gov rotate-pq submit --new-key "), "{args}");
    assert_eq!(args.matches("--new-key").count(), 4);
    assert!(args.contains(&hex::encode(pk(13))));
    assert!(args.contains("--possession @") && args.contains(&format!("--rpc {}", rand.url)), "{args}");

    // The node's nonce moved on: the same lines no longer hold, nothing is sent.
    std::fs::remove_file(dir.path().join("args.txt")).unwrap();
    let moved = node(&[1, 2, 3, 4], 3, true);
    let mut c = gov();
    c.args(["pq-rotate-submit", "--kind", "pq", "--rand-rpc", &moved.url])
        .arg("--new-pq-guardians-file").arg(&new)
        .arg("--quorum").arg(dir.path().join("quorum.txt"))
        .arg("--possession").arg(&possession)
        .arg("--rand-node").arg(&rand_node);
    let o = c.output().unwrap();
    assert!(!o.status.success() && err(&o).contains("do not hold"), "{}", err(&o));
    assert!(!dir.path().join("args.txt").exists());
}

#[test]
fn signing_refuses_a_stale_nonce_a_foreign_set_and_a_stranger_key() {
    let dir = tempfile::tempdir().unwrap();
    let rand = node(&[1, 2, 3, 4], 2, true);
    let current = set_file(dir.path(), "current.json", &[1, 2, 3, 4]);
    let new = set_file(dir.path(), "new.json", &[11, 12, 13, 14]);
    let o = sign_pq(dir.path(), &rand, &current, &new, &[1], &[], "1");
    assert!(!o.status.success() && err(&o).contains("rotation_nonce is 2"), "{}", err(&o));
    let other = set_file(dir.path(), "other.json", &[1, 2, 3, 5]);
    let o = sign_pq(dir.path(), &rand, &other, &new, &[1], &[], "2");
    assert!(!o.status.success() && err(&o).contains("not the PQ guardian set the node serves"), "{}", err(&o));
    let o = sign_pq(dir.path(), &rand, &current, &new, &[9], &[], "2");
    assert!(!o.status.success() && err(&o).contains("not the seed of a key in the current"), "{}", err(&o));
    assert!(!dir.path().join("quorum.txt").exists(), "nothing was written");
}

#[test]
fn the_pause_key_is_rotated_and_a_pending_rotation_can_be_cancelled() {
    let dir = tempfile::tempdir().unwrap();
    let rand = node(&[1, 2, 3], 4, false);
    let current = set_file(dir.path(), "current.json", &[1, 2, 3]);
    let new_key = hex::encode(pk(60));
    let mut c = gov();
    c.args(["pq-rotate-pause", "--rand-chain-id", "21", "--rand-rpc", &rand.url, "--nonce", "4"])
        .arg("--pq-guardians-file").arg(&current)
        .args(["--new-pause-key", &new_key, "--seed-envs", "PQ1,PQ2,PQ3"])
        .arg("--out").arg(dir.path().join("q.txt"));
    for i in 1..=3 {
        c.env(format!("PQ{i}"), seed(i));
    }
    let o = c.output().unwrap();
    assert!(o.status.success(), "{}", err(&o));
    let message = pq_gov::rotate_pause_message_in(&BindingDomain::Genesis(genesis()), 21, 4, &pk(60)).unwrap();
    let lines = pq_gov::parse_signature_lines(&std::fs::read_to_string(dir.path().join("q.txt")).unwrap()).unwrap();
    pq_gov::check_quorum_lines(&lines, &[pk(1), pk(2), pk(3)], &message).unwrap();

    let rand_node = fake_rand_node(dir.path());
    let mut c = gov();
    c.args(["pq-rotate-submit", "--kind", "pause", "--rand-rpc", &rand.url, "--new-pause-key", &new_key])
        .arg("--quorum").arg(dir.path().join("q.txt"))
        .arg("--rand-node").arg(&rand_node);
    let o = c.output().unwrap();
    assert!(o.status.success(), "{}", err(&o));
    let args = std::fs::read_to_string(dir.path().join("args.txt")).unwrap();
    assert!(args.starts_with("bridge-gov rotate-pause submit --new-key "), "{args}");
    assert!(!args.contains("--possession"));

    // A PQ guardian's key cannot become the pause key.
    let mut c = gov();
    c.args(["pq-rotate-submit", "--kind", "pause", "--rand-rpc", &rand.url, "--new-pause-key", &hex::encode(pk(2)), "--dry-run"])
        .arg("--quorum").arg(dir.path().join("q.txt"));
    let o = c.output().unwrap();
    assert!(!o.status.success() && err(&o).contains("is a PQ guardian's key"), "{}", err(&o));

    // The current pause key cancels a pending rotation.
    let mut c = gov();
    c.args(["pq-cancel-rotation", "--rand-chain-id", "21", "--genesis", CHAIN21_GENESIS, "--nonce", "5", "--kind", "pause", "--seed-env", "PAUSE"])
        .arg("--out").arg(dir.path().join("cancel.txt"))
        .env("PAUSE", seed(50));
    let o = c.output().unwrap();
    assert!(o.status.success(), "{}", err(&o));
    let line = pq_gov::parse_signature_lines(&std::fs::read_to_string(dir.path().join("cancel.txt")).unwrap()).unwrap();
    let cancel = pq_gov::cancel_rotation_message_in(&BindingDomain::Genesis(genesis()), 21, 5, RotationKind::PauseKey);
    assert_eq!(line[0].0, 0);
    assert!(pq::verify_raw(&pk(50), &cancel, &line[0].1));
}
