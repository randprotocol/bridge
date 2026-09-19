//! Generates `vectors/pq-cosignatures.json`: the Dilithium2 co-signature
//! vectors of `spec/PQ-COSIGNATURE.md`, built on top of the attestation
//! vectors (which this never modifies).
//!
//! `cargo run --release --bin pq-vectors` writes the file;
//! `cargo run --release --bin pq-vectors -- --check` asserts the file on disk
//! is what the generator produces. Signing is deterministic, so it is.

use std::fs;
use std::path::PathBuf;

use crystals_dilithium::dilithium2;
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};

const DOMAIN: &[u8] = b"rand-bridge-pq-cosign-1";
const TEST_CHAIN_ID: u64 = 99;
const N: usize = 6;

fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

fn seed(i: u8) -> [u8; 32] {
    let mut pre = b"rand-bridge-pq-test-guardian".to_vec();
    pre.push(i);
    keccak256(&pre)
}

fn keypair(i: u8) -> dilithium2::Keypair {
    dilithium2::Keypair::generate(Some(&seed(i))).expect("32-byte seed")
}

/// `M = domain ‖ rand_chain_id (u64 BE) ‖ mu`.
fn message(chain_id: u64, mu: &[u8; 32]) -> Vec<u8> {
    let mut m = DOMAIN.to_vec();
    m.extend_from_slice(&chain_id.to_be_bytes());
    m.extend_from_slice(mu);
    m
}

fn sig(i: u8, m: &[u8]) -> String {
    hex::encode(keypair(i).sign(m))
}

fn sigs(indices: &[u8], m: &[u8]) -> Vec<Value> {
    indices.iter().map(|&i| json!({ "index": i, "signature": sig(i, m) })).collect()
}

fn attestations() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/attestations.json");
    serde_json::from_str(&fs::read_to_string(path).expect("vectors/attestations.json")).expect("json")
}

fn render() -> String {
    let att = attestations();
    let mut bodies = Vec::new();
    for v in att["vectors"].as_array().expect("vectors") {
        // Everything Rand accepts from the guardians: verifier chain 1, expected ok.
        if v["verifier_chain"] != 1 || v["expect"] != "ok" {
            continue;
        }
        let mu: [u8; 32] = hex::decode(v["digest"].as_str().expect("digest").trim_start_matches("0x"))
            .expect("hex")
            .try_into()
            .expect("32 bytes");
        let m = message(TEST_CHAIN_ID, &mu);
        bodies.push(json!({
            "attestation_vector": v["name"],
            "mu": hex::encode(mu),
            "message": hex::encode(&m),
            "pq_signatures": sigs(&[0, 1, 2, 3, 4, 5], &m),
        }));
    }
    assert!(bodies.len() >= 4, "expected the ok vectors addressed to Rand");

    // The cases run over the first body.
    let mu: [u8; 32] = hex::decode(bodies[0]["mu"].as_str().unwrap()).unwrap().try_into().unwrap();
    let m = message(TEST_CHAIN_ID, &mu);
    let case = |name: &str, expect: &str, chain_id: u64, list: Vec<Value>| {
        json!({ "name": name, "expect": expect, "rand_chain_id": chain_id, "mu": hex::encode(mu), "pq_signatures": list })
    };
    let mut short = sigs(&[0, 1, 2, 3, 4], &m);
    let full = short[4]["signature"].as_str().unwrap().to_string();
    short[4]["signature"] = json!(full[..full.len() - 2]); // 2,419 bytes
    let mut wrong_index = sigs(&[0, 1, 2, 3, 4], &m);
    wrong_index[4]["signature"] = json!(sig(5, &m)); // guardian 5's signature filed under index 4
    let mut other_mu = mu;
    other_mu[0] ^= 1;
    let cases = vec![
        case("quorum_lowest_five_ok", "ok", TEST_CHAIN_ID, sigs(&[0, 1, 2, 3, 4], &m)),
        case("quorum_any_five_ok", "ok", TEST_CHAIN_ID, sigs(&[0, 2, 3, 4, 5], &m)),
        case("all_six_ok", "ok", TEST_CHAIN_ID, sigs(&[0, 1, 2, 3, 4, 5], &m)),
        case("four_of_six", "PqNoQuorum", TEST_CHAIN_ID, sigs(&[0, 1, 2, 3], &m)),
        case("empty", "PqNoQuorum", TEST_CHAIN_ID, vec![]),
        case("repeated_index", "PqIndexOrder", TEST_CHAIN_ID, sigs(&[0, 1, 2, 3, 3], &m)),
        case("descending_indices", "PqIndexOrder", TEST_CHAIN_ID, sigs(&[4, 3, 2, 1, 0], &m)),
        case("index_out_of_range", "PqIndexOutOfRange", TEST_CHAIN_ID, {
            let mut l = sigs(&[0, 1, 2, 3], &m);
            l.push(json!({ "index": 6, "signature": sig(5, &m) }));
            l
        }),
        case("signature_one_byte_short", "PqBadSignatureLength", TEST_CHAIN_ID, short),
        case("signature_filed_under_the_wrong_index", "PqBadSignature", TEST_CHAIN_ID, wrong_index),
        case("signed_for_another_chain_id", "PqBadSignature", TEST_CHAIN_ID + 1, sigs(&[0, 1, 2, 3, 4], &m)),
        case("signed_over_another_mu", "PqBadSignature", TEST_CHAIN_ID, sigs(&[0, 1, 2, 3, 4], &message(TEST_CHAIN_ID, &other_mu))),
    ];

    // The Rand-only governance messages (spec §8): fixed big-endian layouts,
    // written out here by hand so the daemons' builders are checked against
    // an independent construction.
    let gov = |domain: &[u8], nonce: u64, tail: &[u8]| {
        let mut m = domain.to_vec();
        m.extend_from_slice(&TEST_CHAIN_ID.to_be_bytes());
        m.extend_from_slice(&nonce.to_be_bytes());
        m.extend_from_slice(tail);
        m
    };
    let usdt: [u8; 32] = {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&hex::decode("dac17f958d2ee523a2206206994597c13d831ec7").unwrap());
        w
    };
    let sol_usdc: [u8; 32] = hex::decode("c6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d61").unwrap().try_into().unwrap();
    let mut register_tail = vec![4u8];
    register_tail.extend_from_slice(b"zUSD");
    register_tail.push(4);
    register_tail.extend_from_slice(b"zUSD");
    register_tail.extend_from_slice(&[0x5a; 32]); // salt
    register_tail.extend_from_slice(&2u16.to_be_bytes());
    register_tail.extend_from_slice(&usdt);
    register_tail.push(6);
    let mut list_tail = 1u32.to_be_bytes().to_vec();
    list_tail.extend_from_slice(&5u16.to_be_bytes());
    list_tail.extend_from_slice(&sol_usdc);
    list_tail.push(6);
    let pause_seed = keccak256(b"rand-bridge-pq-test-pause-key");
    let pause_key = dilithium2::Keypair::generate(Some(&pause_seed)).expect("seed");
    let pause_m = gov(b"rand-bridge-pause-1", 0, &[]);
    let quorum_over = |m: &[u8]| sigs(&[0, 1, 2, 3, 4], m);
    let register_m = gov(b"rand-bridge-pq-register-1", 0, &register_tail);
    let list_m = gov(b"rand-bridge-pq-list-1", 1, &list_tail);
    let unpause_m = gov(b"rand-bridge-pq-unpause-1", 1, &[]);
    let governance = json!({
        "register": { "list_nonce": 0, "name": "zUSD", "symbol": "zUSD", "salt": hex::encode([0x5a; 32]),
                      "chain": 2, "token": hex::encode(usdt), "decimals": 6,
                      "message": hex::encode(&register_m), "pq_signatures": quorum_over(&register_m) },
        "list": { "list_nonce": 1, "token_index": 1, "chain": 5, "token": hex::encode(sol_usdc), "decimals": 6,
                  "message": hex::encode(&list_m), "pq_signatures": quorum_over(&list_m) },
        "unpause": { "pause_nonce": 1, "message": hex::encode(&unpause_m), "pq_signatures": quorum_over(&unpause_m) },
        "pause": { "pause_nonce": 0, "pause_key_seed": hex::encode(pause_seed),
                   "pause_key": hex::encode(pause_key.public.to_bytes()),
                   "message": hex::encode(&pause_m), "signature": hex::encode(pause_key.sign(&pause_m)) },
    });

    let guardians: Vec<Value> = (0..N as u8)
        .map(|i| json!({ "index": i, "seed": hex::encode(seed(i)), "public_key": hex::encode(keypair(i).public.to_bytes()) }))
        .collect();
    let file = json!({
        "spec": "spec/PQ-COSIGNATURE.md",
        "scheme": "Dilithium2 (round 3), crystals-dilithium 2.0 `dilithium2`, deterministic signing",
        "domain": String::from_utf8_lossy(DOMAIN),
        "rand_chain_id": TEST_CHAIN_ID,
        "quorum": N * 2 / 3 + 1,
        "pq_guardians": guardians,
        "bodies": bodies,
        "cases": cases,
        "governance": governance,
    });
    let mut out = serde_json::to_string_pretty(&file).expect("json");
    out.push('\n');
    out
}

fn main() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/pq-cosignatures.json");
    let rendered = render();
    if std::env::args().any(|a| a == "--check") {
        let on_disk = fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        assert!(on_disk == rendered, "{} is not what the generator produces", path.display());
        println!("OK: {} matches the generator", path.display());
        return;
    }
    fs::write(&path, rendered).unwrap_or_else(|e| panic!("writing {}: {e}", path.display()));
    println!("wrote {}", path.display());
}
