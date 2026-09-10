//! Cross-chain conformance: the Solana verifier must agree, vector for
//! vector, with the Rust reference verifier in `shrugg-core` and with the
//! Solidity verifier, over the shared `vectors/attestations.json`.
//!
//! Only signature-level `expect` codes are asserted here; ledger-level
//! codes (`wrong_emitter`, `replay`, `fee_exceeds_amount`, ...) belong to
//! the processor tests in later tasks.

use rand_bridge::attestation::verify;
use rand_bridge::error::BridgeError;
use rand_bridge::state::GuardianSetAccount;
use serde_json::Value;

/// The shared vectors, baked in at compile time so the test needs no
/// working-directory assumptions.
const VECTORS: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../vectors/attestations.json"));

/// Decodes hex that may or may not carry a `0x` prefix.
fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.trim_start_matches("0x")).expect("valid hex")
}

/// Resolves the guardian set with `index` out of a vector's `sets` array,
/// mirroring what the processor does when it derives the `guardian` PDA:
/// `None` means "no such guardian set", i.e. `UnknownGuardianSet`.
fn resolve_set(sets: &[Value], index: u32) -> Option<GuardianSetAccount> {
    let set = sets
        .iter()
        .find(|s| s["index"].as_u64().expect("set index") as u32 == index)?;
    let keys = set["keys"]
        .as_array()
        .expect("keys array")
        .iter()
        .map(|k| {
            let bytes = unhex(k.as_str().expect("key hex"));
            <[u8; 20]>::try_from(&bytes[..]).expect("20-byte guardian key")
        })
        .collect();
    Some(GuardianSetAccount {
        index,
        keys,
        expiration_time: set["expires_at"].as_u64().expect("expires_at"),
    })
}

#[test]
fn shared_vectors_match_verify() {
    let file: Value = serde_json::from_str(VECTORS).expect("vectors.json parses");
    let now = file["now"].as_u64().expect("now");

    const SIGNATURE_LEVEL: &[&str] = &[
        "ok",
        "no_quorum",
        "index_order",
        "index_out_of_range",
        "high_s",
        "wrong_guardian",
        "bad_version",
        "set_expired",
        "unknown_set",
    ];

    let mut checked = 0usize;
    for v in file["vectors"].as_array().expect("vectors array") {
        let name = v["name"].as_str().expect("name");
        let expect = v["expect"].as_str().expect("expect");
        if !SIGNATURE_LEVEL.contains(&expect) {
            continue;
        }
        checked += 1;

        let bytes = unhex(v["attestation"].as_str().expect("attestation"));
        let index = v["guardian_set_index"].as_u64().expect("guardian_set_index") as u32;
        let sets = v["sets"].as_array().expect("sets array");

        if expect == "unknown_set" {
            assert!(
                resolve_set(sets, index).is_none(),
                "{name}: expected no guardian set at index {index}"
            );
            continue;
        }

        let set = resolve_set(sets, index)
            .unwrap_or_else(|| panic!("{name}: missing guardian set {index}"));
        let result = verify(&bytes, &set, now);

        match expect {
            "ok" => {
                let (_, digest) =
                    result.unwrap_or_else(|e| panic!("{name}: expected ok, got {e:?}"));
                assert_eq!(
                    hex::encode(digest),
                    v["digest"].as_str().expect("digest").trim_start_matches("0x"),
                    "{name}: digest mismatch"
                );
            }
            "no_quorum" => assert_eq!(result.unwrap_err(), BridgeError::NoQuorum, "{name}"),
            "index_order" => assert_eq!(result.unwrap_err(), BridgeError::IndexOrder, "{name}"),
            "index_out_of_range" => {
                assert_eq!(result.unwrap_err(), BridgeError::IndexOutOfRange, "{name}")
            }
            "high_s" => assert_eq!(result.unwrap_err(), BridgeError::HighS, "{name}"),
            "wrong_guardian" => {
                assert_eq!(result.unwrap_err(), BridgeError::WrongGuardian, "{name}")
            }
            "bad_version" => assert_eq!(result.unwrap_err(), BridgeError::BadVersion, "{name}"),
            "set_expired" => {
                assert_eq!(result.unwrap_err(), BridgeError::GuardianSetExpired, "{name}")
            }
            other => panic!("{name}: unhandled expect {other}"),
        }
    }

    assert!(
        checked >= 10,
        "expected at least 10 signature-level vectors, checked {checked}"
    );
}

/// The `ok` vectors must not be accepted by a *different* guardian set:
/// a set of the same size holding foreign keys has to fail closed.
#[test]
fn tampered_guardian_set_rejects_good_attestations() {
    let file: Value = serde_json::from_str(VECTORS).expect("vectors.json parses");
    let now = file["now"].as_u64().expect("now");
    let mut checked = 0usize;
    for v in file["vectors"].as_array().expect("vectors array") {
        if v["expect"].as_str() != Some("ok") {
            continue;
        }
        let index = v["guardian_set_index"].as_u64().expect("guardian_set_index") as u32;
        let mut set = match resolve_set(v["sets"].as_array().expect("sets"), index) {
            Some(s) => s,
            None => continue,
        };
        for key in set.keys.iter_mut() {
            *key = [0xaa; 20];
        }
        let bytes = unhex(v["attestation"].as_str().expect("attestation"));
        assert_eq!(
            verify(&bytes, &set, now).unwrap_err(),
            BridgeError::WrongGuardian,
            "{}: tampered set accepted",
            v["name"].as_str().unwrap_or("?")
        );
        checked += 1;
    }
    assert!(checked > 0, "no ok vectors exercised");
}
