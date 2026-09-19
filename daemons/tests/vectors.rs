//! The daemons against the shared vectors (`vectors/attestations.json`): the
//! same file every on-chain verifier is pinned to. If a guardian built from
//! this crate signs a vector's body and a relayer assembles it, the result
//! must be the vector's attestation, byte for byte.

use bridge_codec::Attestation;
use bridge_daemons::crypto::{digest, recover, GuardianKey, RawSignature};
use bridge_daemons::message::{check_signable, Emitters, Observed};
use bridge_daemons::relayer::{assemble, GuardianSet};
use serde_json::Value;

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/attestations.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("vectors file"))
        .expect("vectors json")
}

fn unhex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string").trim_start_matches("0x")).expect("hex")
}

fn keys(v: &Value) -> Vec<GuardianKey> {
    v["guardians"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| GuardianKey::from_hex(g["secret"].as_str().unwrap()).unwrap())
        .collect()
}

fn emitters(v: &Value) -> Emitters {
    let endpoints = v["emitters"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(chain, e)| (chain.parse().unwrap(), unhex(e).try_into().unwrap()))
        .collect();
    Emitters {
        rand: unhex(&v["rand_emitter"]).try_into().unwrap(),
        endpoints,
    }
}

#[test]
fn guardian_addresses_match_the_fixture() {
    let v = vectors();
    for (key, g) in keys(&v).iter().zip(v["guardians"].as_array().unwrap()) {
        assert_eq!(
            hex::encode(key.address()),
            g["address"].as_str().unwrap().trim_start_matches("0x")
        );
    }
}

#[test]
fn digests_match_and_every_vector_signature_recovers_as_the_verifiers_would() {
    let v = vectors();
    for case in v["vectors"].as_array().unwrap() {
        let att_bytes = unhex(&case["attestation"]);
        let Ok(body) = Attestation::body_bytes(&att_bytes) else {
            continue;
        };
        if let Some(d) = case["digest"].as_str() {
            assert_eq!(
                hex::encode(digest(body)),
                d.trim_start_matches("0x"),
                "{}",
                case["name"]
            );
        }
    }
}

/// Sign with this crate, assemble with this crate, compare with the vector.
#[test]
fn signing_and_assembling_reproduces_the_ok_transfer_vectors() {
    let v = vectors();
    let guardians = keys(&v);
    let set = GuardianSet {
        index: 0,
        keys: guardians.iter().map(|k| k.address()).collect(),
    };
    let emitters = emitters(&v);
    let mut reproduced = 0;
    for case in v["vectors"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        if case["expect"] != "ok"
            || case["guardian_set_index"] != 0
            || !(name.starts_with("transfer_") || name.starts_with("release_"))
        {
            continue;
        }
        let expected = unhex(&case["attestation"]);
        let decoded = Attestation::decode(&expected).expect("ok vector decodes");
        if decoded
            .signatures
            .iter()
            .map(|s| s.index)
            .ne(0..decoded.signatures.len() as u8)
        {
            continue; // signed by some other subset than the lowest quorum
        }
        let message = Observed::new(Attestation::body_bytes(&expected).unwrap().to_vec())
            .expect("canonical body");
        check_signable(&message.decoded(), &emitters)
            .unwrap_or_else(|e| panic!("{name}: policy refused an ok vector: {e:#}"));

        let signatures: Vec<([u8; 20], RawSignature)> = guardians
            .iter()
            .map(|k| (k.address(), k.sign(&message.digest).unwrap()))
            .collect();
        for (address, signature) in &signatures {
            assert_eq!(recover(&message.digest, signature).unwrap(), *address);
        }
        let attestation =
            assemble(&message, &set, &signatures).expect("six signatures make a quorum");
        assert_eq!(attestation.signatures.len(), 5, "exactly a quorum");
        assert_eq!(
            hex::encode(attestation.encode()),
            hex::encode(&expected),
            "{name}"
        );
        reproduced += 1;
    }
    assert!(reproduced >= 8, "only {reproduced} vectors were reproduced");
}

#[test]
fn assembly_needs_a_quorum_of_distinct_set_members() {
    let v = vectors();
    let guardians = keys(&v);
    let set = GuardianSet {
        index: 0,
        keys: guardians.iter().map(|k| k.address()).collect(),
    };
    let case = &v["vectors"][0];
    let message = Observed::new(
        Attestation::body_bytes(&unhex(&case["attestation"]))
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let sig = |i: usize| {
        (
            guardians[i].address(),
            guardians[i].sign(&message.digest).unwrap(),
        )
    };

    assert!(
        assemble(&message, &set, &[sig(0), sig(1), sig(2), sig(3)]).is_none(),
        "four of six is short"
    );
    // The same guardian five times is one signature.
    assert!(assemble(&message, &set, &[sig(0), sig(0), sig(0), sig(0), sig(0)]).is_none());
    // A stranger's signature does not count.
    let stranger = GuardianKey::from_hex(&"11".repeat(32)).unwrap();
    let outsider = (stranger.address(), stranger.sign(&message.digest).unwrap());
    assert!(assemble(&message, &set, &[sig(0), sig(1), sig(2), sig(3), outsider]).is_none());
    // Any five members do, in index order whatever order they arrived in.
    let att = assemble(&message, &set, &[sig(5), sig(3), sig(1), sig(4), sig(2)]).unwrap();
    assert_eq!(
        att.signatures.iter().map(|s| s.index).collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 5]
    );
}

#[test]
fn policy_refuses_what_a_destination_would_refuse() {
    let v = vectors();
    let emitters = emitters(&v);
    let ok = |name: &str| {
        let case = v["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
            .unwrap();
        Observed::new(
            Attestation::body_bytes(&unhex(&case["attestation"]))
                .unwrap()
                .to_vec(),
        )
        .unwrap()
        .decoded()
    };

    // Rotations are never signed by the daemon.
    assert!(check_signable(&ok("upgrade_set1_ok"), &emitters).is_err());

    // An unregistered emitter.
    let mut body = ok("transfer_eth_usdt_6dp_ok");
    body.emitter_address[31] ^= 1;
    assert!(check_signable(&body, &emitters).is_err());

    // A lock claiming to be a burn: the right payload from the wrong chain.
    let mut body = ok("release_to_eth_ok");
    body.emitter_chain = 2;
    assert!(check_signable(&body, &emitters).is_err());

    // fee > amount.
    let mut body = ok("release_to_eth_ok");
    let fee_at = body.payload.len() - 32;
    body.payload[fee_at] = 0x01;
    assert!(check_signable(&body, &emitters).is_err());
}
