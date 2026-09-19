//! `vectors/pq-cosignatures.json` against the daemons' PQ code: the same file
//! the fullnode tests its ledger rules against (`spec/PQ-COSIGNATURE.md` §7).

use bridge_daemons::pq::{self, PqError, PqKey, PqSignature};
use serde_json::Value;

fn file() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../vectors/pq-cosignatures.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("pq vectors")).expect("json")
}

fn mu(v: &Value) -> [u8; 32] {
    hex::decode(v.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn list(v: &Value) -> Vec<PqSignature> {
    serde_json::from_value(v.clone()).expect("pq_signatures")
}

fn guardians(f: &Value) -> Vec<Vec<u8>> {
    f["pq_guardians"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| hex::decode(g["public_key"].as_str().unwrap()).unwrap())
        .collect()
}

#[test]
fn keys_and_signatures_reproduce_byte_for_byte() {
    let f = file();
    let chain_id = f["rand_chain_id"].as_u64().unwrap();
    let keys: Vec<PqKey> = f["pq_guardians"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| PqKey::from_seed_hex(g["seed"].as_str().unwrap()).unwrap())
        .collect();
    for (key, g) in keys.iter().zip(f["pq_guardians"].as_array().unwrap()) {
        assert_eq!(
            hex::encode(key.public_key()),
            g["public_key"].as_str().unwrap()
        );
        assert_eq!(key.public_key().len(), pq::PUBLIC_KEY_LEN);
    }
    for body in f["bodies"].as_array().unwrap() {
        let mu = mu(&body["mu"]);
        assert_eq!(
            hex::encode(pq::message(chain_id, &mu)),
            body["message"].as_str().unwrap()
        );
        for s in list(&body["pq_signatures"]) {
            let signed = keys[usize::from(s.index)].sign(chain_id, &mu);
            assert_eq!(
                hex::encode(&signed),
                s.signature,
                "{} index {}",
                body["attestation_vector"],
                s.index
            );
        }
    }
}

#[test]
fn every_case_gets_the_ledgers_verdict() {
    let f = file();
    let guardians = guardians(&f);
    for case in f["cases"].as_array().unwrap() {
        let verdict = pq::check(
            &list(&case["pq_signatures"]),
            &guardians,
            case["rand_chain_id"].as_u64().unwrap(),
            &mu(&case["mu"]),
        );
        let expected = match case["expect"].as_str().unwrap() {
            "ok" => Ok(()),
            "PqNoQuorum" => Err(PqError::PqNoQuorum),
            "PqIndexOrder" => Err(PqError::PqIndexOrder),
            "PqIndexOutOfRange" => Err(PqError::PqIndexOutOfRange),
            "PqBadSignatureLength" => Err(PqError::PqBadSignatureLength),
            "PqBadSignature" => Err(PqError::PqBadSignature),
            other => panic!("unknown verdict {other}"),
        };
        assert_eq!(verdict, expected, "{}", case["name"]);
    }
}

#[test]
fn assembly_keeps_exactly_a_verified_quorum() {
    let f = file();
    let guardians = guardians(&f);
    let chain_id = f["rand_chain_id"].as_u64().unwrap();
    let body = &f["bodies"][0];
    let mu = mu(&body["mu"]);
    let all: Vec<(u8, Vec<u8>)> = list(&body["pq_signatures"])
        .into_iter()
        .map(|s| (s.index, hex::decode(s.signature).unwrap()))
        .collect();

    let quorum = pq::assemble(&all, &guardians, chain_id, &mu).expect("six make a quorum");
    assert_eq!(
        quorum.iter().map(|s| s.index).collect::<Vec<_>>(),
        vec![0, 1, 2, 3, 4]
    );
    assert_eq!(pq::check(&quorum, &guardians, chain_id, &mu), Ok(()));

    // A co-signature that does not verify is dropped, not submitted.
    let mut tampered = all.clone();
    tampered[1].1[10] ^= 1;
    let quorum = pq::assemble(&tampered, &guardians, chain_id, &mu).expect("five good ones remain");
    assert_eq!(
        quorum.iter().map(|s| s.index).collect::<Vec<_>>(),
        vec![0, 2, 3, 4, 5]
    );
    assert!(pq::assemble(&all[..4], &guardians, chain_id, &mu).is_none());
    // Under another chain id nothing verifies.
    assert!(pq::assemble(&all, &guardians, chain_id + 1, &mu).is_none());
}

/// Guardian to relayer, end to end: six guardians sign a deposit and a burn;
/// the deposit carries co-signatures, the burn does not; the relayer files
/// each co-signature under its guardian's ECDSA index and keeps a quorum.
#[test]
fn guardians_cosign_deposits_only_and_the_relayer_assembles_the_pq_quorum() {
    use bridge_codec::Attestation;
    use bridge_daemons::api::{Collected, SignedMessage, SIGNED};
    use bridge_daemons::crypto::GuardianKey;
    use bridge_daemons::guardian::{sign_one, PqSigner};
    use bridge_daemons::message::{Emitters, Observed};
    use bridge_daemons::relayer::{assemble_pq, GuardianSet};
    use bridge_daemons::store::Store;

    let f = file();
    let chain_id = f["rand_chain_id"].as_u64().unwrap();
    let att: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../vectors/attestations.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let unhex = |v: &Value| hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap();
    let emitters = Emitters {
        rand: unhex(&att["rand_emitter"]).try_into().unwrap(),
        endpoints: att["emitters"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(c, e)| (c.parse().unwrap(), unhex(e).try_into().unwrap()))
            .collect(),
    };
    let body_of = |name: &str| {
        let v = att["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == name)
            .unwrap();
        Observed::new(
            Attestation::body_bytes(&unhex(&v["attestation"]))
                .unwrap()
                .to_vec(),
        )
        .unwrap()
    };
    let deposit = body_of("transfer_eth_usdt_6dp_ok");
    let burn = body_of("release_to_eth_ok");

    let tmp = tempfile::tempdir().unwrap();
    let mut collected = Vec::new();
    let mut keys = Vec::new();
    for (i, g) in att["guardians"].as_array().unwrap().iter().enumerate() {
        let key = GuardianKey::from_hex(g["secret"].as_str().unwrap()).unwrap();
        let pq = PqSigner {
            key: PqKey::from_seed_hex(f["pq_guardians"][i]["seed"].as_str().unwrap()).unwrap(),
            rand_chain_id: chain_id,
        };
        let store = Store::open(&tmp.path().join(i.to_string())).unwrap();
        assert!(sign_one(&store, &key, Some(&pq), &emitters, &deposit).unwrap());
        assert!(sign_one(&store, &key, Some(&pq), &emitters, &burn).unwrap());

        let d: SignedMessage = store
            .read_message(SIGNED, deposit.emitter_chain, deposit.sequence)
            .unwrap()
            .unwrap();
        let b: SignedMessage = store
            .read_message(SIGNED, burn.emitter_chain, burn.sequence)
            .unwrap()
            .unwrap();
        assert!(b.pq_signature.is_none(), "a release stays classical");
        let pq_signature = hex::decode(d.pq_signature.expect("a deposit is co-signed")).unwrap();
        assert_eq!(pq_signature.len(), pq::SIGNATURE_LEN);
        collected.push(Collected {
            address: key.address(),
            signature: d.signature,
            pq_signature: Some(pq_signature),
        });
        keys.push(key.address());
    }

    let set = GuardianSet {
        index: 0,
        keys,
        pq_keys: guardians(&f),
        rand_chain_id: Some(chain_id),
    };
    let quorum = assemble_pq(&deposit, &set, &collected).expect("a PQ quorum");
    assert_eq!(quorum.len(), 5);
    assert_eq!(
        pq::check(&quorum, &set.pq_keys, chain_id, &deposit.digest),
        Ok(())
    );
    // What the wallet will read from `--pq @file`.
    let json = serde_json::to_string(&quorum).unwrap();
    assert!(json.starts_with("[{\"index\":0,\"signature\":\""));
    // The PQ set need not be aligned with the ECDSA set (chain 14 starts with
    // `guardians` at set 0 and `pq_guardians` owned by set 1's operators):
    // each co-signature is filed under the PQ key it verifies with.
    let mut misaligned = GuardianSet {
        index: 0,
        keys: set.keys.clone(),
        pq_keys: set.pq_keys.clone(),
        rand_chain_id: Some(chain_id),
    };
    misaligned.keys.reverse();
    let quorum = assemble_pq(&deposit, &misaligned, &collected).expect("still a PQ quorum");
    assert_eq!(
        pq::check(&quorum, &misaligned.pq_keys, chain_id, &deposit.digest),
        Ok(())
    );
    let strangers = GuardianSet {
        index: 0,
        keys: vec![[9u8; 20]; 6],
        pq_keys: set.pq_keys.clone(),
        rand_chain_id: Some(chain_id),
    };
    assert!(
        assemble_pq(&deposit, &strangers, &collected).is_some(),
        "ECDSA membership is the attestation's business, not the PQ quorum's"
    );

    // One guardian short of five co-signatures: no quorum, nothing submitted.
    assert!(assemble_pq(&deposit, &set, &collected[..4]).is_none());
}
