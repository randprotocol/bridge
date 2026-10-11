//! The store, the guardian's signature API, the guardian loop and the
//! relayer's quorum logic, end to end over loopback.

mod common;

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;

use bridge_codec::{Body, GuardianSetUpgrade, Payload};
use bridge_daemons::api::{self, GuardianClient, SignedMessage};
use bridge_daemons::config::EvmKind;
use bridge_daemons::crypto::{GuardianKey, RawSignature};
use bridge_daemons::guardian::{self, Equivocation, PqSigner, Refused};
use bridge_daemons::message::{Emitters, Observed};
use bridge_daemons::pq::PqKey;
use bridge_daemons::relayer::{self, Destinations, EndpointSubmitter, GuardianSet, Progress};
use bridge_daemons::sources::{Cursor, Source};
use bridge_daemons::store::Store;
use bridge_daemons::submit::evm::EvmSubmitter;
use bridge_daemons::submit::process::{RandSubmitter, SolanaSubmitter};
use bridge_daemons::submit::Outcome;
use common::*;
use serde_json::json;

fn store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("data")).unwrap();
    (dir, store)
}

const ETH_CONTRACT: &str = "0x1111111111111111111111111111111111111111";

fn emitters() -> Emitters {
    Emitters { rand: RAND_EMITTER, endpoints: vec![(2, word(ETH_CONTRACT))] }
}

/// A lock on Ethereum minted on Rand to `recipient`.
fn eth_lock(sequence: u64, recipient: [u8; 32]) -> Observed {
    lock(2, word(ETH_CONTRACT), sequence, recipient)
}

// ---- store.rs ---------------------------------------------------------------

#[test]
fn the_store_round_trips_and_leaves_no_temp_files() {
    let (dir, store) = store();
    assert_eq!(store.read::<Vec<u32>>(&["a", "b.json"]).unwrap(), None);
    store.write(&["a", "b.json"], &vec![1u32, 2, 3]).unwrap();
    store.write(&["a", "b.json"], &vec![4u32]).unwrap();
    assert_eq!(store.read::<Vec<u32>>(&["a", "b.json"]).unwrap(), Some(vec![4]));
    let names: Vec<_> = std::fs::read_dir(dir.path().join("data/a")).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(names, vec![std::ffi::OsString::from("b.json")], "the temp file was renamed away");
}

#[test]
fn a_corrupt_file_is_an_error_naming_the_file() {
    let (dir, store) = store();
    std::fs::create_dir_all(dir.path().join("data/a")).unwrap();
    std::fs::write(dir.path().join("data/a/b.json"), "{not json").unwrap();
    let err = format!("{:#}", store.read::<Vec<u32>>(&["a", "b.json"]).unwrap_err());
    assert!(err.contains("parsing") && err.contains("b.json"), "{err}");
}

#[test]
fn a_file_where_a_directory_belongs_is_an_error_not_a_none() {
    let (dir, store) = store();
    std::fs::write(dir.path().join("data/a"), "x").unwrap();
    assert!(store.write(&["a", "b.json"], &1u32).is_err());
    assert!(store.sequences("a", 1).is_err() || store.sequences("a", 1).unwrap().is_empty());
    assert!(Store::open(&dir.path().join("data/a/inside")).is_err(), "cannot create a root under a file");
}

#[test]
fn cursors_are_kept_per_source() {
    let (_dir, store) = store();
    assert_eq!(store.cursor("eth").unwrap(), None);
    store.set_cursor("eth", &Cursor { next_block: 9, next_sequence: 2 }).unwrap();
    store.set_cursor("bsc", &Cursor { next_block: 1, next_sequence: 0 }).unwrap();
    assert_eq!(store.cursor("eth").unwrap(), Some(Cursor { next_block: 9, next_sequence: 2 }));
    assert_eq!(store.cursor("bsc").unwrap().unwrap().next_block, 1);
}

#[test]
fn messages_live_at_kind_chain_zero_padded_sequence() {
    assert_eq!(Store::message_parts("signed", 2, 17), ["signed".to_string(), "2".to_string(), "00000000000000000017.json".to_string()]);
    let (dir, store) = store();
    store.write_message("signed", 2, 17, &"x".to_string()).unwrap();
    assert!(dir.path().join("data/signed/2/00000000000000000017.json").exists());
    assert_eq!(store.read_message::<String>("signed", 2, 17).unwrap().as_deref(), Some("x"));
    assert_eq!(store.read_message::<String>("signed", 2, 18).unwrap(), None);
}

#[test]
fn sequences_are_listed_ascending_and_ignore_strays() {
    let (dir, store) = store();
    assert_eq!(store.sequences("signed", 2).unwrap(), Vec::<u64>::new(), "no directory is no messages");
    for seq in [10u64, 2, 300] {
        store.write_message("signed", 2, seq, &seq).unwrap();
    }
    let chain_dir = dir.path().join("data/signed/2");
    std::fs::write(chain_dir.join("notes.txt"), "").unwrap();
    std::fs::write(chain_dir.join("abc.json"), "").unwrap();
    assert_eq!(store.sequences("signed", 2).unwrap(), vec![2, 10, 300]);
    assert_eq!(store.sequences("signed", 3).unwrap(), Vec::<u64>::new());
}

// ---- api.rs -----------------------------------------------------------------

/// Serves `store` as a guardian with `key`, returning a client for it.
async fn serve(store: &Store, key: &GuardianKey) -> (GuardianClient, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let router = api::router(store.clone(), key.address());
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (GuardianClient::new(&format!("{origin}/")), origin)
}

#[tokio::test]
async fn the_api_serves_health_and_what_was_signed() {
    let (_dir, store) = store();
    let key = &guardian_keys(1)[0];
    let (client, origin) = serve(&store, key).await;
    assert_eq!(client.origin(), origin, "a trailing slash is trimmed");

    let health: api::Health = reqwest::get(format!("{origin}/v1/health")).await.unwrap().json().await.unwrap();
    assert_eq!(health.guardian, hex::encode(key.address()));

    let message = burn(0, 2, 50_000_000, 0);
    assert!(client.signature(&message).await.unwrap().is_none(), "404 is not yet signed");
    assert!(guardian::sign_one(&store, key, None, &emitters(), &message).unwrap());
    let found = client.signature(&message).await.unwrap().expect("signed");
    assert_eq!(found.address, key.address());
    assert_eq!(found.signature, key.sign(&message.digest).unwrap());
    assert!(found.pq_signature.is_none());

    // The raw route.
    let raw: SignedMessage = reqwest::get(format!("{origin}/v1/signature/1/0")).await.unwrap().json().await.unwrap();
    assert_eq!(raw.message, message);
    assert_eq!(reqwest::get(format!("{origin}/v1/signature/1/99")).await.unwrap().status(), 404);
    assert_eq!(reqwest::get(format!("{origin}/v1/signature/x/0")).await.unwrap().status(), 400);
}

#[tokio::test]
async fn an_unreadable_signature_file_is_a_500_not_a_404() {
    let (dir, store) = store();
    let key = &guardian_keys(1)[0];
    let (client, origin) = serve(&store, key).await;
    std::fs::create_dir_all(dir.path().join("data/signed/1")).unwrap();
    std::fs::write(dir.path().join("data/signed/1/00000000000000000000.json"), "garbage").unwrap();
    assert_eq!(reqwest::get(format!("{origin}/v1/signature/1/0")).await.unwrap().status(), 500);
    assert!(client.signature(&burn(0, 2, 1, 0)).await.is_err());
}

/// A fake guardian answering every signature request with `signed`.
fn lying_guardian(signed: SignedMessage) -> (GuardianClient, Fake) {
    let fake = http(move |_| (200, serde_json::to_string(&signed).unwrap()));
    (GuardianClient::new(&fake.url), fake)
}

#[tokio::test]
async fn nothing_a_guardian_says_is_taken_on_trust() {
    let key = &guardian_keys(1)[0];
    let message = burn(0, 2, 50_000_000, 0);
    let honest = SignedMessage {
        message: message.clone(),
        guardian: hex::encode(key.address()),
        signature: key.sign(&message.digest).unwrap(),
        pq_signature: Some("0a0b".into()),
    };
    let (client, _fake) = lying_guardian(honest.clone());
    let found = client.signature(&message).await.unwrap().unwrap();
    assert_eq!(found.pq_signature, Some(vec![0x0a, 0x0b]));

    // Not valid hex: dropped, not fatal.
    let (client, _fake) = lying_guardian(SignedMessage { pq_signature: Some("zz".into()), ..honest.clone() });
    assert_eq!(client.signature(&message).await.unwrap().unwrap().pq_signature, None);

    // A different body under the same sequence.
    let other = burn(0, 2, 49_000_000, 0);
    let (client, _fake) = lying_guardian(SignedMessage { message: other, ..honest.clone() });
    let err = client.signature(&message).await.err().expect("refused").to_string();
    assert!(err.contains("signed a different body"), "{err}");

    // A signature that is not low-s, or has a bad recovery id, is refused by the same rules as on-chain.
    let (client, _fake) = lying_guardian(SignedMessage { signature: RawSignature { v: 2, ..honest.signature.clone() }, ..honest.clone() });
    assert!(client.signature(&message).await.err().expect("refused").to_string().contains("recovery id"));
    let mut high = honest.signature.clone();
    high.s = [0xff; 32];
    let (client, _fake) = lying_guardian(SignedMessage { signature: high, ..honest.clone() });
    assert!(client.signature(&message).await.err().expect("refused").to_string().contains("high-s"));

    // A signature that recovers to someone else is still returned, under that other address:
    // the relayer's quorum logic only counts addresses in the set.
    let intruder = &guardian_keys(2)[1];
    let (client, _fake) = lying_guardian(SignedMessage { signature: intruder.sign(&message.digest).unwrap(), ..honest });
    assert_eq!(client.signature(&message).await.unwrap().unwrap().address, intruder.address());

    // A 500 or an unreachable guardian is an error.
    let down = http(|_| (500, String::new()));
    assert!(GuardianClient::new(&down.url).signature(&message).await.is_err());
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    assert!(GuardianClient::new(&format!("http://127.0.0.1:{port}")).signature(&message).await.is_err());
}

// ---- guardian.rs ------------------------------------------------------------

struct Script {
    name: String,
    start: Cursor,
    batches: std::sync::Mutex<Vec<anyhow::Result<(Vec<Observed>, Cursor)>>>,
}

impl Source for Script {
    fn name(&self) -> &str {
        &self.name
    }
    fn start(&self) -> Cursor {
        self.start.clone()
    }
    async fn poll(&self, _cursor: &Cursor) -> anyhow::Result<(Vec<Observed>, Cursor)> {
        self.batches.lock().unwrap().remove(0)
    }
}

fn script(batches: Vec<anyhow::Result<(Vec<Observed>, Cursor)>>) -> Script {
    Script { name: "script".into(), start: Cursor { next_block: 5, next_sequence: 0 }, batches: std::sync::Mutex::new(batches) }
}

#[tokio::test]
async fn a_guardian_step_signs_what_the_policy_allows_and_moves_the_cursor_after() {
    let (_dir, store) = store();
    let key = &guardian_keys(1)[0];
    let good = burn(0, 2, 50_000_000, 0);
    let bad = burn(1, 2, 0, 0); // zero amount
    let next = Cursor { next_block: 6, next_sequence: 2 };
    let source = script(vec![Ok((vec![good.clone(), bad.clone()], next.clone())), Ok((vec![], next.clone()))]);

    assert_eq!(guardian::step(&source, &store, key, None, &emitters()).await.unwrap(), 1);
    assert_eq!(store.cursor("script").unwrap(), Some(next.clone()));
    let signed: SignedMessage = store.read_message(api::SIGNED, 1, 0).unwrap().unwrap();
    assert_eq!(signed.guardian, hex::encode(key.address()));
    assert_eq!(bridge_daemons::crypto::recover(&good.digest, &signed.signature).unwrap(), key.address());
    let refused: Refused = store.read_message(guardian::REFUSED, 1, 1).unwrap().unwrap();
    assert_eq!(refused.message, bad);
    assert_eq!(refused.reason, "zero amount");
    assert!(store.read_message::<SignedMessage>(api::SIGNED, 1, 1).unwrap().is_none(), "nothing is signed for a refused message");

    // Nothing new: nothing signed, cursor unchanged.
    assert_eq!(guardian::step(&source, &store, key, None, &emitters()).await.unwrap(), 0);
}

#[tokio::test]
async fn a_failing_source_leaves_the_cursor_where_it_was() {
    let (_dir, store) = store();
    let key = &guardian_keys(1)[0];
    let source = script(vec![Err(anyhow::anyhow!("rpc down"))]);
    assert!(guardian::step(&source, &store, key, None, &emitters()).await.is_err());
    assert_eq!(store.cursor("script").unwrap(), None);
}

#[test]
fn signing_is_idempotent_for_a_body_and_fatal_for_a_second_body() {
    let (_dir, store) = store();
    let key = &guardian_keys(1)[0];
    let message = burn(0, 2, 50_000_000, 0);
    assert!(guardian::sign_one(&store, key, None, &emitters(), &message).unwrap());
    assert!(!guardian::sign_one(&store, key, None, &emitters(), &message).unwrap(), "already signed");

    let forged = burn(0, 2, 49_000_000, 0);
    let err = guardian::sign_one(&store, key, None, &emitters(), &forged).unwrap_err();
    let eq = err.downcast_ref::<Equivocation>().expect("equivocation");
    assert_eq!((eq.chain, eq.sequence), (1, 0));
    assert_eq!(eq.signed, hex::encode(message.digest));
    assert_eq!(eq.observed, hex::encode(forged.digest));
    assert!(err.to_string().contains("equivocation on chain 1 sequence 0"));
}

#[test]
fn a_rotation_is_refused_and_recorded() {
    let (_dir, store) = store();
    let key = &guardian_keys(1)[0];
    let body = Body {
        timestamp: 1,
        nonce: 0,
        emitter_chain: 1,
        emitter_address: RAND_EMITTER,
        sequence: 3,
        consistency_level: 0,
        payload: Payload::GuardianSetUpgrade(GuardianSetUpgrade { new_index: 1, keys: vec![[7; 20]] }).encode(),
    };
    let message = Observed::new(body.encode()).unwrap();
    assert!(!guardian::sign_one(&store, key, None, &emitters(), &message).unwrap());
    let refused: Refused = store.read_message(guardian::REFUSED, 1, 3).unwrap().unwrap();
    assert!(refused.reason.contains("rotations are not signed"), "{}", refused.reason);
}

#[test]
fn only_deposits_addressed_to_rand_get_a_post_quantum_cosignature() {
    let (_dir, store) = store();
    let key = &guardian_keys(1)[0];
    let seed = "07".repeat(32);
    let pq = PqSigner { key: PqKey::from_seed_hex(&seed).unwrap(), rand_chain_id: 14 };

    let deposit = eth_lock(0, [9; 32]);
    assert!(guardian::sign_one(&store, key, Some(&pq), &emitters(), &deposit).unwrap());
    let signed: SignedMessage = store.read_message(api::SIGNED, 2, 0).unwrap().unwrap();
    let co = hex::decode(signed.pq_signature.expect("co-signed")).unwrap();
    assert!(bridge_daemons::pq::verify(&pq.key.public_key(), 14, &deposit.digest, &co));
    assert!(!bridge_daemons::pq::verify(&pq.key.public_key(), 15, &deposit.digest, &co), "bound to the chain id");

    let release = burn(0, 2, 50_000_000, 0);
    assert!(guardian::sign_one(&store, key, Some(&pq), &emitters(), &release).unwrap());
    let signed: SignedMessage = store.read_message(api::SIGNED, 1, 0).unwrap().unwrap();
    assert!(signed.pq_signature.is_none(), "releases stay classical");
}

// ---- relayer.rs: assembly ---------------------------------------------------

fn set_of(keys: &[GuardianKey]) -> GuardianSet {
    GuardianSet { index: 3, keys: keys.iter().map(|k| k.address()).collect(), pq_keys: vec![], rand_chain_id: None }
}

#[test]
fn an_attestation_takes_exactly_a_quorum_lowest_indices_first() {
    let keys = guardian_keys(6); // quorum 5
    let set = set_of(&keys);
    let message = burn(0, 2, 50_000_000, 0);
    let sigs: Vec<_> = keys.iter().map(|k| (k.address(), k.sign(&message.digest).unwrap())).collect();

    assert!(relayer::assemble(&message, &set, &sigs[..4]).is_none());
    let a = relayer::assemble(&message, &set, &sigs).unwrap();
    assert_eq!(a.guardian_set_index, 3);
    assert_eq!(a.signatures.iter().map(|s| s.index).collect::<Vec<_>>(), vec![0, 1, 2, 3, 4]);
    assert_eq!(a.body, message.decoded());

    // Out-of-order input, one duplicate, one stranger: still strictly increasing and a quorum.
    let stranger = GuardianKey::from_hex(&format!("{:064x}", 99)).unwrap();
    let mut shuffled = vec![sigs[5].clone(), sigs[2].clone(), sigs[2].clone(), (stranger.address(), stranger.sign(&message.digest).unwrap())];
    shuffled.extend([sigs[0].clone(), sigs[4].clone(), sigs[3].clone()]);
    let a = relayer::assemble(&message, &set, &shuffled).unwrap();
    assert_eq!(a.signatures.iter().map(|s| s.index).collect::<Vec<_>>(), vec![0, 2, 3, 4, 5]);
    // A stranger and a duplicate do not make a quorum.
    assert!(relayer::assemble(&message, &set, &[sigs[0].clone(), sigs[0].clone(), sigs[1].clone(), sigs[2].clone(), sigs[3].clone()]).is_none());
}

fn collected(key: &GuardianKey, message: &Observed, pq: Option<Vec<u8>>) -> bridge_daemons::api::Collected {
    bridge_daemons::api::Collected { address: key.address(), signature: key.sign(&message.digest).unwrap(), pq_signature: pq }
}

#[test]
fn the_pq_quorum_is_found_under_whatever_index_the_key_sits_at() {
    let keys = guardian_keys(3); // pq quorum of 3 keys is 3
    let pq: Vec<PqKey> = (1..=3u8).map(|i| PqKey::from_seed_hex(&format!("{i:064x}")).unwrap()).collect();
    let mut set = set_of(&keys);
    set.pq_keys = pq.iter().map(|k| k.public_key()).collect();
    let message = eth_lock(0, [9; 32]);

    assert!(relayer::assemble_pq(&message, &set, &[]).is_none(), "no chain id: no PQ quorum");
    set.rand_chain_id = Some(14);
    let cosign = |k: &PqKey| Some(k.sign(14, &message.digest));
    let all = vec![
        collected(&keys[0], &message, cosign(&pq[0])),
        collected(&keys[1], &message, cosign(&pq[1])),
        collected(&keys[2], &message, cosign(&pq[2])),
    ];
    let list = relayer::assemble_pq(&message, &set, &all).expect("quorum");
    assert_eq!(list.iter().map(|s| s.index).collect::<Vec<_>>(), vec![0, 1, 2]);

    // A guardian whose PQ key is not aligned with its ECDSA key (rotation): found by trying each key.
    let swapped = vec![
        collected(&keys[0], &message, cosign(&pq[2])),
        collected(&keys[1], &message, cosign(&pq[0])),
        collected(&keys[2], &message, cosign(&pq[1])),
    ];
    let list = relayer::assemble_pq(&message, &set, &swapped).expect("quorum");
    assert_eq!(list.iter().map(|s| s.index).collect::<Vec<_>>(), vec![0, 1, 2]);

    // Missing, for the wrong chain, or garbage co-signatures do not count.
    let short = vec![
        collected(&keys[0], &message, cosign(&pq[0])),
        collected(&keys[1], &message, None),
        collected(&keys[2], &message, Some(pq[2].sign(15, &message.digest))),
    ];
    assert!(relayer::assemble_pq(&message, &set, &short).is_none());
}

// ---- relayer.rs: observe / pending ------------------------------------------

#[tokio::test]
async fn observe_records_messages_and_pending_lists_the_undone_oldest_first() {
    let (_dir, store) = store();
    let (a, b, c) = (burn(0, 2, 1, 0), burn(1, 2, 1, 0), eth_lock(0, [9; 32]));
    let next = Cursor { next_block: 0, next_sequence: 2 };
    let source = script(vec![Ok((vec![a.clone(), b.clone()], next.clone())), Ok((vec![c.clone()], Cursor { next_block: 8, next_sequence: 1 }))]);
    assert_eq!(relayer::observe(&source, &store).await.unwrap(), 2);
    assert_eq!(store.cursor("script").unwrap(), Some(next));
    assert_eq!(relayer::observe(&source, &store).await.unwrap(), 1);

    let pending = relayer::pending(&store).unwrap();
    assert_eq!(pending, vec![a.clone(), b.clone(), c.clone()], "chain 1 first, then chain 2, each ascending");

    store.write_message(relayer::DONE, 1, 0, &json!({})).unwrap();
    assert_eq!(relayer::pending(&store).unwrap(), vec![b, c]);

    let failing = script(vec![Err(anyhow::anyhow!("down"))]);
    assert!(relayer::observe(&failing, &store).await.is_err());
}

// ---- relayer.rs: relay_one --------------------------------------------------

struct Guardians {
    clients: Vec<GuardianClient>,
    keys: Vec<GuardianKey>,
    stores: Vec<Store>,
    _dirs: Vec<tempfile::TempDir>,
}

/// `n` guardian APIs; the first `signing` of them have signed each of `messages`.
async fn guardians(n: u8, signing: usize, messages: &[&Observed]) -> Guardians {
    let keys = guardian_keys(n);
    let (mut clients, mut stores, mut dirs) = (vec![], vec![], vec![]);
    for (i, key) in keys.iter().enumerate() {
        let (dir, store) = store();
        for m in messages.iter().filter(|_| i < signing) {
            guardian::sign_one(&store, key, None, &emitters(), m).unwrap();
        }
        clients.push(serve(&store, key).await.0);
        stores.push(store);
        dirs.push(dir);
    }
    Guardians { clients, keys, stores, _dirs: dirs }
}

fn no_destinations() -> Destinations {
    Destinations { endpoints: BTreeMap::new(), solana: None, rand: None, min_relayer_fee: 0 }
}

fn tool(dir: &std::path::Path, script: &str) -> std::path::PathBuf {
    let path = dir.join("tool.sh");
    std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

#[tokio::test]
async fn messages_this_relayer_cannot_or_will_not_relay_are_skipped_before_asking_anyone() {
    let (_dir, rstore) = store();
    let g = guardians(6, 0, &[]).await;
    let set = set_of(&g.keys);

    // Not a transfer.
    let rotation = Observed::new(
        Body {
            timestamp: 1,
            nonce: 0,
            emitter_chain: 1,
            emitter_address: RAND_EMITTER,
            sequence: 0,
            consistency_level: 0,
            payload: Payload::GuardianSetUpgrade(GuardianSetUpgrade { new_index: 1, keys: vec![[7; 20]] }).encode(),
        }
        .encode(),
    )
    .unwrap();
    let skipped = |p: Progress| match p {
        Progress::Skipped(why) => why,
        other => panic!("expected Skipped, got {other:?}"),
    };
    let dest = no_destinations();
    assert_eq!(skipped(relayer::relay_one(&rotation, &rstore, &g.clients, &set, &dest).await.unwrap()), "not a transfer");

    let to_rand = eth_lock(0, [9; 32]);
    assert_eq!(skipped(relayer::relay_one(&to_rand, &rstore, &g.clients, &set, &dest).await.unwrap()), "no Rand wallet configured");
    assert_eq!(skipped(relayer::relay_one(&burn(0, 5, 1, 0), &rstore, &g.clients, &set, &dest).await.unwrap()), "no Solana submitter configured");
    assert_eq!(skipped(relayer::relay_one(&burn(0, 3, 1, 0), &rstore, &g.clients, &set, &dest).await.unwrap()), "no submitter for chain 3");

    // A fee below the floor, for a chain that has a submitter.
    let evm = tool_evm_consumed(true);
    let mut dest = no_destinations();
    dest.endpoints.insert(2, evm.0);
    dest.min_relayer_fee = 2_000_000;
    let why = skipped(relayer::relay_one(&burn(0, 2, 50_000_000, 1_000_000), &rstore, &g.clients, &set, &dest).await.unwrap());
    assert_eq!(why, "relayer fee 1000000 below the floor 2000000");
    assert!(g.stores.iter().all(|s| s.sequences(api::SIGNED, 1).unwrap().is_empty()));
}

/// An EVM destination whose `consumed()` answers `consumed`.
fn tool_evm_consumed(consumed: bool) -> (EndpointSubmitter, Fake) {
    let node = rpc(move |m, _| (m == "eth_call").then(|| Ok(json!(format!("0x{:064x}", u8::from(consumed))))));
    let cfg = bridge_daemons::config::EvmConfig {
        name: "dest".into(),
        chain: 2,
        kind: EvmKind::Evm,
        rpc: node.url.clone(),
        contract: ETH_CONTRACT.into(),
        finality: bridge_daemons::config::Finality::Tag("latest".into()),
        start_block: 0,
        max_log_range: 1,
    };
    let key = "0000000000000000000000000000000000000000000000000000000000000001";
    (EndpointSubmitter::Evm(EvmSubmitter::new(&cfg, key).unwrap()), node)
}

#[tokio::test]
async fn a_release_waits_for_a_quorum_then_submits_and_records_it() {
    let (_dir, rstore) = store();
    let message = burn(0, 2, 50_000_000, 1_000_000);

    // Four of six guardians have signed: quorum is five.
    let g = guardians(6, 4, &[&message]).await;
    let set = set_of(&g.keys);
    let (submitter, node) = tool_evm_consumed(true);
    let mut dest = no_destinations();
    dest.endpoints.insert(2, submitter);
    let progress = relayer::relay_one(&message, &rstore, &g.clients, &set, &dest).await.unwrap();
    assert_eq!(progress, Progress::AwaitingQuorum { have: 4, need: 5 });
    assert_eq!(node.count("eth_call"), 0, "nothing is submitted short of a quorum");
    assert!(rstore.read_message::<relayer::Done>(relayer::DONE, 1, 0).unwrap().is_none());

    // The fifth signs; the destination already consumed the digest (someone else relayed it).
    guardian::sign_one(&g.stores[4], &g.keys[4], None, &emitters(), &message).unwrap();
    let progress = relayer::relay_one(&message, &rstore, &g.clients, &set, &dest).await.unwrap();
    assert_eq!(progress, Progress::Done(Outcome::AlreadyDone));
    let done: relayer::Done = rstore.read_message(relayer::DONE, 1, 0).unwrap().unwrap();
    assert_eq!((done.to_chain, done.outcome, done.digest), (2, Outcome::AlreadyDone, hex::encode(message.digest)));
}

#[tokio::test]
async fn a_guardian_that_errors_does_not_stop_the_others_counting() {
    let (_dir, rstore) = store();
    let message = burn(0, 2, 50_000_000, 0);
    let g = guardians(3, 3, &[&message]).await;
    let set = set_of(&g.keys); // quorum 3 of 3
    let mut clients = g.clients.clone();
    clients.push(GuardianClient::new("http://127.0.0.1:1"));
    let (submitter, _node) = tool_evm_consumed(true);
    let mut dest = no_destinations();
    dest.endpoints.insert(2, submitter);
    let progress = relayer::relay_one(&message, &rstore, &clients, &set, &dest).await.unwrap();
    assert_eq!(progress, Progress::Done(Outcome::AlreadyDone));
}

#[tokio::test]
async fn a_solana_release_goes_through_the_cli() {
    let (dir, rstore) = store();
    let message = burn(0, 5, 50_000_000, 0);
    let g = guardians(3, 3, &[&message]).await;
    let set = set_of(&g.keys);
    let mut dest = no_destinations();
    dest.solana = Some(SolanaSubmitter {
        cli: tool(dir.path(), "echo sig-5Zq"),
        rpc: "http://sol".into(),
        program: "P".into(),
        scratch: dir.path().join("scratch"),
    });
    let progress = relayer::relay_one(&message, &rstore, &g.clients, &set, &dest).await.unwrap();
    assert_eq!(progress, Progress::Done(Outcome::Submitted("sig-5Zq".into())));
}

#[tokio::test]
async fn a_deposit_waits_for_its_recipient_then_is_minted_through_the_wallet() {
    let (dir, rstore) = store();
    let recipient = [0x42u8; 32];
    let message = eth_lock(0, recipient);
    let g = guardians(3, 3, &[&message]).await;
    let set = set_of(&g.keys);
    let mut dest = no_destinations();
    dest.rand = Some(RandSubmitter {
        cli: tool(dir.path(), "echo \"$@\" > \"$0.args\"; echo minted-1"),
        extra_args: vec![],
        scratch: dir.path().join("scratch"),
    });

    let progress = relayer::relay_one(&message, &rstore, &g.clients, &set, &dest).await.unwrap();
    assert_eq!(progress, Progress::AwaitingRecipient);

    relayer::register_recipient(&rstore, &recipient, "rand1someone").unwrap();
    assert_eq!(relayer::recipient_address(&rstore, &recipient).unwrap().as_deref(), Some("rand1someone"));
    let progress = relayer::relay_one(&message, &rstore, &g.clients, &set, &dest).await.unwrap();
    assert_eq!(progress, Progress::Done(Outcome::Submitted("minted-1".into())));
    let args = std::fs::read_to_string(dir.path().join("tool.sh.args")).unwrap();
    assert!(args.starts_with("bridge-mint @") && args.contains("--to rand1someone") && !args.contains("--pq"), "{args}");
}

#[tokio::test]
async fn a_rand_chain_that_lists_pq_guardians_gets_no_mint_without_their_quorum() {
    let (dir, rstore) = store();
    let recipient = [0x42u8; 32];
    relayer::register_recipient(&rstore, &recipient, "rand1someone").unwrap();
    let message = eth_lock(0, recipient);
    // Three guardians sign classically but none co-signs.
    let g = guardians(3, 3, &[&message]).await;
    let mut set = set_of(&g.keys);
    set.pq_keys = (1..=3u8).map(|i| PqKey::from_seed_hex(&format!("{i:064x}")).unwrap().public_key()).collect();
    set.rand_chain_id = Some(14);
    let mut dest = no_destinations();
    dest.rand = Some(RandSubmitter { cli: tool(dir.path(), "echo minted"), extra_args: vec![], scratch: dir.path().join("scratch") });
    let progress = relayer::relay_one(&message, &rstore, &g.clients, &set, &dest).await.unwrap();
    assert_eq!(progress, Progress::AwaitingQuorum { have: 0, need: 3 });
    assert!(rstore.read_message::<relayer::Done>(relayer::DONE, 2, 0).unwrap().is_none());
}

#[test]
fn recipient_hashes_are_checked_for_shape() {
    assert!(relayer::recipient_hash(&"rand1".repeat(500)).unwrap_err().to_string().contains("too long"));
    assert!(relayer::recipient_hash("btc1abc").unwrap_err().to_string().contains("must start with rand1"));
    assert!(relayer::recipient_hash("rand1not-base58-0OIl").unwrap_err().to_string().contains("not base58"));
    let short = format!("rand1{}", bs58::encode([1u8; 10]).into_string());
    assert!(relayer::recipient_hash(&short).unwrap_err().to_string().contains("decodes to 10 bytes"));
}
