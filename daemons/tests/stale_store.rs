//! BR-502: a guardian whose store was restored from a snapshot taken before
//! it signed a lock has no local record of that signature. Before a first
//! signature it asks its peers, and refuses when a guardian has already
//! signed a different body for the same (chain, sequence).

mod common;

use bridge_daemons::api::{self, GuardianClient, SignedMessage};
use bridge_daemons::crypto::GuardianKey;
use bridge_daemons::guardian::{self, Guards};
use bridge_daemons::limits;
use bridge_daemons::message::{Emitters, Observed};
use bridge_daemons::sources::{Cursor, Source};
use bridge_daemons::store::Store;
use common::*;

const ETH: &str = "0x1111111111111111111111111111111111111111";

fn emitters() -> Emitters {
    Emitters {
        rand: RAND_EMITTER,
        endpoints: vec![(2, word(ETH))],
    }
}

fn lock_of(amount: u128) -> Observed {
    Observed::new(transfer_body(2, word(ETH), 0, transfer(amount, 0, 2, 1, [9; 32]))).unwrap()
}

async fn serve(store: &Store, key: &GuardianKey) -> GuardianClient {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let router = api::router(store.clone(), key.address());
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    GuardianClient::new(&origin)
}

struct Once(std::sync::Mutex<Vec<Observed>>);

impl Source for Once {
    fn name(&self) -> &str {
        "eth"
    }
    fn start(&self) -> Cursor {
        Cursor::default()
    }
    async fn poll(&self, _: &Cursor) -> anyhow::Result<(Vec<Observed>, Cursor)> {
        let m = std::mem::take(&mut *self.0.lock().unwrap());
        Ok((m, Cursor { next_block: 60, next_sequence: 1 }))
    }
}

fn once(m: Observed) -> Once {
    Once(std::sync::Mutex::new(vec![m]))
}

fn tmp_store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    (dir, store)
}

/// A peer whose store holds `record` for (2, 0), serving it.
async fn peer_with(record: &SignedMessage, key: &GuardianKey) -> (tempfile::TempDir, GuardianClient) {
    let (dir, store) = tmp_store();
    store.write_message(api::SIGNED, 2, 0, record).unwrap();
    let client = serve(&store, key).await;
    (dir, client)
}

fn signed_by(key: &GuardianKey, m: &Observed) -> SignedMessage {
    SignedMessage {
        message: m.clone(),
        guardian: hex::encode(key.address()),
        signature: key.sign(&m.digest).unwrap(),
        pq_signature: None,
    }
}

fn dead_peer() -> GuardianClient {
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    GuardianClient::new(&format!("http://127.0.0.1:{port}"))
}

#[tokio::test]
async fn another_keys_record_never_blocks_whatever_its_body() {
    let keys = guardian_keys(3);
    // A guardian (keys[0]) pre-signs junk for the next sequence and serves it.
    let (_pd, peer) = peer_with(&signed_by(&keys[0], &lock_of(5)), &keys[0]).await;
    let (_d, me) = tmp_store();
    let peers = [peer];
    let guards = Guards { peers: &peers, ..Default::default() };
    let n = guardian::step_guarded(&once(lock_of(100_000_000)), &me, &keys[1], None, &emitters(), &guards)
        .await
        .unwrap();
    assert_eq!(n, 1, "signed: only this guardian's own signature proves anything");
    assert!(limits::held(&me).unwrap().is_empty());
}

#[tokio::test]
async fn my_own_conflicting_signature_at_a_peer_holds_the_sequence() {
    let keys = guardian_keys(2);
    let first = lock_of(100_000_000);
    let second = lock_of(100_000_001); // what the providers report after the restore
    // The peer keeps what this guardian (keys[1]) signed before its store was restored.
    let (_pd, peer) = peer_with(&signed_by(&keys[1], &first), &keys[0]).await;
    let (_d, me) = tmp_store();
    let peers = [peer];
    let guards = Guards { peers: &peers, ..Default::default() };
    let n = guardian::step_guarded(&once(second.clone()), &me, &keys[1], None, &emitters(), &guards)
        .await
        .unwrap();
    assert_eq!(n, 0);
    assert!(me.read_message::<SignedMessage>(api::SIGNED, 2, 0).unwrap().is_none());
    assert_eq!(limits::held(&me).unwrap(), vec![(2, 0)], "held, not skipped");
    let held: limits::Held = me.read_message(limits::HELD, 2, 0).unwrap().unwrap();
    assert!(held.reason.contains("BR-502") && held.reason.contains(&hex::encode(first.digest)), "{}", held.reason);
    // The same body is signed as usual.
    let (_d2, fresh) = tmp_store();
    assert_eq!(
        guardian::step_guarded(&once(first.clone()), &fresh, &keys[1], None, &emitters(), &guards).await.unwrap(),
        1
    );
}

#[tokio::test]
async fn with_no_peer_answering_the_transfer_waits_and_signs_once_one_does() {
    let keys = guardian_keys(2);
    let (_d, me) = tmp_store();
    let peers = [dead_peer(), dead_peer()];
    let guards = Guards { peers: &peers, ..Default::default() };
    let m = lock_of(100_000_000);
    let n = guardian::step_guarded(&once(m.clone()), &me, &keys[1], None, &emitters(), &guards).await.unwrap();
    assert_eq!(n, 0);
    assert_eq!(me.cursor("eth").unwrap(), Some(Cursor { next_block: 60, next_sequence: 1 }));
    assert_eq!(limits::listed(&me, limits::DEFERRED).unwrap(), vec![(2, 0)], "deferred, not skipped");
    // Still nobody: still waiting.
    assert_eq!(guardian::retry_deferred(&me, &keys[1], None, &emitters(), &guards).await.unwrap(), 0);
    assert_eq!(limits::listed(&me, limits::DEFERRED).unwrap(), vec![(2, 0)]);
    // A peer answers (it has no record): the retry signs it.
    let (_pd, empty_store) = tmp_store();
    let up = [serve(&empty_store, &keys[0]).await];
    let guards = Guards { peers: &up, ..Default::default() };
    assert_eq!(guardian::retry_deferred(&me, &keys[1], None, &emitters(), &guards).await.unwrap(), 1);
    assert!(me.read_message::<SignedMessage>(api::SIGNED, 2, 0).unwrap().is_some());
    assert!(limits::listed(&me, limits::DEFERRED).unwrap().is_empty());
}

#[tokio::test]
async fn without_peers_a_restored_store_is_guarded_by_nothing_else() {
    // The behaviour BR-502 records, kept when no peers are configured.
    let keys = guardian_keys(2);
    let (_d, me) = tmp_store();
    let n = guardian::step(&once(lock_of(100_000_001)), &me, &keys[1], None, &emitters()).await.unwrap();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn a_forged_record_of_my_key_whose_body_does_not_match_its_digest_is_ignored() {
    let keys = guardian_keys(2);
    let first = lock_of(100_000_000);
    // A real signature by this guardian over `first`, served with another body.
    let fake = SignedMessage { message: Observed { body: lock_of(5).body, ..first.clone() }, ..signed_by(&keys[1], &first) };
    let text = serde_json::to_string(&fake).unwrap();
    let liar = http(move |_| (200, text.clone()));
    let (_d, me) = tmp_store();
    let peers = [GuardianClient::new(&liar.url)];
    let guards = Guards { peers: &peers, ..Default::default() };
    let n = guardian::step_guarded(&once(lock_of(100_000_001)), &me, &keys[1], None, &emitters(), &guards)
        .await
        .unwrap();
    assert_eq!(n, 1);
}
