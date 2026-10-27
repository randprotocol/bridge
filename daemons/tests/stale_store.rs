//! BR-502: a guardian whose store was restored from a snapshot taken before
//! it signed a lock has no local record of that signature. Before a first
//! signature it asks its peers, and refuses when a guardian has already
//! signed a different body for the same (chain, sequence).

mod common;

use bridge_daemons::api::{self, GuardianClient, SignedMessage};
use bridge_daemons::crypto::GuardianKey;
use bridge_daemons::guardian::{self, Guards, Refused};
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

/// A peer that signed `first`; and a guardian with an empty ("restored") store.
async fn setup(first: &Observed) -> (Vec<GuardianKey>, Vec<tempfile::TempDir>, GuardianClient, Store) {
    let keys = guardian_keys(3);
    let (peer_dir, peer_store) = tmp_store();
    assert!(guardian::sign_one(&peer_store, &keys[0], None, &emitters(), first).unwrap());
    let peer = serve(&peer_store, &keys[0]).await;
    let (me_dir, me) = tmp_store();
    (keys, vec![peer_dir, me_dir], peer, me)
}

#[tokio::test]
async fn a_restored_guardian_refuses_a_second_body_a_peer_already_signed() {
    let first = lock_of(100_000_000);
    let second = lock_of(100_000_001); // what a lying RPC reports after the restore
    let (keys, _dirs, peer, me) = setup(&first).await;
    let known = [keys[0].address(), keys[1].address()];
    let peers = [peer];
    let guards = Guards { peers: &peers, known: &known, ..Default::default() };

    let n = guardian::step_guarded(&once(second.clone()), &me, &keys[1], None, &emitters(), &guards)
        .await
        .unwrap();
    assert_eq!(n, 0);
    assert!(me.read_message::<SignedMessage>(api::SIGNED, 2, 0).unwrap().is_none());
    let refused: Refused = me.read_message(guardian::REFUSED, 2, 0).unwrap().unwrap();
    assert!(refused.reason.contains("BR-502") && refused.reason.contains(&hex::encode(first.digest)), "{}", refused.reason);

    // The same body the peer signed is signed as usual.
    let (_d, fresh) = tmp_store();
    let n = guardian::step_guarded(&once(first.clone()), &fresh, &keys[1], None, &emitters(), &guards)
        .await
        .unwrap();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn without_peers_a_restored_store_is_guarded_by_nothing_else() {
    // The behaviour BR-502 records, kept when no peers are configured.
    let first = lock_of(100_000_000);
    let (keys, _dirs, _peer, me) = setup(&first).await;
    let n = guardian::step(&once(lock_of(100_000_001)), &me, &keys[1], None, &emitters())
        .await
        .unwrap();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn a_peer_record_not_signed_by_a_guardian_or_a_dead_peer_proves_nothing() {
    let first = lock_of(100_000_000);
    let (keys, _dirs, peer, me) = setup(&first).await;
    // keys[0] signed the peer's record, but it is not in this set.
    let known = [keys[1].address(), keys[2].address()];
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let peers = [peer, GuardianClient::new(&format!("http://127.0.0.1:{port}"))];
    let guards = Guards { peers: &peers, known: &known, ..Default::default() };
    let n = guardian::step_guarded(&once(lock_of(100_000_001)), &me, &keys[1], None, &emitters(), &guards)
        .await
        .unwrap();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn a_peer_record_whose_body_does_not_match_its_digest_is_ignored() {
    let first = lock_of(100_000_000);
    let keys = guardian_keys(2);
    // A forged record: a real signature over `first`, served with another body.
    let fake = SignedMessage {
        message: Observed { body: lock_of(5).body, ..first.clone() },
        guardian: hex::encode(keys[0].address()),
        signature: keys[0].sign(&first.digest).unwrap(),
        pq_signature: None,
    };
    let text = serde_json::to_string(&fake).unwrap();
    let liar = http(move |_| (200, text.clone()));
    let (_d, me) = tmp_store();
    let peers = [GuardianClient::new(&liar.url)];
    let known = [keys[0].address()];
    let guards = Guards { peers: &peers, known: &known, ..Default::default() };
    let n = guardian::step_guarded(&once(lock_of(100_000_001)), &me, &keys[1], None, &emitters(), &guards)
        .await
        .unwrap();
    assert_eq!(n, 1);
}
