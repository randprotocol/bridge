//! BRG-1: the caps a guardian holds every message to before it signs — per
//! transfer and per rolling window, per token and direction — and the pause
//! a breach puts on all signing.

mod common;

use bridge_daemons::api::{self, SignedMessage};
use bridge_daemons::config::Config;
use bridge_daemons::guardian::{self, Guards, Refused};
use bridge_daemons::limits::{self, Limits, LimitsConfig, TokenLimit};
use bridge_daemons::message::{Emitters, Observed};
use bridge_daemons::sources::{Cursor, Located, Source};
use bridge_daemons::store::Store;
use common::*;

const ETH: &str = "0x1111111111111111111111111111111111111111";
const UNIT: u64 = 100_000_000; // one whole token at 8 decimals

fn emitters() -> Emitters {
    Emitters {
        rand: RAND_EMITTER,
        endpoints: vec![(2, word(ETH))],
    }
}

fn store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("data")).unwrap();
    (dir, store)
}

/// The published caps: 100 per transfer, 1,000 per day.
fn published() -> Limits {
    Limits::new(&LimitsConfig {
        per_transfer: 100 * UNIT,
        per_window: 1_000 * UNIT,
        window_secs: 86_400,
        token: vec![],
    })
    .unwrap()
}

fn lock_of(sequence: u64, whole: u64) -> Observed {
    Observed::new(transfer_body(
        2,
        word(ETH),
        sequence,
        transfer(u128::from(whole * UNIT), 0, 2, 1, [9; 32]),
    ))
    .unwrap()
}

fn sign(store: &Store, limits: &Limits, m: &Observed, now: u64) -> bool {
    let key = &guardian_keys(1)[0];
    let guards = Guards {
        limits: Some(limits),
        ..Default::default()
    };
    guardian::sign_one_guarded(store, key, None, &emitters(), &guards, m, now).unwrap()
}

#[test]
fn a_transfer_over_the_per_transfer_cap_is_refused_and_pauses_signing() {
    let (_dir, store) = store();
    let l = published();
    assert!(sign(&store, &l, &lock_of(0, 100), 1_000), "exactly the cap is fine");
    assert!(!sign(&store, &l, &lock_of(1, 101), 1_001));
    let refused: Refused = store.read_message(guardian::REFUSED, 2, 1).unwrap().unwrap();
    assert!(refused.reason.contains("per-transfer cap"), "{}", refused.reason);
    let p = limits::paused(&store).unwrap().expect("paused");
    assert_eq!((p.chain, p.sequence), (2, 1));
    assert!(store
        .read_message::<SignedMessage>(api::SIGNED, 2, 1)
        .unwrap()
        .is_none());
}

#[test]
fn the_window_rolls_and_is_kept_per_token_and_direction() {
    let (_dir, store) = store();
    let l = published();
    let t0 = 10_000_000;
    for i in 0..10 {
        assert!(sign(&store, &l, &lock_of(i, 100), t0 + i), "deposit {i}");
    }
    // A release of the same token counts in its own window.
    assert!(sign(&store, &l, &burn(0, 2, u128::from(100 * UNIT), 0), t0 + 20));
    // The 11th deposit inside the day breaches.
    assert!(!sign(&store, &l, &lock_of(10, 1), t0 + 30));
    let refused: Refused = store.read_message(guardian::REFUSED, 2, 10).unwrap().unwrap();
    assert!(refused.reason.contains("cap 100000000000"), "{}", refused.reason);
    assert!(limits::resume(&store).unwrap().is_some());
    // A day after the first deposit, its 100 has left the window.
    assert!(sign(&store, &l, &lock_of(11, 100), t0 + 86_400));
    assert!(!sign(&store, &l, &lock_of(12, 1), t0 + 86_400), "the other nine still count");
}

#[test]
fn a_token_override_has_its_own_caps() {
    let (_dir, store) = store();
    let token = "0x00000000000000000000000000000000000000dd"; // what common::transfer locks
    let l = Limits::new(&LimitsConfig {
        per_transfer: UNIT,
        per_window: UNIT,
        window_secs: 60,
        token: vec![TokenLimit {
            chain: 2,
            address: token.into(),
            per_transfer: 500 * UNIT,
            per_window: 500 * UNIT,
        }],
    })
    .unwrap();
    assert!(sign(&store, &l, &lock_of(0, 500), 1));
    assert!(!sign(&store, &l, &lock_of(1, 1), 2));
}

#[test]
fn bad_limits_are_refused() {
    let base = LimitsConfig {
        per_transfer: 2,
        per_window: 1,
        window_secs: 60,
        token: vec![],
    };
    assert!(Limits::new(&base).is_err(), "per_transfer above per_window");
    assert!(Limits::new(&LimitsConfig { per_transfer: 1, window_secs: 0, ..base.clone() }).is_err());
    let token = |chain, address: &str| LimitsConfig {
        per_transfer: 1,
        token: vec![TokenLimit { chain, address: address.into(), per_transfer: 1, per_window: 1 }],
        ..base.clone()
    };
    assert!(Limits::new(&token(2, "0x12")).is_err());
    assert!(Limits::new(&token(9, "0x00000000000000000000000000000000000000dd")).is_err());
    assert!(Limits::new(&token(4, "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t")).is_ok(), "a Tron address");
    assert!(Limits::new(&token(5, "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB")).is_ok(), "a Solana mint");
}

/// A source that hands out one batch, with each message's exact resume cursor.
struct Batch {
    polls: std::sync::Mutex<usize>,
    located: Vec<Located>,
    next: Cursor,
}

impl Source for Batch {
    fn name(&self) -> &str {
        "batch"
    }
    fn start(&self) -> Cursor {
        Cursor::default()
    }
    async fn poll(&self, _: &Cursor) -> anyhow::Result<(Vec<Observed>, Cursor)> {
        unreachable!()
    }
    async fn poll_located(&self, _: &Cursor) -> anyhow::Result<(Vec<Located>, Cursor)> {
        *self.polls.lock().unwrap() += 1;
        Ok((self.located.clone(), self.next.clone()))
    }
}

#[tokio::test]
async fn a_breach_stops_the_poll_and_nothing_is_read_until_the_pause_is_cleared() {
    let (_dir, store) = store();
    let l = published();
    let at = |seq: u64, block: u64, whole: u64| Located {
        message: lock_of(seq, whole),
        resume: Cursor { next_block: block, next_sequence: seq },
    };
    let source = Batch {
        polls: Default::default(),
        located: vec![at(0, 10, 5), at(1, 11, 5000), at(2, 12, 5)],
        next: Cursor { next_block: 13, next_sequence: 3 },
    };
    let key = &guardian_keys(1)[0];
    let guards = Guards { limits: Some(&l), ..Default::default() };
    let n = guardian::step_guarded(&source, &store, key, None, &emitters(), &guards).await.unwrap();
    assert_eq!(n, 1, "lock 0 only");
    assert_eq!(
        store.cursor("batch").unwrap(),
        Some(Cursor { next_block: 12, next_sequence: 2 }),
        "past the breach, before what was not looked at"
    );
    assert!(store.read_message::<SignedMessage>(api::SIGNED, 2, 2).unwrap().is_none());

    // Paused: the next round reads nothing at all.
    assert_eq!(guardian::step_guarded(&source, &store, key, None, &emitters(), &guards).await.unwrap(), 0);
    assert_eq!(*source.polls.lock().unwrap(), 1);

    // The operator clears it; lock 2 is signed, the breach stays refused.
    limits::resume(&store).unwrap();
    let after = Batch {
        polls: Default::default(),
        located: vec![at(2, 12, 5)],
        next: Cursor { next_block: 13, next_sequence: 3 },
    };
    assert_eq!(guardian::step_guarded(&after, &store, key, None, &emitters(), &guards).await.unwrap(), 1);
    assert!(store.read_message::<SignedMessage>(api::SIGNED, 2, 1).unwrap().is_none());
}

/// The repository's mainnet guardian configs carry the published caps: 100 per transfer and
/// 1,000 per day, in 8-decimal units, for every token.
#[test]
fn the_mainnet_guardian_configs_carry_the_published_caps() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("mainnet");
    for i in 1..=8 {
        let config = Config::load(&dir.join(format!("guardian-{i}.toml"))).unwrap();
        let limits = config.guardian.unwrap().limits.unwrap_or_else(|| panic!("guardian-{i} has no [guardian.limits]"));
        assert_eq!(
            (limits.per_transfer, limits.per_window, limits.window_secs),
            (100 * UNIT, 1_000 * UNIT, 86_400),
            "guardian-{i}"
        );
    }
}
