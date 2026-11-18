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
        per_window_total: None,
        delay_above: None,
        delay_secs: None,
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

fn try_sign(store: &Store, limits: &Limits, m: &Observed, now: u64) -> anyhow::Result<bool> {
    let key = &guardian_keys(1)[0];
    let guards = Guards {
        limits: Some(limits),
        ..Default::default()
    };
    guardian::sign_one_guarded(store, key, None, &emitters(), &guards, m, now)
}

fn is_signed(store: &Store, chain: u16, seq: u64) -> bool {
    store
        .read_message::<SignedMessage>(api::SIGNED, chain, seq)
        .unwrap()
        .is_some()
}

#[test]
fn a_transfer_over_the_per_transfer_cap_is_withheld_while_others_sign() {
    let (_dir, store) = store();
    let l = published();
    assert!(sign(&store, &l, &lock_of(0, 100), 1_000), "exactly the cap is fine");
    assert!(!sign(&store, &l, &lock_of(1, 101), 1_001));
    assert!(!is_signed(&store, 2, 1));
    let held: limits::Held = store.read_message(limits::HELD, 2, 1).unwrap().unwrap();
    assert!(held.reason.contains("per-transfer cap"), "{}", held.reason);
    assert_eq!(limits::held(&store).unwrap(), vec![(2, 1)]);
    assert!(limits::paused(&store).unwrap().is_none(), "nothing pauses on its own");
    // The next normal transfer signs at once.
    assert!(sign(&store, &l, &lock_of(2, 5), 1_002));

    // Released by the operator, for that (chain, sequence) only.
    let key = &guardian_keys(1)[0];
    let guards = Guards { limits: Some(&l), ..Default::default() };
    assert!(guardian::release_held(&store, key, None, &emitters(), &guards, 2, 1, 1_003).unwrap());
    assert!(is_signed(&store, 2, 1));
    assert!(limits::held(&store).unwrap().is_empty());
    assert!(guardian::release_held(&store, key, None, &emitters(), &guards, 2, 1, 1_004).is_err(), "not held any more");
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
    // The 11th deposit inside the day is deferred: nothing written, nothing paused.
    let err = try_sign(&store, &l, &lock_of(10, 1), t0 + 30).unwrap_err();
    let d = err.downcast_ref::<guardian::Deferred>().expect("deferred");
    assert!(d.reason.contains("cap 100000000000"), "{}", d.reason);
    assert!(!is_signed(&store, 2, 10));
    assert!(store.read_message::<Refused>(guardian::REFUSED, 2, 10).unwrap().is_none());
    assert!(limits::paused(&store).unwrap().is_none());
    // A day after the first deposit its 100 has left the window: the deferred one signs.
    assert!(try_sign(&store, &l, &lock_of(10, 1), t0 + 86_400).unwrap());
    assert!(try_sign(&store, &l, &lock_of(11, 100), t0 + 86_400).is_err(), "the other nine still count");
}

#[test]
fn a_token_override_has_its_own_caps() {
    let (_dir, store) = store();
    let token = "0x00000000000000000000000000000000000000dd"; // what common::transfer locks
    let l = Limits::new(&LimitsConfig {
        per_transfer: UNIT,
        per_window: UNIT,
        window_secs: 60,
        per_window_total: None,
        delay_above: None,
        delay_secs: None,
        token: vec![TokenLimit {
            chain: 2,
            address: token.into(),
            per_transfer: 500 * UNIT,
            per_window: 500 * UNIT,
        }],
    })
    .unwrap();
    assert!(sign(&store, &l, &lock_of(0, 500), 1));
    assert!(try_sign(&store, &l, &lock_of(1, 1), 2).is_err(), "its own window is full");
}

#[test]
fn bad_limits_are_refused() {
    let base = LimitsConfig {
        per_transfer: 2,
        per_window: 1,
        window_secs: 60,
        per_window_total: None,
        delay_above: None,
        delay_secs: None,
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

fn at(seq: u64, block: u64, whole: u64) -> Located {
    Located {
        message: lock_of(seq, whole),
        resume: Cursor { next_block: block, next_sequence: seq },
    }
}

#[tokio::test]
async fn an_oversize_transfer_is_held_while_the_rest_of_the_poll_signs() {
    let (_dir, store) = store();
    let l = published();
    let source = Batch {
        polls: Default::default(),
        located: vec![at(0, 10, 5), at(1, 11, 5000), at(2, 12, 5)],
        next: Cursor { next_block: 13, next_sequence: 3 },
    };
    let key = &guardian_keys(1)[0];
    let guards = Guards { limits: Some(&l), ..Default::default() };
    let n = guardian::step_guarded(&source, &store, key, None, &emitters(), &guards).await.unwrap();
    assert_eq!(n, 2, "locks 0 and 2");
    assert!(!is_signed(&store, 2, 1));
    assert_eq!(limits::held(&store).unwrap(), vec![(2, 1)]);
    assert_eq!(store.cursor("batch").unwrap(), Some(Cursor { next_block: 13, next_sequence: 3 }));
    // The next round polls as usual.
    guardian::step_guarded(&source, &store, key, None, &emitters(), &guards).await.unwrap();
    assert_eq!(*source.polls.lock().unwrap(), 2);
}

/// A lock of `whole` tokens of the token whose address ends in `tok`.
fn lock_tok(seq: u64, whole: u64, tok: u8) -> Observed {
    let mut t = transfer(u128::from(whole * UNIT), 0, 2, 1, [9; 32]);
    t.token_address = word(&format!("0x{tok:040x}"));
    Observed::new(transfer_body(2, word(ETH), seq, t)).unwrap()
}

fn at_msg(message: Observed, block: u64) -> Located {
    let seq = message.sequence;
    Located { message, resume: Cursor { next_block: block, next_sequence: seq } }
}

#[tokio::test]
async fn a_full_window_defers_only_its_token_and_signs_it_later_on_its_own() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let l = Limits::new(&LimitsConfig {
        per_transfer: 10 * UNIT,
        per_window: 10 * UNIT,
        window_secs: 3,
        per_window_total: None,
        delay_above: None,
        delay_secs: None,
        token: vec![],
    })
    .unwrap();
    // Token A (0xa1) fills its window at lock 0; lock 1 and lock 3 of A wait; B (0xb2) and a
    // release on Rand flow.
    let source = Batch {
        polls: Default::default(),
        located: vec![
            at_msg(lock_tok(0, 6, 0xa1), 10),
            at_msg(lock_tok(1, 6, 0xa1), 11),
            at_msg(lock_tok(2, 6, 0xb2), 12),
            at_msg(lock_tok(3, 1, 0xa1), 13),
        ],
        next: Cursor { next_block: 14, next_sequence: 4 },
    };
    let key = &guardian_keys(1)[0];
    let guards = Guards { limits: Some(&l), ..Default::default() };
    let n = guardian::step_guarded(&source, &store, key, None, &emitters(), &guards).await.unwrap();
    assert_eq!(n, 2, "lock 0 (A) and lock 2 (B)");
    assert!(is_signed(&store, 2, 2), "token B is not delayed");
    assert_eq!(store.cursor("batch").unwrap(), Some(Cursor { next_block: 14, next_sequence: 4 }), "the cursor moves on");
    assert_eq!(limits::listed(&store, limits::DEFERRED).unwrap(), vec![(2, 1), (2, 3)]);
    // lock 3 would fit A's window (6 + 1), but waits behind lock 1: sequence order per token.
    assert!(!is_signed(&store, 2, 3));
    let release = burn(0, 2, u128::from(5 * UNIT), 0);
    assert!(sign(&store, &l, &release, limits::now()), "a release on Rand is not delayed");

    // Nothing frees yet.
    assert_eq!(guardian::retry_deferred(&store, key, None, &emitters(), &guards).await.unwrap(), 0);
    // A restart keeps the deferred set, and once A's window rolls they sign on their own, in order.
    drop(store);
    let store = Store::open(dir.path()).unwrap();
    assert_eq!(limits::listed(&store, limits::DEFERRED).unwrap(), vec![(2, 1), (2, 3)]);
    std::thread::sleep(std::time::Duration::from_millis(4100));
    assert_eq!(guardian::retry_deferred(&store, key, None, &emitters(), &guards).await.unwrap(), 2);
    assert!(is_signed(&store, 2, 1) && is_signed(&store, 2, 3));
    assert!(limits::listed(&store, limits::DEFERRED).unwrap().is_empty());
}

#[tokio::test]
async fn an_unreadable_window_defers_its_token_only() {
    let (dir, store) = store();
    let l = published();
    let key = &guardian_keys(1)[0];
    let guards = Guards { limits: Some(&l), ..Default::default() };
    assert!(sign(&store, &l, &lock_tok(0, 1, 0xa1), 1));
    // Break token A's window record.
    let window = std::fs::read_dir(dir.path().join("data/limits/window")).unwrap().next().unwrap().unwrap().path();
    std::fs::write(&window, b"").unwrap();
    let source = Batch {
        polls: Default::default(),
        located: vec![at_msg(lock_tok(1, 1, 0xa1), 10), at_msg(lock_tok(2, 1, 0xb2), 11)],
        next: Cursor { next_block: 12, next_sequence: 3 },
    };
    let n = guardian::step_guarded(&source, &store, key, None, &emitters(), &guards).await.unwrap();
    assert_eq!(n, 1, "token B signs");
    assert_eq!(limits::listed(&store, limits::DEFERRED).unwrap(), vec![(2, 1)]);
}

#[tokio::test]
async fn only_an_operator_pauses_and_a_pause_reads_nothing() {
    let (_dir, store) = store();
    let l = published();
    let source = Batch {
        polls: Default::default(),
        located: vec![at(0, 10, 5)],
        next: Cursor { next_block: 11, next_sequence: 1 },
    };
    let key = &guardian_keys(1)[0];
    let guards = Guards { limits: Some(&l), ..Default::default() };
    limits::pause(&store, 1, "incident review").unwrap();
    assert_eq!(guardian::step_guarded(&source, &store, key, None, &emitters(), &guards).await.unwrap(), 0);
    assert_eq!(*source.polls.lock().unwrap(), 0);
    assert_eq!(limits::resume(&store).unwrap().unwrap().reason, "incident review");
    assert_eq!(guardian::step_guarded(&source, &store, key, None, &emitters(), &guards).await.unwrap(), 1);
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

// ---- the all-token cap and the delay (BRG-1) -------------------------------------

fn with(per_window_total: Option<u64>, delay: Option<(u64, u64)>) -> Limits {
    Limits::new(&LimitsConfig {
        per_transfer: 100 * UNIT,
        per_window: 1_000 * UNIT,
        window_secs: 86_400,
        per_window_total,
        delay_above: delay.map(|d| d.0),
        delay_secs: delay.map(|d| d.1),
        token: vec![],
    })
    .unwrap()
}

fn deferred(r: anyhow::Result<bool>) -> guardian::Deferred {
    let e = r.unwrap_err();
    let d = e.downcast_ref::<guardian::Deferred>().unwrap_or_else(|| panic!("not deferred: {e:#}"));
    guardian::Deferred { chain: d.chain, sequence: d.sequence, reason: d.reason.clone(), delay: d.delay }
}

#[test]
fn the_all_token_cap_bounds_every_token_together_per_direction() {
    let (_dir, store) = store();
    // Each token may move 1,000 a day; all of them together 250.
    let l = with(Some(250 * UNIT), None);
    let t0 = 5_000_000;
    assert!(sign(&store, &l, &lock_tok(0, 100, 0xa1), t0));
    assert!(sign(&store, &l, &lock_tok(1, 100, 0xb2), t0 + 1));
    // A third token: its own window is empty, the total is not.
    let d = deferred(try_sign(&store, &l, &lock_tok(2, 51, 0xc3), t0 + 2));
    assert!(d.reason.contains("across all tokens") && d.reason.contains("per_window_total"), "{}", d.reason);
    assert!(!d.delay);
    assert!(!is_signed(&store, 2, 2));
    assert!(sign(&store, &l, &lock_tok(3, 50, 0xc3), t0 + 3), "exactly the total is fine");
    // Releases are counted on their own.
    assert!(sign(&store, &l, &burn(0, 2, u128::from(100 * UNIT), 0), t0 + 4));
    // Once the first deposit has left the window there is room again.
    assert!(try_sign(&store, &l, &lock_tok(2, 51, 0xc3), t0 + 86_400).is_ok_and(|s| s));
    assert!(try_sign(&store, &l, &lock_tok(4, 100, 0xa1), t0 + 86_400).is_err(), "the rest still counts");
}

#[test]
fn a_deferred_transfer_is_counted_in_neither_window() {
    let (dir, store) = store();
    let l = with(Some(100 * UNIT), None);
    assert!(sign(&store, &l, &lock_tok(0, 100, 0xa1), 1_000));
    deferred(try_sign(&store, &l, &lock_tok(1, 1, 0xb2), 1_001));
    // Token B's window was never written: a deferral over the total leaves no count behind.
    let windows: Vec<String> = std::fs::read_dir(dir.path().join("data/limits/window"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(windows.len(), 2, "{windows:?}");
    assert!(windows.contains(&"deposit-total.json".to_string()), "{windows:?}");
}

#[test]
fn an_unreadable_all_token_window_defers_its_direction_only() {
    let (dir, store) = store();
    let l = with(Some(250 * UNIT), None);
    assert!(sign(&store, &l, &lock_tok(0, 1, 0xa1), 1_000));
    std::fs::write(dir.path().join("data/limits/window/deposit-total.json"), b"").unwrap();
    let d = deferred(try_sign(&store, &l, &lock_tok(1, 1, 0xa1), 1_001));
    assert!(d.reason.contains("cannot be read"), "{}", d.reason);
    assert!(sign(&store, &l, &burn(0, 2, u128::from(UNIT), 0), 1_002), "releases have their own total");
}

#[test]
fn a_transfer_above_the_delay_threshold_waits_on_the_guardians_clock() {
    let (dir, store) = store();
    // Above 50, wait an hour.
    let l = with(None, Some((50 * UNIT, 3_600)));
    let t0 = 7_000_000;
    assert!(sign(&store, &l, &lock_of(0, 50), t0), "exactly the threshold is not delayed");
    let d = deferred(try_sign(&store, &l, &lock_of(1, 51), t0));
    assert!(d.delay, "it waits out a delay, not a window");
    assert!(d.reason.contains("delay_above") && d.reason.contains(&(t0 + 3_600).to_string()), "{}", d.reason);
    assert!(!is_signed(&store, 2, 1));
    // The wait is counted from the first read, whatever happens in between: a later look, or
    // a restart, does not start it again.
    deferred(try_sign(&store, &l, &lock_of(1, 51), t0 + 3_599));
    drop(store);
    let store = Store::open(&dir.path().join("data")).unwrap();
    assert!(try_sign(&store, &l, &lock_of(1, 51), t0 + 3_600).unwrap());
    assert!(is_signed(&store, 2, 1));
    assert!(
        store.read_message::<limits::Delayed>(limits::DELAYED, 2, 1).unwrap().is_none(),
        "the delay record goes once the transfer is signed"
    );
    // It was counted in its window only when it was signed.
    assert!(sign(&store, &l, &lock_of(2, 1), t0 + 3_601));
}

#[test]
fn a_delay_record_this_guardian_did_not_write_starts_the_wait_again() {
    let (_dir, store) = store();
    let l = with(None, Some((50 * UNIT, 3_600)));
    let m = lock_of(1, 51);
    let t0 = 7_000_000;
    deferred(try_sign(&store, &l, &m, t0));
    let honest: limits::Delayed = store.read_message(limits::DELAYED, 2, 1).unwrap().unwrap();
    assert_eq!(honest.at, t0);
    // Someone who can write the data directory backdates the record to skip the wait.
    let planted = limits::Delayed { at: t0 - 3_600, ..honest.clone() };
    store.write_message(limits::DELAYED, 2, 1, &planted).unwrap();
    deferred(try_sign(&store, &l, &m, t0 + 10));
    let again: limits::Delayed = store.read_message(limits::DELAYED, 2, 1).unwrap().unwrap();
    assert_eq!(again.at, t0 + 10, "the wait starts again from now");
    assert!(!is_signed(&store, 2, 1));
    // A record from the future (the clock was set back) starts again too.
    deferred(try_sign(&store, &l, &m, t0 + 5));
    // An empty record likewise.
    let path = store.root().join("delayed/2").read_dir().unwrap().next().unwrap().unwrap().path();
    std::fs::write(path, b"").unwrap();
    deferred(try_sign(&store, &l, &m, t0 + 20));
    deferred(try_sign(&store, &l, &m, t0 + 3_619));
    assert!(try_sign(&store, &l, &m, t0 + 3_620).unwrap());
}

#[test]
fn an_operators_release_of_a_held_transfer_is_not_delayed_and_small_ones_never_are() {
    let (_dir, store) = store();
    let l = with(None, Some((50 * UNIT, 3_600)));
    let key = &guardian_keys(1)[0];
    let guards = Guards { limits: Some(&l), ..Default::default() };
    // 101 is over the per-transfer cap once its delay has passed: it is then held like any other.
    deferred(try_sign(&store, &l, &lock_of(0, 101), 1_000));
    assert!(!try_sign(&store, &l, &lock_of(0, 101), 4_600).unwrap());
    assert_eq!(limits::held(&store).unwrap(), vec![(2, 0)]);
    assert!(guardian::release_held(&store, key, None, &emitters(), &guards, 2, 0, 4_601).unwrap());
    assert!(sign(&store, &l, &lock_of(1, 50), 4_602));
}

#[test]
fn the_delay_and_the_all_token_cap_are_checked_in_the_config() {
    let base = LimitsConfig {
        per_transfer: 10,
        per_window: 100,
        window_secs: 60,
        per_window_total: None,
        delay_above: None,
        delay_secs: None,
        token: vec![],
    };
    assert!(Limits::new(&base).is_ok());
    assert!(Limits::new(&LimitsConfig { per_window_total: Some(9), ..base.clone() }).is_err(), "below per_transfer");
    assert!(Limits::new(&LimitsConfig { per_window_total: Some(10), ..base.clone() }).is_ok());
    assert!(Limits::new(&LimitsConfig { delay_above: Some(5), ..base.clone() }).is_err(), "no delay_secs");
    assert!(Limits::new(&LimitsConfig { delay_secs: Some(5), ..base.clone() }).is_err(), "no delay_above");
    assert!(Limits::new(&LimitsConfig { delay_above: Some(5), delay_secs: Some(0), ..base.clone() }).is_err());
    let l = Limits::new(&LimitsConfig { delay_above: Some(5), delay_secs: Some(7), ..base.clone() }).unwrap();
    assert_eq!(l.delay_rule(), Some((5, 7)));
    // And from TOML, where all three are optional.
    let parsed: LimitsConfig = toml::from_str(
        "per_transfer = 10\nper_window = 100\nper_window_total = 300\ndelay_above = 5\ndelay_secs = 3600\n",
    )
    .unwrap();
    assert_eq!((parsed.per_window_total, parsed.delay_above, parsed.delay_secs), (Some(300), Some(5), Some(3_600)));
    let plain: LimitsConfig = toml::from_str("per_transfer = 10\nper_window = 100\n").unwrap();
    assert_eq!((plain.per_window_total, plain.delay_above, plain.delay_secs), (None, None, None));
}

#[tokio::test]
async fn a_delayed_transfer_holds_back_nothing_and_signs_on_its_own_later() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    // Above 5, wait 2 s; the window is 3 s and holds 10 per token.
    let l = Limits::new(&LimitsConfig {
        per_transfer: 10 * UNIT,
        per_window: 10 * UNIT,
        window_secs: 3,
        per_window_total: None,
        delay_above: Some(5 * UNIT),
        delay_secs: Some(2),
        token: vec![],
    })
    .unwrap();
    let source = Batch {
        polls: Default::default(),
        located: vec![
            at_msg(lock_tok(0, 6, 0xa1), 10), // delayed
            at_msg(lock_tok(1, 2, 0xa1), 11), // same token, small: not held back
            at_msg(lock_tok(2, 3, 0xb2), 12),
        ],
        next: Cursor { next_block: 13, next_sequence: 3 },
    };
    let key = &guardian_keys(1)[0];
    let guards = Guards { limits: Some(&l), ..Default::default() };
    let n = guardian::step_guarded(&source, &store, key, None, &emitters(), &guards).await.unwrap();
    assert_eq!(n, 2, "locks 1 and 2");
    assert!(!is_signed(&store, 2, 0) && is_signed(&store, 2, 1) && is_signed(&store, 2, 2));
    assert_eq!(limits::listed(&store, limits::DEFERRED).unwrap(), vec![(2, 0)]);
    let record: limits::Deferral = store.read_message(limits::DEFERRED, 2, 0).unwrap().unwrap();
    assert!(record.delay && record.seal.is_some());
    assert_eq!(store.cursor("batch").unwrap(), Some(Cursor { next_block: 13, next_sequence: 3 }));
    // A later poll brings another small transfer of the same token: still not held back.
    let later = Batch {
        polls: Default::default(),
        located: vec![at_msg(lock_tok(3, 1, 0xa1), 14)],
        next: Cursor { next_block: 15, next_sequence: 4 },
    };
    assert_eq!(guardian::step_guarded(&later, &store, key, None, &emitters(), &guards).await.unwrap(), 1);
    assert_eq!(guardian::retry_deferred(&store, key, None, &emitters(), &guards).await.unwrap(), 0, "not yet");
    // After the delay (and, here, after the small ones have left the 3 s window) it signs.
    std::thread::sleep(std::time::Duration::from_millis(4100));
    assert_eq!(guardian::retry_deferred(&store, key, None, &emitters(), &guards).await.unwrap(), 1);
    assert!(is_signed(&store, 2, 0));
    assert!(limits::listed(&store, limits::DEFERRED).unwrap().is_empty());
}

#[tokio::test]
async fn a_delayed_transfer_that_then_meets_a_full_window_queues_like_any_other() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let l = Limits::new(&LimitsConfig {
        per_transfer: 10 * UNIT,
        per_window: 10 * UNIT,
        window_secs: 6,
        per_window_total: None,
        delay_above: Some(5 * UNIT),
        delay_secs: Some(1),
        token: vec![],
    })
    .unwrap();
    let key = &guardian_keys(1)[0];
    let guards = Guards { limits: Some(&l), ..Default::default() };
    let first = Batch {
        polls: Default::default(),
        located: vec![at_msg(lock_tok(0, 6, 0xa1), 10), at_msg(lock_tok(1, 5, 0xa1), 11)],
        next: Cursor { next_block: 12, next_sequence: 2 },
    };
    // Lock 0 is delayed; lock 1 (5, not above the threshold) signs and takes half the window.
    assert_eq!(guardian::step_guarded(&first, &store, key, None, &emitters(), &guards).await.unwrap(), 1);
    std::thread::sleep(std::time::Duration::from_millis(1100));
    // Its delay has passed, but 5 + 6 is over the window: now it waits for room …
    assert_eq!(guardian::retry_deferred(&store, key, None, &emitters(), &guards).await.unwrap(), 0);
    let record: limits::Deferral = store.read_message(limits::DEFERRED, 2, 0).unwrap().unwrap();
    assert!(!record.delay, "the record says it waits for room now");
    // … and a later transfer of its token queues behind it.
    let second = Batch {
        polls: Default::default(),
        located: vec![at_msg(lock_tok(2, 1, 0xa1), 13)],
        next: Cursor { next_block: 14, next_sequence: 3 },
    };
    assert_eq!(guardian::step_guarded(&second, &store, key, None, &emitters(), &guards).await.unwrap(), 0);
    assert_eq!(limits::listed(&store, limits::DEFERRED).unwrap(), vec![(2, 0), (2, 2)]);
}
