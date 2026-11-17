//! Audit v14 (addendum S7 to S8, 2026-11-16): the bridge rows that are about what a provider
//! or a file on disk can make a daemon do.
//!
//! BR-846   a provider-chosen offset, length, head, gas estimate or fee is an error, never a panic
//! BR-761   under a provider quorum a refused range is not counted; short of a quorum that
//!          serves it the chain halts with an error, it is never skipped
//! BR-1008  one provider that refuses a range does not move the cursor, whatever `sequence()` says

mod common;

use bridge_codec::{Attestation, Payload, CHAIN_RAND};
use bridge_daemons::config::{EvmConfig, EvmKind, Finality};
use bridge_daemons::sources::evm::EvmSource;
use bridge_daemons::sources::{self, Cursor, Source};
use bridge_daemons::submit::evm::EvmSubmitter;
use common::*;
use serde_json::{json, Value};

const CONTRACT: &str = "0x1111111111111111111111111111111111111111";
const KEY: &str = "0x0000000000000000000000000000000000000000000000000000000000000001";
const MAX64: &str = "ffffffffffffffff";

fn evm_cfg(urls: &[&str], quorum: Option<usize>, finality: Finality) -> EvmConfig {
    EvmConfig {
        name: "eth".into(),
        chain: 2,
        kind: EvmKind::Evm,
        rpc: urls[0].into(),
        rpcs: urls[1..].iter().map(|u| u.to_string()).collect(),
        rpc_quorum: quorum,
        contract: CONTRACT.into(),
        finality,
        start_block: 7,
        max_log_range: 2000,
    }
}

fn payload(amount: u128) -> Vec<u8> {
    Payload::Transfer(transfer(amount, 0, 2, CHAIN_RAND, [7; 32])).encode()
}

/// A `MessagePublished` log whose third data word (the payload offset) and whose length word
/// are given as hex, so a test can write what no contract would.
fn raw_log(sequence: u64, offset_hex: &str, len_hex: &str, payload: &[u8], block: u64) -> Value {
    let mut data = Vec::new();
    data.extend_from_slice(&word("9"));
    data.extend_from_slice(&word("f"));
    data.extend_from_slice(&word(offset_hex));
    data.extend_from_slice(&word(len_hex));
    data.extend_from_slice(&pad32(payload));
    json!({
        "address": CONTRACT,
        "topics": ["0xabcd", format!("0x{}", hex::encode(word(&format!("{sequence:x}"))))],
        "data": format!("0x{}", hex::encode(data)),
        "blockNumber": format!("0x{block:x}"),
        "removed": false,
    })
}

fn log(sequence: u64, payload: &[u8], block: u64) -> Value {
    raw_log(sequence, "60", &format!("{:x}", payload.len()), payload, block)
}

fn number(v: &Value) -> u64 {
    u64::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

/// A provider whose head is the hex quantity `head`. `logs`: what it serves, within the range
/// asked for; `None` refuses every `eth_getLogs` the way a public RPC refuses a range behind
/// its log window. `counter`: its answer to `sequence()`.
fn node(head: &str, logs: Option<Vec<Value>>, counter: Option<u64>) -> Fake {
    let head = format!("0x{head}");
    rpc(move |m, p| match m {
        "eth_blockNumber" => Some(Ok(json!(head))),
        "eth_getBlockByNumber" => Some(Ok(json!({ "number": head, "timestamp": "0x6553f100" }))),
        "eth_getLogs" => match &logs {
            None => Some(Err(json!({ "code": -32602, "message": "Archive requests require a personal token" }))),
            Some(logs) => {
                let (from, to) = (number(&p[0]["fromBlock"]), number(&p[0]["toBlock"]));
                Some(Ok(Value::Array(
                    logs.iter()
                        .filter(|l| (from..=to).contains(&number(&l["blockNumber"])))
                        .cloned()
                        .collect(),
                )))
            }
        },
        "eth_call" => counter.map(|n| Ok(json!(format!("0x{}", hex::encode(word(&format!("{n:x}"))))))),
        _ => None,
    })
}

fn at(next_block: u64, next_sequence: u64) -> Cursor {
    Cursor {
        next_block,
        next_sequence,
    }
}

// ---- BR-846: the EVM source ---------------------------------------------------

/// The auditor's two logs: a payload offset of 2^64-1 and a payload length of 2^64-1. Each was
/// an addition that overflowed, which the release profile (overflow checks on) and this debug
/// build both turn into a panic; the daemon loop awaits the source inline, so that was an exit.
#[tokio::test]
async fn br846_a_log_whose_offset_or_length_word_is_2_64_minus_1_is_an_error_not_a_panic() {
    for (what, bad) in [
        ("offset", raw_log(0, MAX64, "40", &payload(5), 50)),
        ("length", raw_log(0, "60", MAX64, &payload(5), 50)),
        // Neighbours of the same two sums: an offset that only overflows once 32 is added, and
        // a length that only overflows once the offset is.
        ("offset", raw_log(0, "ffffffffffffffe0", "40", &payload(5), 50)),
        ("length", raw_log(0, "60", "ffffffffffffff80", &payload(5), 50)),
        ("offset", raw_log(0, "ffffffffffffffff0000000000000060", "40", &payload(5), 50)),
    ] {
        let provider = node("64", Some(vec![bad]), Some(1));
        let source = EvmSource::new(&evm_cfg(&[&provider.url], None, Finality::Confirmations(10))).unwrap();
        let err = source.poll(&at(7, 0)).await.expect_err(what);
        let text = format!("{err:#}");
        assert!(
            text.contains("out of range") || text.contains("wider than its type"),
            "{what}: {text}"
        );
    }
}

/// A safe head of u64::MAX, by tag and by confirmation count, from a provider that serves the
/// range and from one that refuses it: `safe + 1` and `cursor + range` are no longer sums that
/// can overflow.
#[tokio::test]
async fn br846_a_safe_head_of_u64_max_is_an_error_not_a_panic() {
    for finality in [Finality::Tag("finalized".into()), Finality::Confirmations(0)] {
        // Refused, with the counter the cursor expects: the branch that computed `safe + 1`.
        let refusing = node(MAX64, None, Some(0));
        let source = EvmSource::new(&evm_cfg(&[&refusing.url], None, finality.clone())).unwrap();
        assert!(source.poll(&at(7, 0)).await.is_err());

        // Served: a cursor near the top of the range would overflow `cursor + max_log_range`
        // and then `to + 1`.
        let serving = node(MAX64, Some(vec![]), Some(0));
        let source = EvmSource::new(&evm_cfg(&[&serving.url], None, finality.clone())).unwrap();
        let err = source.poll(&at(u64::MAX - 5, 0)).await.unwrap_err();
        assert!(format!("{err:#}").contains("u64::MAX"), "{err:#}");
        // Far from the top the same head is only a head: one range is read and the cursor steps.
        let (none, next) = source.poll(&at(7, 0)).await.unwrap();
        assert!(none.is_empty());
        assert_eq!(next, at(2007, 0));
    }
}

/// A cursor whose sequence is u64::MAX and a log that carries it: the count past it does not fit.
#[tokio::test]
async fn br846_a_sequence_of_u64_max_is_an_error_not_a_panic() {
    let provider = node("64", Some(vec![raw_log(u64::MAX, "60", "53", &payload(5), 50)]), None);
    let source = EvmSource::new(&evm_cfg(&[&provider.url], None, Finality::Confirmations(10))).unwrap();
    assert!(source.poll(&at(7, u64::MAX)).await.is_err());
}

// ---- BR-846: the relayer's submitter -------------------------------------------

fn attestation() -> (Attestation, [u8; 32]) {
    let message = burn(0, 2, 50_000_000, 1_000_000);
    let signatures = guardian_keys(2)
        .iter()
        .enumerate()
        .map(|(i, k)| k.sign(&message.digest).unwrap().indexed(i as u8))
        .collect();
    (
        Attestation {
            guardian_set_index: 0,
            signatures,
            body: message.decoded(),
        },
        message.digest,
    )
}

/// A destination node that answers a release with `gas`, `tip` and `base_fee` as given.
fn destination(gas: &'static str, tip: &'static str, base_fee: &'static str) -> Fake {
    rpc(move |m, _| {
        Some(Ok(match m {
            "eth_call" => json!(format!("0x{:064x}", 0)),
            "eth_estimateGas" => json!(gas),
            "eth_chainId" => json!("0x7a69"),
            "eth_getTransactionCount" => json!("0x9"),
            "eth_maxPriorityFeePerGas" => json!(tip),
            "eth_getBlockByNumber" => json!({ "baseFeePerGas": base_fee }),
            "eth_sendRawTransaction" => json!("0xabc123"),
            "eth_getTransactionReceipt" => json!({ "status": "0x1" }),
            _ => return None,
        }))
    })
}

/// The submitter adds a fifth to the estimate and computes `2 * base fee + tip`. A node that
/// answers u64::MAX, u128::MAX or 2^256-1 gets an error back and no transaction: nothing is
/// signed over a number that did not fit.
#[tokio::test]
async fn br846_a_gas_estimate_or_fee_at_the_top_of_its_type_is_an_error_and_nothing_is_sent() {
    let u128_max = "0xffffffffffffffffffffffffffffffff";
    let u256_max = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    for (what, gas, tip, base_fee) in [
        ("gas estimate u64::MAX", "0xffffffffffffffff", "0x3b9aca00", "0x64"),
        ("gas estimate above u64", "0x10000000000000000", "0x3b9aca00", "0x64"),
        ("base fee u128::MAX", "0x186a0", "0x3b9aca00", u128_max),
        ("base fee 2^256-1", "0x186a0", "0x3b9aca00", u256_max),
        ("base fee whose double overflows", "0x186a0", "0x3b9aca00", "0x80000000000000000000000000000000"),
        ("tip u128::MAX", "0x186a0", u128_max, "0x64"),
        ("tip 2^256-1", "0x186a0", u256_max, "0x64"),
    ] {
        let dest = destination(gas, tip, base_fee);
        let cfg = evm_cfg(&[&dest.url], None, Finality::Tag("latest".into()));
        let submitter = EvmSubmitter::new(&cfg, KEY).unwrap();
        let (attestation, digest) = attestation();
        let result = submitter.release(&attestation, &digest).await;
        assert!(result.is_err(), "{what}: {result:?}");
        assert_eq!(dest.count("eth_sendRawTransaction"), 0, "{what}: nothing is sent");
    }
    // The ordinary answers still go through.
    let dest = destination("0x186a0", "0x3b9aca00", "0x64");
    let cfg = evm_cfg(&[&dest.url], None, Finality::Tag("latest".into()));
    let (attestation, digest) = attestation();
    EvmSubmitter::new(&cfg, KEY).unwrap().release(&attestation, &digest).await.unwrap();
    assert_eq!(dest.count("eth_sendRawTransaction"), 1);
}

// ---- BR-1008: one provider ------------------------------------------------------

/// The auditor's stub: it refuses the range and answers the `sequence()` the cursor expects,
/// while block 50 holds lock 0. That used to move the cursor to the safe head, past the lock.
/// A refusal is now an error and the cursor stays; the error says what an operator can do.
#[tokio::test]
async fn br1008_a_provider_that_refuses_a_range_never_moves_the_cursor() {
    let refuser = node("4e20", None, Some(0)); // head 20 000, "nothing published"
    for cfg in [
        evm_cfg(&[&refuser.url], None, Finality::Confirmations(15)),
        evm_cfg(&[&refuser.url], Some(1), Finality::Tag("finalized".into())),
    ] {
        // The bare source, and the same provider as a quorum of one (what the guardian runs).
        let bare = EvmSource::new(&cfg).unwrap();
        let err = format!("{:#}", bare.poll(&at(7, 0)).await.unwrap_err());
        assert!(err.contains("Archive requests") && err.contains("not served"), "{err}");
        let quorum = sources::evm_quorum(&cfg).unwrap();
        let err = format!("{:#}", quorum.poll(&at(7, 0)).await.unwrap_err());
        assert!(err.contains("not served") && err.contains("cursors/eth.json"), "{err}");
    }
}

/// Through the guardian's own step: the stored cursor is untouched and nothing is signed.
#[tokio::test]
async fn br1008_the_guardians_stored_cursor_does_not_move_on_a_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let store = bridge_daemons::store::Store::open(dir.path()).unwrap();
    let refuser = node("4e20", None, Some(0));
    let cfg = evm_cfg(&[&refuser.url], None, Finality::Confirmations(15));
    let source = sources::evm_quorum(&cfg).unwrap();
    store.set_cursor("eth", &at(7, 0)).unwrap();
    let key = &guardian_keys(1)[0];
    let emitters = bridge_daemons::message::Emitters::default();
    assert!(bridge_daemons::guardian::step(&source, &store, key, None, &emitters).await.is_err());
    assert_eq!(store.cursor("eth").unwrap(), Some(at(7, 0)));
}

// ---- BR-761: a provider quorum ----------------------------------------------------

/// The deadlock: the range is empty, one provider refuses it and one serves it. Before, the
/// refuser answered "empty, resume past my safe head" and the server "empty, resume after one
/// range"; the two never agreed, the poll returned Ok with the cursor unchanged, for ever, and
/// said so only at warn level. Now the refuser is not counted for the range, and whether the
/// cursor moves depends only on how many providers served it.
#[tokio::test]
async fn br761_a_refuser_is_not_counted_and_a_quorum_of_servers_catches_up() {
    let refuser = node("4e20", None, Some(0));
    let (b, c) = (node("4e20", Some(vec![]), Some(0)), node("4e20", Some(vec![]), Some(0)));
    let finality = Finality::Confirmations(15);

    // Two of three serve the empty range and agree: the cursor steps one range, in any order.
    for order in [[&refuser, &b, &c], [&b, &refuser, &c], [&b, &c, &refuser]] {
        let urls: Vec<&str> = order.iter().map(|f| f.url.as_str()).collect();
        let source = sources::evm_quorum(&evm_cfg(&urls, None, finality.clone())).unwrap();
        let (messages, next) = source.poll(&at(7, 0)).await.unwrap();
        assert!(messages.is_empty());
        assert_eq!(next, at(2007, 0), "one range, as the two that served it say");
    }

    // One of two serves it: short of a quorum. An error that names the range and what to do,
    // not a silent Ok — and never the refuser's jump.
    for order in [[&refuser, &b], [&b, &refuser]] {
        let source =
            sources::evm_quorum(&evm_cfg(&[&order[0].url, &order[1].url], None, finality.clone())).unwrap();
        let err = format!("{:#}", source.poll(&at(7, 0)).await.unwrap_err());
        assert!(
            err.contains("1 of 2") && err.contains("2 needed") && err.contains("[7, 2006]") && err.contains("halted"),
            "{err}"
        );
    }
}

/// The safety case. Block 50 holds lock 0. Refusers that answer the expected `sequence()` can
/// never be the reason the cursor passes it, however many there are.
#[tokio::test]
async fn br761_refusals_and_a_sequence_claim_cannot_skip_a_block_that_holds_a_lock() {
    let lock = vec![log(0, &payload(100_000_000), 50)];
    let finality = Finality::Confirmations(15);
    let (r1, r2) = (node("4e20", None, Some(0)), node("4e20", None, Some(0)));
    let honest = node("4e20", Some(lock.clone()), Some(1));

    // Two refusers of three, quorum two: before, the two agreed on "empty, resume at 19 986"
    // and the cursor jumped past the lock on the strength of two refusals.
    for order in [[&r1, &r2, &honest], [&honest, &r1, &r2], [&r1, &honest, &r2]] {
        let urls: Vec<&str> = order.iter().map(|f| f.url.as_str()).collect();
        let source = sources::evm_quorum(&evm_cfg(&urls, None, finality.clone())).unwrap();
        let err = format!("{:#}", source.poll(&at(7, 0)).await.unwrap_err());
        assert!(err.contains("1 of 3") && err.contains("halted"), "{err}");
    }

    // One refuser beside the honest provider, quorum two: the same.
    let source = sources::evm_quorum(&evm_cfg(&[&r1.url, &honest.url], None, finality.clone())).unwrap();
    assert!(source.poll(&at(7, 0)).await.is_err());

    // One refuser and two that serve the lock: it is read, and the cursor ends after the range.
    let honest2 = node("4e20", Some(lock), Some(1));
    let source =
        sources::evm_quorum(&evm_cfg(&[&r1.url, &honest.url, &honest2.url], None, finality.clone())).unwrap();
    let (messages, next) = source.poll(&at(7, 0)).await.unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].sequence, 0);
    assert_eq!(next, at(2007, 1));

    // One refuser, one that serves the lock, one that serves the range as empty: no two agree
    // on what the range holds, so nothing is read and nothing is passed over.
    let empty = node("4e20", Some(vec![]), Some(0));
    let source =
        sources::evm_quorum(&evm_cfg(&[&r1.url, &honest.url, &empty.url], None, finality)).unwrap();
    let (messages, next) = source.poll(&at(7, 0)).await.unwrap();
    assert!(messages.is_empty());
    assert_eq!(next, at(7, 0));
}

// ---- BR-1004: a planted deferred record -----------------------------------------

mod br1004 {
    use super::*;
    use bridge_daemons::guardian::{self, Guards};
    use bridge_daemons::limits::{self, Limits, LimitsConfig};
    use bridge_daemons::message::{Emitters, Observed};
    use bridge_daemons::sources::Located;
    use bridge_daemons::store::Store;

    const ETH: &str = "0x1111111111111111111111111111111111111111";

    fn emitters() -> Emitters {
        Emitters {
            rand: RAND_EMITTER,
            endpoints: vec![(2, word(ETH))],
        }
    }

    fn signed(store: &Store, chain: u16, sequence: u64) -> Option<Value> {
        store.read_message("signed", chain, sequence).unwrap()
    }

    fn plant(store: &Store, chain: u16, sequence: u64, record: Value) {
        store.write_message(limits::DEFERRED, chain, sequence, &record).unwrap();
    }

    fn record_of(m: &Observed) -> Value {
        json!({ "message": m, "at": 1, "kind": "window", "reason": "planted" })
    }

    /// The auditor's record: the body of a small burn, and beside it the digest of a burn of a
    /// million tokens. The retry signed the stored digest — a valid guardian signature over a
    /// burn the cap would have held — with no caps and no peers configured.
    #[tokio::test]
    async fn br1004_a_planted_record_whose_digest_is_not_its_bodys_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let key = &guardian_keys(1)[0];
        let (small, big) = (burn(7, 2, 100_000_000, 0), burn(7, 2, 100_000_000_000_000, 0));
        let mut record = record_of(&small);
        record["message"]["digest"] = json!(hex::encode(big.digest));
        plant(&store, 1, 7, record);

        let n = guardian::retry_deferred(&store, key, None, &emitters(), &Guards::default()).await.unwrap();
        assert_eq!(n, 0);
        assert!(signed(&store, 1, 7).is_none(), "no signature over the planted digest");
        assert_eq!(limits::listed(&store, limits::DEFERRED).unwrap(), vec![(1, 7)], "left for the operator");
    }

    /// A record that is consistent with itself but that this daemon never wrote — a burn no
    /// source ever showed it — and one filed under another sequence than its body's.
    #[tokio::test]
    async fn br1004_a_planted_record_this_guardian_did_not_seal_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let keys = guardian_keys(2);
        let invented = burn(3, 2, 50_000_000, 0);
        plant(&store, 1, 3, record_of(&invented));
        // Sealed, but by another guardian's key.
        let mut foreign = record_of(&burn(4, 2, 50_000_000, 0));
        foreign["seal"] = json!(limits::deferral_seal(&keys[1], &burn(4, 2, 50_000_000, 0)));
        plant(&store, 1, 4, foreign);
        // This guardian's seal over sequence 5, moved to sequence 6's place.
        let mut moved = record_of(&burn(5, 2, 50_000_000, 0));
        moved["seal"] = json!(limits::deferral_seal(&keys[0], &burn(5, 2, 50_000_000, 0)));
        plant(&store, 1, 6, moved);

        let n = guardian::retry_deferred(&store, &keys[0], None, &emitters(), &Guards::default()).await.unwrap();
        assert_eq!(n, 0);
        for sequence in [3, 4, 5, 6] {
            assert!(signed(&store, 1, sequence).is_none(), "sequence {sequence}");
        }
    }

    struct Batch(Vec<Located>, Cursor);

    impl Source for Batch {
        fn name(&self) -> &str {
            "batch"
        }
        fn start(&self) -> Cursor {
            Cursor::default()
        }
        async fn poll(&self, _: &Cursor) -> anyhow::Result<(Vec<Observed>, Cursor)> {
            Ok((self.0.iter().map(|l| l.message.clone()).collect(), self.1.clone()))
        }
    }

    /// What the daemon defers itself is still signed once its window has room; the same record
    /// edited on disk (another amount, digest recomputed to match) is not; and an unsealed
    /// record an operator vouches for goes through the caps like any other.
    #[tokio::test]
    async fn br1004_the_daemons_own_deferred_record_signs_and_an_edited_one_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let key = &guardian_keys(1)[0];
        let caps = Limits::new(&LimitsConfig {
            per_transfer: 1_000_000_000,
            per_window: 1_000_000_000,
            window_secs: 2,
            token: vec![],
        })
        .unwrap();
        let guards = Guards { limits: Some(&caps), ..Default::default() };
        let burns: Vec<Observed> = (0..3).map(|s| burn(s, 2, 600_000_000, 0)).collect();
        let source = Batch(
            burns.iter().map(|m| Located { message: m.clone(), resume: Cursor::default() }).collect(),
            at(0, 3),
        );
        assert_eq!(guardian::step_guarded(&source, &store, key, None, &emitters(), &guards).await.unwrap(), 1);
        assert_eq!(limits::listed(&store, limits::DEFERRED).unwrap(), vec![(1, 1), (1, 2)]);

        // Sequence 1 is edited in place: ten times the per-transfer cap, digest to match, the
        // daemon's seal left as it was.
        let mut edited: Value = store.read_message(limits::DEFERRED, 1, 1).unwrap().unwrap();
        assert!(edited["seal"].is_string(), "the daemon seals what it defers");
        edited["message"] = json!(burn(1, 2, 10_000_000_000, 0));
        plant(&store, 1, 1, edited);

        std::thread::sleep(std::time::Duration::from_millis(3100));
        let n = guardian::retry_deferred(&store, key, None, &emitters(), &guards).await.unwrap();
        assert_eq!(n, 1, "sequence 2, the daemon's own record; the edited one holds nothing back");
        assert!(signed(&store, 1, 1).is_none());
        assert_eq!(signed(&store, 1, 2).unwrap()["message"]["digest"], hex::encode(burns[2].digest));

        // An operator vouches for an unsealed record (one from before this build): it is then
        // checked like any other — here, over the per-transfer cap, so held and not signed.
        plant(&store, 1, 9, record_of(&burn(9, 2, 10_000_000_000, 0)));
        plant(&store, 1, 10, record_of(&burn(10, 2, 100_000_000, 0)));
        for sequence in [9, 10] {
            guardian::vouch_deferred(&store, key, 1, sequence).unwrap();
        }
        std::thread::sleep(std::time::Duration::from_millis(2100));
        guardian::retry_deferred(&store, key, None, &emitters(), &guards).await.unwrap();
        assert!(signed(&store, 1, 9).is_none() && limits::held(&store).unwrap().contains(&(1, 9)));
        assert!(signed(&store, 1, 10).is_some());
        // Vouching does not launder a record whose digest is not its body's.
        let mut bad = record_of(&burn(11, 2, 100_000_000, 0));
        bad["message"]["digest"] = json!(hex::encode(burns[0].digest));
        plant(&store, 1, 11, bad);
        assert!(guardian::vouch_deferred(&store, key, 1, 11).is_err());
    }
}
