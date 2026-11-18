//! BR-402: how many guardians are signing, against the quorum — computed from
//! each guardian's `/v1/health` and the registered set, and reported by
//! `rand-bridge-audit --headroom`.

mod common;

use std::process::Command;

use bridge_daemons::api::{self, Health};
use bridge_daemons::headroom::{self, pq_key_id, quorum, Line, Probe};
use bridge_daemons::pq::PqKey;
use bridge_daemons::store::Store;
use common::*;
use serde_json::json;

fn pk(i: u8) -> Vec<u8> {
    PqKey::from_seed_hex(&format!("{:064x}", 0x300 + u64::from(i))).unwrap().public_key()
}

fn addr(i: u8) -> [u8; 20] {
    [i; 20]
}

fn health(i: u8, pq: Option<u8>, paused: bool) -> Result<Health, String> {
    Ok(Health {
        guardian: hex::encode(addr(i)),
        paused: paused.then(|| "since 1: drill".to_string()),
        held: vec![],
        deferred: vec![],
        pq_key_sha256: pq.map(|k| pq_key_id(&pk(k))),
    })
}

fn probes(list: Vec<Result<Health, String>>) -> Vec<Probe> {
    list.into_iter().enumerate().map(|(i, health)| Probe { origin: format!("g{i}"), health }).collect()
}

fn set(n: u8) -> (Vec<[u8; 20]>, Vec<Vec<u8>>) {
    ((1..=n).map(addr).collect(), (1..=n).map(pk).collect())
}

#[test]
fn the_quorum_is_two_thirds_plus_one() {
    assert_eq!((quorum(8), quorum(6), quorum(10), quorum(1)), (6, 5, 7, 1));
}

#[test]
fn six_of_eight_running_is_exactly_the_quorum_with_no_spare() {
    let (guardians, pq) = set(8);
    // The live shape: six answer, 7 and 8 do not.
    let mut list: Vec<_> = (1..=6).map(|i| health(i, Some(i), false)).collect();
    list.push(Err("connection refused".into()));
    list.push(Err("connection refused".into()));
    let r = headroom::report(&guardians, &pq, &probes(list));
    assert_eq!((r.registered, r.quorum, r.signing, r.spare()), (8, 6, 6, 0));
    assert_eq!(r.missing, vec![6, 7]);
    assert_eq!(r.pq_spare(), Some(0));
    assert!(r.ok(0) && !r.ok(1), "no spare is an alert at the default");
    let text = headroom::render(&r, 1);
    assert!(text.contains("registered guardians: 8; signatures required: 6"), "{text}");
    assert!(text.contains("releases: 6 of 6 required are signing; NO SPARE"), "{text}");
    assert!(text.contains("mints: 6 of 6 required PQ co-signers are signing; NO SPARE"), "{text}");
    assert!(text.contains("no origin answered as registered guardian(s) 6, 7") && text.contains("ALERT"), "{text}");
    // All eight: two spare.
    let r = headroom::report(&guardians, &pq, &probes((1..=8).map(|i| health(i, Some(i), false)).collect()));
    assert_eq!((r.spare(), r.pq_spare()), (2, Some(2)));
    assert!(r.ok(1) && headroom::render(&r, 1).contains("OK"));
    // Five: below quorum.
    let r = headroom::report(&guardians, &pq, &probes((1..=5).map(|i| health(i, Some(i), false)).collect()));
    assert_eq!(r.spare(), -1);
    assert!(headroom::render(&r, 1).contains("BELOW QUORUM by 1"));
}

#[test]
fn only_a_registered_unpaused_guardian_counts_and_only_once() {
    let (guardians, pq) = set(4); // quorum 3
    let r = headroom::report(
        &guardians,
        &pq,
        &probes(vec![
            health(1, Some(1), false),
            health(1, Some(1), false), // a second origin for guardian 1
            health(2, Some(2), true),  // paused
            health(9, Some(9), false), // not in the set
            health(3, Some(3), false),
        ]),
    );
    assert_eq!(r.signing, 2);
    assert!(matches!(r.lines[1].1, Line::Duplicate { index: 0 }));
    assert!(matches!(r.lines[2].1, Line::Paused { index: 1, .. }));
    assert!(matches!(r.lines[3].1, Line::NotRegistered { .. }));
    assert_eq!(r.missing, vec![3], "a paused guardian answered; it is not missing");
    assert_eq!(r.spare(), -1);
}

#[test]
fn a_pq_key_counts_only_when_it_is_the_registered_one_at_that_index() {
    let (guardians, pq) = set(4);
    let r = headroom::report(
        &guardians,
        &pq,
        &probes(vec![
            health(1, Some(1), false),
            health(2, Some(3), false), // guardian 2 runs guardian 3's key: wrong index
            health(3, None, false),    // an older build, or no seed: not known
            health(4, Some(4), false),
        ]),
    );
    assert_eq!(r.signing, 4);
    let p = r.pq.clone().unwrap();
    assert_eq!((p.signing, p.unknown, p.quorum), (2, 1, 3));
    assert_eq!(r.pq_spare(), Some(-1), "unknown is not counted as present");
    assert!(!r.ok(0), "releases have a spare; mints do not");
    let text = headroom::render(&r, 0);
    assert!(text.contains("NOT the registered one") && text.contains("not reported by this build") && text.contains("1 more unknown"), "{text}");
    // A chain without the co-signature has no PQ line.
    let r = headroom::report(&guardians, &[], &probes((1..=4).map(|i| health(i, None, false)).collect()));
    assert!(r.pq.is_none() && r.ok(1));
}

// ---- the guardian's health, and the binary --------------------------------------

async fn serve(router: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    url
}

#[tokio::test(flavor = "multi_thread")]
async fn the_audit_counts_live_guardians_against_the_registered_set() {
    let keys = guardian_keys(4);
    let dirs: Vec<_> = (0..4).map(|_| tempfile::tempdir().unwrap()).collect();
    let pqs: Vec<Vec<u8>> = (1..=4).map(pk).collect();
    // Guardians 0-2 run; 0 and 1 report their PQ key, 2 is a build that does not; 3 is down.
    let mut origins = Vec::new();
    for i in 0..3 {
        let store = Store::open(dirs[i].path()).unwrap();
        let router = if i < 2 {
            api::router_with_pq(store, keys[i].address(), Some(&pqs[i]))
        } else {
            api::router(store, keys[i].address())
        };
        origins.push(serve(router).await);
    }
    origins.push(format!("http://127.0.0.1:{}", free_port()));
    // The health record names the key by its hash; a client of an older build ignores the field.
    let h = api::GuardianClient::new(&origins[0]).health().await.unwrap();
    assert_eq!(h.pq_key_sha256, Some(pq_key_id(&pqs[0])));
    assert!(api::GuardianClient::new(&origins[2]).health().await.unwrap().pq_key_sha256.is_none());

    let addresses: Vec<String> = keys.iter().map(|k| format!("0x{}", hex::encode(k.address()))).collect();
    let pq_hex: Vec<String> = pqs.iter().map(hex::encode).collect();
    let node = rpc(move |m, _| match m {
        "rand_getBridgeState" => Some(Ok(json!({
            "enabled": true, "guardian_set_index": 1, "guardians": addresses, "burn_sequence": 0, "pq_guardians": pq_hex,
        }))),
        _ => None,
    });
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let list = origins.iter().map(|o| format!("{o:?}")).collect::<Vec<_>>().join(", ");
    std::fs::write(
        &path,
        format!(
            "data_dir = {:?}\n[rand]\nrpc = {:?}\nemitter = {:?}\n[relayer]\nguardians = [{list}]\n",
            dir.path().join("data"),
            node.url,
            hex::encode(RAND_EMITTER)
        ),
    )
    .unwrap();
    let run = |extra: Vec<String>| {
        let path = path.clone();
        tokio::task::spawn_blocking(move || {
            let o = Command::new(env!("CARGO_BIN_EXE_rand-bridge-audit"))
                .env_remove("RAND_BRIDGE_CONFIG")
                .arg("--config")
                .arg(&path)
                .arg("--headroom")
                .args(extra)
                .output()
                .unwrap();
            (o.status.success(), String::from_utf8_lossy(&o.stdout).to_string(), String::from_utf8_lossy(&o.stderr).to_string())
        })
    };
    // 3 of 4 signing at a quorum of 3: no spare, which is an alert at the default.
    let (ok, out, err) = run(vec![]).await.unwrap();
    assert!(!ok && err.contains("BR-402"), "{out}\n{err}");
    assert!(out.contains("releases: 3 of 3 required are signing; NO SPARE"), "{out}");
    assert!(out.contains("mints: 2 of 3 required PQ co-signers are signing (1 more unknown, not counted); BELOW QUORUM by 1"), "{out}");
    assert!(out.contains("DOWN:") && out.contains("registered guardian(s) 3") && out.contains("ALERT"), "{out}");
    // Asking for no spare still fails: the PQ side is short.
    let (ok, _, _) = run(vec!["--min-spare".into(), "0".into()]).await.unwrap();
    assert!(!ok);
    // Only the two that report the right key, at no spare, on a narrower question: still short of 3.
    let (ok, out, _) = run(vec!["--min-spare".into(), "0".into(), "--guardian-origins".into(), origins[..2].join(",")]).await.unwrap();
    assert!(!ok && out.contains("BELOW QUORUM by 1"), "{out}");
    // The node was only read.
    assert_eq!(node.rpc_methods().into_iter().collect::<std::collections::BTreeSet<_>>().len(), 1);
}
