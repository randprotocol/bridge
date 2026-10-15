//! The Rand-only governance messages in both binding forms (BRG-901): the
//! chain-id layouts of `spec/PQ-COSIGNATURE.md` §8 (chains 14–19) and the
//! genesis-bound `…-2` layouts a chain cut with `binding_domain: 1` verifies
//! (chain 20 onward; fullnode `crates/randprotocol-core/src/bridge/gov.rs`,
//! the `*_message_in` functions). The expected bytes below were written out
//! by hand from the fullnode's layout — tag, genesis hash, chain id, nonce,
//! tail, all big-endian — not produced by the code under test.

use bridge_daemons::pq_gov::{self, Backing, BindingDomain};

/// Chain 21's genesis hash (fullnode `deploy/cut-records/chain21.record`).
const CHAIN21_GENESIS: &str = "ca76c2766ed6090ac6ba5dad86b724dd5d2b80c0edfaed287cd8b129e663ca9a";

fn genesis() -> [u8; 32] {
    hex::decode(CHAIN21_GENESIS).unwrap().try_into().unwrap()
}

fn usdt() -> Backing {
    let mut token = [0u8; 32];
    token[12..].copy_from_slice(&hex::decode("dac17f958d2ee523a2206206994597c13d831ec7").unwrap());
    Backing {
        chain: 2,
        token,
        decimals: 6,
    }
}

#[test]
fn chain_21_pause_and_unpause_bind_the_genesis_hash_under_the_v2_tags() {
    let d = BindingDomain::Genesis(genesis());
    // "rand-bridge-pause-2" ‖ genesis ‖ 21 ‖ 3
    assert_eq!(
        hex::encode(pq_gov::pause_message_in(&d, 21, 3)),
        "72616e642d6272696467652d70617573652d32ca76c2766ed6090ac6ba5dad86b724dd5d2b80c0edfaed287cd8b129e663ca9a00000000000000150000000000000003"
    );
    // "rand-bridge-pq-unpause-2" ‖ genesis ‖ 21 ‖ 3
    assert_eq!(
        hex::encode(pq_gov::unpause_message_in(&d, 21, 3)),
        "72616e642d6272696467652d70712d756e70617573652d32ca76c2766ed6090ac6ba5dad86b724dd5d2b80c0edfaed287cd8b129e663ca9a00000000000000150000000000000003"
    );
}

#[test]
fn chain_21_list_and_register_bind_the_genesis_hash_under_the_v2_tags() {
    let d = BindingDomain::Genesis(genesis());
    // "rand-bridge-pq-list-2" ‖ genesis ‖ 21 ‖ 2 ‖ token_index 1 ‖ chain 2 ‖ USDT ‖ 6
    assert_eq!(
        hex::encode(pq_gov::list_message_in(&d, 21, 2, 1, &usdt())),
        "72616e642d6272696467652d70712d6c6973742d32ca76c2766ed6090ac6ba5dad86b724dd5d2b80c0edfaed287cd8b129e663ca9a00000000000000150000000000000002000000010002000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec706"
    );
    // "rand-bridge-pq-register-2" ‖ genesis ‖ 21 ‖ 2 ‖ 12 "Shielded USD" ‖ 4 "zUSD" ‖ salt 5a×32 ‖ chain 2 ‖ USDT ‖ 6
    assert_eq!(
        hex::encode(
            pq_gov::register_message_in(&d, 21, 2, "Shielded USD", "zUSD", &[0x5a; 32], &usdt())
                .unwrap()
        ),
        "72616e642d6272696467652d70712d72656769737465722d32ca76c2766ed6090ac6ba5dad86b724dd5d2b80c0edfaed287cd8b129e663ca9a000000000000001500000000000000020c536869656c64656420555344047a5553445a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a0002000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec706"
    );
    // The register bounds still hold under either form.
    assert!(pq_gov::register_message_in(&d, 21, 2, "", "zUSD", &[0; 32], &usdt()).is_err());
}

#[test]
fn the_chain_id_form_is_the_v1_message_and_the_genesis_form_is_v1_behind_the_hash() {
    let v0 = BindingDomain::ChainId;
    let (ga, gb) = (
        BindingDomain::Genesis([0xa; 32]),
        BindingDomain::Genesis([0xb; 32]),
    );
    let b = usdt();
    let all = |d: &BindingDomain| -> Vec<Vec<u8>> {
        vec![
            pq_gov::pause_message_in(d, 7, 9),
            pq_gov::unpause_message_in(d, 7, 9),
            pq_gov::list_message_in(d, 7, 9, 3, &b),
            pq_gov::register_message_in(d, 7, 9, "Shielded USD", "zUSD", &[0x5a; 32], &b).unwrap(),
        ]
    };
    let v1 = vec![
        pq_gov::pause_message(7, 9),
        pq_gov::unpause_message(7, 9),
        pq_gov::list_message(7, 9, 3, &b),
        pq_gov::register_message(7, 9, "Shielded USD", "zUSD", &[0x5a; 32], &b).unwrap(),
    ];
    assert_eq!(
        all(&v0),
        v1,
        "the chain-id domain is the §8 message, byte for byte"
    );
    // "rand-bridge-pause-1" ‖ 14 ‖ 3: the chain-14 form stands.
    assert_eq!(
        hex::encode(pq_gov::pause_message_in(&v0, 14, 3)),
        "72616e642d6272696467652d70617573652d31000000000000000e0000000000000003"
    );

    let tags: [(&[u8], &[u8]); 4] = [
        (pq_gov::DOMAIN_PAUSE, pq_gov::DOMAIN_PAUSE_V2),
        (pq_gov::DOMAIN_UNPAUSE, pq_gov::DOMAIN_UNPAUSE_V2),
        (pq_gov::DOMAIN_LIST, pq_gov::DOMAIN_LIST_V2),
        (pq_gov::DOMAIN_REGISTER, pq_gov::DOMAIN_REGISTER_V2),
    ];
    let (on_a, on_b) = (all(&ga), all(&gb));
    for (i, (tag, tag_v2)) in tags.iter().enumerate() {
        assert_eq!(
            tag_v2.len(),
            tag.len(),
            "kind {i}: only the version digit moves"
        );
        assert_eq!(&tag_v2[..tag.len() - 1], &tag[..tag.len() - 1]);
        assert_eq!(tag_v2[tag.len() - 1], b'2');
        let m = &on_a[i];
        assert_eq!(&m[..tag.len()], *tag_v2, "kind {i}");
        assert_eq!(
            &m[tag.len()..tag.len() + 32],
            &[0xa; 32],
            "kind {i}: the genesis follows the tag"
        );
        assert_eq!(
            &m[tag.len() + 32..],
            &v1[i][tag.len()..],
            "kind {i}: then the v1 bytes"
        );
        assert_ne!(
            on_a[i], on_b[i],
            "kind {i}: another genesis is another message"
        );
        assert_ne!(
            on_a[i], v1[i],
            "kind {i}: the genesis form is never the chain-id form"
        );
    }
}

#[test]
fn the_binding_domain_is_decided_by_the_chain_id() {
    // Chains 14–19 were cut without `binding_domain`: the chain-id form, a genesis is not needed.
    for id in 14..=19u64 {
        assert_eq!(
            pq_gov::binding_domain_for(id, None).unwrap(),
            BindingDomain::ChainId
        );
    }
    // Chain 20 onward binds the genesis hash: without it there is no message to sign.
    for id in [20u64, 21, 22, 99] {
        let err = pq_gov::binding_domain_for(id, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("genesis"), "{err}");
        assert_eq!(
            pq_gov::binding_domain_for(id, Some(genesis())).unwrap(),
            BindingDomain::Genesis(genesis())
        );
    }
    // A genesis handed in for a chain-id chain is a mistake worth refusing: the real chain with
    // that id accepts nothing but the chain-id form.
    let err = pq_gov::binding_domain_for(14, Some(genesis()))
        .unwrap_err()
        .to_string();
    assert!(err.contains("chain 14"), "{err}");
    assert_eq!(
        pq_gov::CHAIN_ID_BINDING_CHAIN_IDS,
        &[14, 15, 16, 17, 18, 19]
    );
}
