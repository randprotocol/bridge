//! `POST /v1/recipients`: a registration names a recipient hash and the
//! `rand1…` address it stands for. The relayer seals every Rand deposit to
//! the address it holds for the hash, so whoever can write that table decides
//! whether a deposit can be minted at all.

use bridge_daemons::relayer::{self, RegistrationError};
use bridge_daemons::store::Store;

/// A real chain-13 payout address and its recipient hash, the pair
/// randbridge.org's status service and the wallet core pin against
/// `ShieldedAddress::recipient_hash` (validators[0].payout of
/// fullnode/deploy/genesis-chain13.json).
const REAL: &str = include_str!("fixtures/rand-address.txt");
const REAL_HASH: &str = "58bbaf413a0a303a1740c286673f0ce74199c7b64d035a7a6772468bac66b972";

/// A well-formed address that is not the one `REAL_HASH` names.
fn other_address() -> String {
    format!("rand1{}", bs58::encode(vec![7u8; 32 + 1184]).into_string())
}

fn store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    (dir, store)
}

fn held(store: &Store) -> Option<String> {
    relayer::recipient_address(store, &bridge_daemons::config::hex32(REAL_HASH).unwrap()).unwrap()
}

#[test]
fn the_real_address_hashes_to_the_pinned_value() {
    assert_eq!(
        hex::encode(relayer::recipient_hash(REAL).unwrap()),
        REAL_HASH
    );
}

#[test]
fn an_honest_registration_is_accepted_and_can_be_repeated() {
    let (_dir, store) = store();
    relayer::register_request(&store, REAL_HASH, REAL).unwrap();
    relayer::register_request(&store, REAL_HASH, REAL).unwrap();
    assert_eq!(held(&store).as_deref(), Some(REAL));
}

#[test]
fn a_registration_whose_address_is_not_the_hash_preimage_is_refused() {
    let (_dir, store) = store();
    let refused = relayer::register_request(&store, REAL_HASH, &other_address());
    assert!(
        matches!(refused, Err(RegistrationError::HashMismatch)),
        "{refused:?}"
    );
    assert_eq!(held(&store), None);
}

#[test]
fn an_unauthenticated_overwrite_of_a_registration_is_refused() {
    let (_dir, store) = store();
    relayer::register_request(&store, REAL_HASH, REAL).unwrap();
    let refused = relayer::register_request(&store, REAL_HASH, &other_address());
    assert!(refused.is_err(), "the overwrite was accepted");
    assert_eq!(held(&store).as_deref(), Some(REAL));
}

#[test]
fn a_conflicting_entry_already_in_the_store_is_never_replaced() {
    // An entry written before registrations were checked (or by hand) is
    // the operator's; the API cannot replace it, even with the true preimage.
    let (_dir, store) = store();
    let hash = bridge_daemons::config::hex32(REAL_HASH).unwrap();
    relayer::register_recipient(&store, &hash, &other_address()).unwrap();
    let refused = relayer::register_request(&store, REAL_HASH, REAL);
    assert!(
        matches!(refused, Err(RegistrationError::AlreadyRegistered)),
        "{refused:?}"
    );
    assert_eq!(held(&store), Some(other_address()));
}

#[test]
fn malformed_input_is_refused() {
    let (_dir, store) = store();
    for (hash, address) in [
        ("zz", REAL),
        (REAL_HASH, "rond1abc"),
        (REAL_HASH, "rand10OIl"),
        (
            REAL_HASH,
            &*format!("rand1{}", bs58::encode([7u8; 32]).into_string()),
        ),
    ] {
        let refused = relayer::register_request(&store, hash, address);
        assert!(
            matches!(refused, Err(RegistrationError::BadRequest(_))),
            "{hash} {address}: {refused:?}"
        );
    }
    assert_eq!(held(&store), None);
}
