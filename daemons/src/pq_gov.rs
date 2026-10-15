//! The Rand-only governance messages (`spec/PQ-COSIGNATURE.md` §8): fixed
//! big-endian layouts that an auditor or a hardware signer can reproduce by
//! hand. None of them ever reaches a source-chain endpoint.
//!
//! Two binding forms (BRG-901). A chain cut without `binding_domain` in its
//! genesis (chains 14–19) verifies the §8 layouts, which bind the chain id
//! alone. A chain cut with `binding_domain: 1` (chain 20 onward) verifies the
//! genesis-bound form: the same message with the tag's version digit bumped
//! to `2` and the 32-byte genesis hash between the tag and the chain id —
//! `tag_v2 ‖ genesis [32] ‖ chain_id u64 ‖ nonce u64 ‖ tail` — so a pause or a
//! quorum signed for one chain verifies on no re-cut sharing its id. The
//! `*_message_in` functions build either from a [`BindingDomain`], byte for
//! byte what the fullnode verifies (`crates/randprotocol-core/src/bridge/gov.rs`).
//! Which form a chain takes is decided by its chain id, never by what a node
//! claims ([`binding_domain_for`]).

use anyhow::{bail, Result};

use crate::pq::{self, PqKey, PqSignature};

pub const DOMAIN_PAUSE: &[u8] = b"rand-bridge-pause-1";
pub const DOMAIN_UNPAUSE: &[u8] = b"rand-bridge-pq-unpause-1";
pub const DOMAIN_LIST: &[u8] = b"rand-bridge-pq-list-1";
pub const DOMAIN_REGISTER: &[u8] = b"rand-bridge-pq-register-1";

/// The genesis-bound tags: the §8 tags with their version digit at `2`.
pub const DOMAIN_PAUSE_V2: &[u8] = b"rand-bridge-pause-2";
pub const DOMAIN_UNPAUSE_V2: &[u8] = b"rand-bridge-pq-unpause-2";
pub const DOMAIN_LIST_V2: &[u8] = b"rand-bridge-pq-list-2";
pub const DOMAIN_REGISTER_V2: &[u8] = b"rand-bridge-pq-register-2";

/// The chain ids of every public Rand chain whose genesis carries no
/// `binding_domain`: chains 14–19. On these, and only these, a governance
/// message binds the chain id alone. Every later chain binds its genesis hash.
/// Mirrors the fullnode's `randprotocol_client::CHAIN_ID_BINDING_CHAIN_IDS`.
pub const CHAIN_ID_BINDING_CHAIN_IDS: &[u64] = &[14, 15, 16, 17, 18, 19];

/// What a governance message binds besides its chain id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingDomain {
    /// A chain cut without `binding_domain`: the §8 layouts.
    ChainId,
    /// A chain cut with `binding_domain: 1`: this genesis hash, under the `…-2` tags.
    Genesis([u8; 32]),
}

impl BindingDomain {
    /// One line for a signer's output: which form, and which genesis if any.
    pub fn describe(&self) -> String {
        match self {
            BindingDomain::ChainId => "chain id only (the `…-1` layouts, chains 14-19)".into(),
            BindingDomain::Genesis(g) => {
                format!("genesis {} (the `…-2` layouts)", hex::encode(g))
            }
        }
    }
}

/// The binding a message for `rand_chain_id` takes, given the chain's genesis
/// hash when the caller has one. Decided by the chain id: a chain in
/// [`CHAIN_ID_BINDING_CHAIN_IDS`] takes the chain-id form and refuses a
/// genesis (the real chain with that id accepts nothing else); every other
/// chain needs its genesis hash and takes the genesis-bound form.
pub fn binding_domain_for(rand_chain_id: u64, genesis: Option<[u8; 32]>) -> Result<BindingDomain> {
    if CHAIN_ID_BINDING_CHAIN_IDS.contains(&rand_chain_id) {
        if genesis.is_some() {
            bail!(
                "Rand chain {rand_chain_id} was cut without binding_domain and signs the chain-id \
                 form: drop the genesis hash"
            );
        }
        return Ok(BindingDomain::ChainId);
    }
    match genesis {
        Some(g) => Ok(BindingDomain::Genesis(g)),
        None => bail!(
            "Rand chain {rand_chain_id} binds its genesis hash (binding_domain 1): pass the \
             32-byte genesis hash (--genesis <hex>, or --rand-rpc <url> to read \
             rand_getGenesisHash)"
        ),
    }
}

/// `v1` as it stands under [`BindingDomain::ChainId`]; under `Genesis`, `v1`
/// with its tag (`tag`, a prefix of it) replaced by `tag_v2 ‖ genesis`.
fn rebind(domain: &BindingDomain, tag: &[u8], tag_v2: &[u8], v1: Vec<u8>) -> Vec<u8> {
    match domain {
        BindingDomain::ChainId => v1,
        BindingDomain::Genesis(genesis) => {
            let mut m = Vec::with_capacity(tag_v2.len() + 32 + v1.len() - tag.len());
            m.extend_from_slice(tag_v2);
            m.extend_from_slice(genesis);
            m.extend_from_slice(&v1[tag.len()..]);
            m
        }
    }
}

fn head(domain: &[u8], rand_chain_id: u64, nonce: u64) -> Vec<u8> {
    let mut m = domain.to_vec();
    m.extend_from_slice(&rand_chain_id.to_be_bytes());
    m.extend_from_slice(&nonce.to_be_bytes());
    m
}

/// Signed by the one genesis pause key. It can pause minting, never unpause.
pub fn pause_message(rand_chain_id: u64, pause_nonce: u64) -> Vec<u8> {
    head(DOMAIN_PAUSE, rand_chain_id, pause_nonce)
}

/// [`pause_message`] on a chain of `domain`.
pub fn pause_message_in(domain: &BindingDomain, rand_chain_id: u64, pause_nonce: u64) -> Vec<u8> {
    rebind(
        domain,
        DOMAIN_PAUSE,
        DOMAIN_PAUSE_V2,
        pause_message(rand_chain_id, pause_nonce),
    )
}

/// Signed by a PQ guardian quorum.
pub fn unpause_message(rand_chain_id: u64, pause_nonce: u64) -> Vec<u8> {
    head(DOMAIN_UNPAUSE, rand_chain_id, pause_nonce)
}

/// [`unpause_message`] on a chain of `domain`.
pub fn unpause_message_in(domain: &BindingDomain, rand_chain_id: u64, pause_nonce: u64) -> Vec<u8> {
    rebind(
        domain,
        DOMAIN_UNPAUSE,
        DOMAIN_UNPAUSE_V2,
        unpause_message(rand_chain_id, pause_nonce),
    )
}

/// One backing: a coin on a source chain, as the endpoint names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Backing {
    /// Bridge chain id, 2..=5.
    pub chain: u16,
    /// The 32-byte wire form of the token (`docs/architecture.md` §10.1).
    pub token: [u8; 32],
    /// The coin's decimals on its own chain.
    pub decimals: u8,
}

fn backing_tail(m: &mut Vec<u8>, b: &Backing) {
    m.extend_from_slice(&b.chain.to_be_bytes());
    m.extend_from_slice(&b.token);
    m.push(b.decimals);
}

/// `ListBacking`: add `backing` to the bridged token at `token_index`.
pub fn list_message(
    rand_chain_id: u64,
    list_nonce: u64,
    token_index: u32,
    backing: &Backing,
) -> Vec<u8> {
    let mut m = head(DOMAIN_LIST, rand_chain_id, list_nonce);
    m.extend_from_slice(&token_index.to_be_bytes());
    backing_tail(&mut m, backing);
    m
}

/// [`list_message`] on a chain of `domain`.
pub fn list_message_in(
    domain: &BindingDomain,
    rand_chain_id: u64,
    list_nonce: u64,
    token_index: u32,
    backing: &Backing,
) -> Vec<u8> {
    rebind(
        domain,
        DOMAIN_LIST,
        DOMAIN_LIST_V2,
        list_message(rand_chain_id, list_nonce, token_index, backing),
    )
}

/// `RegisterBridgedToken`: a new bridged token with its first backing.
pub fn register_message(
    rand_chain_id: u64,
    list_nonce: u64,
    name: &str,
    symbol: &str,
    salt: &[u8; 32],
    backing: &Backing,
) -> Result<Vec<u8>> {
    if name.is_empty() || name.len() > 255 || symbol.is_empty() || symbol.len() > 255 {
        bail!("name and symbol are 1..=255 bytes (a u8 length prefix)");
    }
    let mut m = head(DOMAIN_REGISTER, rand_chain_id, list_nonce);
    m.push(name.len() as u8);
    m.extend_from_slice(name.as_bytes());
    m.push(symbol.len() as u8);
    m.extend_from_slice(symbol.as_bytes());
    m.extend_from_slice(salt);
    backing_tail(&mut m, backing);
    Ok(m)
}

/// [`register_message`] on a chain of `domain`.
pub fn register_message_in(
    domain: &BindingDomain,
    rand_chain_id: u64,
    list_nonce: u64,
    name: &str,
    symbol: &str,
    salt: &[u8; 32],
    backing: &Backing,
) -> Result<Vec<u8>> {
    let v1 = register_message(rand_chain_id, list_nonce, name, symbol, salt, backing)?;
    Ok(rebind(domain, DOMAIN_REGISTER, DOMAIN_REGISTER_V2, v1))
}

/// A PQ guardian quorum over an arbitrary governance message: each seed is
/// matched to `pq_guardians` by public key, exactly a quorum is kept (lowest
/// indices first) and the result is checked under the ledger's five rules.
pub fn sign_quorum(
    message: &[u8],
    pq_guardians: &[Vec<u8>],
    signers: &[PqKey],
) -> Result<Vec<PqSignature>> {
    let mut found = Vec::new();
    for key in signers {
        let Some(index) = pq_guardians.iter().position(|k| *k == key.public_key()) else {
            bail!("a signer's key is not in pq_guardians");
        };
        found.push((index as u8, key.sign_raw(message)));
    }
    let Some(quorum) = pq::assemble_raw(&found, pq_guardians, message) else {
        bail!(
            "{} signers, but {} keys need {}",
            found.len(),
            pq_guardians.len(),
            pq::quorum(pq_guardians.len())
        );
    };
    if let Err(e) = pq::check_raw(&quorum, pq_guardians, message) {
        bail!("self-check failed: {e:?}");
    }
    Ok(quorum)
}
