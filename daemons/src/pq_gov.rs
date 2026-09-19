//! The Rand-only governance messages (`spec/PQ-COSIGNATURE.md` §8): fixed
//! big-endian layouts that an auditor or a hardware signer can reproduce by
//! hand. None of them ever reaches a source-chain endpoint.

use anyhow::{bail, Result};

use crate::pq::{self, PqKey, PqSignature};

pub const DOMAIN_PAUSE: &[u8] = b"rand-bridge-pause-1";
pub const DOMAIN_UNPAUSE: &[u8] = b"rand-bridge-pq-unpause-1";
pub const DOMAIN_LIST: &[u8] = b"rand-bridge-pq-list-1";
pub const DOMAIN_REGISTER: &[u8] = b"rand-bridge-pq-register-1";

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

/// Signed by a PQ guardian quorum.
pub fn unpause_message(rand_chain_id: u64, pause_nonce: u64) -> Vec<u8> {
    head(DOMAIN_UNPAUSE, rand_chain_id, pause_nonce)
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
