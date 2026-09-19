//! The Dilithium2 co-signature on Rand mints (`spec/PQ-COSIGNATURE.md`): a
//! second, post-quantum quorum by the same guardians, carried beside the
//! attestation and verified by the Rand ledger only.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Result};
use crystals_dilithium::dilithium2;
use serde::{Deserialize, Serialize};

pub const DOMAIN: &[u8] = b"rand-bridge-pq-cosign-1";
pub const PUBLIC_KEY_LEN: usize = dilithium2::PUBLICKEYBYTES;
pub const SIGNATURE_LEN: usize = dilithium2::SIGNBYTES;

/// `M = domain ‖ rand_chain_id (u64 BE) ‖ mu`: what a co-signature is over.
/// The chain id is what an attestation alone lacks — a testnet co-signature
/// does not verify on a mainnet Rand chain, whatever keys were reused.
pub fn message(rand_chain_id: u64, mu: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(DOMAIN.len() + 8 + 32);
    m.extend_from_slice(DOMAIN);
    m.extend_from_slice(&rand_chain_id.to_be_bytes());
    m.extend_from_slice(mu);
    m
}

/// A guardian's post-quantum key, derived from its 32-byte seed exactly as
/// the Rand node derives a validator key. Never printed, never serialised.
pub struct PqKey {
    keypair: dilithium2::Keypair,
}

impl PqKey {
    /// `0x` + 64 hex, or 64 hex: the seed.
    pub fn from_seed_hex(seed: &str) -> Result<PqKey> {
        let bytes = hex::decode(seed.trim().trim_start_matches("0x"))
            .map_err(|_| anyhow!("PQ seed is not hex"))?;
        if bytes.len() != 32 {
            bail!("PQ seed must be 32 bytes");
        }
        let keypair = dilithium2::Keypair::generate(Some(&bytes))
            .map_err(|e| anyhow!("PQ key generation: {e:?}"))?;
        Ok(PqKey { keypair })
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.keypair.public.to_bytes().to_vec()
    }

    /// Deterministic, so the vectors reproduce byte for byte.
    pub fn sign(&self, rand_chain_id: u64, mu: &[u8; 32]) -> Vec<u8> {
        self.keypair.sign(&message(rand_chain_id, mu)).to_vec()
    }
}

pub fn verify(public_key: &[u8], rand_chain_id: u64, mu: &[u8; 32], signature: &[u8]) -> bool {
    if signature.len() != SIGNATURE_LEN {
        return false;
    }
    match dilithium2::PublicKey::from_bytes(public_key) {
        Ok(pk) => pk.verify(&message(rand_chain_id, mu), signature),
        Err(_) => false,
    }
}

/// One entry of `BridgeAttest::pq_signatures`, as `rand bridge-mint --pq` reads it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSignature {
    pub index: u8,
    /// Hex, exactly 2,420 bytes.
    pub signature: String,
}

/// Why the ledger would refuse a `pq_signatures` list (spec §4).
#[derive(Debug, PartialEq, Eq)]
pub enum PqError {
    PqNoQuorum,
    PqIndexOrder,
    PqIndexOutOfRange,
    PqBadSignatureLength,
    PqBadSignature,
}

pub fn quorum(n: usize) -> usize {
    n * 2 / 3 + 1
}

/// The ledger's rules, mirrored: the relayer checks what it is about to
/// submit, and the vectors pin this function to the fullnode's.
pub fn check(
    list: &[PqSignature],
    pq_guardians: &[Vec<u8>],
    rand_chain_id: u64,
    mu: &[u8; 32],
) -> Result<(), PqError> {
    let n = pq_guardians.len();
    if list.len() < quorum(n) || list.len() > n {
        return Err(PqError::PqNoQuorum);
    }
    for pair in list.windows(2) {
        if pair[1].index <= pair[0].index {
            return Err(PqError::PqIndexOrder);
        }
    }
    if list.iter().any(|s| usize::from(s.index) >= n) {
        return Err(PqError::PqIndexOutOfRange);
    }
    let mut decoded = Vec::with_capacity(list.len());
    for s in list {
        match hex::decode(&s.signature) {
            Ok(bytes) if bytes.len() == SIGNATURE_LEN => decoded.push(bytes),
            _ => return Err(PqError::PqBadSignatureLength),
        }
    }
    for (s, bytes) in list.iter().zip(&decoded) {
        if !verify(
            &pq_guardians[usize::from(s.index)],
            rand_chain_id,
            mu,
            bytes,
        ) {
            return Err(PqError::PqBadSignature);
        }
    }
    Ok(())
}

/// Exactly a quorum, lowest indices first, out of co-signatures that each
/// verify under the key at their index. `None` short of a quorum.
pub fn assemble(
    found: &[(u8, Vec<u8>)],
    pq_guardians: &[Vec<u8>],
    rand_chain_id: u64,
    mu: &[u8; 32],
) -> Option<Vec<PqSignature>> {
    let mut by_index: BTreeMap<u8, &Vec<u8>> = BTreeMap::new();
    for (index, signature) in found {
        let Some(key) = pq_guardians.get(usize::from(*index)) else {
            continue;
        };
        if verify(key, rand_chain_id, mu, signature) {
            by_index.entry(*index).or_insert(signature);
        }
    }
    let need = quorum(pq_guardians.len());
    if by_index.len() < need {
        return None;
    }
    Some(
        by_index
            .into_iter()
            .take(need)
            .map(|(index, s)| PqSignature {
                index,
                signature: hex::encode(s),
            })
            .collect(),
    )
}
