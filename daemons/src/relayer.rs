//! The relayer: observe a message, collect a quorum of guardian signatures
//! over it, assemble the attestation, submit it where it is addressed.
//!
//! A relayer holds no authority. Everything it submits is verified on the
//! destination chain, so the worst a faulty relayer can do is fail to relay —
//! and anyone else may run another.

use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use bridge_codec::{quorum, Attestation, Payload, CHAIN_RAND, CHAIN_SOLANA};

use crate::api::{Collected, GuardianClient};
use crate::crypto::RawSignature;
use crate::message::Observed;
use crate::pq::{self, PqSignature};
use crate::sources::Source;
use crate::store::Store;
use crate::submit::evm::EvmSubmitter;
use crate::submit::process::{RandSubmitter, SolanaSubmitter};
use crate::submit::tron::TronSubmitter;
use crate::submit::Outcome;

pub const OBSERVED: &str = "observed";
pub const DONE: &str = "done";
pub const RECIPIENTS: &str = "recipients";

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Done {
    pub digest: String,
    pub to_chain: u16,
    pub outcome: Outcome,
}

/// The guardian set attestations are assembled under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardianSet {
    pub index: u32,
    pub keys: Vec<[u8; 20]>,
    /// Dilithium2 keys, index-aligned with `keys`, and the Rand chain id the
    /// co-signatures name. Empty / `None` when Rand does not require them.
    pub pq_keys: Vec<Vec<u8>>,
    pub rand_chain_id: Option<u64>,
}

/// Builds the attestation for `message` from whatever signatures are in
/// hand, or `None` short of a quorum.
///
/// Exactly a quorum is used, lowest indices first: every extra signature is
/// 66 bytes and one more recovery the submitter pays for, and on Solana the
/// transaction size leaves no slack. Indices come out strictly increasing,
/// each signer counted once, as every verifier requires.
pub fn assemble(
    message: &Observed,
    set: &GuardianSet,
    signatures: &[([u8; 20], RawSignature)],
) -> Option<Attestation> {
    assemble_inner(message, set, signatures)
}

/// The Dilithium2 quorum for a message addressed to Rand: each guardian's
/// co-signature is filed under the index its ECDSA address has in the set,
/// verified, and exactly a quorum kept (`spec/PQ-COSIGNATURE.md` §6).
pub fn assemble_pq(
    message: &Observed,
    set: &GuardianSet,
    collected: &[Collected],
) -> Option<Vec<PqSignature>> {
    let chain_id = set.rand_chain_id?;
    let found: Vec<(u8, Vec<u8>)> = collected
        .iter()
        .filter_map(|c| {
            let signature = c.pq_signature.clone()?;
            // Normally a guardian's PQ key sits at the index of its ECDSA
            // key. It need not: the PQ set does not move with an ECDSA
            // rotation (spec §5), and chain 14 starts with `guardians` at set
            // 0 while `pq_guardians` belongs to set 1's operators. So the
            // index is whichever PQ key the co-signature verifies under,
            // trying the aligned one first.
            let aligned = set.keys.iter().position(|k| *k == c.address);
            let index = aligned.into_iter().chain(0..set.pq_keys.len()).find(|&i| {
                set.pq_keys
                    .get(i)
                    .is_some_and(|key| pq::verify(key, chain_id, &message.digest, &signature))
            })?;
            Some((index as u8, signature))
        })
        .collect();
    pq::assemble(&found, &set.pq_keys, chain_id, &message.digest)
}

fn assemble_inner(
    message: &Observed,
    set: &GuardianSet,
    signatures: &[([u8; 20], RawSignature)],
) -> Option<Attestation> {
    let mut by_index: BTreeMap<u8, &RawSignature> = BTreeMap::new();
    for (address, signature) in signatures {
        if let Some(index) = set.keys.iter().position(|k| k == address) {
            by_index.entry(index as u8).or_insert(signature);
        }
    }
    let need = quorum(set.keys.len());
    if by_index.len() < need {
        return None;
    }
    Some(Attestation {
        guardian_set_index: set.index,
        signatures: by_index
            .into_iter()
            .take(need)
            .map(|(i, s)| s.indexed(i))
            .collect(),
        body: message.decoded(),
    })
}

pub enum EndpointSubmitter {
    Evm(EvmSubmitter),
    Tron(TronSubmitter),
}

pub struct Destinations {
    /// Keyed by bridge chain id (2, 3, 4).
    pub endpoints: BTreeMap<u16, EndpointSubmitter>,
    pub solana: Option<SolanaSubmitter>,
    pub rand: Option<RandSubmitter>,
    /// Smallest attested relayer fee worth a release; 0 relays everything.
    pub min_relayer_fee: u64,
}

/// Records everything final a source has to offer. Returns how many new
/// messages were seen.
pub async fn observe<S: Source>(source: &S, store: &Store) -> Result<usize> {
    let cursor = match store.cursor(source.name())? {
        Some(c) => c,
        None => source.start(),
    };
    let (messages, next) = source.poll(&cursor).await?;
    for message in &messages {
        store.write_message(OBSERVED, message.emitter_chain, message.sequence, message)?;
    }
    if next != cursor {
        store.set_cursor(source.name(), &next)?;
    }
    Ok(messages.len())
}

/// Every observed message not yet done, oldest first per chain.
pub fn pending(store: &Store) -> Result<Vec<Observed>> {
    let mut out = Vec::new();
    for chain in 1..=5u16 {
        let done = store.sequences(DONE, chain)?;
        for sequence in store.sequences(OBSERVED, chain)? {
            if done.binary_search(&sequence).is_err() {
                if let Some(message) = store.read_message::<Observed>(OBSERVED, chain, sequence)? {
                    out.push(message);
                }
            }
        }
    }
    Ok(out)
}

pub fn recipient_address(store: &Store, recipient_hash: &[u8; 32]) -> Result<Option<String>> {
    store.read(&[RECIPIENTS, &format!("{}.json", hex::encode(recipient_hash))])
}

pub fn register_recipient(store: &Store, recipient_hash: &[u8; 32], address: &str) -> Result<()> {
    store.write(
        &[RECIPIENTS, &format!("{}.json", hex::encode(recipient_hash))],
        &address.to_string(),
    )
}

/// What happened to one pending message this round.
#[derive(Debug, PartialEq, Eq)]
pub enum Progress {
    Done(Outcome),
    /// Fewer than a quorum of guardians have signed yet.
    AwaitingQuorum {
        have: usize,
        need: usize,
    },
    /// A deposit whose recipient has not registered a Rand address.
    AwaitingRecipient,
    /// Not ours to relay: no submitter for the destination, or the fee is
    /// below this relayer's floor.
    Skipped(String),
}

pub async fn relay_one(
    message: &Observed,
    store: &Store,
    guardians: &[GuardianClient],
    set: &GuardianSet,
    destinations: &Destinations,
) -> Result<Progress> {
    let body = message.decoded();
    let Ok(Payload::Transfer(transfer)) = Payload::decode(&body.payload) else {
        return Ok(Progress::Skipped("not a transfer".into()));
    };
    let to_chain = transfer.to_chain;

    // Routing first: there is no point collecting signatures for a message
    // this relayer has nowhere to send.
    if to_chain == CHAIN_RAND {
        if destinations.rand.is_none() {
            return Ok(Progress::Skipped("no Rand wallet configured".into()));
        }
        if recipient_address(store, &transfer.to)?.is_none() {
            return Ok(Progress::AwaitingRecipient);
        }
    } else if to_chain == CHAIN_SOLANA {
        if destinations.solana.is_none() {
            return Ok(Progress::Skipped("no Solana submitter configured".into()));
        }
    } else if !destinations.endpoints.contains_key(&to_chain) {
        return Ok(Progress::Skipped(format!(
            "no submitter for chain {to_chain}"
        )));
    }
    if to_chain != CHAIN_RAND {
        let fee = transfer.fee_u128().unwrap_or(0);
        if fee < u128::from(destinations.min_relayer_fee) {
            return Ok(Progress::Skipped(format!(
                "relayer fee {fee} below the floor {}",
                destinations.min_relayer_fee
            )));
        }
    }

    let mut signatures = Vec::new();
    for guardian in guardians {
        match guardian.signature(message).await {
            Ok(Some(found)) => signatures.push(found),
            Ok(None) => {}
            Err(e) => tracing::warn!("{}: {e:#}", guardian.origin()),
        }
    }
    let ecdsa: Vec<([u8; 20], RawSignature)> = signatures
        .iter()
        .map(|c| (c.address, c.signature.clone()))
        .collect();
    let Some(attestation) = assemble(message, set, &ecdsa) else {
        return Ok(Progress::AwaitingQuorum {
            have: signatures.len(),
            need: quorum(set.keys.len()),
        });
    };
    // A Rand chain that lists PQ guardians refuses a mint without their
    // quorum, so there is no point submitting one.
    let pq_quorum = if to_chain == CHAIN_RAND && !set.pq_keys.is_empty() {
        match assemble_pq(message, set, &signatures) {
            Some(list) => Some(list),
            None => {
                return Ok(Progress::AwaitingQuorum {
                    have: signatures
                        .iter()
                        .filter(|c| c.pq_signature.is_some())
                        .count(),
                    need: pq::quorum(set.pq_keys.len()),
                })
            }
        }
    } else {
        None
    };

    let outcome = if to_chain == CHAIN_RAND {
        let to =
            recipient_address(store, &transfer.to)?.ok_or_else(|| anyhow!("recipient vanished"))?;
        destinations
            .rand
            .as_ref()
            .expect("checked above")
            .mint(&attestation, &message.digest, &to, pq_quorum.as_deref())
            .await?
    } else if to_chain == CHAIN_SOLANA {
        destinations
            .solana
            .as_ref()
            .expect("checked above")
            .release(&attestation, &message.digest)
            .await?
    } else {
        match &destinations.endpoints[&to_chain] {
            EndpointSubmitter::Evm(s) => s.release(&attestation, &message.digest).await?,
            EndpointSubmitter::Tron(s) => s.release(&attestation, &message.digest).await?,
        }
    };
    store.write_message(
        DONE,
        message.emitter_chain,
        message.sequence,
        &Done {
            digest: hex::encode(message.digest),
            to_chain,
            outcome: outcome.clone(),
        },
    )?;
    Ok(Progress::Done(outcome))
}
