//! The guardian loop: read final messages off each source, check them
//! against the signing policy, sign, persist.

use anyhow::Result;

use crate::api::{SignedMessage, SIGNED};
use crate::crypto::GuardianKey;
use crate::message::{check_signable, Emitters, Observed};
use crate::pq::PqKey;
use crate::sources::Source;
use crate::store::Store;

pub const REFUSED: &str = "refused";

/// Two different final bodies under one `(emitter chain, sequence)`. Fatal:
/// the daemon stops rather than sign both.
#[derive(Debug)]
pub struct Equivocation {
    pub chain: u16,
    pub sequence: u64,
    pub signed: String,
    pub observed: String,
}

impl std::fmt::Display for Equivocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "equivocation on chain {} sequence {}: already signed {}, now observed {}",
            self.chain, self.sequence, self.signed, self.observed
        )
    }
}

impl std::error::Error for Equivocation {}

/// A message the policy turned down, kept so an operator can see why a
/// transfer is not moving.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Refused {
    pub message: Observed,
    pub reason: String,
}

/// A guardian's post-quantum half: its Dilithium2 key and the Rand chain id
/// its co-signatures name.
pub struct PqSigner {
    pub key: PqKey,
    pub rand_chain_id: u64,
}

/// One poll of one source. Returns how many messages were signed.
pub async fn step<S: Source>(
    source: &S,
    store: &Store,
    key: &GuardianKey,
    pq: Option<&PqSigner>,
    emitters: &Emitters,
) -> Result<usize> {
    let cursor = match store.cursor(source.name())? {
        Some(c) => c,
        None => source.start(),
    };
    let (messages, next) = source.poll(&cursor).await?;
    let mut signed = 0;
    for message in messages {
        if sign_one(store, key, pq, emitters, &message)? {
            signed += 1;
        }
    }
    // Only now: a crash before this line re-reads the same messages, and
    // `sign_one` is idempotent for a body it has already signed.
    if next != cursor {
        store.set_cursor(source.name(), &next)?;
    }
    Ok(signed)
}

/// Signs `message` unless the policy refuses it. `Ok(true)` when a new
/// signature was written.
pub fn sign_one(
    store: &Store,
    key: &GuardianKey,
    pq: Option<&PqSigner>,
    emitters: &Emitters,
    message: &Observed,
) -> Result<bool> {
    let (chain, sequence) = (message.emitter_chain, message.sequence);
    if let Some(existing) = store.read_message::<SignedMessage>(SIGNED, chain, sequence)? {
        if existing.message.digest != message.digest {
            // Two final bodies under one (emitter, sequence) cannot both be
            // honest. Signing the second would hand an attacker a quorum for
            // each; stop and let a human look.
            return Err(Equivocation {
                chain,
                sequence,
                signed: hex::encode(existing.message.digest),
                observed: hex::encode(message.digest),
            }
            .into());
        }
        return Ok(false);
    }
    if let Err(reason) = check_signable(&message.decoded(), emitters) {
        tracing::warn!(chain, sequence, "refusing to sign: {reason:#}");
        store.write_message(
            REFUSED,
            chain,
            sequence,
            &Refused {
                message: message.clone(),
                reason: format!("{reason:#}"),
            },
        )?;
        return Ok(false);
    }
    let signature = key.sign(&message.digest)?;
    // Only what Rand will verify is co-signed: releases stay classical.
    let pq_signature = match pq {
        Some(pq) if message.to_chain() == Some(bridge_codec::CHAIN_RAND) => {
            Some(hex::encode(pq.key.sign(pq.rand_chain_id, &message.digest)))
        }
        _ => None,
    };
    let signed = SignedMessage {
        message: message.clone(),
        guardian: hex::encode(key.address()),
        signature,
        pq_signature,
    };
    store.write_message(SIGNED, chain, sequence, &signed)?;
    tracing::info!(chain, sequence, digest = %hex::encode(message.digest), "signed");
    Ok(true)
}
