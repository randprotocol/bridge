//! The guardian loop: read final messages off each source, check them
//! against the signing policy, sign, persist.

use anyhow::{Context, Result};

use crate::api::{GuardianClient, SignedMessage, SIGNED};
use crate::crypto::GuardianKey;
use crate::message::{check_signable, Emitters, Observed};
use crate::pq::PqKey;
use crate::limits::{self, Limits};
use crate::sources::{Located, Source};
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

/// This guardian's own record for `(chain, sequence)` exists but cannot be
/// read: empty, truncated or not JSON (BR-951). Whether it signed that
/// sequence, and which body, is unknown, so it signs nothing for it until an
/// operator repairs or removes the file — but every other sequence is signed
/// as usual: one bad file never stops a source.
#[derive(Debug)]
pub struct UnreadableRecord {
    pub chain: u16,
    pub sequence: u64,
    pub error: String,
}

impl std::fmt::Display for UnreadableRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the signed record for chain {} sequence {} is unreadable ({}); not signing it until \
             an operator repairs or removes the file",
            self.chain, self.sequence, self.error
        )
    }
}

impl std::error::Error for UnreadableRecord {}

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

/// What a guardian checks beyond the signing policy before it signs.
#[derive(Default)]
pub struct Guards<'a> {
    /// The per-transfer and per-window caps (BRG-1), when configured.
    pub limits: Option<&'a Limits>,
    /// The other guardians, asked before a first signature (BR-502).
    pub peers: &'a [GuardianClient],
    /// The guardian set a peer's record must be signed by to count; empty,
    /// the address the record names.
    pub known: &'a [[u8; 20]],
}

/// What the peers say about `message`'s `(chain, sequence)`: `Some(reason)`
/// when one of them holds a valid signature, by a guardian, over a
/// different body (BR-502). Peers that cannot be reached, have no record or
/// serve something malformed prove nothing and are passed over.
pub async fn peer_conflict(
    peers: &[GuardianClient],
    known: &[[u8; 20]],
    message: &Observed,
) -> Option<String> {
    let (chain, sequence) = (message.emitter_chain, message.sequence);
    for peer in peers {
        let record = match peer.record(chain, sequence).await {
            Ok(Some(r)) => r,
            Ok(None) => continue,
            Err(e) => {
                tracing::debug!("peer {}: {e:#}", peer.origin());
                continue;
            }
        };
        // The record must be what it says: its body hashes to its digest,
        // names this (chain, sequence), and is signed by a guardian.
        let Ok(body) = Observed::new(record.message.body.clone()) else {
            continue;
        };
        if body.digest != record.message.digest
            || (body.emitter_chain, body.sequence) != (chain, sequence)
        {
            continue;
        }
        let Ok(signer) = crate::crypto::recover(&body.digest, &record.signature) else {
            continue;
        };
        let counts = if known.is_empty() {
            hex::decode(&record.guardian).ok().as_deref() == Some(&signer[..])
        } else {
            known.contains(&signer)
        };
        if counts && body.digest != message.digest {
            return Some(format!(
                "guardian 0x{} (at {}) signed digest {} for chain {chain} sequence {sequence}, \
                 this guardian observed {}: not signing a second body (BR-502)",
                hex::encode(signer),
                peer.origin(),
                hex::encode(body.digest),
                hex::encode(message.digest)
            ));
        }
    }
    None
}

/// One poll of one source. Returns how many messages were signed.
pub async fn step<S: Source>(
    source: &S,
    store: &Store,
    key: &GuardianKey,
    pq: Option<&PqSigner>,
    emitters: &Emitters,
) -> Result<usize> {
    step_guarded(source, store, key, pq, emitters, &Guards::default()).await
}

/// A transfer that would overrun its rolling window (BRG-1): it is not
/// signed now, and the source resumes at it so it is read again.
#[derive(Debug)]
pub struct Deferred {
    pub chain: u16,
    pub sequence: u64,
    pub reason: String,
}

impl std::fmt::Display for Deferred {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "chain {} sequence {} deferred until its window has room: {}",
            self.chain, self.sequence, self.reason
        )
    }
}

impl std::error::Error for Deferred {}

/// [`step`] under `guards`. While an operator has paused signing nothing is
/// read, so nothing is passed over. A transfer over its window is deferred:
/// the poll stops there and the cursor stays on it.
pub async fn step_guarded<S: Source>(
    source: &S,
    store: &Store,
    key: &GuardianKey,
    pq: Option<&PqSigner>,
    emitters: &Emitters,
    guards: &Guards<'_>,
) -> Result<usize> {
    if let Some(p) = limits::paused(store).context("reading the signing pause; signing stays off")? {
        tracing::warn!(
            "{}: signing is paused by an operator since {} ({}); clear it with \
             rand-guardian --resume-signing",
            source.name(),
            p.at,
            p.reason
        );
        return Ok(0);
    }
    let cursor = match store.cursor(source.name())? {
        Some(c) => c,
        None => source.start(),
    };
    let (located, mut next) = source.poll_located(&cursor).await?;
    let mut signed = 0;
    for Located { message, resume } in located {
        if !guards.peers.is_empty() && !has_record(store, &message) {
            if let Some(reason) = peer_conflict(guards.peers, guards.known, &message).await {
                tracing::error!("{reason}");
                store.write_message(
                    REFUSED,
                    message.emitter_chain,
                    message.sequence,
                    &Refused {
                        message: message.clone(),
                        reason,
                    },
                )?;
                continue;
            }
        }
        match sign_one_guarded(store, key, pq, emitters, guards, &message, limits::now()) {
            Ok(true) => signed += 1,
            Ok(false) => {}
            Err(e) if e.downcast_ref::<UnreadableRecord>().is_some() => {
                // That sequence alone: recorded where an operator looks, and on.
                tracing::error!("{e:#}");
                let refused = Refused {
                    message: message.clone(),
                    reason: format!("{e:#}"),
                };
                if let Err(w) =
                    store.write_message(REFUSED, message.emitter_chain, message.sequence, &refused)
                {
                    tracing::error!("recording the refusal: {w:#}");
                }
            }
            Err(e) if e.downcast_ref::<Deferred>().is_some() => {
                // Read it again next poll, and nothing after it on this source yet.
                tracing::warn!("{}: {e:#}", source.name());
                next = resume;
                break;
            }
            Err(e) => return Err(e),
        }
    }
    // Only now: a crash before this line re-reads the same messages, and
    // `sign_one` is idempotent for a body it has already signed.
    if next != cursor {
        store.set_cursor(source.name(), &next)?;
    }
    Ok(signed)
}

/// Whether this guardian has a signed record (readable or not) for
/// `message`'s `(chain, sequence)`: then `sign_one` decides on its own.
fn has_record(store: &Store, message: &Observed) -> bool {
    !matches!(
        store.read_message::<serde_json::Value>(SIGNED, message.emitter_chain, message.sequence),
        Ok(None)
    )
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
    sign_one_guarded(store, key, pq, emitters, &Guards::default(), message, limits::now())
}

/// [`sign_one`] under `guards`, at time `now` (unix seconds). A transfer over
/// the per-transfer cap is withheld (`held/`, `Ok(false)`); one over its
/// window is [`Deferred`] (an error, nothing written) (BRG-1).
pub fn sign_one_guarded(
    store: &Store,
    key: &GuardianKey,
    pq: Option<&PqSigner>,
    emitters: &Emitters,
    guards: &Guards<'_>,
    message: &Observed,
    now: u64,
) -> Result<bool> {
    sign_checked(store, key, pq, emitters, guards, message, now, false)
}

/// Signs a withheld transfer an operator has released, by `(chain,
/// sequence)`: the body is the one recorded when it was held, every policy
/// check but the caps runs again, and it is counted in its window.
#[allow(clippy::too_many_arguments)]
pub fn release_held(
    store: &Store,
    key: &GuardianKey,
    pq: Option<&PqSigner>,
    emitters: &Emitters,
    guards: &Guards<'_>,
    chain: u16,
    sequence: u64,
    now: u64,
) -> Result<bool> {
    let held: limits::Held = store
        .read_message(limits::HELD, chain, sequence)?
        .ok_or_else(|| anyhow::anyhow!("chain {chain} sequence {sequence} is not held"))?;
    let message = Observed::new(held.message.body.clone())?;
    if message != held.message {
        anyhow::bail!("the held record for chain {chain} sequence {sequence} is inconsistent");
    }
    let signed = sign_checked(store, key, pq, emitters, guards, &message, now, true)?;
    limits::unhold(store, chain, sequence)?;
    Ok(signed)
}

#[allow(clippy::too_many_arguments)]
fn sign_checked(
    store: &Store,
    key: &GuardianKey,
    pq: Option<&PqSigner>,
    emitters: &Emitters,
    guards: &Guards<'_>,
    message: &Observed,
    now: u64,
    released: bool,
) -> Result<bool> {
    let (chain, sequence) = (message.emitter_chain, message.sequence);
    let existing = store
        .read_message::<SignedMessage>(SIGNED, chain, sequence)
        .map_err(|e| UnreadableRecord {
            chain,
            sequence,
            error: format!("{e:#}"),
        })?;
    if let Some(existing) = existing {
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
    if let Some(limits) = guards.limits {
        match limits.admit(store, message, now, released)? {
            limits::Verdict::Admit => {}
            limits::Verdict::Hold(reason) => {
                tracing::error!(
                    chain,
                    sequence,
                    "WITHHELD, not signed: {reason}; release it with rand-guardian \
                     --release-held {chain}:{sequence} after review"
                );
                store.write_message(
                    limits::HELD,
                    chain,
                    sequence,
                    &limits::Held {
                        message: message.clone(),
                        at: now,
                        reason,
                    },
                )?;
                return Ok(false);
            }
            limits::Verdict::Defer(reason) => {
                return Err(Deferred {
                    chain,
                    sequence,
                    reason,
                }
                .into())
            }
        }
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
