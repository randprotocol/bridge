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
}

/// What the peers say about a `(chain, sequence)` this guardian has no record of.
#[derive(Debug, PartialEq, Eq)]
pub enum PeerVerdict {
    /// No peer holds a signature by this guardian over another body.
    Clear,
    /// A peer holds this guardian's own signature over a different body: it
    /// signed that sequence before and has forgotten (a restored store).
    Conflict(String),
    /// No peer answered: the check could not be made.
    Unchecked(String),
}

/// Asks every peer, at once, for its record of `message`'s `(chain,
/// sequence)` (BR-502). Only this guardian's own signature proves anything —
/// the threat is a guardian that forgot what it signed — so a record signed
/// by any other key is ignored (logged at debug), whatever its body. With no
/// peer answering the check is [`PeerVerdict::Unchecked`].
pub async fn peer_conflict(peers: &[GuardianClient], own: [u8; 20], message: &Observed) -> PeerVerdict {
    let (chain, sequence) = (message.emitter_chain, message.sequence);
    let mut asks = tokio::task::JoinSet::new();
    for peer in peers {
        let peer = peer.clone();
        asks.spawn(async move {
            let r = peer.record(chain, sequence).await;
            (peer.origin().to_string(), r)
        });
    }
    let mut answered = 0;
    let mut errors = Vec::new();
    while let Some(joined) = asks.join_next().await {
        let Ok((origin, result)) = joined else { continue };
        let record = match result {
            Ok(Some(r)) => {
                answered += 1;
                r
            }
            Ok(None) => {
                answered += 1;
                continue;
            }
            Err(e) => {
                errors.push(format!("{origin}: {e:#}"));
                continue;
            }
        };
        let Ok(body) = Observed::new(record.message.body.clone()) else {
            tracing::debug!("peer {origin}: an undecodable record for {chain}/{sequence}");
            continue;
        };
        if body.digest != record.message.digest || (body.emitter_chain, body.sequence) != (chain, sequence) {
            tracing::debug!("peer {origin}: a malformed record for {chain}/{sequence}");
            continue;
        }
        match crate::crypto::recover(&body.digest, &record.signature) {
            Ok(signer) if signer == own => {
                if body.digest != message.digest {
                    return PeerVerdict::Conflict(format!(
                        "peer {origin} holds this guardian's own signature over digest {} for \
                         chain {chain} sequence {sequence}, and the providers now report {}: \
                         not signing a second body (BR-502)",
                        hex::encode(body.digest),
                        hex::encode(message.digest)
                    ));
                }
            }
            Ok(signer) => tracing::debug!(
                "peer {origin}: {chain}/{sequence} signed by 0x{}, not this guardian; ignored",
                hex::encode(signer)
            ),
            Err(_) => tracing::debug!("peer {origin}: an unrecoverable signature for {chain}/{sequence}"),
        }
    }
    if answered == 0 {
        return PeerVerdict::Unchecked(format!("no peer answered ({})", errors.join("; ")));
    }
    PeerVerdict::Clear
}

/// The peer check before a first signature: `true` when signing may go on.
/// A conflict holds the transfer for an operator; no answer defers it.
async fn peers_allow(store: &Store, key: &GuardianKey, guards: &Guards<'_>, message: &Observed) -> Result<bool> {
    if guards.peers.is_empty() || has_record(store, message) {
        return Ok(true);
    }
    match peer_conflict(guards.peers, key.address(), message).await {
        PeerVerdict::Clear => Ok(true),
        PeerVerdict::Conflict(reason) => {
            tracing::error!("WITHHELD: {reason}");
            store.write_message(
                limits::HELD,
                message.emitter_chain,
                message.sequence,
                &limits::Held {
                    message: message.clone(),
                    at: limits::now(),
                    reason,
                },
            )?;
            Ok(false)
        }
        PeerVerdict::Unchecked(reason) => {
            tracing::warn!(
                "chain {} sequence {}: peer check not possible, retried next round: {reason}",
                message.emitter_chain,
                message.sequence
            );
            limits::defer(store, message, limits::now(), limits::DeferKind::Peers, &reason)?;
            Ok(false)
        }
    }
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
/// signed now; it waits in `deferred/` and is retried every round.
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
/// read, so nothing is passed over. A transfer over its window — or behind
/// one of its token's that is already deferred — goes to `deferred/` and the
/// cursor moves on; [`retry_deferred`] signs it once there is room.
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
    let (located, next) = source.poll_located(&cursor).await?;
    let mut signed = 0;
    let mut waiting = deferred_windows(store)?;
    for Located { message, .. } in located {
        if !has_record(store, &message) {
            if let Some(w) = limits::window_of(&message).filter(|w| waiting.contains(w)) {
                // Its token already has a transfer waiting: keep sequence order.
                limits::defer(
                    store,
                    &message,
                    limits::now(),
                    limits::DeferKind::Window,
                    &format!("behind an earlier deferred transfer on {w}"),
                )?;
                continue;
            }
        }
        if !peers_allow(store, key, guards, &message).await? {
            if is_deferred(store, &message)? {
                if let Some(w) = limits::window_of(&message) {
                    waiting.insert(w);
                }
            }
            continue;
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
                tracing::warn!("{}: {e:#}", source.name());
                limits::defer(store, &message, limits::now(), limits::DeferKind::Window, &format!("{e:#}"))?;
                if let Some(w) = limits::window_of(&message) {
                    waiting.insert(w);
                }
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

fn is_deferred(store: &Store, message: &Observed) -> Result<bool> {
    Ok(store
        .read_message::<limits::Deferral>(limits::DEFERRED, message.emitter_chain, message.sequence)?
        .is_some())
}

/// The windows that have a deferred transfer waiting.
fn deferred_windows(store: &Store) -> Result<std::collections::BTreeSet<String>> {
    let mut out = std::collections::BTreeSet::new();
    for (chain, sequence) in limits::listed(store, limits::DEFERRED)? {
        if let Some(d) = store.read_message::<limits::Deferral>(limits::DEFERRED, chain, sequence)? {
            // Whatever it waits for, later transfers of its token wait behind it.
            if let Some(w) = limits::window_of(&d.message) {
                out.insert(w);
            }
        }
    }
    Ok(out)
}

/// Retries every deferred transfer, in `(chain, sequence)` order, so each
/// token's go in sequence order: the first still deferred holds back the
/// later ones of its window. Returns how many were signed.
pub async fn retry_deferred(
    store: &Store,
    key: &GuardianKey,
    pq: Option<&PqSigner>,
    emitters: &Emitters,
    guards: &Guards<'_>,
) -> Result<usize> {
    if limits::paused(store)?.is_some() {
        return Ok(0);
    }
    let mut signed = 0;
    let mut blocked = std::collections::BTreeSet::new();
    for (chain, sequence) in limits::listed(store, limits::DEFERRED)? {
        let Some(d) = store.read_message::<limits::Deferral>(limits::DEFERRED, chain, sequence)? else {
            continue;
        };
        let window = limits::window_of(&d.message);
        if window.as_ref().is_some_and(|w| blocked.contains(w)) {
            continue; // behind an earlier one of its token that still waits
        }
        // Every deferred transfer passes the peer check before it is signed, whatever it
        // waited for: one queued behind a full window has not been checked yet.
        if !peers_allow(store, key, guards, &d.message).await? {
            // Still unchecked (rewritten in place), or now held.
            if limits::held(store)?.contains(&(chain, sequence)) {
                limits::remove(store, limits::DEFERRED, chain, sequence)?;
            } else if let Some(w) = window {
                blocked.insert(w);
            }
            continue;
        }
        match sign_one_guarded(store, key, pq, emitters, guards, &d.message, limits::now()) {
            Ok(s) => {
                if s {
                    signed += 1;
                }
                limits::remove(store, limits::DEFERRED, chain, sequence)?;
            }
            Err(e) if e.downcast_ref::<Deferred>().is_some() => {
                if let Some(w) = window {
                    blocked.insert(w);
                }
            }
            Err(e) => tracing::error!("retrying deferred chain {chain} sequence {sequence}: {e:#}"),
        }
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
        let verdict = match limits.admit(store, message, now, released) {
            Ok(v) => v,
            // A broken window record holds back its own token only.
            Err(e) => limits::Verdict::Defer(format!("the cap window cannot be read: {e:#}")),
        };
        match verdict {
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
