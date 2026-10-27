//! The guardian loop: read final messages off each source, check them
//! against the signing policy, sign, persist.

use anyhow::{Context, Result};

use crate::api::{SignedMessage, SIGNED};
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

/// [`step`] under `guards`. While signing is paused (a cap was breached)
/// nothing is read, so nothing is passed over: the cursor stays where the
/// pause found it.
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
            "{}: signing is paused since {} (chain {} sequence {}: {}); clear it with \
             rand-guardian --resume-signing",
            source.name(),
            p.at,
            p.chain,
            p.sequence,
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
    let mut queue = located.into_iter().peekable();
    while let Some(Located { message, .. }) = queue.next() {
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
            Err(e) => return Err(e),
        }
        if limits::paused(store).unwrap_or(None).is_some() {
            // This message was the breach: the next one is where to resume.
            if let Some(after) = queue.peek() {
                next = after.resume.clone();
            }
            break;
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
    sign_one_guarded(store, key, pq, emitters, &Guards::default(), message, limits::now())
}

/// [`sign_one`] under `guards`, at time `now` (unix seconds). A message over
/// a cap is refused and pauses signing (BRG-1).
pub fn sign_one_guarded(
    store: &Store,
    key: &GuardianKey,
    pq: Option<&PqSigner>,
    emitters: &Emitters,
    guards: &Guards<'_>,
    message: &Observed,
    now: u64,
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
        if let Err(reason) = limits.admit(store, message, now)? {
            tracing::error!(chain, sequence, "cap breached, refusing and pausing signing: {reason}");
            store.write_message(
                REFUSED,
                chain,
                sequence,
                &Refused {
                    message: message.clone(),
                    reason: format!("cap breached: {reason}"),
                },
            )?;
            limits::pause(store, message, now, &reason)?;
            return Ok(false);
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
