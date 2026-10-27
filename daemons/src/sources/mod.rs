//! Where messages come from. Every source yields [`Observed`] messages in
//! sequence order, and only once the emitting chain's consistency level is
//! met: a guardian's signature is irrevocable, a reorged lock is not.
//!
//! A guardian reads each chain through one or more providers (BR-4):
//! [`Quorum`] signs nothing one provider alone reports. Each message one
//! provider scans must be confirmed, independently, by enough of the others
//! that a configured quorum of providers agree on it — the same event body
//! (amount, recipient, token, nonce), in the same block, final at each one's
//! own consistency level.

pub mod evm;
pub mod rand;
pub mod solana;

use anyhow::{anyhow, Result};

use crate::message::Observed;

/// A resumable position in one source, persisted between polls.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Cursor {
    /// EVM family: the next block to scan. Unused elsewhere.
    #[serde(default)]
    pub next_block: u64,
    /// The next message sequence expected.
    #[serde(default)]
    pub next_sequence: u64,
}

/// A message, and the cursor that reads it again: where a poll resumes when
/// this message is not to be passed over yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Located {
    pub message: Observed,
    pub resume: Cursor,
}

#[allow(async_fn_in_trait)]
pub trait Source {
    /// A stable name, used for the cursor file and in logs.
    fn name(&self) -> &str;
    /// The cursor a fresh data dir starts from.
    fn start(&self) -> Cursor;
    /// Everything final past `cursor`, plus the cursor to resume from.
    async fn poll(&self, cursor: &Cursor) -> Result<(Vec<Observed>, Cursor)>;
    /// [`Source::poll`], with the cursor that re-reads each message. By
    /// default every message resumes at `cursor` (re-read from the start).
    async fn poll_located(&self, cursor: &Cursor) -> Result<(Vec<Located>, Cursor)> {
        let (messages, next) = self.poll(cursor).await?;
        Ok((
            messages
                .into_iter()
                .map(|message| Located {
                    message,
                    resume: cursor.clone(),
                })
                .collect(),
            next,
        ))
    }
}

/// One provider's independent check of what another provider scanned.
#[allow(async_fn_in_trait)]
pub trait Confirm: Source {
    /// Whether this provider reports `located.message`, byte for byte, as
    /// final (at its own safe head) where the scanner saw it. `Ok(false)` is
    /// a contradiction; an error is no answer.
    async fn confirm(&self, located: &Located) -> Result<bool>;
    /// Whether this provider's own counter says nothing was published before
    /// `next` beyond what was scanned (`None`: no such counter, or no answer).
    async fn confirm_through(&self, _next: &Cursor) -> Result<Option<bool>> {
        Ok(None)
    }
}

/// The providers one chain is read through, and how many must agree (BR-4).
pub struct Quorum<S> {
    members: Vec<S>,
    quorum: usize,
}

/// The default quorum of `n` providers: a majority, so with two or more no
/// single provider can get a message signed.
pub fn default_quorum(n: usize) -> usize {
    n / 2 + 1
}

impl<S: Confirm> Quorum<S> {
    /// `members[0]` names the source; `quorum` is clamped to `1..=n`.
    pub fn new(members: Vec<S>, quorum: usize) -> Result<Quorum<S>> {
        if members.is_empty() {
            return Err(anyhow!("a source needs at least one RPC"));
        }
        if quorum == 0 || quorum > members.len() {
            return Err(anyhow!(
                "an RPC quorum of {quorum} out of {} providers",
                members.len()
            ));
        }
        Ok(Quorum { members, quorum })
    }

    pub fn members(&self) -> &[S] {
        &self.members
    }

    pub fn quorum(&self) -> usize {
        self.quorum
    }

    /// How many providers, beside the scanner `scanner`, confirm `located`.
    async fn agreement(&self, scanner: usize, located: &Located) -> (usize, Vec<String>) {
        let mut agree = 1; // the scanner's own report
        let mut notes = Vec::new();
        for (i, other) in self.members.iter().enumerate() {
            if i == scanner || agree >= self.quorum {
                continue;
            }
            match other.confirm(located).await {
                Ok(true) => agree += 1,
                Ok(false) => notes.push(format!("provider {i} reports otherwise")),
                Err(e) => notes.push(format!("provider {i}: {e:#}")),
            }
        }
        (agree, notes)
    }

    /// Whether the providers' counters accept `next`: a quorum says yes, or
    /// none contradicts it and none could answer (an RPC without the state
    /// that far back). A contradiction short of a quorum rejects the scan.
    async fn counters_accept(&self, cursor: &Cursor, next: &Cursor) -> Result<bool> {
        if next == cursor {
            return Ok(true);
        }
        let (mut yes, mut no, mut notes) = (0, 0, Vec::new());
        for (i, member) in self.members.iter().enumerate() {
            match member.confirm_through(next).await {
                Ok(Some(true)) => yes += 1,
                Ok(Some(false)) => {
                    no += 1;
                    notes.push(format!("provider {i}: the counter disagrees"))
                }
                Ok(None) => {}
                Err(e) => notes.push(format!("provider {i}: {e:#}")),
            }
        }
        if yes >= self.quorum || no == 0 {
            if yes < self.quorum && !notes.is_empty() {
                tracing::debug!("{}: counters unconfirmed: {}", self.name(), notes.join("; "));
            }
            return Ok(true);
        }
        tracing::warn!(
            "{}: through block {} sequence {}: {} of {} counters agree ({})",
            self.name(),
            next.next_block,
            next.next_sequence,
            yes,
            self.quorum,
            notes.join("; ")
        );
        Ok(false)
    }
}

impl<S: Confirm> Source for Quorum<S> {
    fn name(&self) -> &str {
        self.members[0].name()
    }

    fn start(&self) -> Cursor {
        self.members[0].start()
    }

    async fn poll(&self, cursor: &Cursor) -> Result<(Vec<Observed>, Cursor)> {
        let (located, next) = self.poll_located(cursor).await?;
        Ok((located.into_iter().map(|l| l.message).collect(), next))
    }

    /// Scans with each provider in turn until one's scan is confirmed in
    /// full. A scan whose message `k` lacks a quorum yields messages
    /// `0..k` and resumes at `k`, if no provider does better; a scan whose
    /// counters are contradicted is not used at all.
    async fn poll_located(&self, cursor: &Cursor) -> Result<(Vec<Located>, Cursor)> {
        if self.quorum == 1 {
            // Any one provider will do: the first that answers.
            let mut last = None;
            for member in &self.members {
                match member.poll_located(cursor).await {
                    Ok(scan) => return Ok(scan),
                    Err(e) => last = Some(e),
                }
            }
            return Err(last.expect("at least one member"));
        }
        let mut best: Option<(Vec<Located>, Cursor)> = None;
        let mut errors = Vec::new();
        for (i, scanner) in self.members.iter().enumerate() {
            let (located, next) = match scanner.poll_located(cursor).await {
                Ok(scan) => scan,
                Err(e) => {
                    errors.push(format!("provider {i}: {e:#}"));
                    continue;
                }
            };
            let mut confirmed = Vec::new();
            let mut stopped = None;
            for l in located {
                let (agree, notes) = self.agreement(i, &l).await;
                if agree < self.quorum {
                    tracing::warn!(
                        "{}: chain {} sequence {} (digest {}) has {agree} of {} providers ({}); not signed yet",
                        self.name(),
                        l.message.emitter_chain,
                        l.message.sequence,
                        hex::encode(l.message.digest),
                        self.quorum,
                        notes.join("; ")
                    );
                    stopped = Some(l.resume.clone());
                    break;
                }
                confirmed.push(l);
            }
            match stopped {
                None => {
                    if self.counters_accept(cursor, &next).await? {
                        return Ok((confirmed, next));
                    }
                    errors.push(format!("provider {i}: its scan is contradicted by the counters"));
                }
                Some(resume) => {
                    if best.as_ref().map_or(true, |(b, _)| confirmed.len() > b.len()) {
                        best = Some((confirmed, resume));
                    }
                }
            }
        }
        match best {
            Some(b) => Ok(b),
            None => Err(anyhow!(
                "{}: no provider's scan reached a quorum of {}: {}",
                self.name(),
                self.quorum,
                errors.join("; ")
            )),
        }
    }
}

/// A configured chain's providers as one [`Quorum`] source.
pub fn evm_quorum(cfg: &crate::config::EvmConfig) -> Result<Quorum<evm::EvmSource>> {
    let (urls, quorum) = cfg.providers();
    let members = urls
        .iter()
        .map(|u| evm::EvmSource::with_rpc(cfg, u))
        .collect::<Result<Vec<_>>>()?;
    Quorum::new(members, quorum)
}

pub fn solana_quorum(cfg: &crate::config::SolanaConfig) -> Result<Quorum<solana::SolanaSource>> {
    let (urls, quorum) = cfg.providers();
    let members = urls
        .iter()
        .map(|u| solana::SolanaSource::with_rpc(cfg, u))
        .collect::<Result<Vec<_>>>()?;
    Quorum::new(members, quorum)
}

pub fn rand_quorum(cfg: &crate::config::RandConfig) -> Result<Quorum<rand::RandSource>> {
    let (urls, quorum) = cfg.providers();
    let members = urls
        .iter()
        .map(|u| rand::RandSource::with_rpc(cfg, u))
        .collect();
    Quorum::new(members, quorum)
}

/// The startup line for one chain's providers: a warning when one provider
/// alone could get a message signed.
pub fn describe_providers(name: &str, urls: &[String], quorum: usize) {
    let shown: Vec<String> = urls
        .iter()
        .map(|u| crate::rpc::JsonRpc::new(u).shown())
        .collect();
    if quorum < 2 {
        tracing::warn!(
            "{name}: read through {} RPC(s) with a quorum of {quorum} ({}): a single provider can \
             get a message signed; configure `rpcs` with independent providers (BR-4)",
            urls.len(),
            shown.join(", ")
        );
    } else {
        tracing::info!(
            "{name}: {quorum} of {} RPCs must agree before signing ({})",
            urls.len(),
            shown.join(", ")
        );
    }
}
