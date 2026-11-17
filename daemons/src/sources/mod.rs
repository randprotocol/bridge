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

/// A provider did not serve the logs of a block range (BR-1008, BR-761). Never a reading of
/// the range: it is not "empty", it moves no cursor, and under a quorum the provider is simply
/// not counted for that range.
#[derive(Debug, Clone)]
pub struct RangeNotServed {
    pub source_name: String,
    pub from: u64,
    pub to: u64,
    /// What the provider answered instead.
    pub cause: String,
    /// What the same provider says its endpoint's `sequence()` is: information for the
    /// operator, never grounds to pass the range over.
    pub claim: String,
}

impl std::fmt::Display for RangeNotServed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{name}: eth_getLogs for blocks [{from}, {to}] was not served ({cause}). A range that \
             is not served is never passed over: the cursor stays at block {from}. Use an RPC \
             that serves that range (an archive provider); or, only after checking on an \
             independent node that no MessagePublished was emitted in the blocks to be passed \
             over, stop the daemon and set next_block in cursors/{name}.json by hand. ({claim})",
            name = self.source_name,
            from = self.from,
            to = self.to,
            cause = self.cause,
            claim = self.claim,
        )
    }
}

impl std::error::Error for RangeNotServed {}

/// What a provider offers for a quorum read (BR-4).
#[allow(async_fn_in_trait)]
pub trait Confirm: Source {
    /// This provider's safe head, for a block-scanned source; `None` for a
    /// source walked by sequence.
    async fn head(&self) -> Result<Option<u64>> {
        Ok(None)
    }
    /// [`Source::poll_located`], scanning no block past `cap`.
    async fn poll_capped(&self, cursor: &Cursor, _cap: Option<u64>) -> Result<(Vec<Located>, Cursor)> {
        self.poll_located(cursor).await
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
    /// `members[0]` names the source; `quorum` is in `1..=n`.
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

    /// The highest block a quorum of providers each call safe: the
    /// `quorum`-th highest of their heads. A provider that does not answer
    /// does not count; short of a quorum of answers, nothing may advance.
    async fn quorum_head(&self) -> Result<Option<u64>> {
        let mut heads = Vec::new();
        let mut walked = false;
        let mut errors = Vec::new();
        for (i, m) in self.members.iter().enumerate() {
            match m.head().await {
                Ok(Some(h)) => heads.push(h),
                Ok(None) => walked = true,
                Err(e) => errors.push(format!("provider {i}: {e:#}")),
            }
        }
        if walked && heads.is_empty() {
            return Ok(None);
        }
        if heads.len() < self.quorum {
            return Err(anyhow!(
                "{}: {} of {} providers report a safe head, {} needed ({})",
                self.name(),
                heads.len(),
                self.members.len(),
                self.quorum,
                errors.join("; ")
            ));
        }
        heads.sort_unstable_by(|a, b| b.cmp(a));
        Ok(Some(heads[self.quorum - 1]))
    }
}

/// The cursor that resumes after `messages[..len]` as `supporters` saw them:
/// the lowest block any of them put the last message in, past its sequence.
fn agreed(
    supporters: &[&(Vec<Located>, Cursor)],
    len: usize,
) -> Vec<Located> {
    (0..len)
        .map(|k| Located {
            message: supporters[0].0[k].message.clone(),
            resume: Cursor {
                next_block: supporters.iter().map(|s| s.0[k].resume.next_block).min().unwrap_or(0),
                next_sequence: supporters[0].0[k].resume.next_sequence,
            },
        })
        .collect()
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

    /// Every provider scans the same range — capped at the quorum's safe
    /// head — and only what a quorum of them report identically is read. A
    /// provider that errors agrees with nothing, and one that refuses the
    /// range (`RangeNotServed`) is an error like any other: the cursor moves
    /// over a range only when a quorum positively served it with the same
    /// contents, empty or not (BR-761). If a quorum agrees on the
    /// whole scan, the cursor moves to its end; otherwise to just past the
    /// longest prefix a quorum agrees on (the lowest block among them), or
    /// not at all.
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
        let cap = self.quorum_head().await?;
        let mut scans = Vec::new();
        let mut errors = Vec::new();
        let mut not_served: Option<(u64, u64)> = None;
        for (i, m) in self.members.iter().enumerate() {
            match m.poll_capped(cursor, cap).await {
                Ok(scan) => scans.push(scan),
                // A provider that errors — a refused range among the errors — is not counted
                // for this range: it agrees with nothing and advances nothing (BR-761).
                Err(e) => {
                    if let Some(r) = e.downcast_ref::<RangeNotServed>() {
                        not_served = Some((r.from, r.to));
                    }
                    errors.push(format!("provider {i}: {e:#}"));
                }
            }
        }
        let same = |a: &[Located], b: &[Located]| {
            a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.message == y.message)
        };
        // A quorum on the whole scan, its end included.
        for scan in &scans {
            let group: Vec<_> = scans
                .iter()
                .filter(|s| s.1 == scan.1 && same(&s.0, &scan.0))
                .collect();
            if group.len() >= self.quorum {
                return Ok((agreed(&group, scan.0.len()), scan.1.clone()));
            }
        }
        // Else the longest prefix a quorum agrees on.
        let longest = scans.iter().map(|s| s.0.len()).max().unwrap_or(0);
        for len in (1..=longest).rev() {
            for scan in scans.iter().filter(|s| s.0.len() >= len) {
                let group: Vec<_> = scans
                    .iter()
                    .filter(|s| s.0.len() >= len && same(&s.0[..len], &scan.0[..len]))
                    .collect();
                if group.len() >= self.quorum {
                    let located = agreed(&group, len);
                    let last = &located[len - 1];
                    let resume = Cursor {
                        next_block: last.resume.next_block,
                        next_sequence: last.message.sequence + 1,
                    };
                    tracing::warn!(
                        "{}: providers agree on {len} message(s) only; the rest waits ({})",
                        self.name(),
                        errors.join("; ")
                    );
                    return Ok((located, resume));
                }
            }
        }
        if scans.len() < self.quorum {
            if let Some((from, to)) = not_served {
                // Short of a quorum that can serve the range: the chain halts here, loudly,
                // until an operator gives it providers that serve it. It is never skipped.
                let e = anyhow!(
                    "{}: halted at block {from} — blocks [{from}, {to}] were served by {} of {} \
                     providers, {} needed. A provider that refuses a range is not counted and \
                     the range is not passed over (BR-761): configure enough providers that \
                     serve it (archive access), then the daemon catches up on its own: {}",
                    self.name(),
                    scans.len(),
                    self.members.len(),
                    self.quorum,
                    errors.join("; ")
                );
                tracing::error!("{e:#}");
                return Err(e);
            }
            return Err(anyhow!(
                "{}: {} of {} providers answered, {} needed: {}",
                self.name(),
                scans.len(),
                self.members.len(),
                self.quorum,
                errors.join("; ")
            ));
        }
        tracing::warn!(
            "{}: no {} providers agree on the range from block {} sequence {}; not advancing",
            self.name(),
            self.quorum,
            cursor.next_block,
            cursor.next_sequence
        );
        Ok((Vec::new(), cursor.clone()))
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
