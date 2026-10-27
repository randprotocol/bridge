//! Loss bounds a guardian enforces itself (BRG-1), before it signs: a cap on
//! each transfer and a cap on what it signs per token in a rolling window,
//! from `[guardian.limits]`. They need no contract change and hold even when
//! a destination's own caps are wider (or absent): a forged or oversized
//! message gets no signature from a guardian that runs them.
//!
//! Amounts are the attested 8-decimal units every body carries. Deposits
//! (locks minted on Rand) and releases (burns paid out on a source chain)
//! are counted in separate windows, per token (`token_chain`, token word).
//! The window is this guardian's own clock at signing, never a timestamp a
//! message carries, so backdated bodies cannot slip under it.
//!
//! A transfer over the per-transfer cap is **withheld**: not signed, written
//! to `held/<chain>/<sequence>.json` with the reason, logged at error level,
//! and signed only when an operator releases that one `(chain, sequence)`
//! (`rand-guardian --release-held <chain>:<sequence>`); every other transfer
//! keeps flowing. A transfer that would overrun its window is **deferred**:
//! the source stops at it and reads it again each poll, and it is signed on
//! its own once the window has room. The global pause (`limits/paused.json`)
//! is never set automatically, only by `rand-guardian --pause-signing`.

use anyhow::{anyhow, bail, Context, Result};
use bridge_codec::{Payload, CHAIN_RAND, CHAIN_SOLANA};
use serde::{Deserialize, Serialize};

use crate::message::Observed;
use crate::store::Store;

/// `[guardian.limits]`.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Largest single transfer, in attested 8-decimal units, for every token
    /// without its own entry.
    pub per_transfer: u64,
    /// Most signed per token and direction in any `window_secs`.
    pub per_window: u64,
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
    /// Per-token overrides.
    #[serde(default)]
    pub token: Vec<TokenLimit>,
}

fn default_window_secs() -> u64 {
    86_400
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TokenLimit {
    /// The token's home chain (2 Ethereum, 3 BSC, 4 Tron, 5 Solana).
    pub chain: u16,
    /// The token: `0x` + 40 hex (EVM family; Tron in EVM form), `0x` + 64
    /// hex (the wire word), or base58 (a Solana mint).
    pub address: String,
    pub per_transfer: u64,
    pub per_window: u64,
}

/// Which way a transfer moves value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// A lock on a source chain, minted on Rand.
    Deposit,
    /// A burn on Rand, released on a source chain.
    Release,
}

impl Direction {
    fn of(message: &Observed) -> Direction {
        if message.emitter_chain == CHAIN_RAND {
            Direction::Release
        } else {
            Direction::Deposit
        }
    }

    fn label(self) -> &'static str {
        match self {
            Direction::Deposit => "deposit",
            Direction::Release => "release",
        }
    }
}

/// One signature counted against a window.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub at: u64,
    pub amount: u64,
    pub chain: u16,
    pub sequence: u64,
}

/// What the caps say about one transfer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Within both caps; counted in its window.
    Admit,
    /// Over the per-transfer cap: withheld until an operator releases it.
    Hold(String),
    /// The window has no room for it yet: read it again later.
    Defer(String),
}

/// A withheld transfer, as written to `held/<chain>/<sequence>.json`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Held {
    pub message: Observed,
    pub at: u64,
    pub reason: String,
}

pub const HELD: &str = "held";

/// Every withheld `(chain, sequence)`.
pub fn held(store: &Store) -> Result<Vec<(u16, u64)>> {
    let mut out = Vec::new();
    let dir = store.root().join(HELD);
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e).with_context(|| format!("listing {}", dir.display())),
    };
    for entry in entries {
        let Some(chain) = entry?.file_name().to_str().and_then(|c| c.parse::<u16>().ok()) else {
            continue;
        };
        for sequence in store.sequences(HELD, chain)? {
            out.push((chain, sequence));
        }
    }
    out.sort_unstable();
    Ok(out)
}

/// Removes the held record of `(chain, sequence)`.
pub fn unhold(store: &Store, chain: u16, sequence: u64) -> Result<()> {
    let parts = Store::message_parts(HELD, chain, sequence);
    let path = store.root().join(&parts[0]).join(&parts[1]).join(&parts[2]);
    std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))
}

/// Why signing is paused, as written to `limits/paused.json` by an operator.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Paused {
    pub at: u64,
    pub reason: String,
}

pub const PAUSED: [&str; 2] = ["limits", "paused.json"];

/// The pause, if signing is paused.
pub fn paused(store: &Store) -> Result<Option<Paused>> {
    store.read(&PAUSED)
}

/// Clears the pause; returns what it was.
pub fn resume(store: &Store) -> Result<Option<Paused>> {
    let was = paused(store)?;
    if was.is_some() {
        let path = store.root().join(PAUSED[0]).join(PAUSED[1]);
        std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
    }
    Ok(was)
}

/// A token: its home chain and its 32-byte wire word.
type TokenKey = (u16, [u8; 32]);
/// `(per_transfer, per_window)`.
type Caps = (u64, u64);

/// The limits in force, parsed.
#[derive(Clone, Debug)]
pub struct Limits {
    cfg: LimitsConfig,
    overrides: Vec<(TokenKey, Caps)>,
}

/// A token as its 32-byte wire word.
pub fn token_word(chain: u16, address: &str) -> Result<[u8; 32]> {
    let a = address.trim();
    if let Some(hex) = a.strip_prefix("0x") {
        let bytes = hex::decode(hex).map_err(|_| anyhow!("{a}: not hex"))?;
        return match bytes.len() {
            20 => {
                let mut w = [0u8; 32];
                w[12..].copy_from_slice(&bytes);
                Ok(w)
            }
            32 => Ok(bytes.try_into().expect("32")),
            n => bail!("{a}: {n} bytes, expected 20 or 32"),
        };
    }
    if chain == CHAIN_SOLANA {
        return crate::config::pubkey32(a);
    }
    if chain == bridge_codec::CHAIN_TRON {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&crate::config::tron_address20(a)?);
        return Ok(w);
    }
    bail!("{a}: expected 0x + 40 or 64 hex")
}

impl Limits {
    pub fn new(cfg: &LimitsConfig) -> Result<Limits> {
        if cfg.window_secs == 0 {
            bail!("guardian.limits.window_secs must be positive");
        }
        if cfg.per_transfer > cfg.per_window {
            bail!("guardian.limits: per_transfer is above per_window");
        }
        let mut overrides = Vec::new();
        for t in &cfg.token {
            if !(2..=5).contains(&t.chain) {
                bail!("guardian.limits.token: chain {} is not 2..=5", t.chain);
            }
            let word = token_word(t.chain, &t.address)
                .with_context(|| format!("guardian.limits.token {}", t.address))?;
            if t.per_transfer > t.per_window {
                bail!("guardian.limits.token {}: per_transfer is above per_window", t.address);
            }
            if overrides.iter().any(|(k, _)| *k == (t.chain, word)) {
                bail!("guardian.limits.token {} is listed twice", t.address);
            }
            overrides.push(((t.chain, word), (t.per_transfer, t.per_window)));
        }
        Ok(Limits {
            cfg: cfg.clone(),
            overrides,
        })
    }

    fn caps(&self, chain: u16, token: &[u8; 32]) -> (u64, u64) {
        self.overrides
            .iter()
            .find(|(k, _)| *k == (chain, *token))
            .map(|(_, c)| *c)
            .unwrap_or((self.cfg.per_transfer, self.cfg.per_window))
    }

    pub fn window_secs(&self) -> u64 {
        self.cfg.window_secs
    }

    /// Checks `message` against the caps at `now` and, when it is admitted,
    /// counts it in its window (before the signature is made: a crash in
    /// between over-counts, never under-counts). `released`: an operator
    /// released this held transfer, so neither cap applies, but it is still
    /// counted. The error is a store failure.
    pub fn admit(
        &self,
        store: &Store,
        message: &Observed,
        now: u64,
        released: bool,
    ) -> Result<Verdict> {
        let Ok(Payload::Transfer(t)) = Payload::decode(&message.decoded().payload) else {
            return Ok(Verdict::Hold("not a transfer".into()));
        };
        let amount = match t.amount_u128().and_then(|a| u64::try_from(a).ok()) {
            Some(a) => a,
            None => return Ok(Verdict::Hold("amount above u64".into())),
        };
        let (per_transfer, per_window) = self.caps(t.token_chain, &t.token_address);
        let direction = Direction::of(message);
        let token = format!("chain {} token 0x{}", t.token_chain, hex::encode(t.token_address));
        if amount > per_transfer && !released {
            return Ok(Verdict::Hold(format!(
                "{} of {amount} on {token} is above the per-transfer cap {per_transfer}",
                direction.label()
            )));
        }
        let parts = [
            "limits".to_string(),
            "window".to_string(),
            format!(
                "{}-{}-{}.json",
                direction.label(),
                t.token_chain,
                hex::encode(t.token_address)
            ),
        ];
        let parts = [parts[0].as_str(), parts[1].as_str(), parts[2].as_str()];
        let mut entries: Vec<Entry> = store
            .read(&parts)
            .context("reading the cap window (nothing on this token is signed until it is repaired)")?
            .unwrap_or_default();
        let since = now.saturating_sub(self.cfg.window_secs);
        entries.retain(|e| e.at > since);
        let used: u64 = entries.iter().map(|e| e.amount).fold(0u64, u64::saturating_add);
        if used.saturating_add(amount) > per_window && !released {
            return Ok(Verdict::Defer(format!(
                "{} of {amount} on {token} would bring the last {} s to {} (cap {per_window})",
                direction.label(),
                self.cfg.window_secs,
                used.saturating_add(amount)
            )));
        }
        entries.push(Entry {
            at: now,
            amount,
            chain: message.emitter_chain,
            sequence: message.sequence,
        });
        store.write(&parts, &entries)?;
        Ok(Verdict::Admit)
    }
}

/// Pauses all signing with `reason`: an operator's act, never automatic.
pub fn pause(store: &Store, now: u64, reason: &str) -> Result<()> {
    store.write(
        &PAUSED,
        &Paused {
            at: now,
            reason: reason.to_string(),
        },
    )
}

/// Seconds since the epoch.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
