//! Where messages come from. Every source yields [`Observed`] messages in
//! sequence order, and only once the emitting chain's consistency level is
//! met: a guardian's signature is irrevocable, a reorged lock is not.

pub mod evm;
pub mod rand;
pub mod solana;

use anyhow::Result;

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

#[allow(async_fn_in_trait)]
pub trait Source {
    /// A stable name, used for the cursor file and in logs.
    fn name(&self) -> &str;
    /// The cursor a fresh data dir starts from.
    fn start(&self) -> Cursor;
    /// Everything final past `cursor`, plus the cursor to resume from.
    async fn poll(&self, cursor: &Cursor) -> Result<(Vec<Observed>, Cursor)>;
}
