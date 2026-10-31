//! `PostedMessage` accounts from the Solana program.
//!
//! The program writes each outbound body, already encoded, into a
//! `PostedMessage` account, and its config PDA carries the next sequence, so
//! the source walks sequences rather than scanning transactions: nothing can
//! be missed and nothing needs parsing but three account layouts. Every read
//! is at `finalized` commitment.
//!
//! A message is at one of two addresses. `Lock` writes `["msg", sequence LE]`.
//! `LockKeyed` writes `["keyed-msg", owner, nonce LE]`, which cannot be derived
//! from the sequence, and records the address in the page
//! `["msg-page", sequence / 64 LE]`. The page is read first: anyone can send
//! lamports to an unused `["msg", sequence]`, which would read as an account
//! the program does not own. Both instructions advance the config's sequence
//! themselves, so a sequence below it with nothing behind it means the node is
//! behind: the walk stops there and tries again, and never steps over it. See
//! `docs/solana-upgrade.md`.

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use serde_json::json;
use sha2::{Digest, Sha256};

use super::{Confirm, Cursor, Located, Source};
use crate::config::{pubkey32, SolanaConfig};
use crate::message::Observed;
use crate::rpc::JsonRpc;

const DISCRIMINATOR_CONFIG: u8 = 1;
const DISCRIMINATOR_POSTED_MESSAGE: u8 = 5;
const DISCRIMINATOR_MESSAGE_PAGE: u8 = 6;
/// The program's `MESSAGE_PAGE_SLOTS`, part of the on-chain format.
const MESSAGE_PAGE_SLOTS: u64 = 64;
/// Discriminator, then the page number as a `u64` LE.
const MESSAGE_PAGE_HEADER: usize = 1 + 8;
const MESSAGE_PAGE_LEN: usize = MESSAGE_PAGE_HEADER + MESSAGE_PAGE_SLOTS as usize * 32;
/// Offset of `Config::sequence`: discriminator, three pubkeys, `paused`,
/// the Rand emitter, `current_guardian_set` (state.rs).
const CONFIG_SEQUENCE_OFFSET: usize = 1 + 32 * 3 + 1 + 32 + 4;
/// Most messages fetched per poll.
const BATCH: u64 = 64;

pub struct SolanaSource {
    cfg: SolanaConfig,
    rpc: JsonRpc,
    program: [u8; 32],
}

impl SolanaSource {
    pub fn new(cfg: &SolanaConfig) -> Result<SolanaSource> {
        Self::with_rpc(cfg, &cfg.rpc)
    }

    /// The source read through `rpc`, one of `cfg`'s providers.
    pub fn with_rpc(cfg: &SolanaConfig, rpc: &str) -> Result<SolanaSource> {
        Ok(SolanaSource {
            rpc: JsonRpc::new(rpc),
            program: pubkey32(&cfg.program)?,
            cfg: cfg.clone(),
        })
    }

    /// The data of a program-owned account at `finalized`, or `None`.
    async fn account(&self, key: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        match self.owned_account(key).await? {
            Some((true, data)) => Ok(Some(data)),
            Some((false, _)) => bail!(
                "account {} is not owned by the bridge program",
                bs58::encode(key).into_string()
            ),
            None => Ok(None),
        }
    }

    /// An account at `finalized`, if there is one: whether the program owns it,
    /// and its data.
    async fn owned_account(&self, key: &[u8; 32]) -> Result<Option<(bool, Vec<u8>)>> {
        let result = self
            .rpc
            .call(
                "getAccountInfo",
                json!([bs58::encode(key).into_string(), { "encoding": "base64", "commitment": "finalized" }]),
            )
            .await?;
        let value = &result["value"];
        if value.is_null() {
            return Ok(None);
        }
        let owner = value["owner"].as_str().unwrap_or_default();
        let owned = pubkey32(owner).ok() == Some(self.program);
        let data = value["data"][0]
            .as_str()
            .ok_or_else(|| anyhow!("account data is not base64"))?;
        Ok(Some((
            owned,
            base64::engine::general_purpose::STANDARD
                .decode(data)
                .context("account data")?,
        )))
    }

    /// A message page, or `None` if the program has not created it. Lamports
    /// sent to the address ahead of time leave an account the program does not
    /// own, and that is the same as no page.
    async fn message_page(&self, page: u64) -> Result<Option<Vec<u8>>> {
        let (key, _) = find_program_address(&[b"msg-page", &page.to_le_bytes()], &self.program)?;
        match self.owned_account(&key).await? {
            Some((true, data)) => {
                check_message_page(&data, page)?;
                Ok(Some(data))
            }
            _ => Ok(None),
        }
    }

    async fn program_sequence(&self) -> Result<u64> {
        let (key, _) = find_program_address(&[b"config"], &self.program)?;
        let data = self
            .account(&key)
            .await?
            .ok_or_else(|| anyhow!("{}: the bridge is not initialized", self.cfg.name))?;
        if data.first() != Some(&DISCRIMINATOR_CONFIG) {
            bail!("config account has the wrong discriminator");
        }
        let bytes = data
            .get(CONFIG_SEQUENCE_OFFSET..CONFIG_SEQUENCE_OFFSET + 8)
            .ok_or_else(|| anyhow!("config account too short"))?;
        Ok(u64::from_le_bytes(bytes.try_into().expect("8")))
    }
}

/// `PostedMessage`: discriminator, `sequence: u64` LE, Borsh `Vec<u8>` body.
fn parse_posted_message(data: &[u8], expect_sequence: u64) -> Result<Vec<u8>> {
    if data.first() != Some(&DISCRIMINATOR_POSTED_MESSAGE) {
        bail!("message account has the wrong discriminator");
    }
    let sequence = u64::from_le_bytes(
        data.get(1..9)
            .ok_or_else(|| anyhow!("message account too short"))?
            .try_into()
            .expect("8"),
    );
    if sequence != expect_sequence {
        bail!("message account holds sequence {sequence}, expected {expect_sequence}");
    }
    let len = u32::from_le_bytes(
        data.get(9..13)
            .ok_or_else(|| anyhow!("message account too short"))?
            .try_into()
            .expect("4"),
    ) as usize;
    Ok(data
        .get(13..13 + len)
        .ok_or_else(|| anyhow!("message body truncated"))?
        .to_vec())
}

fn check_message_page(data: &[u8], page: u64) -> Result<()> {
    if data.first() != Some(&DISCRIMINATOR_MESSAGE_PAGE) {
        bail!("message page has the wrong discriminator");
    }
    if data.len() != MESSAGE_PAGE_LEN {
        bail!("message page has the wrong length, {}", data.len());
    }
    let held = u64::from_le_bytes(data[1..MESSAGE_PAGE_HEADER].try_into().expect("8"));
    if held != page {
        bail!("message page holds page {held}, expected {page}");
    }
    Ok(())
}

/// The address in `sequence`'s slot of a checked page, or `None` for all zeroes.
fn message_page_slot(data: &[u8], sequence: u64) -> Option<[u8; 32]> {
    let start = MESSAGE_PAGE_HEADER + (sequence % MESSAGE_PAGE_SLOTS) as usize * 32;
    let slot: [u8; 32] = data[start..start + 32].try_into().expect("32");
    (slot != [0u8; 32]).then_some(slot)
}

impl Source for SolanaSource {
    fn name(&self) -> &str {
        &self.cfg.name
    }

    fn start(&self) -> Cursor {
        Cursor {
            next_block: 0,
            next_sequence: self.cfg.start_sequence,
        }
    }

    async fn poll(&self, cursor: &Cursor) -> Result<(Vec<Observed>, Cursor)> {
        let (located, next) = self.poll_located(cursor).await?;
        Ok((located.into_iter().map(|l| l.message).collect(), next))
    }

    async fn poll_located(&self, cursor: &Cursor) -> Result<(Vec<Located>, Cursor)> {
        let head = self.program_sequence().await?;
        let mut out = Vec::new();
        let mut next = cursor.next_sequence;
        // The page of the last sequence read, so a batch reads each page once.
        let mut page: Option<(u64, Option<Vec<u8>>)> = None;
        while next < head && (out.len() as u64) < BATCH {
            let number = next / MESSAGE_PAGE_SLOTS;
            if page.as_ref().map(|(held, _)| *held) != Some(number) {
                page = Some((number, self.message_page(number).await?));
            }
            let slot = page
                .as_ref()
                .and_then(|(_, data)| data.as_deref())
                .and_then(|data| message_page_slot(data, next));
            let key = match slot {
                Some(key) => key,
                None => find_program_address(&[b"msg", &next.to_le_bytes()], &self.program)?.0,
            };
            // The config is final but the message is not there: the reads
            // straddled a slot. It will be there on the next poll.
            let Some(data) = self.account(&key).await? else {
                break;
            };
            let observed = Observed::new(parse_posted_message(&data, next)?)?;
            if observed.sequence != next || observed.emitter_chain != bridge_codec::CHAIN_SOLANA {
                bail!(
                    "{}: message {next} carries sequence {} from chain {}",
                    self.cfg.name,
                    observed.sequence,
                    observed.emitter_chain
                );
            }
            out.push(Located {
                message: observed,
                resume: Cursor {
                    next_block: 0,
                    next_sequence: next,
                },
            });
            next += 1;
        }
        Ok((
            out,
            Cursor {
                next_block: 0,
                next_sequence: next,
            },
        ))
    }
}

impl Confirm for SolanaSource {}

/// Solana's `Pubkey::find_program_address`, without the SDK: the first bump
/// from 255 down whose hash is *not* a point on the ed25519 curve.
pub fn find_program_address(seeds: &[&[u8]], program: &[u8; 32]) -> Result<([u8; 32], u8)> {
    for bump in (0..=255u8).rev() {
        let mut hasher = Sha256::new();
        for seed in seeds {
            hasher.update(seed);
        }
        hasher.update([bump]);
        hasher.update(program);
        hasher.update(b"ProgramDerivedAddress");
        let hash: [u8; 32] = hasher.finalize().into();
        if curve25519_dalek::edwards::CompressedEdwardsY(hash)
            .decompress()
            .is_none()
        {
            return Ok((hash, bump));
        }
    }
    bail!("no viable bump seed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_posted_message() {
        let mut data = vec![DISCRIMINATOR_POSTED_MESSAGE];
        data.extend_from_slice(&7u64.to_le_bytes());
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(&[1, 2, 3, 0, 0]); // over-allocated tail is ignored
        assert_eq!(parse_posted_message(&data, 7).unwrap(), vec![1, 2, 3]);
        assert!(parse_posted_message(&data, 8).is_err());
    }
}
