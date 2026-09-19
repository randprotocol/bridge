//! `PostedMessage` accounts from the Solana program.
//!
//! The program writes each outbound body, already encoded, into the PDA
//! `["msg", sequence LE]`, and its config PDA carries the next sequence, so
//! the source walks sequences rather than scanning transactions: nothing can
//! be missed and nothing needs parsing but two account layouts. Both reads
//! are at `finalized` commitment.

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use serde_json::json;
use sha2::{Digest, Sha256};

use super::{Cursor, Source};
use crate::config::{pubkey32, SolanaConfig};
use crate::message::Observed;
use crate::rpc::JsonRpc;

const DISCRIMINATOR_CONFIG: u8 = 1;
const DISCRIMINATOR_POSTED_MESSAGE: u8 = 5;
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
        Ok(SolanaSource {
            rpc: JsonRpc::new(&cfg.rpc),
            program: pubkey32(&cfg.program)?,
            cfg: cfg.clone(),
        })
    }

    /// The data of a program-owned account at `finalized`, or `None`.
    async fn account(&self, key: &[u8; 32]) -> Result<Option<Vec<u8>>> {
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
        if pubkey32(owner).ok() != Some(self.program) {
            bail!(
                "account {} is not owned by the bridge program",
                bs58::encode(key).into_string()
            );
        }
        let data = value["data"][0]
            .as_str()
            .ok_or_else(|| anyhow!("account data is not base64"))?;
        Ok(Some(
            base64::engine::general_purpose::STANDARD
                .decode(data)
                .context("account data")?,
        ))
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
        let head = self.program_sequence().await?;
        let mut out = Vec::new();
        let mut next = cursor.next_sequence;
        while next < head && (out.len() as u64) < BATCH {
            let (key, _) = find_program_address(&[b"msg", &next.to_le_bytes()], &self.program)?;
            // The config is final but the message is not there: the two reads
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
            out.push(observed);
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
