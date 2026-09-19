//! `MessagePublished` logs from an EVM-family endpoint (Ethereum, BSC, and
//! Tron through its JSON-RPC facade).
//!
//! The event carries everything in the body but three fields the guardian
//! supplies itself (architecture §6.4): the block timestamp, the emitter
//! chain id and the emitter address.

use anyhow::{anyhow, bail, Context, Result};
use bridge_codec::Body;
use serde_json::{json, Value};

use super::{Cursor, Source};
use crate::config::{address20, EvmConfig, Finality};
use crate::crypto::keccak256;
use crate::message::Observed;
use crate::rpc::{hex_data, quantity, JsonRpc};

pub struct EvmSource {
    cfg: EvmConfig,
    rpc: JsonRpc,
    contract: [u8; 20],
    topic0: String,
}

impl EvmSource {
    pub fn new(cfg: &EvmConfig) -> Result<EvmSource> {
        let url = match cfg.kind {
            crate::config::EvmKind::Evm => cfg.rpc.clone(),
            crate::config::EvmKind::Tron => format!("{}/jsonrpc", cfg.rpc.trim_end_matches('/')),
        };
        Ok(EvmSource {
            rpc: JsonRpc::new(&url),
            contract: address20(&cfg.contract)?,
            topic0: format!(
                "0x{}",
                hex::encode(keccak256(b"MessagePublished(uint64,uint32,uint8,bytes)"))
            ),
            cfg: cfg.clone(),
        })
    }

    /// The highest block whose logs are final enough to sign over.
    async fn safe_head(&self) -> Result<u64> {
        match &self.cfg.finality {
            Finality::Tag(tag) => {
                let block = self
                    .rpc
                    .call("eth_getBlockByNumber", json!([tag, false]))
                    .await?;
                if block.is_null() {
                    bail!("{}: no {tag} block yet", self.cfg.name);
                }
                quantity(&block["number"])
            }
            Finality::Confirmations(n) => {
                let head = quantity(&self.rpc.call("eth_blockNumber", json!([])).await?)?;
                Ok(head.saturating_sub(*n))
            }
        }
    }

    async fn block_timestamp(&self, number: u64) -> Result<u32> {
        let block = self
            .rpc
            .call(
                "eth_getBlockByNumber",
                json!([format!("0x{number:x}"), false]),
            )
            .await?;
        let mut ts =
            quantity(&block["timestamp"]).with_context(|| format!("block {number} timestamp"))?;
        // The body carries what `block.timestamp` is inside the contract:
        // seconds. Tron's API reports milliseconds in places; every guardian
        // must land on the same value, so the unit is normalised by
        // magnitude rather than by trusting the facade.
        if ts > 100_000_000_000 {
            ts /= 1000;
        }
        u32::try_from(ts).map_err(|_| anyhow!("block {number} timestamp out of range"))
    }

    fn body_from_log(&self, log: &Value, timestamp: u32) -> Result<Vec<u8>> {
        let topics = log["topics"]
            .as_array()
            .ok_or_else(|| anyhow!("log without topics"))?;
        if topics.len() != 2 {
            bail!(
                "MessagePublished has one indexed field, got {} topics",
                topics.len()
            );
        }
        let seq_word = hex_data(&topics[1])?;
        if seq_word.len() != 32 || seq_word[..24].iter().any(|b| *b != 0) {
            bail!("sequence topic is not a uint64");
        }
        let sequence = u64::from_be_bytes(seq_word[24..].try_into().expect("8"));

        // data = abi.encode(uint32 nonce, uint8 consistencyLevel, bytes payload)
        let data = hex_data(&log["data"])?;
        let word = |i: usize| -> Result<&[u8]> {
            data.get(i * 32..(i + 1) * 32)
                .ok_or_else(|| anyhow!("log data too short"))
        };
        let small = |w: &[u8], bytes: usize| -> Result<u64> {
            if w[..32 - bytes].iter().any(|b| *b != 0) {
                bail!("ABI word wider than its type");
            }
            let mut v = [0u8; 8];
            v[8 - bytes..].copy_from_slice(&w[32 - bytes..]);
            Ok(u64::from_be_bytes(v))
        };
        let nonce = small(word(0)?, 4)? as u32;
        let consistency_level = small(word(1)?, 1)? as u8;
        let offset = small(word(2)?, 8)? as usize;
        let len_word = data
            .get(offset..offset + 32)
            .ok_or_else(|| anyhow!("payload offset out of range"))?;
        let len = small(len_word, 8)? as usize;
        let payload = data
            .get(offset + 32..offset + 32 + len)
            .ok_or_else(|| anyhow!("payload length out of range"))?
            .to_vec();

        let mut emitter_address = [0u8; 32];
        emitter_address[12..].copy_from_slice(&self.contract);
        Ok(Body {
            timestamp,
            nonce,
            emitter_chain: self.cfg.chain,
            emitter_address,
            sequence,
            consistency_level,
            payload,
        }
        .encode())
    }
}

impl Source for EvmSource {
    fn name(&self) -> &str {
        &self.cfg.name
    }

    fn start(&self) -> Cursor {
        Cursor {
            next_block: self.cfg.start_block,
            next_sequence: 0,
        }
    }

    async fn poll(&self, cursor: &Cursor) -> Result<(Vec<Observed>, Cursor)> {
        let safe = self.safe_head().await?;
        if cursor.next_block > safe {
            return Ok((Vec::new(), cursor.clone()));
        }
        let to = safe.min(cursor.next_block + self.cfg.max_log_range.max(1) - 1);
        let logs = self
            .rpc
            .call(
                "eth_getLogs",
                json!([{
                    "address": format!("0x{}", hex::encode(self.contract)),
                    "topics": [self.topic0],
                    "fromBlock": format!("0x{:x}", cursor.next_block),
                    "toBlock": format!("0x{to:x}"),
                }]),
            )
            .await?;
        let logs = logs
            .as_array()
            .ok_or_else(|| anyhow!("eth_getLogs: not an array"))?;

        let mut out = Vec::new();
        let mut next_sequence = cursor.next_sequence;
        for log in logs {
            if log["removed"].as_bool() == Some(true) {
                bail!(
                    "{}: a log below the safe head was removed; refusing to go on",
                    self.cfg.name
                );
            }
            // The filter is the node's word; the address is re-checked here
            // because a body is about to be signed on the strength of it.
            let address =
                address20(log["address"].as_str().unwrap_or_default()).unwrap_or_default();
            if address != self.contract {
                bail!(
                    "{}: node returned a log from another address",
                    self.cfg.name
                );
            }
            let block = quantity(&log["blockNumber"])?;
            let body = self.body_from_log(log, self.block_timestamp(block).await?)?;
            let observed = Observed::new(body)?;
            if observed.sequence < next_sequence {
                continue; // already seen: a re-scan after a restart
            }
            if observed.sequence != next_sequence {
                bail!(
                    "{}: expected sequence {next_sequence}, saw {} — a log is missing",
                    self.cfg.name,
                    observed.sequence
                );
            }
            next_sequence += 1;
            out.push(observed);
        }
        Ok((
            out,
            Cursor {
                next_block: to + 1,
                next_sequence,
            },
        ))
    }
}
