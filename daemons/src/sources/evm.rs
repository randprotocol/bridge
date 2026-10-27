//! `MessagePublished` logs from an EVM-family endpoint (Ethereum, BSC, and
//! Tron through its JSON-RPC facade).
//!
//! The event carries everything in the body but three fields the guardian
//! supplies itself (architecture §6.4): the block timestamp, the emitter
//! chain id and the emitter address.

use anyhow::{anyhow, bail, Context, Result};
use bridge_codec::Body;
use serde_json::{json, Value};

use super::{Confirm, Cursor, Located, Source};
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
        Self::with_rpc(cfg, &cfg.rpc)
    }

    /// The source read through `rpc`, one of `cfg`'s providers.
    pub fn with_rpc(cfg: &EvmConfig, rpc: &str) -> Result<EvmSource> {
        let url = match cfg.kind {
            crate::config::EvmKind::Evm => rpc.to_string(),
            crate::config::EvmKind::Tron => format!("{}/jsonrpc", rpc.trim_end_matches('/')),
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

    /// The endpoint's `sequence()` as of `block`: how many messages it had
    /// published through that block, since every `lock` emits one
    /// `MessagePublished` and increments the counter (RandBridgeBase.sol).
    async fn published_through(&self, block: u64) -> Result<u64> {
        let selector = &keccak256(b"sequence()")[..4];
        let result = self
            .rpc
            .call(
                "eth_call",
                json!([
                    {
                        "to": format!("0x{}", hex::encode(self.contract)),
                        "data": format!("0x{}", hex::encode(selector)),
                    },
                    format!("0x{block:x}"),
                ]),
            )
            .await?;
        let word = hex_data(&result)?;
        if word.len() != 32 || word[..24].iter().any(|b| *b != 0) {
            bail!("sequence() did not return a uint64");
        }
        Ok(u64::from_be_bytes(word[24..].try_into().expect("8")))
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
        let (located, next) = self.poll_located(cursor).await?;
        Ok((located.into_iter().map(|l| l.message).collect(), next))
    }

    async fn poll_located(&self, cursor: &Cursor) -> Result<(Vec<Located>, Cursor)> {
        let safe = self.safe_head().await?;
        if cursor.next_block > safe {
            return Ok((Vec::new(), cursor.clone()));
        }
        let to = safe.min(cursor.next_block + self.cfg.max_log_range.max(1) - 1);
        let logs = match self
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
            .await
        {
            Ok(logs) => logs,
            // The node will not serve this range: a public RPC that calls any
            // range older than its log window "archive" (publicnode: HTTP 403
            // past 10 000 blocks behind head, on Ethereum and BSC alike), so a
            // daemon stopped for longer than that would otherwise never catch
            // up. The endpoint's own counter settles whether the range holds
            // anything: `sequence()` at the safe head equal to the sequence the
            // cursor is waiting for means nothing was published through that
            // block, and the scan may resume past it. Anything else keeps the
            // cursor where it is, since a message would be missed.
            Err(refused) => {
                let published = match self.published_through(safe).await {
                    Ok(n) => n,
                    Err(e) => {
                        return Err(refused.context(format!(
                            "{}: and sequence() at block {safe} could not be read: {e:#}",
                            self.cfg.name
                        )))
                    }
                };
                if published != cursor.next_sequence {
                    return Err(refused.context(format!(
                        "{}: blocks [{}, {to}] hold a message this node will not serve (sequence() is {published} at block {safe}, the cursor expects {}); use an RPC that serves that range",
                        self.cfg.name, cursor.next_block, cursor.next_sequence
                    )));
                }
                tracing::warn!(
                    "{}: eth_getLogs [{}, {to}] refused ({refused:#}); sequence() at block {safe} is still {published}, nothing was published through it — resuming at {}",
                    self.cfg.name,
                    cursor.next_block,
                    safe + 1
                );
                return Ok((
                    Vec::new(),
                    Cursor {
                        next_block: safe + 1,
                        next_sequence: cursor.next_sequence,
                    },
                ));
            }
        };
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
            if block < cursor.next_block || block > to {
                bail!(
                    "{}: node returned a log from block {block}, outside the range [{}, {to}] asked for",
                    self.cfg.name,
                    cursor.next_block
                );
            }
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
            // Re-reading this message means scanning its block again; the
            // sequence skips what came before it in that block.
            out.push(Located {
                resume: Cursor {
                    next_block: block,
                    next_sequence: observed.sequence,
                },
                message: observed,
            });
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

impl EvmSource {
    /// The one `MessagePublished` with `sequence` in `block`, from this
    /// provider, rebuilt into a body with this provider's block timestamp.
    async fn body_at(&self, block: u64, sequence: u64) -> Result<Option<Vec<u8>>> {
        let mut seq_word = [0u8; 32];
        seq_word[24..].copy_from_slice(&sequence.to_be_bytes());
        let logs = self
            .rpc
            .call(
                "eth_getLogs",
                json!([{
                    "address": format!("0x{}", hex::encode(self.contract)),
                    "topics": [self.topic0, format!("0x{}", hex::encode(seq_word))],
                    "fromBlock": format!("0x{block:x}"),
                    "toBlock": format!("0x{block:x}"),
                }]),
            )
            .await?;
        let logs = logs
            .as_array()
            .ok_or_else(|| anyhow!("eth_getLogs: not an array"))?;
        let mut found = None;
        for log in logs {
            // The filter is the node's word: every field is checked here.
            if log["removed"].as_bool() == Some(true)
                || address20(log["address"].as_str().unwrap_or_default()).ok()
                    != Some(self.contract)
                || quantity(&log["blockNumber"]).ok() != Some(block)
            {
                continue;
            }
            let topics = log["topics"].as_array();
            let seq_topic = topics.and_then(|t| t.get(1)).and_then(|t| hex_data(t).ok());
            if seq_topic.as_deref() != Some(&seq_word[..]) {
                continue;
            }
            if found.is_some() {
                bail!("{}: two logs for sequence {sequence} in block {block}", self.cfg.name);
            }
            found = Some(self.body_from_log(log, self.block_timestamp(block).await?)?);
        }
        Ok(found)
    }
}

impl Confirm for EvmSource {
    async fn confirm(&self, located: &Located) -> Result<bool> {
        let block = located.resume.next_block;
        if block > self.safe_head().await? {
            return Ok(false); // not final here (yet)
        }
        Ok(self
            .body_at(block, located.message.sequence)
            .await?
            .is_some_and(|body| body == located.message.body))
    }

    /// `sequence()` at the last block scanned equals the next sequence the
    /// scan expects: no lock in the range was left out.
    async fn confirm_through(&self, next: &Cursor) -> Result<Option<bool>> {
        if next.next_block == 0 {
            return Ok(None);
        }
        Ok(Some(
            self.published_through(next.next_block - 1).await? == next.next_sequence,
        ))
    }
}
