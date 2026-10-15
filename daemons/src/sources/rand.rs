//! Burn messages from a Rand node.
//!
//! `rand_getBridgeBurn(sequence)` serves the outbound body verbatim, from
//! committed storage: a Rand block is final when it commits, so there is no
//! confirmation depth to wait out.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::json;

use super::{Cursor, Source};
use crate::config::RandConfig;
use crate::message::Observed;
use crate::rpc::{hex_data, JsonRpc};

const BATCH: u64 = 64;

pub struct RandSource {
    cfg: RandConfig,
    rpc: JsonRpc,
}

impl RandSource {
    pub fn new(cfg: &RandConfig) -> RandSource {
        RandSource {
            rpc: JsonRpc::new(&cfg.rpc),
            cfg: cfg.clone(),
        }
    }
}

/// The bridge's public state, as far as the daemons need it.
pub struct BridgeState {
    pub guardian_set_index: u32,
    pub guardians: Vec<[u8; 20]>,
    pub burn_sequence: u64,
    /// Dilithium2 public keys, index-aligned with `guardians`; empty on a
    /// chain that does not require the co-signature.
    pub pq_guardians: Vec<Vec<u8>>,
}

/// The Rand chain's id, as the node serves it.
pub async fn chain_id(rpc: &JsonRpc) -> Result<u64> {
    rpc.call("rand_chainId", json!([]))
        .await?
        .as_u64()
        .ok_or_else(|| anyhow!("rand_chainId: not a number"))
}

/// The chain's genesis hash, as the node serves it (`rand_getGenesisHash`,
/// 32 bytes as hex). What a genesis-bound governance message binds.
pub async fn genesis_hash(rpc: &JsonRpc) -> Result<[u8; 32]> {
    let v = rpc.call("rand_getGenesisHash", json!([])).await?;
    let text = v
        .as_str()
        .ok_or_else(|| anyhow!("rand_getGenesisHash: not a string"))?;
    crate::config::hex32(text).map_err(|e| anyhow!("rand_getGenesisHash: {e:#}"))
}

pub async fn bridge_state(rpc: &JsonRpc) -> Result<Option<BridgeState>> {
    let v = rpc.call("rand_getBridgeState", json!([])).await?;
    if v["enabled"].as_bool() != Some(true) {
        return Ok(None);
    }
    let guardians = v["guardians"]
        .as_array()
        .ok_or_else(|| anyhow!("rand_getBridgeState: no guardians"))?
        .iter()
        .map(|g| crate::config::address20(g.as_str().unwrap_or_default()))
        .collect::<Result<Vec<_>>>()?;
    Ok(Some(BridgeState {
        guardian_set_index: v["guardian_set_index"]
            .as_u64()
            .ok_or_else(|| anyhow!("no guardian_set_index"))? as u32,
        guardians,
        burn_sequence: v["burn_sequence"]
            .as_u64()
            .ok_or_else(|| anyhow!("no burn_sequence"))?,
        pq_guardians: v["pq_guardians"]
            .as_array()
            .map(|keys| {
                keys.iter()
                    .filter_map(|k| hex::decode(k.as_str()?).ok())
                    .collect()
            })
            .unwrap_or_default(),
    }))
}

/// The message for a Rand cursor past the chain: a cursor kept from another chain, or a node
/// on another chain than the cursor was made for. Named in full so an operator can act on it.
fn ahead(cursor: &Cursor, burn_sequence: u64) -> anyhow::Error {
    anyhow!(
        "rand: the cursor is ahead of the chain — cursors/rand.json expects next_sequence {} but \
         rand_getBridgeState says burn_sequence {burn_sequence}: this cursor was not made for \
         this chain (a cursor kept across a cut, or a node on the wrong chain). Fix the cursor \
         or the node; nothing is read until then",
        cursor.next_sequence
    )
}

/// What a daemon settles with its Rand node before it reads anything (BR-401): the node answers
/// and serves the configured chain (`rand.chain_id`, when set), and the Rand cursor it would
/// resume from is not past the chain's `burn_sequence`. Every failure is an error — a node that
/// does not answer is not skipped over, a cursor ahead of the chain is not polled in silence.
pub async fn check_startup(
    rpc: &JsonRpc,
    configured_chain_id: Option<u64>,
    cursor: &Cursor,
) -> Result<()> {
    if let Some(expected) = configured_chain_id {
        let served = chain_id(rpc).await.context(
            "the Rand node at rand.rpc did not answer rand_chainId; a daemon does not start \
             without confirming its chain",
        )?;
        if served != expected {
            bail!("rand.chain_id is {expected} but the node at rand.rpc serves chain {served}");
        }
    }
    let state = bridge_state(rpc).await.context(
        "the Rand node at rand.rpc did not serve rand_getBridgeState; the Rand cursor cannot be \
         checked against the chain",
    )?;
    if let Some(state) = state {
        if cursor.next_sequence > state.burn_sequence {
            return Err(ahead(cursor, state.burn_sequence));
        }
    }
    Ok(())
}

impl Source for RandSource {
    fn name(&self) -> &str {
        "rand"
    }

    fn start(&self) -> Cursor {
        Cursor {
            next_block: 0,
            next_sequence: self.cfg.start_sequence,
        }
    }

    async fn poll(&self, cursor: &Cursor) -> Result<(Vec<Observed>, Cursor)> {
        let Some(state) = bridge_state(&self.rpc).await? else {
            return Ok((Vec::new(), cursor.clone())); // a chain without a bridge
        };
        if cursor.next_sequence > state.burn_sequence {
            // Never quietly: before this, a cursor past the chain polled forever as "caught up".
            let e = ahead(cursor, state.burn_sequence);
            tracing::error!("{e:#}");
            return Err(e);
        }
        let mut out = Vec::new();
        let mut next = cursor.next_sequence;
        while next < state.burn_sequence && (out.len() as u64) < BATCH {
            let row = self.rpc.call("rand_getBridgeBurn", json!([next])).await?;
            if row.is_null() {
                break;
            }
            let observed = Observed::new(hex_data(&row["body_hex"])?)?;
            if observed.sequence != next || observed.emitter_chain != bridge_codec::CHAIN_RAND {
                bail!(
                    "rand: burn {next} carries sequence {} from chain {}",
                    observed.sequence,
                    observed.emitter_chain
                );
            }
            // The node's digest is a convenience; the one signed is ours.
            if let Some(d) = row["digest"].as_str() {
                if hex::decode(d).ok().as_deref() != Some(&observed.digest[..]) {
                    bail!(
                        "rand: burn {next}: node reports digest {d}, the body hashes to {}",
                        hex::encode(observed.digest)
                    );
                }
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
