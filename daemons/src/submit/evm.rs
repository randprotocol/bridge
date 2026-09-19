//! `release(bytes)` on an Ethereum-style chain: an EIP-1559 transaction,
//! built, signed and sent over plain JSON-RPC.

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use bridge_codec::Attestation;
use k256::ecdsa::SigningKey;
use rlp::RlpStream;
use serde_json::json;

use super::{consumed_calldata, release_calldata, Outcome};
use crate::config::{address20, EvmConfig};
use crate::crypto::{address_of, keccak256};
use crate::rpc::{hex_data, quantity, quantity_u128, JsonRpc};

pub struct EvmSubmitter {
    name: String,
    rpc: JsonRpc,
    contract: [u8; 20],
    key: SigningKey,
    from: [u8; 20],
}

impl EvmSubmitter {
    pub fn new(cfg: &EvmConfig, secret_hex: &str) -> Result<EvmSubmitter> {
        let bytes = hex::decode(secret_hex.trim().trim_start_matches("0x"))
            .map_err(|_| anyhow!("relayer key is not hex"))?;
        let key = SigningKey::from_slice(&bytes)
            .map_err(|_| anyhow!("relayer key is not a valid scalar"))?;
        let from = address_of(key.verifying_key());
        Ok(EvmSubmitter {
            name: cfg.name.clone(),
            rpc: JsonRpc::new(&cfg.rpc),
            contract: address20(&cfg.contract)?,
            key,
            from,
        })
    }

    pub fn address(&self) -> [u8; 20] {
        self.from
    }

    fn hex_addr(a: &[u8; 20]) -> String {
        format!("0x{}", hex::encode(a))
    }

    pub async fn is_consumed(&self, digest: &[u8; 32]) -> Result<bool> {
        let result = self
            .rpc
            .call(
                "eth_call",
                json!([{ "to": Self::hex_addr(&self.contract), "data": format!("0x{}", hex::encode(consumed_calldata(digest))) }, "latest"]),
            )
            .await?;
        Ok(hex_data(&result)?.last() == Some(&1))
    }

    pub async fn release(&self, attestation: &Attestation, digest: &[u8; 32]) -> Result<Outcome> {
        self.submit(release_calldata(attestation), digest, "release")
            .await
    }

    /// `submitGuardianSetUpgrade(bytes)`: open to anyone, like `release`.
    pub async fn guardian_set_upgrade(
        &self,
        attestation: &[u8],
        digest: &[u8; 32],
    ) -> Result<Outcome> {
        self.submit(
            crate::governance::upgrade_calldata(attestation),
            digest,
            "guardian-set upgrade",
        )
        .await
    }

    /// Sends `data` to the endpoint, unless `digest` is already consumed.
    async fn submit(&self, data: Vec<u8>, digest: &[u8; 32], what: &str) -> Result<Outcome> {
        if self.is_consumed(digest).await? {
            return Ok(Outcome::AlreadyDone);
        }
        let call = json!({
            "from": Self::hex_addr(&self.from),
            "to": Self::hex_addr(&self.contract),
            "data": format!("0x{}", hex::encode(&data)),
        });
        // A release that would revert is found out here, for free.
        let gas = quantity(
            &self
                .rpc
                .call("eth_estimateGas", json!([call]))
                .await
                .with_context(|| format!("{}: {what} would revert", self.name))?,
        )?;
        let gas = gas + gas / 5;

        let chain_id = quantity(&self.rpc.call("eth_chainId", json!([])).await?)?;
        let nonce = quantity(
            &self
                .rpc
                .call(
                    "eth_getTransactionCount",
                    json!([Self::hex_addr(&self.from), "pending"]),
                )
                .await?,
        )?;
        let tip = match self.rpc.call("eth_maxPriorityFeePerGas", json!([])).await {
            Ok(v) => quantity_u128(&v)?,
            Err(_) => 1_000_000_000,
        };
        let head = self
            .rpc
            .call("eth_getBlockByNumber", json!(["latest", false]))
            .await?;
        let base_fee = head
            .get("baseFeePerGas")
            .filter(|v| !v.is_null())
            .map(quantity_u128)
            .transpose()?
            .unwrap_or(0);
        let max_fee = base_fee * 2 + tip;

        let raw = sign_eip1559(
            &self.key,
            chain_id,
            nonce,
            tip,
            max_fee,
            gas,
            &self.contract,
            &data,
        )?;
        let hash = self
            .rpc
            .call(
                "eth_sendRawTransaction",
                json!([format!("0x{}", hex::encode(&raw))]),
            )
            .await?;
        let hash = hash
            .as_str()
            .ok_or_else(|| anyhow!("no transaction hash"))?
            .to_string();
        tracing::info!("{}: {what} sent in {hash}", self.name);

        for _ in 0..120 {
            let receipt = self
                .rpc
                .call("eth_getTransactionReceipt", json!([hash]))
                .await?;
            if !receipt.is_null() {
                if quantity(&receipt["status"])? == 1 {
                    return Ok(Outcome::Submitted(hash));
                }
                // Lost a race to another relayer, most likely.
                if self.is_consumed(digest).await? {
                    return Ok(Outcome::AlreadyDone);
                }
                bail!("{}: {what} {hash} reverted", self.name);
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        bail!("{}: {what} {hash} not mined after six minutes", self.name)
    }
}

fn trimmed(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    &bytes[start..]
}

/// A signed type-2 transaction: `0x02 || rlp([chain_id, nonce, tip, max_fee,
/// gas, to, value = 0, data, access_list = [], y_parity, r, s])`.
#[allow(clippy::too_many_arguments)]
pub fn sign_eip1559(
    key: &SigningKey,
    chain_id: u64,
    nonce: u64,
    tip: u128,
    max_fee: u128,
    gas: u64,
    to: &[u8; 20],
    data: &[u8],
) -> Result<Vec<u8>> {
    let fields = |s: &mut RlpStream| {
        s.append(&chain_id);
        s.append(&nonce);
        s.append(&trimmed(&tip.to_be_bytes()));
        s.append(&trimmed(&max_fee.to_be_bytes()));
        s.append(&gas);
        s.append(&to.as_slice());
        s.append(&0u8); // value
        s.append(&data);
        s.begin_list(0); // access list
    };
    let mut unsigned = RlpStream::new_list(9);
    fields(&mut unsigned);
    let mut preimage = vec![0x02];
    preimage.extend_from_slice(&unsigned.out());
    let hash = keccak256(&preimage);

    let sig = crate::crypto::sign_recoverable(key, &hash)?;
    let mut signed = RlpStream::new_list(12);
    fields(&mut signed);
    signed.append(&sig.v);
    signed.append(&trimmed(&sig.r));
    signed.append(&trimmed(&sig.s));
    let mut raw = vec![0x02];
    raw.extend_from_slice(&signed.out());
    Ok(raw)
}
